//! A test agent that speaks MCP to the job's real host broker. Instead of
//! spawning a CLI in the sandbox it starts the broker in-process, connects to
//! its socket and plays a script of tool calls. The catalog, ingress, gate,
//! dispatch, retry and phase client all run; only bwrap and the model are
//! absent.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;

use super::mcp::{McpBroker, McpContext};
use super::{LlmBackend, LlmRequest, LlmResponse};
use crate::ServerClient;

type Script =
	Arc<dyn Fn(ScriptedAgent) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;

/// One tool result as the model would see it.
// debug-ok: test fixture output only.
#[derive(Debug, Clone)]
pub struct ToolResult {
	pub is_error: bool,
	pub text: String,
}

/// The agent's side of one MCP session, handed to the script.
pub struct ScriptedAgent {
	/// The rendered prompt the agent was launched with.
	pub prompt: String,
	reader: BufReader<OwnedReadHalf>,
	writer: OwnedWriteHalf,
	next_id: u64,
}

impl ScriptedAgent {
	async fn send(&mut self, method: &str, params: Option<Value>) -> Result<Value> {
		self.next_id += 1;
		let mut request = json!({"jsonrpc": "2.0", "id": self.next_id, "method": method});
		if let Some(params) = params {
			request["params"] = params;
		}
		self.writer.write_all(format!("{request}\n").as_bytes()).await?;
		let mut line = String::new();
		if self.reader.read_line(&mut line).await? == 0 {
			anyhow::bail!("MCP broker closed the session");
		}
		let response: Value = serde_json::from_str(&line).context("decoding MCP response")?;
		if let Some(error) = response.get("error") {
			anyhow::bail!("MCP protocol error: {error}");
		}
		Ok(response["result"].clone())
	}

	async fn notify(&mut self, method: &str) -> Result<()> {
		let notification = json!({"jsonrpc": "2.0", "method": method});
		self.writer.write_all(format!("{notification}\n").as_bytes()).await?;
		Ok(())
	}

	/// The advertised tool names, in catalog order.
	pub async fn list_tools(&mut self) -> Result<Vec<String>> {
		let result = self.send("tools/list", None).await?;
		let tools =
			result["tools"].as_array().ok_or_else(|| anyhow!("tools/list without tools"))?;
		Ok(tools.iter().filter_map(|tool| tool["name"].as_str().map(str::to_owned)).collect())
	}

	/// Call one tool and return what the model would see.
	pub async fn call(&mut self, name: &str, arguments: Value) -> Result<ToolResult> {
		let result =
			self.send("tools/call", Some(json!({"name": name, "arguments": arguments}))).await?;
		let text = result["content"][0]["text"].as_str().unwrap_or_default().to_owned();
		Ok(ToolResult { is_error: result["isError"] == json!(true), text })
	}
}

/// An [`LlmBackend`] whose "agent" is a script of MCP tool calls.
pub struct ScriptedMcpBackend {
	context: McpContext,
	script: Script,
}

impl ScriptedMcpBackend {
	/// `script` runs once per invocation against a fresh broker session.
	pub fn new<F, Fut>(client: Arc<ServerClient>, script: F) -> Self
	where
		F: Fn(ScriptedAgent) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<()>> + Send + 'static,
	{
		let context = McpContext {
			worker_binary: crate::sandbox::SandboxPath::fixture("/nonexistent/loupe-worker".into()),
			client,
			bkb_mcp_path: None,
			bkb_api_url: crate::config::SandboxLaunchConfig::default().bkb_api_url().clone(),
		};
		Self { context, script: Arc::new(move |agent| Box::pin(script(agent))) }
	}
}

#[async_trait]
impl LlmBackend for ScriptedMcpBackend {
	fn id(&self) -> &'static str {
		"scripted-mcp"
	}

	async fn run(&self, req: LlmRequest) -> Result<LlmResponse> {
		let broker = McpBroker::start_for_request(&self.context, &req).await?;
		let played = self.play(&broker, &req).await;
		let finished = broker.finish().await;
		played?;
		finished?;
		let text = super::cli_output::synthetic_output("scripted agent finished".to_owned())?;
		Ok(LlmResponse { text, backend_id: self.id() })
	}
}

impl ScriptedMcpBackend {
	/// Run the script until it ends, the request is cancelled or its timeout
	/// passes. Stopping drops the script and with it the session socket.
	async fn play(&self, broker: &McpBroker, req: &LlmRequest) -> Result<()> {
		let stream = UnixStream::connect(broker.host_dir().join("session.sock"))
			.await
			.context("connecting to the MCP broker")?;
		let (read, write) = stream.into_split();
		let mut agent = ScriptedAgent {
			prompt: req.prompt.expose().to_owned(),
			reader: BufReader::new(read),
			writer: write,
			next_id: 0,
		};
		agent.send("initialize", Some(json!({"protocolVersion": "2025-06-18"}))).await?;
		agent.notify("notifications/initialized").await?;
		tokio::select! {
			result = (self.script)(agent) => result,
			_ = req.cancel.cancelled() => Err(anyhow!("scripted agent cancelled")),
			_ = tokio::time::sleep(req.timeout) => Err(anyhow!("scripted agent timed out")),
		}
	}
}

#[cfg(test)]
mod tests {
	use std::path::PathBuf;
	use std::time::{Duration, Instant};

	use tokio_util::sync::CancellationToken;

	use super::*;

	fn client() -> Arc<ServerClient> {
		Arc::new(ServerClient::from_parts(
			reqwest::Client::new(),
			"http://127.0.0.1:9/".parse().unwrap(),
		))
	}

	fn request(timeout: Duration, cancel: CancellationToken) -> LlmRequest {
		LlmRequest {
			security: crate::canary::JobSecurity::new(Default::default(), Vec::new()).unwrap(),
			tool_boundary: crate::llm::prompt::JobToolBoundary::new().unwrap(),
			prompt: crate::llm::prompts::Prompt::instruction("scripted fixture prompt").unwrap(),
			sandbox_workdir: crate::sandbox::SandboxPath::fixture(PathBuf::from("/tmp")),
			workdir: PathBuf::from("/tmp"),
			timeout,
			cancel,
			repo_id: Some(1),
			mcp_mode: crate::mcp::McpMode::LegacyDiscovery { job_id: Some(7) },
			phase: None,
			token_budget: None,
			job_capability: Some(loupe_proto::JobCapability::from_secret("scripted-capability")),
		}
	}

	#[tokio::test]
	async fn plays_a_script_against_the_real_broker() {
		let seen = Arc::new(std::sync::Mutex::new(None));
		let observed = seen.clone();
		let backend = ScriptedMcpBackend::new(client(), move |mut agent| {
			let observed = observed.clone();
			async move {
				let tools = agent.list_tools().await?;
				let unknown = agent.call("no_such_tool", json!({})).await?;
				*observed.lock().unwrap() = Some((agent.prompt.clone(), tools, unknown));
				Ok(())
			}
		});
		let response = backend.run(request(Duration::from_secs(5), CancellationToken::new())).await;
		assert!(response.is_ok(), "{response:?}");
		let (prompt, tools, unknown) = seen.lock().unwrap().take().expect("script ran");
		assert!(prompt.contains("scripted fixture prompt"));
		assert!(tools.iter().any(|tool| tool == "query_prior_findings"), "{tools:?}");
		assert!(unknown.is_error, "{unknown:?}");
	}

	async fn stalled(cancel: CancellationToken, timeout: Duration) -> Duration {
		let started_script = Arc::new(std::sync::atomic::AtomicBool::new(false));
		let flag = started_script.clone();
		let backend = ScriptedMcpBackend::new(client(), move |mut agent| {
			let flag = flag.clone();
			async move {
				agent.list_tools().await?;
				flag.store(true, std::sync::atomic::Ordering::SeqCst);
				std::future::pending::<()>().await;
				Ok(())
			}
		});
		let started = Instant::now();
		let result =
			tokio::time::timeout(Duration::from_secs(5), backend.run(request(timeout, cancel)))
				.await
				.expect("the backend must stop a stalled script");
		assert!(result.is_err(), "a stopped script is not a successful run");
		assert!(started_script.load(std::sync::atomic::Ordering::SeqCst), "the script never ran");
		started.elapsed()
	}

	#[tokio::test]
	async fn cancellation_stops_the_script() {
		let cancel = CancellationToken::new();
		let trigger = cancel.clone();
		tokio::spawn(async move {
			tokio::time::sleep(Duration::from_millis(100)).await;
			trigger.cancel();
		});
		stalled(cancel, Duration::from_secs(60)).await;
	}

	#[tokio::test]
	async fn the_timeout_stops_the_script() {
		let elapsed = stalled(CancellationToken::new(), Duration::from_millis(100)).await;
		assert!(elapsed >= Duration::from_millis(100), "{elapsed:?}");
	}
}
