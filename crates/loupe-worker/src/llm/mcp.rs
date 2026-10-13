//! Host-side MCP broker plumbing shared by both agent backends.
//!
//! The sandbox sees only a Unix socket and a small proxy subcommand.
//! The trusted worker process retains the server client, mTLS key,
//! job capability, repository id, and job id.

use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::BufReader;
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::LlmRequest;
use crate::sandbox::SandboxBuilder;
use crate::ServerClient;

pub const SANDBOX_LOUPE_BIN: &str = "/loupe/loupe-worker";
pub const SANDBOX_MCP_DIR: &str = "/loupe/mcp";
pub const SANDBOX_MCP_SOCKET: &str = "/loupe/mcp/session.sock";
pub const SANDBOX_BKB_MCP_BIN: &str = "/loupe/bkb-mcp";
pub const DEFAULT_BKB_API_URL: &str = "https://bitcoinknowledge.dev";

/// How long `finish` waits for an accepted session to drain. Only a
/// session that is still serving can consume this; an unclaimed
/// listener is released immediately.
#[cfg(not(test))]
const BROKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const BROKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Clone)]
pub struct McpContext {
	pub worker_binary: crate::sandbox::SandboxPath,
	pub client: Arc<ServerClient>,
	pub bkb_mcp_path: Option<crate::sandbox::SandboxPath>,
	pub bkb_api_url: crate::config::ConfigNonSecret,
}

/// One invocation's trusted broker. Dropping it aborts an unclaimed
/// socket listener; `finish` releases an unclaimed listener and waits
/// for verify-session flushing on a claimed one.
pub struct McpBroker {
	dir: Arc<tempfile::TempDir>,
	task: Option<JoinHandle<Result<()>>>,
	/// Releases the listener when the agent exited without ever
	/// connecting. Signalled only from `finish`, and only observed
	/// before a connection is accepted, so it cannot interrupt a
	/// session that is mid-flush.
	shutdown: CancellationToken,
}

impl McpBroker {
	/// Start a broker with the complete authority and repository scope
	/// carried by one LLM request.
	pub async fn start_for_request(ctx: &McpContext, request: &LlmRequest) -> Result<Self> {
		let repo_id = request.repo_id.context("MCP request is missing its repo id")?;
		let job_capability =
			request.job_capability.clone().context("MCP request is missing its job capability")?;
		let job_id = request.job_id;
		let finding_id = request.finding_id;
		let tool_boundary = request.tool_boundary;
		let security = request.security.clone();
		if finding_id.is_some() && job_id.is_none() {
			anyhow::bail!("verify-mode MCP broker requires both finding_id and job_id");
		}
		let workdir = request.workdir.clone();
		let dir = tempfile::Builder::new()
			.prefix("loupe-mcp-broker-")
			.tempdir()
			.context("creating MCP broker directory")?;
		let socket = dir.path().join("session.sock");
		let listener = UnixListener::bind(&socket)
			.with_context(|| format!("binding MCP broker socket at {}", socket.display()))?;
		let client = ctx.client.clone();
		let shutdown = CancellationToken::new();
		let accept_shutdown = shutdown.clone();
		let task = tokio::spawn(async move {
			let accepted = tokio::select! {
				biased;
				// If both branches are ready, the agent connected before
				// shutdown began. Drain that established session instead of
				// discarding requests already queued on the socket.
				result = listener.accept() => {
					Some(result.context("accepting MCP proxy connection")?)
				},
				_ = accept_shutdown.cancelled() => None,
			};
			// The agent finished without ever starting its MCP client.
			// There is nothing to serve and nothing to flush.
			let Some((stream, _)) = accepted else { return Ok(()) };
			let (read, write) = stream.into_split();
			crate::mcp::run_stream_server(
				crate::mcp::McpSessionContext {
					security,
					tool_boundary,
					client,
					job_capability,
					repo_id,
					job_id,
					finding_id,
					workdir,
				},
				BufReader::new(read),
				write,
			)
			.await
		});
		Ok(Self { dir: Arc::new(dir), task: Some(task), shutdown })
	}

	pub fn sandbox_args(&self) -> Vec<String> {
		vec!["mcp-proxy".into(), "--socket".into(), SANDBOX_MCP_SOCKET.into()]
	}

	pub fn host_dir(&self) -> &Path {
		self.dir.path()
	}
	pub(crate) fn mount_owner(&self) -> Arc<tempfile::TempDir> {
		self.dir.clone()
	}

	/// Wait for the session to drain. Call this on every path out of an
	/// agent invocation, including failure and timeout: the broker
	/// outlives the sandboxed agent, so a verify session's buffered
	/// verdict still reaches the server even when the CLI itself died.
	pub async fn finish(mut self) -> Result<()> {
		self.shutdown.cancel();
		#[allow(
			clippy::expect_used,
			reason = "Consuming finish owns the sole task slot; only finish or Drop can take it."
		)]
		let mut task = self.task.take().expect("broker task is present until finish");
		match tokio::time::timeout(BROKER_SHUTDOWN_TIMEOUT, &mut task).await {
			Ok(result) => {
				result.context("MCP broker task panicked")??;
				Ok(())
			},
			Err(_) => {
				// Dropping a JoinHandle detaches its task. Abort and await it
				// explicitly so a wedged session cannot retain the server
				// client and job capability after this invocation returns.
				task.abort();
				let _ = task.await;
				anyhow::bail!("timed out waiting for MCP broker shutdown")
			},
		}
	}
}

impl Drop for McpBroker {
	fn drop(&mut self) {
		if let Some(task) = self.task.take() {
			task.abort();
		}
	}
}

pub fn bind_mcp_into_sandbox(
	sandbox: SandboxBuilder, ctx: &McpContext, broker: &McpBroker,
) -> SandboxBuilder {
	let mut sandbox = sandbox
		.bind_ro(ctx.worker_binary.clone(), SANDBOX_LOUPE_BIN)
		.bind_ro(crate::sandbox::SandboxPath::mcp_broker(broker), SANDBOX_MCP_DIR);
	if let Some(bkb_path) = &ctx.bkb_mcp_path {
		sandbox = sandbox.bind_ro(bkb_path.clone(), SANDBOX_BKB_MCP_BIN);
	}
	sandbox
}

#[cfg(test)]
mod tests {
	use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
	use tokio::net::UnixStream;
	use tokio_util::sync::CancellationToken;

	use super::*;

	fn test_context() -> McpContext {
		McpContext {
			worker_binary: crate::sandbox::SandboxPath::fixture("/usr/bin/true".into()),
			client: Arc::new(ServerClient::from_parts(
				reqwest::Client::new(),
				"https://loupe-server:8443".parse().unwrap(),
			)),
			bkb_mcp_path: None,
			bkb_api_url: crate::config::SandboxLaunchConfig::default().bkb_api_url().clone(),
		}
	}

	fn test_request() -> LlmRequest {
		LlmRequest {
			security: crate::canary::JobSecurity::new(Default::default(), Vec::new()).unwrap(),
			tool_boundary: crate::llm::prompt::JobToolBoundary::new().unwrap(),
			prompt: crate::llm::prompts::Prompt::instruction("irrelevant").unwrap(),
			sandbox_workdir: crate::sandbox::SandboxPath::fixture(PathBuf::from("/tmp")),
			workdir: PathBuf::from("/tmp"),
			timeout: Duration::from_secs(5),
			cancel: CancellationToken::new(),
			repo_id: Some(1),
			job_id: Some(7),
			job_capability: Some(loupe_proto::JobCapability::from_secret("test-capability")),
			finding_id: None,
		}
	}

	#[tokio::test]
	async fn broker_finishes_when_no_agent_ever_connects() {
		// An agent CLI can exit successfully without ever starting its
		// MCP client. The broker must not turn that into a failure: it
		// blocks in `accept()` forever, so waiting on the task would
		// burn the shutdown timeout and then report an error for a run
		// that actually succeeded.
		let broker = McpBroker::start_for_request(&test_context(), &test_request()).await.unwrap();

		let started = std::time::Instant::now();
		broker.finish().await.expect("an unclaimed broker must finish cleanly");

		assert!(
			started.elapsed() < BROKER_SHUTDOWN_TIMEOUT,
			"finishing an unclaimed broker waited for the shutdown timeout",
		);
	}

	#[tokio::test(flavor = "current_thread")]
	async fn broker_drains_a_connection_queued_before_shutdown() {
		// Keep the broker task from running until both accept and shutdown
		// are ready. Shutdown must not discard a connection the agent
		// established before it exited.
		for attempt in 0..64 {
			let broker =
				McpBroker::start_for_request(&test_context(), &test_request()).await.unwrap();
			let socket = broker.host_dir().join("session.sock");
			let stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
			stream.set_nonblocking(true).unwrap();
			let mut client = BufReader::new(UnixStream::from_std(stream).unwrap());
			client
				.get_mut()
				.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n")
				.await
				.unwrap();
			client.get_mut().shutdown().await.unwrap();

			broker.finish().await.unwrap();

			let mut response = String::new();
			let read = client.read_line(&mut response).await;
			assert!(
				matches!(read, Ok(bytes) if bytes > 0) && response.contains("\"id\":1"),
				"queued MCP connection was discarded during shutdown on attempt {attempt}: \
				 read={read:?}, response={response:?}",
			);
		}
	}

	#[tokio::test]
	async fn broker_aborts_a_session_that_misses_the_shutdown_deadline() {
		let broker = McpBroker::start_for_request(&test_context(), &test_request()).await.unwrap();
		let socket = broker.host_dir().join("session.sock");
		let mut client = BufReader::new(UnixStream::connect(socket).await.unwrap());
		client
			.get_mut()
			.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n")
			.await
			.unwrap();
		let mut response = String::new();
		client.read_line(&mut response).await.unwrap();
		assert!(response.contains("\"id\":1"), "broker did not accept the test session");

		let error = broker.finish().await.expect_err("an open session must hit the deadline");
		assert!(error.to_string().contains("timed out"), "unexpected shutdown error: {error}");

		let mut trailing = String::new();
		let bytes = tokio::time::timeout(Duration::from_secs(1), client.read_line(&mut trailing))
			.await
			.expect("timed-out broker task remained detached and kept its authority")
			.unwrap();
		assert_eq!(bytes, 0, "broker left the session open after its shutdown deadline");
	}

	#[test]
	fn mcp_bind_adds_no_loupe_credentials() {
		let dir = tempfile::tempdir().unwrap();
		let broker =
			McpBroker { dir: Arc::new(dir), task: None, shutdown: CancellationToken::new() };
		let ctx = test_context();
		let cmd = bind_mcp_into_sandbox(SandboxBuilder::fixture("/tmp"), &ctx, &broker)
			.build_fixture("/bin/true");
		let rendered = format!("{:?}", cmd.as_std());
		assert!(!rendered.contains("worker.key"), "private key leaked into sandbox: {rendered}");
		assert!(!rendered.contains("worker.pem"), "worker certificate leaked: {rendered}");
		assert!(!rendered.contains("loupe-server:8443"), "server endpoint leaked: {rendered}");
		assert!(!rendered.contains("LOUPE_WORKER_"), "worker credentials leaked: {rendered}");
	}

	async fn wait_for_source_descriptor(path: &Path, open: bool) -> bool {
		tokio::time::timeout(Duration::from_secs(1), async {
			loop {
				let observed = std::fs::read_dir("/proc/self/fd").unwrap().any(|entry| {
					entry.ok().and_then(|entry| std::fs::read_link(entry.path()).ok()).as_deref()
						== Some(path)
				});
				if observed == open {
					break;
				}
				tokio::time::sleep(Duration::from_millis(2)).await;
			}
		})
		.await
		.is_ok()
	}

	async fn active_citation_stops_with_broker(deadline: bool) {
		let workdir = tempfile::tempdir().unwrap();
		let path = workdir.path().join("source.rs");
		{
			use std::io::Write;
			let mut source = std::fs::File::create(&path).unwrap();
			source.write_all(b"fn vulnerable() {}\n").unwrap();
			// A private sparse regular file keeps the actual streaming traversal
			// active without allocating its logical size. Close this writer before
			// observing the descriptor opened by the MCP citation validator.
			source.set_len(16 * 1024 * 1024 * 1024).unwrap();
		}
		let mut request = test_request();
		request.workdir = workdir.path().to_owned();
		request.sandbox_workdir = crate::sandbox::SandboxPath::fixture(request.workdir.clone());
		let broker = McpBroker::start_for_request(&test_context(), &request).await.unwrap();
		let mut client = UnixStream::connect(broker.host_dir().join("session.sock")).await.unwrap();
		let input = format!(
			"{}\n",
			serde_json::json!({
				"jsonrpc": "2.0", "id": 81, "method": "tools/call",
				"params": {"name": "submit_finding", "arguments": {
					"protocol_version": 1,
					"severity": "high", "title": "Unchecked operation terminates the service",
					"description": "An attacker-controlled request reaches this operation without validation and terminates the service.\n```rust\nfn vulnerable() {}\n```",
					"file": "source.rs", "line_start": 1, "line_end": 1,
					"poc_unified": "--- /dev/null\n+++ b/regression.rs\n@@ -0,0 +1 @@\n+#[test] fn demonstrates_failure() {}\n"
				}}
			})
		);
		client.write_all(input.as_bytes()).await.unwrap();
		let opened = wait_for_source_descriptor(&path, true).await;
		if deadline {
			let error = broker.finish().await.expect_err("active citation must hit the deadline");
			assert!(error.to_string().contains("timed out"));
		} else {
			drop(broker);
		}
		let closed = wait_for_source_descriptor(&path, false).await;
		let shared_cancelled = request.security.cancellation().is_cancelled();
		let quarantined = request.security.is_quarantined();
		// Stop any retained scan before asserting; detached blocking work can
		// otherwise delay runtime shutdown.
		if !closed {
			request.security.cancellation().cancel();
			assert!(wait_for_source_descriptor(&path, false).await, "cleanup did not stop scan");
		}
		assert!(opened, "actual MCP citation traversal never opened its source");
		assert!(!shared_cancelled, "ending one citation operation cancelled shared job security");
		assert!(!quarantined, "ending one citation operation quarantined the job");
		assert!(closed, "forced broker shutdown left the active citation source descriptor open");
	}

	#[tokio::test]
	async fn broker_drop_stops_active_citation_traversal() {
		active_citation_stops_with_broker(false).await;
	}

	#[tokio::test]
	async fn broker_deadline_stops_active_citation_traversal() {
		active_citation_stops_with_broker(true).await;
	}
}
