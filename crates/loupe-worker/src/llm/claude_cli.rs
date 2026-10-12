//! Backend that shells out to the `claude` CLI.
//!
//! Runs `claude --dangerously-skip-permissions -p` with the prompt on stdin in the
//! bubblewrap sandbox so the agent can read the worktree at `/workdir`
//! but can't write to it or persist any state across invocations. The
//! `--dangerously-skip-permissions` flag is acceptable here only
//! because the sandbox is the security boundary, not the CLI's
//! permission system.
//!
//! Model traffic reaches a loopback adapter in the private sandbox network;
//! the host-side broker alone connects to the provider API.
//!
//! When constructed with [`McpContext`], each invocation writes a
//! per-call MCP config and passes `--mcp-config` to claude. The
//! agent then has the loupe tool surface (`query_prior_findings`,
//! etc., served by a host-side broker) for the duration of the call.
//! The sandbox receives only the credential-free proxy and its Unix
//! socket.

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::time::timeout;

use super::cli_output::MAX_CLI_OUTPUT_BYTES;
use super::mcp::{
	bind_mcp_into_sandbox, McpBroker, McpContext, SANDBOX_BKB_MCP_BIN, SANDBOX_LOUPE_BIN,
};
use super::model_broker::{
	bind_model_into_sandbox, ModelBrokerBackend, ModelBrokerContext, SANDBOX_MODEL_SOCKET,
};
use super::{CliModelConfig, LlmBackend, LlmRequest, LlmResponse};
use crate::sandbox::{SandboxBuilder, SandboxNetworkConfig};

const BACKEND_ID: &str = "claude-cli";
const CLAUDE_BIN: &str = "claude";
pub const DEFAULT_CLAUDE_MODEL: &str = "claude-opus-4-7";
pub const DEFAULT_CLAUDE_EFFORT: &str = "max";
const MAX_CLI_DIAGNOSTIC_CHARS: usize = 2_000;
const MODEL_PROXY_LISTEN: &str = "127.0.0.1:0";
const SANDBOX_MODEL_PORT_FILE: &str = "/tmp/loupe-model.port";

fn claude_mcp_args() -> [&'static str; 3] {
	["--mcp-config", SANDBOX_MCP_CONFIG, "--strict-mcp-config"]
}

/// Fixed sandbox path for the per-call MCP config file claude reads.
/// The host-side scratch dir (a `tempfile::TempDir`) bind-mounts
/// onto this path; dropping the scratch dir unlinks the source
/// (sandbox view becomes EROFS, which the next call recreates).
const SANDBOX_MCP_CONFIG: &str = "/loupe/mcp-config.json";

/// Per-call MCP scratch: a host-side tempdir holding the JSON
/// config that `claude --mcp-config` reads. The `TempDir` is
/// returned so the caller keeps it alive until after claude exits;
/// dropping the `TempDir` unlinks the config file.
struct McpScratch {
	#[allow(dead_code)] // RAII — drop at end of caller's scope cleans up.
	dir: tempfile::TempDir,
	config_path: PathBuf,
}

fn prepare_mcp_scratch(ctx: &McpContext, broker: &McpBroker, repo_id: i64) -> Result<McpScratch> {
	let dir = tempfile::Builder::new()
		.prefix("loupe-mcp-")
		.tempdir()
		.context("creating MCP scratch tempdir")?;
	let config_path = dir.path().join("mcp-config.json");
	let args = broker.sandbox_args();
	let mut servers = serde_json::Map::new();
	servers.insert(
		"loupe".to_string(),
		serde_json::json!({
			"type": "stdio",
			// Inside the sandbox the worker binary is mounted at
			// SANDBOX_LOUPE_BIN, the cert files under /loupe/...
			// — see the bind_ro calls above.
			"command": SANDBOX_LOUPE_BIN,
			"args": args,
			// The MCP child inherits the bwrap'd env, including any
			// explicit Claude credential forwarded to the agent
			// (irrelevant for the MCP child but harmless). No extra
			// env is needed at this layer.
			"env": {}
		}),
	);
	// Conditionally attach bkb-mcp. The binary is bind-mounted under
	// /loupe/bkb-mcp by the caller (see `run` below). bkb-mcp itself
	// is a thin client to the BKB HTTP API: we always override its
	// compiled-in localhost default to the worker-configured API URL
	// by setting `BKB_API_URL` in the per-MCP
	// `env` block — that's MCP-server-scoped, doesn't leak into
	// claude or other potential sibling MCP children.
	if ctx.bkb_mcp_path.is_some() {
		servers.insert(
			"bkb".to_string(),
			serde_json::json!({
				"type": "stdio",
				"command": SANDBOX_BKB_MCP_BIN,
				"args": [],
				"env": { "BKB_API_URL": ctx.bkb_api_url.for_operation() }
			}),
		);
	}
	let config = serde_json::json!({ "mcpServers": servers });
	std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)
		.with_context(|| format!("writing MCP config at {}", config_path.display()))?;
	tracing::debug!(
		config_path = %config_path.display(),
		repo_id,
		"loupe-mcp: prepared per-call scratch config",
	);
	Ok(McpScratch { dir, config_path })
}

pub struct ClaudeCliBackend {
	bin: String,
	agent: CliModelConfig,
	mcp: Option<McpContext>,
	model_broker: Option<ModelBrokerContext>,
	network: SandboxNetworkConfig,
	log_agent_output: bool,
	#[cfg(test)]
	disable_sandbox: bool,
	#[cfg(test)]
	disable_network: bool,
}

impl ClaudeCliBackend {
	pub fn new() -> Self {
		Self {
			bin: CLAUDE_BIN.to_owned(),
			agent: CliModelConfig {
				model: crate::config::ConfiguredText::Builtin(DEFAULT_CLAUDE_MODEL),
				effort: crate::config::ConfiguredText::Builtin(DEFAULT_CLAUDE_EFFORT),
			},
			mcp: None,
			model_broker: None,
			network: SandboxNetworkConfig::default(),
			log_agent_output: false,
			#[cfg(test)]
			disable_sandbox: false,
			#[cfg(test)]
			disable_network: false,
		}
	}

	pub fn with_bin(bin: impl Into<String>) -> Self {
		Self { bin: bin.into(), ..Self::new() }
	}

	pub fn with_agent_config(mut self, agent: CliModelConfig) -> Self {
		self.agent = agent;
		self
	}

	pub fn with_log_agent_output(mut self, enabled: bool) -> Self {
		self.log_agent_output = enabled;
		self
	}

	pub fn with_network_config(mut self, network: SandboxNetworkConfig) -> Self {
		self.network = network;
		self
	}

	#[cfg(test)]
	fn with_sandbox_disabled_for_tests(mut self) -> Self {
		self.disable_sandbox = true;
		self
	}

	#[cfg(test)]
	fn with_network_disabled_for_tests(mut self) -> Self {
		self.disable_network = true;
		self
	}

	/// Attach an MCP server to every invocation. When set, each call
	/// writes a temp `mcp-config.json` and passes `--mcp-config` to
	/// claude; the agent sees the host-side broker's tool surface
	/// through a credential-free proxy.
	pub fn with_mcp_context(mut self, mcp: McpContext) -> Self {
		self.mcp = Some(mcp);
		self
	}

	pub fn with_model_broker_context(mut self, model_broker: ModelBrokerContext) -> Self {
		self.model_broker = Some(model_broker);
		self
	}
}

impl Default for ClaudeCliBackend {
	fn default() -> Self {
		Self::new()
	}
}

#[async_trait]
impl LlmBackend for ClaudeCliBackend {
	fn id(&self) -> &'static str {
		BACKEND_ID
	}

	async fn run(&self, req: LlmRequest) -> Result<LlmResponse> {
		tracing::debug!(
			backend = BACKEND_ID,
			workdir = %req.workdir.display(),
			model = %self.agent.model.for_operation(),
			effort = %self.agent.effort.for_operation(),
			prompt_chars = req.prompt.expose().chars().count(),
			timeout_ms = req.timeout.as_millis() as u64,
			"claude-cli: invoking",
		);
		let started = std::time::Instant::now();
		let model_context = self
			.model_broker
			.as_ref()
			.context("claude backend requires a host-side model broker context")?;
		let mut model_broker = Some(
			model_context
				.start_session(ModelBrokerBackend::Claude {
					model: self.agent.model.clone(),
					effort: self.agent.effort.clone(),
				})
				.await
				.context("starting host-side Claude model broker")?,
		);

		#[cfg(test)]
		let sandbox_builder = if self.disable_sandbox {
			SandboxBuilder::disabled_for_tests(&req.workdir)
		} else {
			SandboxBuilder::new(&req.workdir)
		};
		#[cfg(not(test))]
		let sandbox_builder = SandboxBuilder::new(&req.workdir);

		#[cfg(test)]
		let attach_network = !self.disable_network;
		#[cfg(not(test))]
		let attach_network = true;
		let sandbox_builder = if attach_network {
			let bkb_api_url = self
				.mcp
				.as_ref()
				.filter(|ctx| ctx.bkb_mcp_path.is_some())
				.map(|ctx| ctx.bkb_api_url.for_operation());
			let required_hosts = super::required_network_hosts(bkb_api_url)?;
			if super::sandbox_requires_egress_setup(&self.network, &required_hosts) {
				sandbox_builder
					.with_network(self.network.clone(), required_hosts)
					.with_network_supervisor(model_context.worker_binary())
			} else {
				sandbox_builder
			}
		} else {
			sandbox_builder
		};
		let mut sandbox = sandbox_builder
			// Make the `claude` install reachable — by default the
			// sandbox only mounts system binaries, libraries, and public
			// runtime files, so per-user installs at ~/.local/bin/... are
			// invisible without this.
			.allow_binary(&self.bin)
			.with_context(|| format!("preparing sandbox for `{}`", self.bin))?
			// Claude requires a value before attempting an API call. This
			// fixed sentinel is not authority; the host broker strips it.
			.set_env("ANTHROPIC_AUTH_TOKEN", "loupe-brokered")
			.set_env("DISABLE_AUTOUPDATER", "1")
			.set_env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
			.set_env("DISABLE_TELEMETRY", "1")
			.set_env("DISABLE_ERROR_REPORTING", "1")
			.set_env("DISABLE_BUG_COMMAND", "1");
		let model_session = model_broker.as_ref().expect("model broker was just started");
		sandbox = bind_model_into_sandbox(sandbox, model_context, model_session);

		// Optional MCP attachment. Held in a local so its `TempDir`
		// lives until after the subprocess returns — dropping it
		// early would unlink the config file out from under claude.
		let mut mcp_broker = None;
		let _mcp_scratch = match (&self.mcp, req.repo_id) {
			(Some(ctx), Some(repo_id)) => {
				let broker = McpBroker::start_for_request(ctx, &req)
					.await
					.context("starting host-side MCP broker")?;
				let scratch = prepare_mcp_scratch(ctx, &broker, repo_id)
					.context("preparing MCP scratch directory")?;
				sandbox = bind_mcp_into_sandbox(sandbox, ctx, &broker)
					.bind_ro(scratch.config_path.clone(), SANDBOX_MCP_CONFIG);
				mcp_broker = Some(broker);
				Some(scratch)
			},
			(Some(_), None) => {
				tracing::debug!(
					backend = BACKEND_ID,
					"MCP context configured but request has no repo_id; skipping --mcp-config",
				);
				None
			},
			_ => None,
		};

		let mut agent_args = claude_invocation_args(&self.agent);
		if _mcp_scratch.is_some() {
			agent_args.extend(claude_mcp_args().into_iter().map(str::to_owned));
		}
		#[cfg(test)]
		let mut cmd = if self.disable_sandbox {
			let mut cmd =
				sandbox.set_env("ANTHROPIC_BASE_URL", "http://127.0.0.1:1").build(&self.bin);
			cmd.args(&agent_args);
			cmd
		} else {
			build_model_proxied_command(&sandbox, &self.bin, &agent_args)
		};
		#[cfg(not(test))]
		let mut cmd = build_model_proxied_command(&sandbox, &self.bin, &agent_args);
		cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
		cmd.kill_on_drop(true);

		let mut child = cmd
			.spawn()
			.with_context(|| format!("spawning `{}` (is the claude CLI installed?)", self.bin))?;

		let run_outcome = timeout(
			req.timeout,
			super::cli_stdin::drive(&mut child, &req.prompt, req.cancel.clone()),
		)
		.await;

		// `kill_on_drop` only sends the signal. Explicitly kill and wait
		// after a timeout, cancellation, or wait error so broker shutdown
		// cannot race an agent or proxy that is still exiting. If
		// termination itself fails, abort the broker rather than preserving
		// authority for that process.
		if !matches!(&run_outcome, Ok(Ok(_)))
			&& let Err(error) = child.kill().await
		{
			drop(mcp_broker.take());
			drop(model_broker.take());
			return Err(
				anyhow::Error::from(error).context("terminating claude CLI before broker shutdown")
			);
		}

		// The agent process is gone by now, so drain the broker before
		// propagating any failure. A verify session buffers its verdict
		// until the MCP stream closes; aborting the broker on the error
		// paths would discard a verdict the agent had already produced.
		let broker_outcome = match mcp_broker.take() {
			Some(broker) => broker.finish().await.context("finishing host-side MCP broker"),
			None => Ok(()),
		};
		let model_broker_outcome = match model_broker.take() {
			Some(broker) => broker
				.finish()
				.await
				.map(|usage| {
					tracing::debug!(
						requests = usage.requests,
						output_bytes = usage.output_bytes,
						tokens = usage.tokens,
						"claude-cli: model broker usage"
					);
				})
				.context("finishing host-side Claude model broker"),
			None => Ok(()),
		};

		let super::cli_stdin::CliRun { status, stdout, stderr, stdin_failed, killed_for_stdin } =
			match run_outcome {
				Ok(inner) => inner?,
				Err(_) => return Err(anyhow!("claude CLI timed out after {:?}", req.timeout)),
			};

		let output_truncated = stdout.truncated || stderr.truncated;
		if !status.success() && !killed_for_stdin {
			let stderr_text = stderr.diagnostic();
			let stdout_text = stdout.diagnostic();
			tracing::debug!(
				backend = BACKEND_ID,
				exit = ?status.code(),
				stdout_chars = stdout.len(),
				stderr_chars = stderr.len(),
				elapsed_ms = started.elapsed().as_millis() as u64,
				"claude-cli: subprocess failed",
			);
			// Some CLIs (claude included) print "please log in" /
			// auth-error messages to stdout, not stderr — surface
			// both so the operator's log shows whichever the CLI
			// chose. Trim and truncate so a multi-MB diagnostic dump
			// doesn't drown the log line.
			return Err(super::cli_output::CliProcessFailure {
				backend: "claude",
				status,
				stderr: stderr_text,
				stdout: stdout_text,
				max_chars: MAX_CLI_DIAGNOSTIC_CHARS,
			}
			.into());
		}
		if stdin_failed {
			return Err(anyhow!("CLI prompt stdin delivery failed"));
		}
		// Reported last: a CLI failure explains a broker failure, so the
		// CLI diagnostic is the more useful error to surface.
		broker_outcome?;
		model_broker_outcome?;

		if output_truncated {
			return Err(anyhow!(
				"claude CLI output exceeds {MAX_CLI_OUTPUT_BYTES} bytes per stream"
			));
		}
		let text = stdout.text().map_err(|e| anyhow!("claude CLI stdout was not UTF-8: {e}"))?;
		// Debug instrumentation hooks (no-ops when env vars unset):
		//
		// - worker config `[logging].agent_output = true` dumps the full
		//   agent stdout/stderr at info level so a debugging session can
		//   see the agent's prose (the regular flow only logs char counts).
		// - claude's stderr on a *successful* exit is otherwise dropped;
		//   we surface non-empty stderr content at info regardless when
		//   the env var is set, which catches claude's own diagnostics
		//   ("rate-limit hit, retrying", auth warnings, etc.).
		if self.log_agent_output {
			tracing::info!(
				backend = BACKEND_ID,
				agent_stdout = %text.for_log(),
				"claude-cli: agent stdout (full)"
			);
			if !stderr.is_empty() {
				let stderr_text = stderr.diagnostic();
				tracing::info!(
					backend = BACKEND_ID,
					agent_stderr = %stderr_text.for_log(),
					"claude-cli: agent stderr (full)"
				);
			}
		}
		tracing::debug!(
			backend = BACKEND_ID,
			elapsed_ms = started.elapsed().as_millis() as u64,
			stdout_chars = text.for_log().chars().count(),
			stderr_chars = stderr.len(),
			"claude-cli: subprocess succeeded",
		);
		Ok(LlmResponse { text, backend_id: BACKEND_ID })
	}
}

fn build_model_proxied_command(
	sandbox: &SandboxBuilder, agent_bin: &str, agent_args: &[String],
) -> tokio::process::Command {
	let mut cmd = sandbox.build(SANDBOX_LOUPE_BIN);
	cmd.args([
		"model-proxy",
		"--socket",
		SANDBOX_MODEL_SOCKET,
		"--listen",
		MODEL_PROXY_LISTEN,
		"--port-file",
		SANDBOX_MODEL_PORT_FILE,
		"--",
		agent_bin,
	]);
	cmd.args(agent_args);
	cmd
}

fn claude_invocation_args(agent: &CliModelConfig) -> Vec<String> {
	vec![
		"--dangerously-skip-permissions".to_owned(),
		"--model".to_owned(),
		agent.model.for_operation().to_owned(),
		"--effort".to_owned(),
		agent.effort.for_operation().to_owned(),
		"--no-session-persistence".to_owned(),
		"-p".to_owned(),
	]
}

#[cfg(test)]
type PromptTestBackend = ClaudeCliBackend;

#[cfg(test)]
#[path = "prompt_delivery_tests.rs"]
mod prompt_delivery_tests;

#[cfg(test)]
mod tests {
	#[cfg(unix)]
	async fn run_output_fixture(
		stdout_bytes: usize, stderr_bytes: usize, exit_code: u8,
	) -> (Result<LlmResponse>, bool) {
		use std::os::unix::fs::PermissionsExt;
		let workdir = tempfile::tempdir().unwrap();
		let script = workdir.path().join("output-fixture");
		let finished = workdir.path().join("finished");
		std::fs::write(&script, format!(
			"#!/bin/sh\nhead -c {stdout_bytes} /dev/zero | tr '\\000' x\nprintf 'stdout-tail-diagnostic'\nhead -c {stderr_bytes} /dev/zero | tr '\\000' x >&2\nprintf 'stderr-tail-diagnostic' >&2\ntouch {}\nexit {exit_code}\n",
			sh_single_quote(&finished),
		)).unwrap();
		std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
		let backend = ClaudeCliBackend::with_bin(script.to_string_lossy())
			.with_sandbox_disabled_for_tests()
			.with_model_broker_context(test_model_broker("/bin/true"));
		let result = backend
			.run(LlmRequest {
				tool_boundary: crate::llm::prompt::JobToolBoundary::new().unwrap(),
				prompt: crate::llm::prompts::Prompt::instruction("fixture").unwrap(),
				workdir: workdir.path().to_owned(),
				timeout: Duration::from_secs(5),
				cancel: CancellationToken::new(),
				repo_id: None,
				job_id: None,
				job_capability: None,
				finding_id: None,
			})
			.await;
		(result, finished.exists())
	}

	#[cfg(unix)]
	#[tokio::test]
	async fn stdout_collection_has_a_budget_and_drains_the_pipe() {
		// Concurrent test forks can inherit a writable script descriptor and cause ETXTBSY.
		if !in_env(
			"llm::claude_cli::tests::stdout_collection_has_a_budget_and_drains_the_pipe",
			"output-fixture",
			&[],
		) {
			return;
		}
		let (result, finished) = run_output_fixture(1024 * 1024 + 65536, 0, 0).await;
		assert!(finished, "collector must drain the child pipe to avoid deadlock: {result:?}");
		assert!(result.is_err(), "CLI accepted stdout beyond collection budget");
		assert!(result.unwrap_err().to_string().contains("output exceeds"));
	}

	#[cfg(unix)]
	#[tokio::test]
	async fn stderr_collection_has_a_budget_and_drains_the_pipe() {
		if !in_env(
			"llm::claude_cli::tests::stderr_collection_has_a_budget_and_drains_the_pipe",
			"output-fixture",
			&[],
		) {
			return;
		}
		let (result, finished) = run_output_fixture(0, 1024 * 1024 + 65536, 0).await;
		assert!(finished, "collector must drain the child pipe to avoid deadlock: {result:?}");
		assert!(result.is_err(), "CLI accepted stderr beyond collection budget");
		assert!(result.unwrap_err().to_string().contains("output exceeds"));
	}

	#[cfg(unix)]
	#[tokio::test]
	async fn oversized_failed_output_keeps_bounded_head_and_actionable_tail() {
		if !in_env(
			"llm::claude_cli::tests::oversized_failed_output_keeps_bounded_head_and_actionable_tail",
			"output-fixture",
			&[],
		) {
			return;
		}
		let (result, finished) =
			run_output_fixture(1024 * 1024 + 65536, 1024 * 1024 + 65536, 1).await;
		assert!(finished, "both pipes must drain concurrently: {result:?}");
		let error = result.unwrap_err().to_string();
		assert!(error.contains("stdout-tail-diagnostic"));
		assert!(error.contains("stderr-tail-diagnostic"));
		for stream in ["stdout", "stderr"] {
			let start = error.find(&format!("{stream}(chars=")).unwrap();
			let count = error[start..]
				.split_once('=')
				.unwrap()
				.1
				.split_once(')')
				.unwrap()
				.0
				.parse::<usize>()
				.unwrap();
			assert!(count <= 1024 * 1024, "{stream} retained more than collection budget: {count}");
		}
	}

	use std::path::Path;
	use std::time::Duration;

	use tokio_util::sync::CancellationToken;

	use super::*;
	use crate::test_env::in_env;

	#[test]
	fn agent_uses_only_per_job_mcp_config() {
		assert!(
			claude_mcp_args().contains(&"--strict-mcp-config"),
			"Claude must ignore MCP servers outside Loupe's per-job config"
		);
	}

	fn bwrap_present() -> bool {
		std::process::Command::new("bwrap")
			.arg("--version")
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.status()
			.map(|s| s.success())
			.unwrap_or(false)
	}

	pub(super) fn test_model_broker(worker_binary: impl Into<PathBuf>) -> ModelBrokerContext {
		ModelBrokerContext::new(
			worker_binary.into(),
			"http://127.0.0.1:9".parse().unwrap(),
			super::super::model_broker::ModelCredential::anthropic_api_key("host-test-secret"),
			super::super::model_broker::ModelBrokerLimits::default(),
		)
	}

	#[cfg(unix)]
	#[tokio::test(flavor = "current_thread")]
	async fn sandbox_receives_only_the_broker_sentinel_and_loopback_url() {
		use std::os::unix::fs::PermissionsExt;

		if !bwrap_present() {
			eprintln!("skipping: bwrap missing");
			return;
		}

		let workdir = tempfile::tempdir().unwrap();
		let scratch = tempfile::tempdir().unwrap();
		let home = scratch.path().join("home");
		let bin_dir = scratch.path().join("bin");
		std::fs::create_dir_all(&home).unwrap();
		std::fs::create_dir_all(&bin_dir).unwrap();
		std::fs::write(home.join(".claude.json"), "host-login-state-canary").unwrap();

		let bin_path = bin_dir.join("fake-claude");
		std::fs::write(
			&bin_path,
			"#!/bin/sh\n\
			if [ -n \"${ANTHROPIC_API_KEY-}\" ] || [ -n \"${CLAUDE_CODE_OAUTH_TOKEN-}\" ]; then\n\
			  echo LEAKED\n\
			elif [ \"${ANTHROPIC_AUTH_TOKEN-}\" != \"loupe-brokered\" ]; then\n\
			  echo MISSING_SENTINEL\n\
			elif [ \"${ANTHROPIC_BASE_URL-}\" != \"http://127.0.0.1:18080\" ]; then\n\
			  echo BAD_BASE_URL\n\
			elif [ \"${DISABLE_AUTOUPDATER-}\" != \"1\" ] || [ \"${CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC-}\" != \"1\" ]; then\n\
			  echo NONESSENTIAL_TRAFFIC_ENABLED\n\
			elif [ -e /home/scanner/.claude.json ]; then\n\
			  echo LEAKED_LOGIN_STATE\n\
			else\n\
			  echo SAFE\n\
			fi\n",
		)
		.unwrap();
		std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o755)).unwrap();
		let proxy_path = bin_dir.join("fake-loupe-worker");
		std::fs::write(
			&proxy_path,
			"#!/bin/sh\n\
			while [ \"$1\" != \"--\" ]; do shift; done\n\
			shift\n\
			export ANTHROPIC_BASE_URL=http://127.0.0.1:18080\n\
			exec \"$@\"\n",
		)
		.unwrap();
		std::fs::set_permissions(&proxy_path, std::fs::Permissions::from_mode(0o755)).unwrap();

		let mut path_entries = vec![bin_dir];
		if let Some(path) = std::env::var_os("PATH") {
			path_entries.extend(std::env::split_paths(&path));
		}
		let path = std::env::join_paths(path_entries).unwrap();
		if !in_env(
			"llm::claude_cli::tests::sandbox_receives_only_the_broker_sentinel_and_loopback_url",
			"oauth-token",
			&[
				("PATH", Some(path.as_os_str())),
				("HOME", Some(home.as_os_str())),
				("CLAUDE_CODE_OAUTH_TOKEN", Some("host-oauth-secret".as_ref())),
			],
		) {
			return;
		}

		let model_broker = super::super::model_broker::ModelBrokerContext::new(
			proxy_path,
			"http://127.0.0.1:9".parse().unwrap(),
			super::super::model_broker::ModelCredential::anthropic_oauth_token("host-oauth-secret"),
			super::super::model_broker::ModelBrokerLimits::default(),
		);
		let backend = ClaudeCliBackend::with_bin("fake-claude")
			.with_network_disabled_for_tests()
			.with_model_broker_context(model_broker);
		let req = LlmRequest {
			tool_boundary: crate::llm::prompt::JobToolBoundary::new().unwrap(),
			prompt: crate::llm::prompts::Prompt::instruction("irrelevant").unwrap(),
			workdir: workdir.path().to_path_buf(),
			timeout: Duration::from_secs(5),
			cancel: CancellationToken::new(),
			repo_id: None,
			job_id: None,
			job_capability: None,
			finding_id: None,
		};

		let response = backend.run(req).await.expect("fake Claude CLI should run");
		assert_eq!(
			response.text.for_log().trim(),
			"SAFE",
			"the sandbox must receive only local broker configuration, not host auth"
		);
	}

	#[cfg(unix)]
	pub(super) fn sh_single_quote(path: &Path) -> String {
		format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
	}

	#[cfg(unix)]
	fn write_fake_cli(bin_path: &Path, pid_path: &Path, survived_path: &Path) {
		use std::os::unix::fs::PermissionsExt;

		std::fs::write(
			bin_path,
			format!(
				"#!/bin/sh\necho $$ > {}\nsleep 2\necho survived > {}\nsleep 30\n",
				sh_single_quote(pid_path),
				sh_single_quote(survived_path),
			),
		)
		.unwrap();
		std::fs::set_permissions(bin_path, std::fs::Permissions::from_mode(0o755)).unwrap();
	}

	#[cfg(unix)]
	fn process_state(pid: &str) -> Option<String> {
		let output = std::process::Command::new("ps")
			.args(["-o", "stat=", "-p", pid])
			.stdout(Stdio::piped())
			.stderr(Stdio::null())
			.output();
		let Ok(output) = output else {
			return None;
		};
		if !output.status.success() {
			return None;
		}
		let stat = String::from_utf8_lossy(&output.stdout);
		let stat = stat.trim();
		(!stat.is_empty()).then(|| stat.to_owned())
	}

	#[cfg(unix)]
	fn kill_pid(pid: &str) {
		let _ = std::process::Command::new("kill")
			.args(["-9", pid])
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.status();
	}

	#[tokio::test]
	async fn missing_binary_errors_clearly() {
		// `loupe-worker-no-such-bin` definitely does not exist on PATH.
		let workdir = tempfile::tempdir().unwrap();
		let backend = ClaudeCliBackend::with_bin("loupe-worker-no-such-bin")
			.with_model_broker_context(test_model_broker("/bin/true"));
		let req = LlmRequest {
			tool_boundary: crate::llm::prompt::JobToolBoundary::new().unwrap(),
			prompt: crate::llm::prompts::Prompt::instruction("irrelevant").unwrap(),
			workdir: workdir.path().to_path_buf(),
			timeout: Duration::from_secs(5),
			cancel: CancellationToken::new(),
			repo_id: None,
			job_id: None,
			job_capability: None,
			finding_id: None,
		};
		let err = backend.run(req).await.expect_err("must error");
		let msg = err.to_string().to_lowercase();
		// Either spawn-failed in our wrapper, or bwrap reported "no such
		// program inside the sandbox" — both mention the binary in some
		// form. Don't be picky.
		assert!(
			msg.contains("spawn")
				|| msg.contains("loupe-worker-no-such-bin")
				|| msg.contains("not found")
				|| msg.contains("no such")
				|| msg.contains("exited"),
			"unexpected error: {err}"
		);
	}

	#[cfg(unix)]
	#[tokio::test]
	async fn timeout_kills_subprocess() {
		let workdir = tempfile::tempdir().unwrap();
		let scratch = tempfile::tempdir().unwrap();
		let bin_path = scratch.path().join("fake-claude");
		let pid_path = scratch.path().join("pid");
		let survived_path = scratch.path().join("survived");
		write_fake_cli(&bin_path, &pid_path, &survived_path);

		let backend = ClaudeCliBackend::with_bin(bin_path.to_string_lossy())
			.with_sandbox_disabled_for_tests()
			.with_model_broker_context(test_model_broker("/bin/true"));
		let req = LlmRequest {
			tool_boundary: crate::llm::prompt::JobToolBoundary::new().unwrap(),
			prompt: crate::llm::prompts::Prompt::instruction("irrelevant").unwrap(),
			workdir: workdir.path().to_path_buf(),
			timeout: Duration::from_millis(500),
			cancel: CancellationToken::new(),
			repo_id: None,
			job_id: None,
			job_capability: None,
			finding_id: None,
		};

		let err = backend.run(req).await.expect_err("must time out");
		assert!(err.to_string().contains("timed out"), "unexpected error: {err}");

		let pid = std::fs::read_to_string(&pid_path).expect("fake CLI wrote pid");
		let pid = pid.trim();
		if let Some(state) = process_state(pid) {
			if !state.starts_with('Z') {
				kill_pid(pid);
			}
			panic!("subprocess pid {pid} was not reaped before run() returned: state={state}");
		}

		tokio::time::sleep(Duration::from_millis(2500)).await;

		assert!(
			!survived_path.exists(),
			"fake CLI continued executing after run() returned a timeout",
		);
	}

	#[test]
	fn invocation_args_include_configured_model_and_effort() {
		let args = claude_invocation_args(&CliModelConfig {
			model: crate::config::ConfiguredText::Builtin("claude-test"),
			effort: crate::config::ConfiguredText::Builtin("xhigh"),
		});

		assert!(args.windows(2).any(|w| w == ["--model", "claude-test"]));
		assert!(args.windows(2).any(|w| w == ["--effort", "xhigh"]));
		assert!(args.iter().any(|arg| arg == "--no-session-persistence"));
		assert_eq!(args.last().map(String::as_str), Some("-p"));
	}
}
