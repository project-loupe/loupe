//! Backend that shells out to the `codex` CLI (OpenAI Codex).
//!
//! Mirrors [`ClaudeCliBackend`]'s shape: runs the agent inside the
//! bubblewrap sandbox the worker builds. User-level Codex configuration,
//! login state, and provider credentials are not mounted into the sandbox;
//! model traffic goes through a job-scoped, credential-free broker.
//!
//! Wire shape: `codex exec --dangerously-bypass-approvals-and-sandbox
//! --skip-git-repo-check "$prompt"`. The bypass flag is the codex
//! analog of claude's `--dangerously-skip-permissions`; the bwrap
//! sandbox is the actual security boundary, not codex's own
//! permission machinery.
//!
//! When constructed with [`McpContext`] the backend additionally
//! advertises the loupe MCP server (and optionally bkb-mcp) to
//! codex via `-c mcp_servers.<name>.command="..."` /
//! `-c mcp_servers.<name>.args=[...]` overrides — codex's MCP
//! config surface is TOML, but the `-c` overrides take TOML literals
//! one key at a time. The sandboxed agent reaches Loupe through a
//! credential-free proxy while the host-side broker retains the job
//! capability and worker credentials.
//!
//! [`ClaudeCliBackend`]: super::ClaudeCliBackend

use std::process::Stdio;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

use super::mcp::{
	bind_mcp_into_sandbox, McpBroker, McpContext, SANDBOX_BKB_MCP_BIN, SANDBOX_LOUPE_BIN,
};
use super::model_broker::{
	bind_model_into_sandbox, ModelBrokerBackend, ModelBrokerContext, SANDBOX_MODEL_SOCKET,
};
use super::{summarize_cli_stream_for_error, CliModelConfig, LlmBackend, LlmRequest, LlmResponse};
use crate::sandbox::{SandboxBuilder, SandboxNetworkConfig};

const BACKEND_ID: &str = "codex-cli";
const CODEX_BIN: &str = "codex";
pub const DEFAULT_CODEX_MODEL: &str = "gpt-5.5";
pub const DEFAULT_CODEX_EFFORT: &str = "xhigh";
const MAX_CLI_DIAGNOSTIC_CHARS: usize = 2_000;
const MODEL_PROXY_LISTEN: &str = "127.0.0.1:0";
const SANDBOX_MODEL_PORT_FILE: &str = "/tmp/loupe-model.port";
const MODEL_RESPONSES_BASE_URL: &str = "@LOUPE_MODEL_BASE_URL@/v1";

/// Render a Rust string as a TOML basic-string literal: wraps in
/// double quotes, escapes the few characters TOML cares about (`\`,
/// `"`, control chars). Used to build `-c key=value` overrides where
/// `value` is parsed as a TOML literal — sandbox paths and the BKB
/// API URL are ASCII so this is mostly defensive against future
/// regressions.
fn toml_string_literal(s: &str) -> String {
	let mut out = String::with_capacity(s.len() + 2);
	out.push('"');
	for c in s.chars() {
		match c {
			'\\' => out.push_str(r"\\"),
			'"' => out.push_str(r#"\""#),
			'\n' => out.push_str(r"\n"),
			'\r' => out.push_str(r"\r"),
			'\t' => out.push_str(r"\t"),
			c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
			c => out.push(c),
		}
	}
	out.push('"');
	out
}

/// Render a slice of strings as a TOML inline array of basic strings.
/// Codex parses each `-c` value as TOML, so an args list passed as
/// `["mcp-proxy", "--socket", "..." ]` round-trips into the
/// MCP server config's `args` field.
fn toml_string_array(items: &[String]) -> String {
	let parts: Vec<String> = items.iter().map(|s| toml_string_literal(s)).collect();
	format!("[{}]", parts.join(", "))
}

pub struct CodexCliBackend {
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

impl CodexCliBackend {
	pub fn new() -> Self {
		Self {
			bin: CODEX_BIN.to_owned(),
			agent: CliModelConfig {
				model: DEFAULT_CODEX_MODEL.to_owned(),
				effort: DEFAULT_CODEX_EFFORT.to_owned(),
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
	/// emits `-c mcp_servers.loupe.command/args/env=...` overrides
	/// (and the same for `bkb` when bkb-mcp is on the host) so the
	/// agent sees the loupe tool surface for the duration of the call.
	pub fn with_mcp_context(mut self, mcp: McpContext) -> Self {
		self.mcp = Some(mcp);
		self
	}

	pub fn with_model_broker_context(mut self, model_broker: ModelBrokerContext) -> Self {
		self.model_broker = Some(model_broker);
		self
	}
}

impl Default for CodexCliBackend {
	fn default() -> Self {
		Self::new()
	}
}

#[async_trait]
impl LlmBackend for CodexCliBackend {
	fn id(&self) -> &'static str {
		BACKEND_ID
	}

	async fn run(&self, req: LlmRequest) -> Result<LlmResponse> {
		tracing::debug!(
			backend = BACKEND_ID,
			workdir = %req.workdir.display(),
			model = %self.agent.model,
			effort = %self.agent.effort,
			prompt_chars = req.prompt.chars().count(),
			timeout_ms = req.timeout.as_millis() as u64,
			"codex-cli: invoking",
		);
		let started = std::time::Instant::now();
		let model_context = self
			.model_broker
			.as_ref()
			.context("Codex backend requires a host-side model broker context")?;
		let mut model_broker = Some(
			model_context
				.start_session(ModelBrokerBackend::Codex {
					model: self.agent.model.clone(),
					effort: self.agent.effort.clone(),
				})
				.await
				.context("starting host-side Codex model broker")?,
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
				.map(|ctx| ctx.bkb_api_url.as_str());
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
			// Per-user installs (`npm i -g @openai/codex` with a non-root
			// prefix, etc.) live outside the default sandbox mounts —
			// surface the install tree so the wrapped subprocess can
			// `exec` it.
			.allow_binary(&self.bin)
			.with_context(|| format!("preparing sandbox for `{}`", self.bin))?
			// Codex requires its configured env key to be present. This
			// fixed value carries no authority and is stripped by the broker.
			.set_env("CODEX_API_KEY", "loupe-brokered");
		let model_session = model_broker.as_ref().expect("model broker was just started");
		sandbox = bind_model_into_sandbox(sandbox, model_context, model_session);
		// Optional MCP attachment. Codex doesn't take a "config-file"
		// flag like claude's `--mcp-config`; instead it accepts
		// `-c <key>=<toml-literal>` overrides on the command line.
		// Build one override per MCP server table key (command, args,
		// env) so the loupe MCP server (and bkb-mcp when present)
		// shows up in the agent's tool catalog without polluting the
		// operator's `~/.codex/config.toml`.
		let mut mcp_broker = None;
		let mcp_overrides: Vec<String> = match (&self.mcp, req.repo_id) {
			(Some(ctx), Some(_)) => {
				let broker = McpBroker::start_for_request(ctx, &req)
					.await
					.context("starting host-side MCP broker")?;
				sandbox = bind_mcp_into_sandbox(sandbox, ctx, &broker);
				let args = broker.sandbox_args();
				let mut overrides = Vec::new();
				overrides.push(format!(
					"mcp_servers.loupe.command={}",
					toml_string_literal(SANDBOX_LOUPE_BIN)
				));
				overrides.push(format!("mcp_servers.loupe.args={}", toml_string_array(&args)));
				overrides.push("mcp_servers.loupe.env={}".to_owned());
				if ctx.bkb_mcp_path.is_some() {
					overrides.push(format!(
						"mcp_servers.bkb.command={}",
						toml_string_literal(SANDBOX_BKB_MCP_BIN)
					));
					overrides.push("mcp_servers.bkb.args=[]".to_owned());
					overrides.push(format!(
						"mcp_servers.bkb.env={{ BKB_API_URL = {} }}",
						toml_string_literal(&ctx.bkb_api_url)
					));
				}
				mcp_broker = Some(broker);
				overrides
			},
			(Some(_), None) => {
				tracing::debug!(
					backend = BACKEND_ID,
					"MCP context configured but request has no repo_id; skipping codex MCP overrides",
				);
				Vec::new()
			},
			_ => Vec::new(),
		};

		let agent_args = codex_invocation_args(&self.agent, &mcp_overrides, &req.prompt);
		#[cfg(test)]
		let mut cmd = if self.disable_sandbox {
			let mut cmd = sandbox.build(&self.bin);
			cmd.args(&agent_args);
			cmd
		} else {
			build_model_proxied_command(&sandbox, &self.bin, &agent_args)
		};
		#[cfg(not(test))]
		let mut cmd = build_model_proxied_command(&sandbox, &self.bin, &agent_args);
		cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
		cmd.kill_on_drop(true);

		let mut child = cmd
			.spawn()
			.with_context(|| format!("spawning `{}` (is the codex CLI installed?)", self.bin))?;

		let stdout_handle = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
		let stderr_handle = child.stderr.take().ok_or_else(|| anyhow!("no stderr"))?;

		let cancel = req.cancel.clone();
		let run_outcome = timeout(req.timeout, async {
			let mut stdout_buf = Vec::new();
			let mut stderr_buf = Vec::new();
			let mut so = stdout_handle;
			let mut se = stderr_handle;
			let wait_fut = async {
				tokio::select! {
					biased;
					_ = cancel.cancelled() => {
						let _ = child.kill().await;
						Err(anyhow!("cancelled"))
					}
					res = child.wait() => res.map_err(Into::into),
				}
			};
			let (status, _, _) = tokio::join!(
				wait_fut,
				so.read_to_end(&mut stdout_buf),
				se.read_to_end(&mut stderr_buf),
			);
			Result::<_>::Ok((status?, stdout_buf, stderr_buf))
		})
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
				anyhow::Error::from(error).context("terminating codex CLI before broker shutdown")
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
						"codex-cli: model broker usage"
					);
				})
				.context("finishing host-side Codex model broker"),
			None => Ok(()),
		};

		let (status, stdout, stderr) = match run_outcome {
			Ok(inner) => inner?,
			Err(_) => return Err(anyhow!("codex CLI timed out after {:?}", req.timeout)),
		};

		if !status.success() {
			let stderr_text = String::from_utf8_lossy(&stderr);
			let stdout_text = String::from_utf8_lossy(&stdout);
			tracing::debug!(
				backend = BACKEND_ID,
				exit = ?status.code(),
				stdout_chars = stdout.len(),
				stderr_chars = stderr.len(),
				elapsed_ms = started.elapsed().as_millis() as u64,
				"codex-cli: subprocess failed",
			);
			let combined = format!(
				"stderr(chars={})=`{}` stdout(chars={})=`{}`",
				stderr_text.chars().count(),
				summarize_cli_stream_for_error(&stderr_text, MAX_CLI_DIAGNOSTIC_CHARS),
				stdout_text.chars().count(),
				summarize_cli_stream_for_error(&stdout_text, MAX_CLI_DIAGNOSTIC_CHARS),
			);
			return Err(anyhow!("codex CLI exited with {}: {}", status, combined));
		}
		// Reported last: a CLI failure explains a broker failure, so the
		// CLI diagnostic is the more useful error to surface.
		broker_outcome?;
		model_broker_outcome?;

		let text = String::from_utf8(stdout)
			.map_err(|e| anyhow!("codex CLI stdout was not UTF-8: {e}"))?;
		if self.log_agent_output {
			tracing::info!(
				backend = BACKEND_ID,
				agent_stdout = %text,
				"codex-cli: agent stdout (full)"
			);
			if !stderr.is_empty() {
				let stderr_text = String::from_utf8_lossy(&stderr);
				tracing::info!(
					backend = BACKEND_ID,
					agent_stderr = %stderr_text,
					"codex-cli: agent stderr (full)"
				);
			}
		}
		tracing::debug!(
			backend = BACKEND_ID,
			elapsed_ms = started.elapsed().as_millis() as u64,
			stdout_chars = text.chars().count(),
			stderr_chars = stderr.len(),
			"codex-cli: subprocess succeeded",
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
		"--provider",
		"codex",
		"--",
		agent_bin,
	]);
	cmd.args(agent_args);
	cmd
}

fn codex_model_provider_overrides() -> [String; 5] {
	[
		format!("model_provider={}", toml_string_literal("loupe")),
		format!("model_providers.loupe.name={}", toml_string_literal("Loupe broker")),
		format!("model_providers.loupe.base_url={}", toml_string_literal(MODEL_RESPONSES_BASE_URL)),
		format!("model_providers.loupe.env_key={}", toml_string_literal("CODEX_API_KEY")),
		format!("model_providers.loupe.wire_api={}", toml_string_literal("responses")),
	]
}

fn codex_invocation_args(
	agent: &CliModelConfig, mcp_overrides: &[String], prompt: &str,
) -> Vec<String> {
	let mut args = vec![
		"exec".to_owned(),
		"--dangerously-bypass-approvals-and-sandbox".to_owned(),
		"--skip-git-repo-check".to_owned(),
		"--ephemeral".to_owned(),
		"--ignore-user-config".to_owned(),
		"--model".to_owned(),
		agent.model.clone(),
		"-c".to_owned(),
		format!("model_reasoning_effort={}", toml_string_literal(&agent.effort)),
	];
	for ov in codex_model_provider_overrides() {
		args.push("-c".to_owned());
		args.push(ov);
	}
	for ov in mcp_overrides {
		args.push("-c".to_owned());
		args.push(ov.clone());
	}
	args.push(prompt.to_owned());
	args
}

#[cfg(test)]
mod tests {
	use std::path::{Path, PathBuf};
	use std::time::Duration;

	use tokio_util::sync::CancellationToken;

	use super::*;
	use crate::test_env::in_env;

	fn bwrap_present() -> bool {
		std::process::Command::new("bwrap")
			.arg("--version")
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.status()
			.map(|status| status.success())
			.unwrap_or(false)
	}

	fn test_model_broker(
		worker_binary: impl Into<PathBuf>,
	) -> super::super::model_broker::ModelBrokerContext {
		super::super::model_broker::ModelBrokerContext::new(
			worker_binary.into(),
			"http://127.0.0.1:9".parse().unwrap(),
			super::super::model_broker::ModelCredential::openai_api_key("host-test-secret"),
			super::super::model_broker::ModelBrokerLimits::default(),
		)
	}

	#[tokio::test(flavor = "current_thread")]
	async fn sandbox_receives_only_the_codex_broker_sentinel() {
		use std::os::unix::fs::PermissionsExt;

		if !bwrap_present() {
			eprintln!("skipping: bwrap missing");
			return;
		}
		let workdir = tempfile::tempdir().unwrap();
		let scratch = tempfile::tempdir().unwrap();
		let bin_dir = scratch.path().join("bin");
		std::fs::create_dir_all(&bin_dir).unwrap();
		let bin_path = bin_dir.join("fake-codex");
		std::fs::write(
			&bin_path,
			"#!/bin/sh\n\
			if [ \"${CODEX_API_KEY-}\" != \"loupe-brokered\" ] || [ -n \"${OPENAI_API_KEY-}\" ]; then\n\
			  echo LEAKED\n\
			elif [ -e /home/scanner/.codex/auth.json ]; then\n\
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
			export CODEX_API_KEY=loupe-brokered\n\
			unset OPENAI_API_KEY\n\
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
			"llm::codex_cli::tests::sandbox_receives_only_the_codex_broker_sentinel",
			"api-keys",
			&[
				("PATH", Some(path.as_os_str())),
				("CODEX_API_KEY", Some("host-codex-secret".as_ref())),
				("OPENAI_API_KEY", Some("unrelated-host-secret".as_ref())),
			],
		) {
			return;
		}

		let backend = CodexCliBackend::with_bin("fake-codex")
			.with_network_disabled_for_tests()
			.with_model_broker_context(test_model_broker(proxy_path));
		let response = backend
			.run(LlmRequest {
				prompt: "irrelevant".into(),
				workdir: workdir.path().to_path_buf(),
				timeout: Duration::from_secs(5),
				cancel: CancellationToken::new(),
				repo_id: None,
				job_id: None,
				job_capability: None,
				finding_id: None,
			})
			.await
			.expect("fake Codex CLI should run through the credential-free adapter");
		assert_eq!(response.text.trim(), "SAFE");
	}

	#[cfg(unix)]
	fn sh_single_quote(path: &Path) -> String {
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
		let backend = CodexCliBackend::with_bin("loupe-worker-no-such-bin")
			.with_model_broker_context(test_model_broker("/bin/true"));
		let req = LlmRequest {
			prompt: "irrelevant".into(),
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
		assert!(
			msg.contains("spawn")
				|| msg.contains("loupe-worker-no-such-bin")
				|| msg.contains("not found")
				|| msg.contains("no such")
				|| msg.contains("exited")
				|| msg.contains("preparing sandbox"),
			"unexpected error: {err}"
		);
	}

	#[cfg(unix)]
	#[tokio::test]
	async fn timeout_kills_subprocess() {
		let workdir = tempfile::tempdir().unwrap();
		let scratch = tempfile::tempdir().unwrap();
		let bin_path = scratch.path().join("fake-codex");
		let pid_path = scratch.path().join("pid");
		let survived_path = scratch.path().join("survived");
		write_fake_cli(&bin_path, &pid_path, &survived_path);

		let backend = CodexCliBackend::with_bin(bin_path.to_string_lossy())
			.with_sandbox_disabled_for_tests()
			.with_model_broker_context(test_model_broker("/bin/true"));
		let req = LlmRequest {
			prompt: "irrelevant".into(),
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
	fn toml_string_literal_quotes_and_escapes() {
		// Plain ASCII paths are the common case (sandbox paths,
		// BKB_API_URL): quoted, no escapes needed.
		assert_eq!(toml_string_literal("/loupe/loupe-worker"), r#""/loupe/loupe-worker""#);
		// Backslashes and double-quotes both have to escape; otherwise
		// codex's TOML parser splits the string mid-value and the MCP
		// config silently drops the rest.
		assert_eq!(toml_string_literal(r#"a"b\c"#), r#""a\"b\\c""#);
		// A literal newline / tab in a path would fall outside TOML's
		// basic-string set; emit the escape so the override still
		// parses round-trip.
		assert_eq!(toml_string_literal("a\nb"), r#""a\nb""#);
	}

	#[test]
	fn toml_string_array_round_trips_through_a_real_toml_parser() {
		// MCP proxy arguments use a Vec<String>; the array form has
		// to parse back as TOML so codex's `-c key=value` override
		// can read it. Pin the round-trip explicitly — string
		// concatenation bugs in the array helper would otherwise only
		// surface at runtime when codex rejects the override.
		let items = vec![
			"mcp-proxy".to_owned(),
			"--socket".to_owned(),
			"/loupe/mcp/session.sock".to_owned(),
		];
		let rendered = toml_string_array(&items);
		// Wrap in a key=value pair so we can use the standard `toml`
		// parser to validate. Cheap and decisive.
		let parsed: toml::Value = format!("k = {rendered}").parse().expect("must parse");
		let arr = parsed["k"].as_array().expect("must be array");
		let back: Vec<String> = arr.iter().map(|v| v.as_str().unwrap().to_owned()).collect();
		assert_eq!(back, items);
	}

	#[test]
	fn invocation_args_include_configured_model_and_effort() {
		let args = codex_invocation_args(
			&CliModelConfig { model: "gpt-test".into(), effort: "xhigh".into() },
			&["mcp_servers.loupe.env={}".to_owned()],
			"hello",
		);

		assert!(args.windows(2).any(|w| w == ["--model", "gpt-test"]));
		assert!(args.iter().any(|arg| arg == "--ephemeral"));
		assert!(args.iter().any(|arg| arg == "--ignore-user-config"));
		assert!(args.windows(2).any(|w| w == ["-c", r#"model_reasoning_effort="xhigh""#]));
		assert!(args.windows(2).any(|w| w == ["-c", r#"model_provider="loupe""#]));
		assert!(args.windows(2).any(|w| {
			w == ["-c", r#"model_providers.loupe.base_url="@LOUPE_MODEL_BASE_URL@/v1""#]
		}));
		assert!(args
			.windows(2)
			.any(|w| w == ["-c", r#"model_providers.loupe.wire_api="responses""#]));
		assert!(args.windows(2).any(|w| w == ["-c", "mcp_servers.loupe.env={}"]));
		assert_eq!(args.last().map(String::as_str), Some("hello"));
	}
}
