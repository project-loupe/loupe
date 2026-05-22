//! Backend that shells out to the `codex` CLI (OpenAI Codex).
//!
//! Mirrors [`ClaudeCliBackend`]'s shape: runs the agent inside the
//! bubblewrap sandbox the worker builds, forwards the model auth env
//! var (`CODEX_API_KEY`), and bind-mounts the operator's `~/.codex/`
//! config dir so a `codex login`-style OAuth credential can flow in.
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
//! one key at a time, so we stream the same `mcp_serve_args` list
//! that the claude backend writes to its JSON scratch file.
//!
//! [`ClaudeCliBackend`]: super::ClaudeCliBackend

use std::process::Stdio;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

use super::mcp::{
	bind_mcp_into_sandbox, mcp_serve_args, McpContext, SANDBOX_BKB_MCP_BIN, SANDBOX_LOUPE_BIN,
};
use super::{
	codex_api_key_env, codex_home_dir, summarize_cli_stream_for_error, CliModelConfig, LlmBackend,
	LlmRequest, LlmResponse,
};
use crate::sandbox::SandboxBuilder;

const BACKEND_ID: &str = "codex-cli";
const CODEX_BIN: &str = "codex";
pub const DEFAULT_CODEX_MODEL: &str = "gpt-5.5";
pub const DEFAULT_CODEX_EFFORT: &str = "xhigh";
const MAX_CLI_DIAGNOSTIC_CHARS: usize = 2_000;

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
/// `["mcp-serve", "--server-url", "...", ...]` round-trips into the
/// MCP server config's `args` field.
fn toml_string_array(items: &[String]) -> String {
	let parts: Vec<String> = items.iter().map(|s| toml_string_literal(s)).collect();
	format!("[{}]", parts.join(", "))
}

pub struct CodexCliBackend {
	bin: String,
	agent: CliModelConfig,
	mcp: Option<McpContext>,
	log_agent_output: bool,
	#[cfg(test)]
	disable_sandbox: bool,
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
			log_agent_output: false,
			#[cfg(test)]
			disable_sandbox: false,
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

	#[cfg(test)]
	fn with_sandbox_disabled_for_tests(mut self) -> Self {
		self.disable_sandbox = true;
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

		#[cfg(test)]
		let sandbox_builder = if self.disable_sandbox {
			SandboxBuilder::disabled_for_tests(&req.workdir)
		} else {
			SandboxBuilder::new(&req.workdir)
		};
		#[cfg(not(test))]
		let sandbox_builder = SandboxBuilder::new(&req.workdir);

		let mut sandbox = sandbox_builder
			.allow_network()
			// Per-user installs (`npm i -g @openai/codex` with a non-root
			// prefix, etc.) live outside the default sandbox mounts —
			// surface the install tree so the wrapped subprocess can
			// `exec` it.
			.allow_binary(&self.bin)
			.with_context(|| format!("preparing sandbox for `{}`", self.bin))?
			.forward_env("OPENAI_API_KEY");
		if let Some(api_key) = codex_api_key_env() {
			sandbox = sandbox.set_env("CODEX_API_KEY", api_key);
		}
		if let Some(codex_dir) = codex_home_dir() {
			// Bind only the credential + config files read-only,
			// rather than the whole `~/.codex/` tree. Codex writes a
			// models cache and (sometimes) an installation_id to its
			// home dir on every invocation; binding the parent
			// read-only fails those writes with EROFS. Leaving the
			// parent as the sandbox tmpfs keeps `auth.json` /
			// `config.toml` reachable and the cache writable per call.
			//
			// `--ro-bind-try` (used inside SandboxBuilder) makes a
			// missing source a no-op — env-only auth (just
			// `CODEX_API_KEY`) Just Works on hosts that never ran
			// `codex login`, and a missing `config.toml` is fine since
			// codex falls back to defaults.
			sandbox = sandbox
				.bind_ro(codex_dir.join("auth.json"), "/home/scanner/.codex/auth.json")
				.bind_ro(codex_dir.join("config.toml"), "/home/scanner/.codex/config.toml");
		}

		// Optional MCP attachment. Codex doesn't take a "config-file"
		// flag like claude's `--mcp-config`; instead it accepts
		// `-c <key>=<toml-literal>` overrides on the command line.
		// Build one override per MCP server table key (command, args,
		// env) so the loupe MCP server (and bkb-mcp when present)
		// shows up in the agent's tool catalog without polluting the
		// operator's `~/.codex/config.toml`.
		let mcp_overrides: Vec<String> = match (&self.mcp, req.repo_id) {
			(Some(ctx), Some(repo_id)) => {
				let sandbox_workdir = if std::env::var_os(crate::sandbox::DISABLE_SANDBOX_ENV)
					.is_some_and(|v| !v.is_empty())
				{
					req.workdir.to_string_lossy().into_owned()
				} else {
					"/workdir".to_owned()
				};
				sandbox = bind_mcp_into_sandbox(sandbox, ctx);
				let args =
					mcp_serve_args(ctx, repo_id, req.job_id, req.finding_id, &sandbox_workdir);
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

		let mut cmd = sandbox.build(&self.bin);
		for arg in codex_invocation_args(&self.agent, &mcp_overrides, &req.prompt) {
			cmd.arg(arg);
		}
		cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
		cmd.kill_on_drop(true);

		let mut child = cmd
			.spawn()
			.with_context(|| format!("spawning `{}` (is the codex CLI installed?)", self.bin))?;

		let stdout_handle = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
		let stderr_handle = child.stderr.take().ok_or_else(|| anyhow!("no stderr"))?;

		let cancel = req.cancel.clone();
		let wait_fut = async move {
			tokio::select! {
				biased;
				_ = cancel.cancelled() => {
					let _ = child.kill().await;
					Err(anyhow!("cancelled"))
				}
				res = child.wait() => res.map_err(Into::into),
			}
		};

		let (status, stdout, stderr) = match timeout(req.timeout, async {
			let mut stdout_buf = Vec::new();
			let mut stderr_buf = Vec::new();
			let mut so = stdout_handle;
			let mut se = stderr_handle;
			let (status, _, _) = tokio::join!(
				wait_fut,
				so.read_to_end(&mut stdout_buf),
				se.read_to_end(&mut stderr_buf),
			);
			Result::<_>::Ok((status?, stdout_buf, stderr_buf))
		})
		.await
		{
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

fn codex_invocation_args(
	agent: &CliModelConfig, mcp_overrides: &[String], prompt: &str,
) -> Vec<String> {
	let mut args = vec![
		"exec".to_owned(),
		"--dangerously-bypass-approvals-and-sandbox".to_owned(),
		"--skip-git-repo-check".to_owned(),
		"--model".to_owned(),
		agent.model.clone(),
		"-c".to_owned(),
		format!("model_reasoning_effort={}", toml_string_literal(&agent.effort)),
	];
	for ov in mcp_overrides {
		args.push("-c".to_owned());
		args.push(ov.clone());
	}
	args.push(prompt.to_owned());
	args
}

#[cfg(test)]
mod tests {
	use std::path::Path;
	use std::time::Duration;

	use tokio_util::sync::CancellationToken;

	use super::*;

	fn codex_present(bin: &str) -> bool {
		std::process::Command::new(bin)
			.arg("--version")
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.status()
			.map(|s| s.success())
			.unwrap_or(false)
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
	fn process_is_running(pid: &str) -> bool {
		let output = std::process::Command::new("ps")
			.args(["-o", "stat=", "-p", pid])
			.stdout(Stdio::piped())
			.stderr(Stdio::null())
			.output();
		let Ok(output) = output else {
			return false;
		};
		if !output.status.success() {
			return false;
		}
		let stat = String::from_utf8_lossy(&output.stdout);
		let stat = stat.trim();
		!stat.is_empty() && !stat.starts_with('Z')
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
	async fn cli_backend_round_trip_against_real_codex() {
		// Live test: needs `codex` + `bwrap` and either an
		// `CODEX_API_KEY` / `OPENAI_API_KEY` in env or a
		// `~/.codex/auth.json` from
		// `codex login`. The auth dir is bind-mounted read-only into
		// the sandbox, so OAuth flows that would write back token-
		// refresh state can fail; in practice codex's refresh updates
		// the file *before* the call and the in-memory token survives
		// the session. Skip if either binary is missing or no auth
		// material is present — same shape as the claude live test.
		if !codex_present("codex") || !bwrap_present() {
			eprintln!("skipping: codex or bwrap missing");
			return;
		}
		let auth_present = std::env::var_os("CODEX_API_KEY").is_some()
			|| std::env::var_os("OPENAI_API_KEY").is_some()
			|| std::env::var_os("HOME").is_some_and(|h| {
				std::path::PathBuf::from(h).join(".codex").join("auth.json").exists()
			});
		if !auth_present {
			eprintln!("skipping: no CODEX_API_KEY, OPENAI_API_KEY, or ~/.codex/auth.json");
			return;
		}

		let workdir = tempfile::tempdir().unwrap();
		let backend = CodexCliBackend::new();
		let req = LlmRequest {
			prompt: "Reply with only the single word `pong`. No prose, no formatting.".to_owned(),
			workdir: workdir.path().to_path_buf(),
			// Live LLM call — give it generous headroom; codex's first-
			// turn warm-up can take a few seconds.
			timeout: Duration::from_secs(120),
			cancel: CancellationToken::new(),
			repo_id: None,
			job_id: None,
			finding_id: None,
		};
		let resp = backend.run(req).await.expect("codex responded");
		assert_eq!(resp.backend_id, BACKEND_ID);
		assert!(!resp.text.trim().is_empty());
	}

	#[tokio::test]
	async fn missing_binary_errors_clearly() {
		// `loupe-worker-no-such-bin` definitely does not exist on PATH.
		let workdir = tempfile::tempdir().unwrap();
		let backend = CodexCliBackend::with_bin("loupe-worker-no-such-bin");
		let req = LlmRequest {
			prompt: "irrelevant".into(),
			workdir: workdir.path().to_path_buf(),
			timeout: Duration::from_secs(5),
			cancel: CancellationToken::new(),
			repo_id: None,
			job_id: None,
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

		let backend =
			CodexCliBackend::with_bin(bin_path.to_string_lossy()).with_sandbox_disabled_for_tests();
		let req = LlmRequest {
			prompt: "irrelevant".into(),
			workdir: workdir.path().to_path_buf(),
			timeout: Duration::from_millis(500),
			cancel: CancellationToken::new(),
			repo_id: None,
			job_id: None,
			finding_id: None,
		};

		let err = backend.run(req).await.expect_err("must time out");
		assert!(err.to_string().contains("timed out"), "unexpected error: {err}");

		tokio::time::sleep(Duration::from_millis(2500)).await;

		let pid = std::fs::read_to_string(&pid_path).expect("fake CLI wrote pid");
		let pid = pid.trim();
		if process_is_running(pid) {
			kill_pid(pid);
			panic!("subprocess pid {pid} survived past run() timeout");
		}
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
		// `mcp_serve_args` produces a Vec<String>; the array form has
		// to parse back as TOML so codex's `-c key=value` override
		// can read it. Pin the round-trip explicitly — string
		// concatenation bugs in the array helper would otherwise only
		// surface at runtime when codex rejects the override.
		let items = vec![
			"mcp-serve".to_owned(),
			"--server-url".to_owned(),
			"https://loupe-server:8443".to_owned(),
			"--workdir".to_owned(),
			"/workdir".to_owned(),
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
		assert!(args.windows(2).any(|w| w == ["-c", r#"model_reasoning_effort="xhigh""#]));
		assert!(args.windows(2).any(|w| w == ["-c", "mcp_servers.loupe.env={}"]));
		assert_eq!(args.last().map(String::as_str), Some("hello"));
	}
}
