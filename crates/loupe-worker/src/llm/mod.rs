//! LLM backend abstraction.
//!
//! A `LlmBackend` is one provider of agentic completions: it receives a
//! prompt and a read-only working directory, manages its own internal
//! tool loop (the `claude` CLI does this for us; an HTTP backend would
//! manage one explicitly), and returns the model's final text response.
//!
//! Two concrete impls today:
//!
//! - [`ClaudeCliBackend`] shells out to Anthropic's `claude` CLI.
//!   Carries optional MCP context so each invocation can call back
//!   into `loupe-worker mcp-serve` over stdio JSON-RPC — used by the
//!   discovery scanner to query prior findings and submit new ones.
//! - [`CodexCliBackend`] shells out to OpenAI's `codex` CLI. Carries
//!   the same optional MCP context via Codex CLI config overrides.
//!
//! Picking between them at runtime: see [`build_scan_backend`] and
//! [`build_verifier_backend`].

pub mod claude_cli;
pub mod codex_cli;
pub mod mcp;
pub mod prompts;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::ValueEnum;
pub use claude_cli::ClaudeCliBackend;
pub use codex_cli::CodexCliBackend;
pub use mcp::{McpContext, McpTlsSource};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliModelConfig {
	pub model: String,
	pub effort: String,
	/// Optional Codex `model_provider` override. When set, every codex
	/// invocation emits `-c model_provider=<provider>` so two roles that
	/// share the codex backend can target different OpenAI-compatible
	/// providers (e.g. scan -> Z.AI GLM, verify -> Moonshot Kimi).
	/// Ignored by the claude backend.
	pub provider: Option<String>,
	/// Optional name of an env var (read from the worker's own
	/// environment) whose value is injected as CODEX_API_KEY for
	/// this codex invocation. Routes a distinct API key per provider
	/// (e.g. MOONSHOT_API_KEY for the verify role's Kimi provider)
	/// without relying on codex's per-provider env_key support. None
	/// falls back to CODEX_API_KEY / OPENAI_API_KEY.
	pub api_key_env: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum JobAgent {
	#[default]
	Auto,
	Claude,
	Codex,
}

impl JobAgent {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Auto => "auto",
			Self::Claude => "claude",
			Self::Codex => "codex",
		}
	}
}

impl std::fmt::Display for JobAgent {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(self.as_str())
	}
}

const CLI_STREAM_OMISSION: &str = " ... ";

/// Collapse a CLI output stream into a single log-line snippet while
/// preserving both the beginning and the end. Agent CLIs often print a
/// long startup banner first and the actionable error last; head-only
/// truncation hides the part an operator needs.
pub(crate) fn summarize_cli_stream_for_error(s: &str, max_chars: usize) -> String {
	let collapsed = s.split_whitespace().collect::<Vec<_>>().join(" ");
	let len = collapsed.chars().count();
	if len <= max_chars {
		return collapsed;
	}
	if max_chars <= CLI_STREAM_OMISSION.chars().count() + 2 {
		return collapsed.chars().take(max_chars).collect();
	}

	let omission_len = CLI_STREAM_OMISSION.chars().count();
	let head_len = max_chars / 3;
	let tail_len = max_chars.saturating_sub(head_len + omission_len);
	let head: String = collapsed.chars().take(head_len).collect();
	let tail_rev: Vec<char> = collapsed.chars().rev().take(tail_len).collect();
	let tail: String = tail_rev.into_iter().rev().collect();
	format!("{head}{CLI_STREAM_OMISSION}{tail}")
}

/// Default per-call wall-clock budget. Per-file LLM invocations should
/// fit comfortably within this; if they don't, the call is aborted and
/// the file is treated as having produced no findings (logged warning).
///
/// 30 minutes is generous; the goal is to be the *fallback* ceiling,
/// not the operative deadline. Auditing a 1–2k-line source file
/// end-to-end (several MCP round-trips for prior-finding dedup, a PoC
/// regression-test diff, validation) routinely takes 1–3 minutes
/// against real-world Rust repos, and the previous 180s default was
/// killing roughly 4 in 5 sessions before the agent could submit.
/// Operators can still tighten via the per-repo `scanner_config` JSON
/// (`per_request_timeout_seconds`).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(1800);

/// Pull the first balanced JSON object out of a possibly noisy text
/// response. Tolerates prose before/after the object and a single
/// markdown fence around it. Returns the slice as an owned `String`
/// because the model occasionally emits trailing junk after the
/// closing brace; we feed only what's inside the braces.
///
/// Used by the verifier scanner, which still parses JSON from the
/// model's stdout. The discovery flow doesn't need this — submission
/// goes through the MCP `submit_finding` tool.
pub fn extract_json_object(text: &str) -> Option<String> {
	let bytes = text.as_bytes();
	let start = bytes.iter().position(|b| *b == b'{')?;
	let mut depth = 0i32;
	let mut in_str = false;
	let mut escape = false;
	for (i, b) in bytes.iter().enumerate().skip(start) {
		if in_str {
			if escape {
				escape = false;
			} else if *b == b'\\' {
				escape = true;
			} else if *b == b'"' {
				in_str = false;
			}
			continue;
		}
		match *b {
			b'"' => in_str = true,
			b'{' => depth += 1,
			b'}' => {
				depth -= 1;
				if depth == 0 {
					return std::str::from_utf8(&bytes[start..=i]).ok().map(|s| s.to_owned());
				}
			},
			_ => {},
		}
	}
	None
}

#[derive(Debug, Clone)]
pub struct LlmRequest {
	pub prompt: String,
	/// Read-only working directory the backend may inspect (e.g. the
	/// scanned worktree).
	pub workdir: PathBuf,
	pub timeout: Duration,
	pub cancel: CancellationToken,
	/// Repo id for the scan currently in progress. When `Some`, the
	/// backend may attach the loupe MCP server to its agent
	/// invocation so the model can call tools like
	/// `query_prior_findings` scoped to this repo. `None` falls back
	/// to the no-MCP behaviour (just prompt + stdout).
	pub repo_id: Option<i64>,
	/// Job id for the scan currently in progress. Required for the
	/// `submit_finding` MCP tool to POST to
	/// `/v1/jobs/{job_id}/findings`; without it, that tool is not
	/// advertised. `None` falls back to query-only MCP usage (the
	/// agent can read prior findings but can't write new ones).
	pub job_id: Option<i64>,
	/// Finding id for a verify-kind session. When `Some`, the MCP
	/// server enters verify mode: `submit_finding` is hidden;
	/// `submit_verdict`, `submit_patch`, and `validate_patch` are
	/// advertised instead. `None` keeps the discovery-mode catalog.
	pub finding_id: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct LlmResponse {
	pub text: String,
	pub backend_id: &'static str,
}

#[async_trait::async_trait]
pub trait LlmBackend: Send + Sync {
	/// Stable identifier — appears in logs and in `Finding.scanner_id`
	/// when the backend is the source of truth for a finding.
	fn id(&self) -> &'static str;

	async fn run(&self, req: LlmRequest) -> Result<LlmResponse>;
}

/// Probe PATH for `claude --version`. Returns `true` only if the
/// invocation succeeds — a missing binary, non-zero exit, or any IO
/// error all read as "not available."
///
/// Cheap to call at startup. Used with the worker's job-agent
/// selection to decide whether Claude-backed scan or verify work can
/// be registered.
pub fn claude_available() -> bool {
	std::process::Command::new("claude")
		.arg("--version")
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.status()
		.map(|s| s.success())
		.unwrap_or(false)
}

/// Return true when the worker has auth material the claude CLI can
/// use without running an interactive login during a scan.
pub fn claude_auth_available() -> bool {
	env_present("ANTHROPIC_API_KEY") || home_path(".claude.json").is_some_and(|p| p.exists())
}

/// Probe PATH for `bkb-mcp` (Bitcoin Knowledge Base MCP server).
/// Returns the resolved binary path (via `which`-style lookup) when
/// available, `None` otherwise.
///
/// Optional auto-attached MCP server: when present, the discovery
/// scanner advertises bkb's `bkb_search` / `bkb_lookup_bip` /
/// `bkb_lookup_bolt` / etc. tools to the agent so it can pull spec +
/// historical context for bitcoin/lightning code that the worktree alone won't surface. See
/// [`McpContext`] for the attachment plumbing and [`crate::llm::prompts::DISCOVERY`] for the
/// conditional prompt section.
///
/// Install via `cargo install bkb-mcp`; the worker config controls
/// the `BKB_API_URL` passed to the child.
pub fn bkb_mcp_available() -> Option<PathBuf> {
	let path = std::env::var_os("PATH")?;
	for dir in std::env::split_paths(&path) {
		let candidate = dir.join("bkb-mcp");
		if candidate.is_file() {
			let ok = std::process::Command::new(&candidate)
				.arg("--help")
				.stdout(Stdio::null())
				.stderr(Stdio::null())
				.status()
				.map(|s| s.success())
				.unwrap_or(false);
			if ok {
				return Some(candidate);
			}
		}
	}
	None
}

/// Probe PATH for `codex --version`. Returns `true` only if the
/// invocation succeeds — a missing binary, non-zero exit, or any IO
/// error all read as "not available."
///
/// Cheap to call at startup. Used with the worker's job-agent
/// selection to decide whether Codex-backed scan or verify work can
/// be registered.
pub fn codex_available() -> bool {
	std::process::Command::new("codex")
		.arg("--version")
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.status()
		.map(|s| s.success())
		.unwrap_or(false)
}

/// Directory codex should read for login-state files when env-based
/// auth is not used. `CODEX_HOME` mirrors codex's own config-home
/// override; otherwise we use `~/.codex`.
pub fn codex_home_dir() -> Option<PathBuf> {
	if let Some(home) = std::env::var_os("CODEX_HOME").filter(|v| !v.is_empty()) {
		return Some(PathBuf::from(home));
	}
	home_path(".codex")
}

/// Return true when the worker has auth material the codex CLI can use
/// without running an interactive login during a scan.
pub fn codex_auth_available() -> bool {
	codex_api_key_env().is_some() || codex_home_dir().is_some_and(|p| p.join("auth.json").exists())
}

pub(crate) fn codex_api_key_env() -> Option<OsString> {
	env_value("CODEX_API_KEY").or_else(|| env_value("OPENAI_API_KEY"))
}

fn env_present(name: &str) -> bool {
	env_value(name).is_some()
}

fn env_value(name: &str) -> Option<OsString> {
	std::env::var_os(name).filter(|v| !v.is_empty())
}

fn home_path(child: &str) -> Option<PathBuf> {
	std::env::var_os("HOME").filter(|v| !v.is_empty()).map(|h| PathBuf::from(h).join(child))
}

/// Build the scan [`LlmBackend`] according to the configured agent
/// selection. `auto` preserves the historical behaviour: Claude owns
/// LLM discovery when ready; Codex-only workers advertise verify-only
/// unless the operator explicitly selects Codex for scan jobs.
pub fn build_scan_backend(
	mcp: Option<McpContext>, selection: JobAgent, claude_ready: bool, codex_ready: bool,
	codex_agent: CliModelConfig, claude_agent: CliModelConfig, log_agent_output: bool,
) -> Result<Option<Arc<dyn LlmBackend>>> {
	match selection {
		JobAgent::Auto if claude_ready => {
			tracing::info!(
				model = %claude_agent.model,
				effort = %claude_agent.effort,
				"scan backend: claude (auto)"
			);
			Ok(Some(build_claude_backend(mcp, claude_agent, log_agent_output)))
		},
		JobAgent::Auto => {
			tracing::info!(
				"`claude` not ready and scan agent is auto; LLM code-review scanner not registered"
			);
			Ok(None)
		},
		JobAgent::Claude => {
			require_agent_ready("scan", JobAgent::Claude, claude_ready)?;
			tracing::info!(
				model = %claude_agent.model,
				effort = %claude_agent.effort,
				"scan backend: claude (configured)"
			);
			Ok(Some(build_claude_backend(mcp, claude_agent, log_agent_output)))
		},
		JobAgent::Codex => {
			require_agent_ready("scan", JobAgent::Codex, codex_ready)?;
			tracing::info!(
				model = %codex_agent.model,
				effort = %codex_agent.effort,
				"scan backend: codex (configured)"
			);
			Ok(Some(build_codex_backend(mcp, codex_agent, log_agent_output)))
		},
	}
}

/// Build the verifier's [`LlmBackend`]. `auto` preserves the
/// historical verifier behaviour: prefer Codex, falling back to
/// Claude when Codex is unavailable.
///
/// `mcp` (optional) attaches the loupe MCP server to the backend's
/// per-call invocation. Required for the verify-mode tool surface
/// (`submit_verdict` / `submit_patch` / `validate_patch`) — without
/// MCP, the agent has no way to commit a verdict and the runner
/// would receive no feedback to POST. Production callers should
/// always pass `Some(...)`; the `None` form is kept for tests that
/// stub the backend wholesale.
///
/// Logs the choice at info level so operators can see which backend
/// is actually verifying without having to inspect process listings.
pub fn build_verifier_backend(
	mcp: Option<McpContext>, selection: JobAgent, claude_ready: bool, codex_ready: bool,
	codex_agent: CliModelConfig, claude_agent: CliModelConfig, log_agent_output: bool,
) -> Result<Arc<dyn LlmBackend>> {
	match selection {
		JobAgent::Auto if codex_ready => {
			tracing::info!(
				model = %codex_agent.model,
				effort = %codex_agent.effort,
				"verifier backend: codex (auto)"
			);
			Ok(build_codex_backend(mcp, codex_agent, log_agent_output))
		},
		JobAgent::Auto if claude_ready => {
			tracing::info!(
				model = %claude_agent.model,
				effort = %claude_agent.effort,
				"verifier backend: claude (auto, codex unavailable)"
			);
			Ok(build_claude_backend(mcp, claude_agent, log_agent_output))
		},
		JobAgent::Auto => anyhow::bail!("no authenticated verifier backend available"),
		JobAgent::Claude => {
			require_agent_ready("verify", JobAgent::Claude, claude_ready)?;
			tracing::info!(
				model = %claude_agent.model,
				effort = %claude_agent.effort,
				"verifier backend: claude (configured)"
			);
			Ok(build_claude_backend(mcp, claude_agent, log_agent_output))
		},
		JobAgent::Codex => {
			require_agent_ready("verify", JobAgent::Codex, codex_ready)?;
			tracing::info!(
				model = %codex_agent.model,
				effort = %codex_agent.effort,
				"verifier backend: codex (configured)"
			);
			Ok(build_codex_backend(mcp, codex_agent, log_agent_output))
		},
	}
}

fn require_agent_ready(job_kind: &str, agent: JobAgent, ready: bool) -> Result<()> {
	if !ready {
		anyhow::bail!(
			"{job_kind} agent `{agent}` was explicitly selected but that CLI is not installed \
			 or not authenticated"
		);
	}
	Ok(())
}

fn build_claude_backend(
	mcp: Option<McpContext>, agent: CliModelConfig, log_agent_output: bool,
) -> Arc<dyn LlmBackend> {
	let mut backend =
		ClaudeCliBackend::new().with_agent_config(agent).with_log_agent_output(log_agent_output);
	if let Some(ctx) = mcp {
		backend = backend.with_mcp_context(ctx);
	}
	Arc::new(backend)
}

fn build_codex_backend(
	mcp: Option<McpContext>, agent: CliModelConfig, log_agent_output: bool,
) -> Arc<dyn LlmBackend> {
	let mut backend =
		CodexCliBackend::new().with_agent_config(agent).with_log_agent_output(log_agent_output);
	if let Some(ctx) = mcp {
		backend = backend.with_mcp_context(ctx);
	}
	Arc::new(backend)
}

#[cfg(test)]
mod tests {
	use std::ffi::OsString;
	use std::sync::Mutex;

	use super::*;

	static ENV_LOCK: Mutex<()> = Mutex::new(());

	struct EnvGuard {
		name: &'static str,
		old: Option<OsString>,
	}

	impl EnvGuard {
		fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
			let old = std::env::var_os(name);
			std::env::set_var(name, value);
			Self { name, old }
		}

		fn unset(name: &'static str) -> Self {
			let old = std::env::var_os(name);
			std::env::remove_var(name);
			Self { name, old }
		}
	}

	impl Drop for EnvGuard {
		fn drop(&mut self) {
			if let Some(old) = &self.old {
				std::env::set_var(self.name, old);
			} else {
				std::env::remove_var(self.name);
			}
		}
	}

	#[test]
	fn provider_auth_checks_accept_api_keys() {
		let _guard = ENV_LOCK.lock().unwrap();
		let _anthropic = EnvGuard::set("ANTHROPIC_API_KEY", "anthropic-key");
		let _openai = EnvGuard::set("OPENAI_API_KEY", "openai-key");
		let _codex = EnvGuard::unset("CODEX_API_KEY");

		assert!(claude_auth_available());
		assert!(codex_auth_available());
	}

	#[test]
	fn codex_auth_checks_codex_api_key() {
		let _guard = ENV_LOCK.lock().unwrap();
		let _openai = EnvGuard::unset("OPENAI_API_KEY");
		let _codex = EnvGuard::set("CODEX_API_KEY", "codex-key");
		let dir = tempfile::tempdir().unwrap();
		let _codex_home = EnvGuard::set("CODEX_HOME", dir.path().as_os_str());

		assert!(
			codex_auth_available(),
			"CODEX_API_KEY should enable codex auth without OPENAI_API_KEY or auth.json"
		);
	}

	#[test]
	fn cli_error_summary_preserves_the_actionable_tail() {
		let stderr = format!(
			"{}\nERROR: stream disconnected before completion: proxy refused websocket",
			"OpenAI Codex startup banner ".repeat(80)
		);

		let summary = summarize_cli_stream_for_error(&stderr, 180);

		assert!(summary.contains("OpenAI Codex startup banner"), "got: {summary}");
		assert!(summary.contains("proxy refused websocket"), "got: {summary}");
		assert!(summary.contains(CLI_STREAM_OMISSION), "got: {summary}");
		assert!(!summary.contains('\n'), "summary must stay single-line: {summary}");
	}

	#[test]
	fn codex_auth_checks_codex_home_auth_json() {
		let _guard = ENV_LOCK.lock().unwrap();
		let _openai = EnvGuard::unset("OPENAI_API_KEY");
		let _codex = EnvGuard::unset("CODEX_API_KEY");
		let dir = tempfile::tempdir().unwrap();
		std::fs::write(dir.path().join("auth.json"), "{}").unwrap();
		let _codex_home = EnvGuard::set("CODEX_HOME", dir.path().as_os_str());

		assert_eq!(codex_home_dir().as_deref(), Some(dir.path()));
		assert!(codex_auth_available());
	}

	#[test]
	fn scan_backend_auto_preserves_claude_only_discovery_default() {
		let codex = CliModelConfig {
			model: "gpt-test".into(),
			effort: "xhigh".into(),
			provider: None,
			api_key_env: None,
		};
		let claude = CliModelConfig {
			model: "claude-test".into(),
			effort: "max".into(),
			provider: None,
			api_key_env: None,
		};

		let backend = build_scan_backend(
			None,
			JobAgent::Auto,
			true,
			true,
			codex.clone(),
			claude.clone(),
			false,
		)
		.unwrap()
		.expect("claude-ready auto scan should register");
		assert_eq!(backend.id(), "claude-cli");

		let backend = build_scan_backend(
			None,
			JobAgent::Auto,
			false,
			true,
			codex.clone(),
			claude,
			false,
		)
		.unwrap();
		assert!(
			backend.is_none(),
			"auto scan should not switch to codex unless explicitly configured"
		);
	}

	#[test]
	fn scan_backend_allows_explicit_codex_and_fails_when_unavailable() {
		let codex = CliModelConfig {
			model: "gpt-test".into(),
			effort: "xhigh".into(),
			provider: None,
			api_key_env: None,
		};
		let claude = CliModelConfig {
			model: "claude-test".into(),
			effort: "max".into(),
			provider: None,
			api_key_env: None,
		};

		let backend = build_scan_backend(
			None,
			JobAgent::Codex,
			true,
			true,
			codex.clone(),
			claude.clone(),
			false,
		)
		.unwrap()
		.expect("explicit codex scan should register when codex is ready");
		assert_eq!(backend.id(), "codex-cli");

		let err = match build_scan_backend(
			None,
			JobAgent::Codex,
			true,
			false,
			codex,
			claude,
			false,
		) {
			Ok(_) => panic!("explicit unavailable codex scan should fail"),
			Err(e) => e,
		};
		assert!(err.to_string().contains("scan agent `codex`"), "got: {err}");
	}

	#[test]
	fn verifier_backend_auto_prefers_codex_then_claude() {
		let codex = CliModelConfig {
			model: "gpt-test".into(),
			effort: "xhigh".into(),
			provider: None,
			api_key_env: None,
		};
		let claude = CliModelConfig {
			model: "claude-test".into(),
			effort: "max".into(),
			provider: None,
			api_key_env: None,
		};
		let backend = build_verifier_backend(
			None,
			JobAgent::Auto,
			true,
			true,
			codex.clone(),
			claude.clone(),
			false,
		)
		.unwrap();
		assert_eq!(backend.id(), "codex-cli");

		let backend = build_verifier_backend(
			None,
			JobAgent::Auto,
			true,
			false,
			codex.clone(),
			claude.clone(),
			false,
		)
		.unwrap();
		assert_eq!(backend.id(), "claude-cli");

		let err = match build_verifier_backend(
			None,
			JobAgent::Auto,
			false,
			false,
			codex,
			claude,
			false,
		) {
			Ok(_) => panic!("missing verifier backend should be rejected"),
			Err(e) => e,
		};
		assert!(err.to_string().contains("no authenticated verifier backend"));
	}

	#[test]
	fn verifier_backend_honors_explicit_selection() {
		let codex = CliModelConfig {
			model: "gpt-test".into(),
			effort: "xhigh".into(),
			provider: None,
			api_key_env: None,
		};
		let claude = CliModelConfig {
			model: "claude-test".into(),
			effort: "max".into(),
			provider: None,
			api_key_env: None,
		};

		let backend = build_verifier_backend(
			None,
			JobAgent::Claude,
			true,
			true,
			codex.clone(),
			claude.clone(),
			false,
		)
		.unwrap();
		assert_eq!(backend.id(), "claude-cli");

		let err = match build_verifier_backend(
			None,
			JobAgent::Claude,
			false,
			true,
			codex,
			claude,
			false,
		) {
			Ok(_) => panic!("explicit unavailable claude verifier should fail"),
			Err(e) => e,
		};
		assert!(err.to_string().contains("verify agent `claude`"), "got: {err}");
	}
}

pub mod testing {
	//! Stub backend for testing scanners without invoking a real LLM
	//! CLI / API. Tests pass a closure that produces canned responses
	//! based on the request's prompt or workdir.
	//!
	//! Lives outside `#[cfg(test)]` so integration tests in sibling
	//! crates (e.g. `loupe-server/tests/llm_dispatch.rs`) can reach it.
	//! Not intended for production wiring.
	//!
	//! Two constructors:
	//! - [`StubLlmBackend::new`] takes a sync closure — simplest for
	//!   unit tests that just need a canned text response.
	//! - [`StubLlmBackend::new_async`] takes an async closure — needed
	//!   for integration tests that simulate the agent's MCP
	//!   `submit_finding` tool by POSTing to a real loupe-server
	//!   inside the closure. The agent's tool calls happen during the
	//!   session in production; the async stub gives tests the same
	//!   "while the LLM is running" hook.

	use std::future::Future;
	use std::pin::Pin;
	use std::sync::Arc;

	use anyhow::Result;
	use async_trait::async_trait;

	use super::{LlmBackend, LlmRequest, LlmResponse};

	type AsyncStubFn = Arc<
		dyn Fn(LlmRequest) -> Pin<Box<dyn Future<Output = Result<String>> + Send>> + Send + Sync,
	>;

	pub struct StubLlmBackend {
		id: &'static str,
		f: AsyncStubFn,
	}

	impl StubLlmBackend {
		/// Create a stub whose closure is sync — good for unit tests
		/// that don't need to call back into anything async.
		pub fn new<F>(id: &'static str, f: F) -> Self
		where
			F: Fn(&LlmRequest) -> Result<String> + Send + Sync + 'static,
		{
			let f = Arc::new(f);
			Self {
				id,
				f: Arc::new(move |req: LlmRequest| {
					let f = f.clone();
					Box::pin(async move { f(&req) })
				}),
			}
		}

		/// Create a stub whose closure can `.await` — used by tests
		/// that simulate the agent calling `submit_finding` mid-
		/// session against a real server fixture.
		pub fn new_async<F, Fut>(id: &'static str, f: F) -> Self
		where
			F: Fn(LlmRequest) -> Fut + Send + Sync + 'static,
			Fut: Future<Output = Result<String>> + Send + 'static,
		{
			Self { id, f: Arc::new(move |req| Box::pin(f(req))) }
		}
	}

	#[async_trait]
	impl LlmBackend for StubLlmBackend {
		fn id(&self) -> &'static str {
			self.id
		}

		async fn run(&self, req: LlmRequest) -> Result<LlmResponse> {
			let text = (self.f)(req).await?;
			Ok(LlmResponse { text, backend_id: self.id })
		}
	}
}
