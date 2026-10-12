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
//!   into a credential-free proxy connected to the parent worker's
//!   host-side MCP broker.
//! - [`CodexCliBackend`] shells out to OpenAI's `codex` CLI. Carries
//!   the same optional MCP context via Codex CLI config overrides.
//!
//! Picking between them at runtime: see [`build_scan_backend`] and
//! [`build_verifier_backend`].

pub mod claude_cli;
mod cli_stdin;
pub mod codex_cli;
pub mod mcp;
pub mod model_broker;
pub mod model_proxy;
pub mod prompt;
pub mod prompts;

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::ValueEnum;
pub use claude_cli::ClaudeCliBackend;
pub use codex_cli::CodexCliBackend;
use loupe_proto::JobCapability;
use loupe_provenance::{Secret, Zeroise};
pub use mcp::McpContext;
use model_broker::{CredentialKind, ModelBrokerContext, ModelBrokerLimits, ModelCredential};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

use crate::sandbox::{SandboxNetworkConfig, SandboxNetworkMode};

const ANTHROPIC_UPSTREAM_URL: &str = "https://api.anthropic.com";
const OPENAI_UPSTREAM_URL: &str = "https://api.openai.com";

#[derive(Debug, Clone)]
pub struct CliModelConfig {
	pub model: crate::config::ConfiguredText,
	pub effort: crate::config::ConfiguredText,
}

#[derive(Debug, Clone, Default)]
pub struct BackendRuntimeConfig {
	pub network: SandboxNetworkConfig,
	pub log_agent_output: bool,
	pub model_broker: Option<ModelBrokerRuntimeConfig>,
}

#[derive(Debug, Clone)]
pub struct ModelBrokerRuntimeConfig {
	pub worker_binary: PathBuf,
	pub limits: ModelBrokerLimits,
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

mod cli_output;

/// Exercise the production collector with arbitrary streams in the fuzz build.
#[cfg(fuzzing)]
pub async fn fuzz_collect_cli_output(
	reader: impl tokio::io::AsyncRead + Unpin,
) -> std::io::Result<(Vec<u8>, bool)> {
	let output = cli_output::collect_cli_output(reader).await?;
	Ok((output.fixture_bytes(), output.truncated))
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
/// Retained legacy helper with no production caller. Discovery findings and
/// verification verdicts currently arrive through MCP tools instead of stdout.
#[cfg(any(test, fuzzing))]
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
	pub tool_boundary: prompt::JobToolBoundary,
	pub prompt: prompts::Prompt,
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
	/// `/v1/jobs/{job_id}/llm-findings`; without it, that tool is not
	/// advertised. `None` falls back to query-only MCP usage (the
	/// agent can read prior findings but can't write new ones).
	pub job_id: Option<i64>,
	/// Opaque authority for the exact active lease. It remains in the
	/// trusted host broker and is never passed to the agent process.
	pub job_capability: Option<JobCapability>,
	/// Finding id for a verify-kind session. When `Some`, the MCP
	/// server enters verify mode: `submit_finding` is hidden;
	/// `submit_verdict`, `submit_patch`, and `validate_patch` are
	/// advertised instead. `None` keeps the discovery-mode catalog.
	pub finding_id: Option<i64>,
}

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "test-support"), doc = include_str!("../../tests/ui/raw_stub.md"))]
pub struct LlmResponse {
	pub text: cli_output::CliOutputText,
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
/// use non-interactively inside the sandbox.
///
/// Only environment credentials count: `ANTHROPIC_API_KEY`, or a
/// `CLAUDE_CODE_OAUTH_TOKEN` from `claude setup-token`. Subscription
/// login state under `~/.claude` is deliberately not mounted, and its
/// OAuth refresh needs to write — which the read-only sandbox forbids
/// — so a bare `~/.claude.json` no longer counts as usable auth.
pub fn claude_auth_available() -> bool {
	env_present("ANTHROPIC_API_KEY") || env_present("CLAUDE_CODE_OAUTH_TOKEN")
}

fn claude_model_broker_context(runtime: ModelBrokerRuntimeConfig) -> Result<ModelBrokerContext> {
	let credential = if let Some(secret) = utf8_env_value("ANTHROPIC_API_KEY")? {
		ModelCredential::from_secret(CredentialKind::AnthropicApiKey, secret)
	} else if let Some(secret) = utf8_env_value("CLAUDE_CODE_OAUTH_TOKEN")? {
		ModelCredential::from_secret(CredentialKind::AnthropicOAuthToken, secret)
	} else {
		anyhow::bail!("Claude model broker requires ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN");
	};
	Ok(ModelBrokerContext::new(
		runtime.worker_binary,
		ANTHROPIC_UPSTREAM_URL.parse().expect("static Anthropic upstream URL is valid"),
		credential,
		runtime.limits,
	))
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

/// Return true when the worker has auth material the codex CLI can use
/// without running an interactive login during a scan.
pub fn codex_auth_available() -> bool {
	env_present("CODEX_API_KEY") || env_present("OPENAI_API_KEY")
}

fn codex_model_broker_context(runtime: ModelBrokerRuntimeConfig) -> Result<ModelBrokerContext> {
	let secret = if let Some(secret) = utf8_env_value("CODEX_API_KEY")? {
		secret
	} else if let Some(secret) = utf8_env_value("OPENAI_API_KEY")? {
		secret
	} else {
		anyhow::bail!("Codex model broker requires CODEX_API_KEY or OPENAI_API_KEY");
	};
	Ok(ModelBrokerContext::new(
		runtime.worker_binary,
		OPENAI_UPSTREAM_URL.parse().expect("static OpenAI upstream URL is valid"),
		ModelCredential::from_secret(CredentialKind::OpenAiApiKey, secret),
		runtime.limits,
	))
}

pub(crate) fn required_network_hosts(bkb_api_url: Option<&str>) -> Result<Vec<String>> {
	let mut hosts = Vec::new();
	if let Some(bkb_api_url) = bkb_api_url {
		let url = reqwest::Url::parse(bkb_api_url)?;
		let host =
			url.host_str().ok_or_else(|| anyhow::anyhow!("configured BKB API URL has no host"))?;
		hosts.push(host.to_owned());
	}
	Ok(hosts)
}

pub(crate) fn sandbox_requires_egress_setup(
	network: &SandboxNetworkConfig, required_hosts: &[String],
) -> bool {
	network.mode == SandboxNetworkMode::Public
		|| !network.allowlist.is_empty()
		|| !required_hosts.is_empty()
}

fn env_present(name: &str) -> bool {
	env_value(name).is_some()
}

// Own every controllable getenv copy, including probes, empty values and
// invalid UTF-8. The original process environment remains outside this owner.
struct EnvironmentCredential(Vec<u8>);

impl EnvironmentCredential {
	fn new(value: OsString) -> Self {
		Self(value.into_vec())
	}

	fn into_utf8(mut self, name: &str) -> Result<Secret<String>> {
		match String::from_utf8(std::mem::take(&mut self.0)) {
			Ok(value) => Ok(Secret::new(value)),
			Err(error) => {
				let _rejected = Secret::new(error.into_bytes());
				anyhow::bail!("{name} must contain valid UTF-8 for HTTP authentication");
			},
		}
	}
}

impl Drop for EnvironmentCredential {
	fn drop(&mut self) {
		self.0.zeroise();
	}
}

fn env_value(name: &str) -> Option<EnvironmentCredential> {
	std::env::var_os(name).map(EnvironmentCredential::new).filter(|value| !value.0.is_empty())
}

fn utf8_env_value(name: &str) -> Result<Option<Secret<String>>> {
	env_value(name).map(|value| value.into_utf8(name)).transpose()
}

/// Build the scan [`LlmBackend`] according to the configured agent
/// selection. `auto` preserves the historical behaviour: Claude owns
/// LLM discovery when ready; Codex-only workers advertise verify-only
/// unless the operator explicitly selects Codex for scan jobs.
pub fn build_scan_backend(
	mcp: Option<McpContext>, selection: JobAgent, claude_ready: bool, codex_ready: bool,
	codex_agent: CliModelConfig, claude_agent: CliModelConfig, runtime: BackendRuntimeConfig,
) -> Result<Option<Arc<dyn LlmBackend>>> {
	let BackendRuntimeConfig { network, log_agent_output, model_broker } = runtime;
	match selection {
		JobAgent::Auto if claude_ready => {
			tracing::info!(
				model = %claude_agent.model.for_operation(),
				effort = %claude_agent.effort.for_operation(),
				"scan backend: claude (auto)"
			);
			Ok(Some(build_claude_backend(
				mcp,
				claude_agent,
				network,
				log_agent_output,
				model_broker,
			)?))
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
				model = %claude_agent.model.for_operation(),
				effort = %claude_agent.effort.for_operation(),
				"scan backend: claude (configured)"
			);
			Ok(Some(build_claude_backend(
				mcp,
				claude_agent,
				network,
				log_agent_output,
				model_broker,
			)?))
		},
		JobAgent::Codex => {
			require_agent_ready("scan", JobAgent::Codex, codex_ready)?;
			tracing::info!(
				model = %codex_agent.model.for_operation(),
				effort = %codex_agent.effort.for_operation(),
				"scan backend: codex (configured)"
			);
			Ok(Some(build_codex_backend(
				mcp,
				codex_agent,
				network,
				log_agent_output,
				model_broker,
			)?))
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
	codex_agent: CliModelConfig, claude_agent: CliModelConfig, runtime: BackendRuntimeConfig,
) -> Result<Arc<dyn LlmBackend>> {
	let BackendRuntimeConfig { network, log_agent_output, model_broker } = runtime;
	match selection {
		JobAgent::Auto if codex_ready => {
			tracing::info!(
				model = %codex_agent.model.for_operation(),
				effort = %codex_agent.effort.for_operation(),
				"verifier backend: codex (auto)"
			);
			Ok(build_codex_backend(mcp, codex_agent, network, log_agent_output, model_broker)?)
		},
		JobAgent::Auto if claude_ready => {
			tracing::info!(
				model = %claude_agent.model.for_operation(),
				effort = %claude_agent.effort.for_operation(),
				"verifier backend: claude (auto, codex unavailable)"
			);
			Ok(build_claude_backend(mcp, claude_agent, network, log_agent_output, model_broker)?)
		},
		JobAgent::Auto => anyhow::bail!("no authenticated verifier backend available"),
		JobAgent::Claude => {
			require_agent_ready("verify", JobAgent::Claude, claude_ready)?;
			tracing::info!(
				model = %claude_agent.model.for_operation(),
				effort = %claude_agent.effort.for_operation(),
				"verifier backend: claude (configured)"
			);
			Ok(build_claude_backend(mcp, claude_agent, network, log_agent_output, model_broker)?)
		},
		JobAgent::Codex => {
			require_agent_ready("verify", JobAgent::Codex, codex_ready)?;
			tracing::info!(
				model = %codex_agent.model.for_operation(),
				effort = %codex_agent.effort.for_operation(),
				"verifier backend: codex (configured)"
			);
			Ok(build_codex_backend(mcp, codex_agent, network, log_agent_output, model_broker)?)
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
	mcp: Option<McpContext>, agent: CliModelConfig, network: SandboxNetworkConfig,
	log_agent_output: bool, model_broker: Option<ModelBrokerRuntimeConfig>,
) -> Result<Arc<dyn LlmBackend>> {
	let mut backend = ClaudeCliBackend::new()
		.with_agent_config(agent)
		.with_network_config(network)
		.with_log_agent_output(log_agent_output);
	if let Some(ctx) = mcp {
		backend = backend.with_mcp_context(ctx);
	}
	if let Some(runtime) = model_broker {
		backend = backend.with_model_broker_context(claude_model_broker_context(runtime)?);
	}
	Ok(Arc::new(backend))
}

fn build_codex_backend(
	mcp: Option<McpContext>, agent: CliModelConfig, network: SandboxNetworkConfig,
	log_agent_output: bool, model_broker: Option<ModelBrokerRuntimeConfig>,
) -> Result<Arc<dyn LlmBackend>> {
	let mut backend = CodexCliBackend::new()
		.with_agent_config(agent)
		.with_network_config(network)
		.with_log_agent_output(log_agent_output);
	if let Some(ctx) = mcp {
		backend = backend.with_mcp_context(ctx);
	}
	if let Some(runtime) = model_broker {
		backend = backend.with_model_broker_context(codex_model_broker_context(runtime)?);
	}
	Ok(Arc::new(backend))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_env::in_env;

	#[test]
	fn environment_credential_moves_the_same_allocation_into_its_secret_owner() {
		use std::os::unix::ffi::OsStringExt;
		let raw = OsString::from_vec(b"synthetic-environment-key".to_vec());
		let pointer = raw.as_encoded_bytes().as_ptr();
		let guarded = EnvironmentCredential::new(raw);
		assert_eq!(guarded.0.as_ptr(), pointer);
		let secret = guarded.into_utf8("SYNTHETIC_KEY").unwrap();
		assert_eq!(secret.expose().as_ptr(), pointer);
		assert_eq!(secret.expose(), "synthetic-environment-key");
	}

	#[test]
	fn provider_auth_checks_accept_api_keys() {
		if !in_env(
			"llm::tests::provider_auth_checks_accept_api_keys",
			"api-keys",
			&[
				("ANTHROPIC_API_KEY", Some("anthropic-key".as_ref())),
				("OPENAI_API_KEY", Some("openai-key".as_ref())),
				("CODEX_API_KEY", None),
			],
		) {
			return;
		}

		assert!(claude_auth_available());
		assert!(codex_auth_available());
	}

	#[test]
	fn claude_auth_requires_env_token_not_a_stale_config_file() {
		let home = tempfile::tempdir().unwrap();
		std::fs::write(home.path().join(".claude.json"), "{}").unwrap();

		// A leftover `~/.claude.json` carries no usable credential once
		// `~/.claude` (with `.credentials.json`) is no longer mounted,
		// and OAuth refresh cannot write into the read-only sandbox. It
		// must not make the worker advertise Claude as ready.
		for (case, token) in [("stale-config", None), ("oauth-token", Some("oauth-token"))] {
			if in_env(
				"llm::tests::claude_auth_requires_env_token_not_a_stale_config_file",
				case,
				&[
					("ANTHROPIC_API_KEY", None),
					("CLAUDE_CODE_OAUTH_TOKEN", token.map(AsRef::as_ref)),
					("HOME", Some(home.path().as_os_str())),
				],
			) {
				assert_eq!(
					claude_auth_available(),
					token.is_some(),
					"only an explicit token, not a stale ~/.claude.json, must satisfy Claude auth"
				);
			}
		}
	}

	#[test]
	fn codex_auth_checks_codex_api_key() {
		if !in_env(
			"llm::tests::codex_auth_checks_codex_api_key",
			"codex-key",
			&[("OPENAI_API_KEY", None), ("CODEX_API_KEY", Some("codex-key".as_ref()))],
		) {
			return;
		}

		assert!(codex_auth_available(), "CODEX_API_KEY should enable codex authentication");
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
	fn sandbox_network_only_includes_enabled_bkb() {
		assert_eq!(required_network_hosts(None).unwrap(), Vec::<String>::new());
		assert_eq!(
			required_network_hosts(Some(mcp::DEFAULT_BKB_API_URL)).unwrap(),
			["bitcoinknowledge.dev"]
		);
		assert_eq!(
			required_network_hosts(Some("https://knowledge.example.test:8443/api")).unwrap(),
			["knowledge.example.test"]
		);
	}

	#[test]
	fn empty_allowlist_uses_the_private_loopback_namespace() {
		let model_only =
			SandboxNetworkConfig { mode: SandboxNetworkMode::Allowlist, allowlist: Vec::new() };
		assert!(!sandbox_requires_egress_setup(&model_only, &[]));
		assert!(sandbox_requires_egress_setup(&model_only, &["bkb.example".into()]));
		assert!(sandbox_requires_egress_setup(
			&SandboxNetworkConfig {
				mode: SandboxNetworkMode::Allowlist,
				allowlist: vec![crate::config::ConfiguredText::Builtin("docs.example")],
			},
			&[],
		));
		assert!(sandbox_requires_egress_setup(&SandboxNetworkConfig::default(), &[]));
	}

	#[test]
	fn scan_backend_auto_preserves_claude_only_discovery_default() {
		let codex = CliModelConfig {
			model: crate::config::ConfiguredText::Builtin("gpt-test"),
			effort: crate::config::ConfiguredText::Builtin("xhigh"),
		};
		let claude = CliModelConfig {
			model: crate::config::ConfiguredText::Builtin("claude-test"),
			effort: crate::config::ConfiguredText::Builtin("max"),
		};

		let backend = build_scan_backend(
			None,
			JobAgent::Auto,
			true,
			true,
			codex.clone(),
			claude.clone(),
			BackendRuntimeConfig::default(),
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
			BackendRuntimeConfig::default(),
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
			model: crate::config::ConfiguredText::Builtin("gpt-test"),
			effort: crate::config::ConfiguredText::Builtin("xhigh"),
		};
		let claude = CliModelConfig {
			model: crate::config::ConfiguredText::Builtin("claude-test"),
			effort: crate::config::ConfiguredText::Builtin("max"),
		};

		let backend = build_scan_backend(
			None,
			JobAgent::Codex,
			true,
			true,
			codex.clone(),
			claude.clone(),
			BackendRuntimeConfig::default(),
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
			BackendRuntimeConfig::default(),
		) {
			Ok(_) => panic!("explicit unavailable codex scan should fail"),
			Err(e) => e,
		};
		assert!(err.to_string().contains("scan agent `codex`"), "got: {err}");
	}

	#[test]
	fn verifier_backend_auto_prefers_codex_then_claude() {
		let codex = CliModelConfig {
			model: crate::config::ConfiguredText::Builtin("gpt-test"),
			effort: crate::config::ConfiguredText::Builtin("xhigh"),
		};
		let claude = CliModelConfig {
			model: crate::config::ConfiguredText::Builtin("claude-test"),
			effort: crate::config::ConfiguredText::Builtin("max"),
		};
		let backend = build_verifier_backend(
			None,
			JobAgent::Auto,
			true,
			true,
			codex.clone(),
			claude.clone(),
			BackendRuntimeConfig::default(),
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
			BackendRuntimeConfig::default(),
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
			BackendRuntimeConfig::default(),
		) {
			Ok(_) => panic!("missing verifier backend should be rejected"),
			Err(e) => e,
		};
		assert!(err.to_string().contains("no authenticated verifier backend"));
	}

	#[test]
	fn verifier_backend_honors_explicit_selection() {
		let codex = CliModelConfig {
			model: crate::config::ConfiguredText::Builtin("gpt-test"),
			effort: crate::config::ConfiguredText::Builtin("xhigh"),
		};
		let claude = CliModelConfig {
			model: crate::config::ConfiguredText::Builtin("claude-test"),
			effort: crate::config::ConfiguredText::Builtin("max"),
		};

		let backend = build_verifier_backend(
			None,
			JobAgent::Claude,
			true,
			true,
			codex.clone(),
			claude.clone(),
			BackendRuntimeConfig::default(),
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
			BackendRuntimeConfig::default(),
		) {
			Ok(_) => panic!("explicit unavailable claude verifier should fail"),
			Err(e) => e,
		};
		assert!(err.to_string().contains("verify agent `claude`"), "got: {err}");
	}
}

#[cfg(any(test, feature = "test-support"))]
pub mod testing {
	//! Stub backend for testing scanners without invoking a real LLM
	//! CLI / API. Tests pass a closure that produces canned responses
	//! based on the request's prompt or workdir.
	//!
	//! Available to this crate's unit tests and through the non-default
	//! `test-support` feature for sibling integration tests. Enabling that
	//! feature explicitly grants synthetic Sandbox fixture authority; Cargo
	//! features do not enforce that the caller is a test. Normal dependencies
	//! must leave it disabled. These responses are synthetic fixtures, not
	//! evidence of an actual CLI pipe read.
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
			let text = super::cli_output::synthetic_output(text)?;
			Ok(LlmResponse { text, backend_id: self.id })
		}
	}
}
