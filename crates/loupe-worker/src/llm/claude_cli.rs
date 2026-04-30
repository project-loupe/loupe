//! Backend that shells out to the `claude` CLI.
//!
//! Runs `claude --dangerously-skip-permissions -p "$prompt"` inside the
//! bubblewrap sandbox so the agent can read the worktree at `/workdir`
//! but can't write to it or persist any state across invocations. The
//! `--dangerously-skip-permissions` flag is acceptable here only
//! because the sandbox is the security boundary, not the CLI's
//! permission system.
//!
//! Network is allowed through the sandbox so the CLI can reach
//! api.anthropic.com.
//!
//! When constructed with [`McpContext`], each invocation writes a
//! per-call MCP config and passes `--mcp-config` to claude. The
//! agent then has the loupe tool surface (`query_prior_findings`,
//! etc., served by `loupe-worker mcp-serve`) for the duration of
//! the call. Sandbox-side: the worker binary and the worker's mTLS
//! cert are bind-mounted in at fixed paths the MCP child can refer
//! to.

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

use super::{LlmBackend, LlmRequest, LlmResponse};
use crate::sandbox::SandboxBuilder;

const BACKEND_ID: &str = "claude-cli";
const CLAUDE_BIN: &str = "claude";

/// Fixed paths the sandbox uses for the MCP server bundle. The
/// loupe-worker binary and the worker's mTLS cert + key + CA cert
/// get bind-mounted under `/loupe/`; the per-call MCP config lives
/// next to them. Inside the sandbox the agent only ever sees these
/// paths, regardless of where the host install actually lives.
const SANDBOX_LOUPE_BIN: &str = "/loupe/loupe-worker";
const SANDBOX_CA_CERT: &str = "/loupe/ca.pem";
const SANDBOX_CLIENT_CERT: &str = "/loupe/worker.pem";
const SANDBOX_CLIENT_KEY: &str = "/loupe/worker.key";
const SANDBOX_MCP_CONFIG: &str = "/loupe/mcp-config.json";

/// Everything the MCP child needs to talk back to loupe-server.
/// Built once at worker startup from the `loupe-worker run` CLI
/// flags and stashed on the backend; per-call data (the repo id)
/// arrives through [`LlmRequest::repo_id`].
#[derive(Debug, Clone)]
pub struct McpContext {
	/// Path to the loupe-worker binary on the host. Usually
	/// `std::env::current_exe()` for the worker itself, so the same
	/// binary serves both `run` and `mcp-serve` modes.
	pub worker_binary: PathBuf,
	/// loupe-server URL the MCP child will call back to.
	pub server_url: String,
	pub ca_cert_path: PathBuf,
	pub client_cert_path: PathBuf,
	pub client_key_path: PathBuf,
}

/// Per-call MCP scratch: a host-side tempdir holding the JSON
/// config that `claude --mcp-config` reads. The `TempDir` is
/// returned so the caller keeps it alive until after claude exits;
/// dropping the `TempDir` unlinks the config file.
struct McpScratch {
	#[allow(dead_code)] // RAII — drop at end of caller's scope cleans up.
	dir: tempfile::TempDir,
	config_path: PathBuf,
}

fn prepare_mcp_scratch(ctx: &McpContext, repo_id: i64) -> Result<McpScratch> {
	let dir = tempfile::Builder::new()
		.prefix("loupe-mcp-")
		.tempdir()
		.context("creating MCP scratch tempdir")?;
	let config_path = dir.path().join("mcp-config.json");
	let config = serde_json::json!({
		"mcpServers": {
			"loupe": {
				"type": "stdio",
				// Inside the sandbox the worker binary is mounted at
				// SANDBOX_LOUPE_BIN, the cert files under /loupe/...
				// — see the bind_ro calls above.
				"command": SANDBOX_LOUPE_BIN,
				"args": [
					"mcp-serve",
					"--server-url", ctx.server_url,
					"--ca-cert", SANDBOX_CA_CERT,
					"--cert", SANDBOX_CLIENT_CERT,
					"--key", SANDBOX_CLIENT_KEY,
					"--repo-id", repo_id.to_string(),
				],
				// The MCP child inherits the bwrap'd env, which has
				// HOME=/home/scanner + the forwarded ANTHROPIC_API_KEY
				// (irrelevant for the MCP child but harmless). No
				// extra env needed at this layer.
				"env": {}
			}
		}
	});
	std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)
		.with_context(|| format!("writing MCP config at {}", config_path.display()))?;
	tracing::debug!(
		config_path = %config_path.display(),
		repo_id,
		"loupe-mcp: prepared per-call scratch config",
	);
	Ok(McpScratch { dir, config_path })
}

/// Cap a borrow at `n` chars; appends an ellipsis if the original was
/// longer. Used to keep error messages from blowing up when the CLI
/// dumps multi-MB diagnostics on a non-zero exit.
fn truncate(s: &str, n: usize) -> String {
	let mut buf: String = s.chars().take(n).collect();
	if s.chars().nth(n).is_some() {
		buf.push('…');
	}
	buf.replace('\n', " ")
}

pub struct ClaudeCliBackend {
	bin: String,
	mcp: Option<McpContext>,
}

impl ClaudeCliBackend {
	pub fn new() -> Self {
		Self { bin: CLAUDE_BIN.to_owned(), mcp: None }
	}

	pub fn with_bin(bin: impl Into<String>) -> Self {
		Self { bin: bin.into(), mcp: None }
	}

	/// Attach an MCP server to every invocation. When set, each call
	/// writes a temp `mcp-config.json` and passes `--mcp-config` to
	/// claude; the agent then sees the `loupe-worker mcp-serve`
	/// tool surface (currently `query_prior_findings`).
	pub fn with_mcp_context(mut self, mcp: McpContext) -> Self {
		self.mcp = Some(mcp);
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
			prompt_chars = req.prompt.chars().count(),
			timeout_ms = req.timeout.as_millis() as u64,
			"claude-cli: invoking",
		);
		let started = std::time::Instant::now();

		let mut sandbox = SandboxBuilder::new(&req.workdir)
			.allow_network()
			// Make the `claude` install reachable — by default the
			// sandbox only mounts /usr, /etc, /lib*, /bin, /sbin, so
			// per-user installs at ~/.local/bin/... are invisible
			// without this.
			.allow_binary(&self.bin)
			.with_context(|| format!("preparing sandbox for `{}`", self.bin))?
			// Forward auth: ANTHROPIC_API_KEY for env-based auth, plus
			// any user-managed login state under ~/.claude/* which
			// `claude /login` writes to.
			.forward_env("ANTHROPIC_API_KEY");
		if let Some(home) = std::env::var_os("HOME") {
			let host_home = std::path::PathBuf::from(home);
			let claude_dir = host_home.join(".claude");
			let claude_json = host_home.join(".claude.json");
			// Sandbox $HOME is /home/scanner; map the operator's
			// claude state into the equivalent paths there. `--ro-bind-try`
			// (used inside SandboxBuilder) makes missing sources a
			// no-op, so a host without these files just skips.
			sandbox = sandbox
				.bind_ro(claude_dir, "/home/scanner/.claude")
				.bind_ro(claude_json, "/home/scanner/.claude.json");
		}

		// Optional MCP attachment. Held in a local so its `TempDir`
		// lives until after the subprocess returns — dropping it
		// early would unlink the config file out from under claude.
		let _mcp_scratch = match (&self.mcp, req.repo_id) {
			(Some(ctx), Some(repo_id)) => {
				let scratch =
					prepare_mcp_scratch(ctx, repo_id).context("preparing MCP scratch directory")?;
				sandbox = sandbox
					.bind_ro(ctx.worker_binary.clone(), SANDBOX_LOUPE_BIN)
					.bind_ro(ctx.ca_cert_path.clone(), SANDBOX_CA_CERT)
					.bind_ro(ctx.client_cert_path.clone(), SANDBOX_CLIENT_CERT)
					.bind_ro(ctx.client_key_path.clone(), SANDBOX_CLIENT_KEY)
					.bind_ro(scratch.config_path.clone(), SANDBOX_MCP_CONFIG);
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

		let mut cmd = sandbox.build(&self.bin);
		cmd.arg("--dangerously-skip-permissions").arg("-p").arg(&req.prompt);
		if _mcp_scratch.is_some() {
			cmd.arg("--mcp-config").arg(SANDBOX_MCP_CONFIG);
		}
		cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());

		let mut child = cmd
			.spawn()
			.with_context(|| format!("spawning `{}` (is the claude CLI installed?)", self.bin))?;

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
			Err(_) => return Err(anyhow!("claude CLI timed out after {:?}", req.timeout)),
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
				"claude-cli: subprocess failed",
			);
			// Some CLIs (claude included) print "please log in" /
			// auth-error messages to stdout, not stderr — surface
			// both so the operator's log shows whichever the CLI
			// chose. Trim and truncate so a multi-MB diagnostic dump
			// doesn't drown the log line.
			let combined = format!(
				"stderr=`{}` stdout=`{}`",
				truncate(&stderr_text, 400),
				truncate(&stdout_text, 400),
			);
			return Err(anyhow!("claude CLI exited with {}: {}", status, combined));
		}

		let text = String::from_utf8(stdout)
			.map_err(|e| anyhow!("claude CLI stdout was not UTF-8: {e}"))?;
		tracing::debug!(
			backend = BACKEND_ID,
			elapsed_ms = started.elapsed().as_millis() as u64,
			stdout_chars = text.chars().count(),
			stderr_chars = stderr.len(),
			"claude-cli: subprocess succeeded",
		);
		Ok(LlmResponse { text, backend_id: BACKEND_ID })
	}
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use tokio_util::sync::CancellationToken;

	use super::*;

	fn claude_present(bin: &str) -> bool {
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

	#[tokio::test]
	async fn cli_backend_round_trip_against_real_claude() {
		// Live test: needs `claude` + `bwrap` + an `ANTHROPIC_API_KEY`
		// in env. The API-key requirement is because the sandbox
		// mounts `~/.claude` read-only, so OAuth-based logins (which
		// expect to write back token-refresh state) can fail. Env-
		// based auth has no write path and works cleanly.
		if !claude_present("claude") || !bwrap_present() {
			eprintln!("skipping: claude or bwrap missing");
			return;
		}
		if std::env::var_os("ANTHROPIC_API_KEY").is_none() {
			eprintln!(
				"skipping: no ANTHROPIC_API_KEY in env (sandbox blocks OAuth refresh writes)"
			);
			return;
		}

		let workdir = tempfile::tempdir().unwrap();
		let backend = ClaudeCliBackend::new();
		let req = LlmRequest {
			prompt: "Reply with only the single word `pong`. No prose, no formatting.".to_owned(),
			workdir: workdir.path().to_path_buf(),
			timeout: Duration::from_secs(60),
			cancel: CancellationToken::new(),
			repo_id: None,
		};
		let resp = backend.run(req).await.expect("claude responded");
		assert_eq!(resp.backend_id, BACKEND_ID);
		assert!(!resp.text.trim().is_empty());
	}

	#[tokio::test]
	async fn missing_binary_errors_clearly() {
		// `loupe-worker-no-such-bin` definitely does not exist on PATH.
		let workdir = tempfile::tempdir().unwrap();
		let backend = ClaudeCliBackend::with_bin("loupe-worker-no-such-bin");
		let req = LlmRequest {
			prompt: "irrelevant".into(),
			workdir: workdir.path().to_path_buf(),
			timeout: Duration::from_secs(5),
			cancel: CancellationToken::new(),
			repo_id: None,
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
}
