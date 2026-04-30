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

use std::process::Stdio;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

use super::{LlmBackend, LlmRequest, LlmResponse};
use crate::sandbox::SandboxBuilder;

const BACKEND_ID: &str = "claude-cli";
const CLAUDE_BIN: &str = "claude";

pub struct ClaudeCliBackend {
	bin: String,
}

impl ClaudeCliBackend {
	pub fn new() -> Self {
		Self { bin: CLAUDE_BIN.to_owned() }
	}

	pub fn with_bin(bin: impl Into<String>) -> Self {
		Self { bin: bin.into() }
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
		let mut cmd = SandboxBuilder::new(&req.workdir).allow_network().build(&self.bin);
		cmd.arg("--dangerously-skip-permissions").arg("-p").arg(&req.prompt);
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
			tracing::debug!(
				backend = BACKEND_ID,
				exit = ?status.code(),
				stderr_chars = stderr.len(),
				elapsed_ms = started.elapsed().as_millis() as u64,
				"claude-cli: subprocess failed",
			);
			return Err(anyhow!("claude CLI exited with {}: {}", status, stderr_text.trim()));
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
		// Live test: needs both `claude` and `bwrap` on PATH. Skips
		// otherwise. Asks Claude a tiny deterministic question and
		// confirms we get *some* non-empty response back.
		if !claude_present("claude") || !bwrap_present() {
			eprintln!("skipping: claude or bwrap missing");
			return;
		}

		let workdir = tempfile::tempdir().unwrap();
		let backend = ClaudeCliBackend::new();
		let req = LlmRequest {
			prompt: "Reply with only the single word `pong`. No prose, no formatting.".to_owned(),
			workdir: workdir.path().to_path_buf(),
			timeout: Duration::from_secs(60),
			cancel: CancellationToken::new(),
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
