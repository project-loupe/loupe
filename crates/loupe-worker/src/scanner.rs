//! `Scanner` trait — the extension point for security checks.
//!
//! M1 ships one trivial implementation (`RegexScanner`) so the
//! end-to-end pipeline can produce findings. Real LLM-agent and fuzz
//! scanners land in M3 behind this same trait.

use std::path::PathBuf;

use async_trait::async_trait;
use loupe_core::{Finding, RepoSpec, Verdict};
use tokio_util::sync::CancellationToken;

#[async_trait]
pub trait Scanner: Send + Sync {
	fn id(&self) -> &'static str;
	fn capabilities(&self) -> &[&'static str];
	async fn scan(&self, ctx: &ScanContext) -> anyhow::Result<Vec<Finding>>;

	/// Default impl: not a verifier. Override in scanners that
	/// advertise a `verify:*` capability.
	async fn verify(&self, _ctx: &VerifyContext) -> anyhow::Result<Verdict> {
		Ok(Verdict::Inconclusive { reason: "scanner does not verify".into() })
	}
}

pub struct ScanContext {
	pub workdir: PathBuf,
	pub repo: RepoSpec,
	/// Server-side repo id from the lease envelope. Used by LLM
	/// backends to scope MCP tool calls (e.g. `query_prior_findings`)
	/// to this repo without relying on the agent to keep state.
	pub repo_id: i64,
	pub head_sha: String,
	pub base_sha: Option<String>,
	pub config: serde_json::Value,
	pub cancel: CancellationToken,
}

pub struct VerifyContext {
	pub workdir: PathBuf,
	pub repo: RepoSpec,
	pub repo_id: i64,
	pub finding: Finding,
	pub config: serde_json::Value,
	pub cancel: CancellationToken,
}
