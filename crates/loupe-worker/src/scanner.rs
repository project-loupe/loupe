//! `Scanner` trait — the extension point for security checks.
//!
//! Built-in scanners cover regex-based secret discovery, LLM discovery,
//! and LLM verification. Future scanner families plug into this same
//! trait.

use std::path::PathBuf;

use async_trait::async_trait;
use loupe_core::{Finding, RepoSpec, Verdict};
use tokio_util::sync::CancellationToken;

/// Outcome of `Scanner::verify`. Discriminates the two ways a
/// verifier scanner can hand a verdict back to the runner:
///
/// - `Verdict(v)` — scanner ran in-process and returns the verdict
///   for the runner to POST. The original (regex / stdout-JSON-LLM)
///   shape; the runner does the network hop.
/// - `Submitted` — scanner already POSTed the verdict via an
///   out-of-band channel (today: the MCP server in verify mode
///   flushes a `VerdictSubmission` at session end). The runner
///   must NOT POST again or the server will see two verification
///   rows for one verify job.
pub enum VerifyOutcome {
	Verdict(Verdict),
	Submitted,
}

#[async_trait]
pub trait Scanner: Send + Sync {
	fn id(&self) -> &'static str;
	fn capabilities(&self) -> &[&'static str];
	async fn scan(&self, ctx: &ScanContext) -> anyhow::Result<Vec<Finding>>;

	/// Default impl: not a verifier. Override in scanners that
	/// advertise a `verify:*` capability.
	async fn verify(&self, _ctx: &VerifyContext) -> anyhow::Result<VerifyOutcome> {
		Ok(VerifyOutcome::Verdict(Verdict::Inconclusive {
			reason: "scanner does not verify".into(),
		}))
	}
}

pub struct ScanContext {
	pub workdir: PathBuf,
	pub repo: RepoSpec,
	/// Server-side repo id from the lease envelope. Used by LLM
	/// backends to scope MCP tool calls (e.g. `query_prior_findings`)
	/// to this repo without relying on the agent to keep state.
	pub repo_id: i64,
	/// Server-side job id from the lease envelope. The agent's MCP
	/// `submit_finding` tool uses it to POST findings to
	/// `/v1/jobs/{job_id}/findings` directly — submission no longer
	/// goes through the runner's batch call at end-of-scan.
	pub job_id: i64,
	pub head_sha: String,
	pub base_sha: Option<String>,
	pub config: serde_json::Value,
	pub cancel: CancellationToken,
}

pub struct VerifyContext {
	pub workdir: PathBuf,
	pub repo: RepoSpec,
	pub repo_id: i64,
	/// Server-side job id for this verify job. Required by the
	/// MCP-driven verifier path: the agent's `submit_verdict` /
	/// `submit_patch` tools POST against `/v1/jobs/{job_id}/...`,
	/// so the LLM-backed scanner forwards this id into `LlmRequest`
	/// (and the MCP server gets it via `--job-id`).
	pub job_id: i64,
	/// Server-side finding id this verify job is targeting. Same
	/// purpose as `job_id` but for the verify-mode tool catalog —
	/// the MCP server only flips into verify mode when it sees both
	/// `--job-id` and `--finding-id`. Carried here so the LLM
	/// verifier scanner doesn't have to re-derive it from the
	/// finding's fingerprint.
	pub finding_id: i64,
	pub finding: Finding,
	pub config: serde_json::Value,
	pub cancel: CancellationToken,
}
