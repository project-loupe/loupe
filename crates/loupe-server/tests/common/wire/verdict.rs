use serde::{Deserialize, Serialize};

/// Candidate fix attached to a `Verdict::Confirmed`. Carries the
/// unified diff plus a short rationale from the verifier.
///
/// Patches only ride on confirmed verdicts — by construction.
/// Dismissed and inconclusive verdicts have no place to attach a
/// fix, and the type system pins that down by living only on the
/// `Confirmed` variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictPatch {
	/// Unified diff of the proposed fix. Must apply cleanly against
	/// the worktree the verifier was reasoning over (the MCP-side
	/// `validate_patch` tool runs `git apply --check` before this
	/// reaches the server).
	pub patch_unified: String,
	/// One- or two-sentence rationale from the verifier: what the
	/// fix does and why this is the minimal correct change. Surfaced
	/// to human reviewers via `loupectl finding show`.
	pub notes: String,
}

/// Outcome of a verification job — a verifier's vote on whether a finding
/// from a prior scan is real, false-positive, or undecidable.
///
/// The server's rollup policy aggregates one or more `Verdict`s into the
/// finding's `state` (`confirmed` / `dismissed` / stays `validating`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Verdict {
	Confirmed {
		#[serde(default, skip_serializing_if = "Option::is_none")]
		notes: Option<String>,
		/// Optional candidate fix. Omitted when the verifier confirms
		/// the finding without proposing a patch.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		patch: Option<VerdictPatch>,
	},
	Dismissed {
		#[serde(default, skip_serializing_if = "Option::is_none")]
		notes: Option<String>,
	},
	Inconclusive {
		reason: String,
		#[serde(default, skip_serializing_if = "std::ops::Not::not")]
		terminal: bool,
	},
}
