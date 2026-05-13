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
	},
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn round_trips_each_variant() {
		let cases = [
			Verdict::Confirmed { notes: Some("matched second scanner".into()), patch: None },
			Verdict::Confirmed {
				notes: Some("real bug".into()),
				patch: Some(VerdictPatch {
					patch_unified: "--- a/x\n+++ b/x\n@@\n-old\n+new\n".into(),
					notes: "swap the comparison operator".into(),
				}),
			},
			Verdict::Dismissed { notes: None },
			Verdict::Inconclusive { reason: "scanner does not verify".into() },
		];
		for v in cases {
			let s = serde_json::to_string(&v).unwrap();
			let back: Verdict = serde_json::from_str(&s).unwrap();
			assert_eq!(v, back);
		}
	}

	#[test]
	fn tag_field_is_outcome() {
		let v = Verdict::Dismissed { notes: None };
		let s = serde_json::to_string(&v).unwrap();
		assert!(s.contains(r#""outcome":"dismissed""#), "got: {s}");
	}

	#[test]
	fn confirmed_without_patch_omits_field_on_wire() {
		// `skip_serializing_if = Option::is_none` is what keeps an
		// older verifier worker (or any caller that doesn't propose a
		// patch) from polluting the wire shape with a `"patch":null`
		// noise field. If this regresses, every Confirmed verdict
		// suddenly grows a null field — visible to operators
		// inspecting raw JSON, and a needless wire-shape diff.
		let v = Verdict::Confirmed { notes: Some("real bug".into()), patch: None };
		let s = serde_json::to_string(&v).unwrap();
		assert!(!s.contains("patch"), "got: {s}");
	}
}
