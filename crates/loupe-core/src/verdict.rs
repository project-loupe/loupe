use loupe_provenance::Source;
use serde::Serialize;

use super::text::BoundedText;
use crate::text::policy::{PatchNotes, PatchUnified, VerdictNotes, VerdictReason};

/// Exact candidate fix and rationale. Applicability belongs to the Git check.
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct VerdictPatch<S: Source> {
	pub patch_unified: BoundedText<PatchUnified, S>,
	pub notes: BoundedText<PatchNotes, S>,
}
record_impls!(VerdictPatch { patch_unified, notes });

/// A verifier's vote, with source-retaining explanations and optional fix.
#[derive(Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case", bound(serialize = ""))]
pub enum Verdict<S: Source> {
	Confirmed {
		#[serde(skip_serializing_if = "Option::is_none")]
		notes: Option<BoundedText<VerdictNotes, S>>,
		#[serde(skip_serializing_if = "Option::is_none")]
		patch: Option<VerdictPatch<S>>,
	},
	Dismissed {
		#[serde(skip_serializing_if = "Option::is_none")]
		notes: Option<BoundedText<VerdictNotes, S>>,
	},
	Inconclusive {
		reason: BoundedText<VerdictReason, S>,
		#[serde(skip_serializing_if = "std::ops::Not::not")]
		terminal: bool,
	},
}
impl<S: Source> Clone for Verdict<S> {
	fn clone(&self) -> Self {
		match self {
			Self::Confirmed { notes, patch } => {
				Self::Confirmed { notes: notes.clone(), patch: patch.clone() }
			},
			Self::Dismissed { notes } => Self::Dismissed { notes: notes.clone() },
			Self::Inconclusive { reason, terminal } => {
				Self::Inconclusive { reason: reason.clone(), terminal: *terminal }
			},
		}
	}
}
impl<S: Source> PartialEq for Verdict<S> {
	fn eq(&self, other: &Self) -> bool {
		match (self, other) {
			(Self::Confirmed { notes: a, patch: p }, Self::Confirmed { notes: b, patch: q }) => {
				a == b && p == q
			},
			(Self::Dismissed { notes: a }, Self::Dismissed { notes: b }) => a == b,
			(
				Self::Inconclusive { reason: a, terminal: x },
				Self::Inconclusive { reason: b, terminal: y },
			) => a == b && x == y,
			_ => false,
		}
	}
}
impl<S: Source> Eq for Verdict<S> {}
impl<S: Source> std::fmt::Debug for Verdict<S> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "Verdict<{}>([redacted])", S::NAME)
	}
}
#[cfg(test)]
mod tests {
	use loupe_provenance::Agent;

	use super::*;
	use crate::test_support::text;
	type Verdict = super::Verdict<Agent>;

	#[test]
	fn round_trips_each_variant() {
		let cases = [
			Verdict::Confirmed {
				notes: Some(text("matched second scanner").unwrap()),
				patch: None,
			},
			Verdict::Confirmed {
				notes: Some(text("real bug").unwrap()),
				patch: Some(VerdictPatch {
					patch_unified: text("--- a/x\n+++ b/x\n@@\n-old\n+new\n").unwrap(),
					notes: text("swap the comparison operator").unwrap(),
				}),
			},
			Verdict::Dismissed { notes: None },
			Verdict::Inconclusive {
				reason: text("scanner does not verify").unwrap(),
				terminal: false,
			},
		];
		let expected = [
			serde_json::json!({"outcome":"confirmed","notes":"matched second scanner"}),
			serde_json::json!({"outcome":"confirmed","notes":"real bug","patch":{"patch_unified":"--- a/x\n+++ b/x\n@@\n-old\n+new\n","notes":"swap the comparison operator"}}),
			serde_json::json!({"outcome":"dismissed"}),
			serde_json::json!({"outcome":"inconclusive","reason":"scanner does not verify"}),
		];
		for (v, expected) in cases.into_iter().zip(expected) {
			let s = serde_json::to_string(&v).unwrap();
			let back: serde_json::Value = serde_json::from_str(&s).unwrap();
			assert_eq!(back, expected);
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
		// An absent patch is omitted rather than serialized as null.
		let v = Verdict::Confirmed { notes: Some(text("real bug").unwrap()), patch: None };
		let s = serde_json::to_string(&v).unwrap();
		assert!(!s.contains("patch"), "got: {s}");
	}

	#[test]
	fn inconclusive_omits_nonterminal_flag() {
		let v =
			Verdict::Inconclusive { reason: text("not enough context").unwrap(), terminal: false };
		let s = serde_json::to_string(&v).unwrap();
		assert!(!s.contains("terminal"), "got: {s}");
		let back: serde_json::Value = serde_json::from_str(&s).unwrap();
		assert_eq!(
			back,
			serde_json::json!({"outcome":"inconclusive","reason":"not enough context"})
		);
	}

	#[test]
	fn inconclusive_default_wire_shape_remains_compatible() {
		let raw = r#"{"outcome":"inconclusive","reason":"not enough context"}"#;
		let back: serde_json::Value = serde_json::from_str(raw).unwrap();
		assert_eq!(
			back,
			serde_json::to_value(Verdict::Inconclusive {
				reason: text("not enough context").unwrap(),
				terminal: false
			})
			.unwrap()
		);
	}
}
