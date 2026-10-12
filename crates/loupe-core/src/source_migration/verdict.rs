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
