//! Independent serde oracle for the original-token fixture comparison.
//! No production caller can deserialize these unlabelled reference types.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictSubmission {
	pub protocol_version: u16,
	pub verdict: Verdict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Verdict {
	Confirmed {
		#[serde(default, skip_serializing_if = "Option::is_none")]
		notes: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictPatch {
	pub patch_unified: String,
	pub notes: String,
}
