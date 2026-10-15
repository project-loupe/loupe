use loupe_core::Severity;
use serde::{Deserialize, Serialize};

/// Human-facing reference to a stored finding. The numeric ID remains
/// unchanged in storage and HTTP APIs; the prefix distinguishes Loupe
/// findings from issue numbers in a reporting repository.
pub fn format_finding_id(id: i64) -> String {
	format!("LUP-{id}")
}

/// A single security finding produced by a `Scanner` and ferried back to
/// the server. The wire format intentionally mirrors the `findings` table
/// columns one-for-one so the worker can construct one without consulting
/// the storage layer.
///
/// `fingerprint` is the server-side dedup key. Scanners treat it as
/// opaque; the built-in implementations currently hash scanner id,
/// file path, and a normalized source window.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
	pub scanner_id: String,
	pub severity: Severity,
	pub title: String,
	pub description: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub file_path: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub line_start: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub line_end: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub cwe: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub patch_unified: Option<String>,
	/// Unified diff that adds a regression test demonstrating the
	/// vulnerability — fails on HEAD, passes after a fix is applied.
	/// Distinct from `patch_unified` which carries a candidate *fix*.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub poc_unified: Option<String>,
	pub fingerprint: String,
}

// Findings contain repository and agent text, including paths that can embed
// secrets. Diagnostics expose only severity and source line numbers; serde
// remains the explicit transport for the complete finding.
impl std::fmt::Debug for Finding {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Finding")
			.field("severity", &self.severity)
			.field("line_start", &self.line_start)
			.field("line_end", &self.line_end)
			.finish_non_exhaustive()
	}
}
