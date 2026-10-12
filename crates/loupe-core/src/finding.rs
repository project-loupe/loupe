use loupe_provenance::Source;
use serde::Serialize;

use super::text::{BoundedText, RepoPath};
use crate::text::policy::{
	CweText, FindingDescription, FindingFingerprintText, FindingTitle, PatchUnified, PocUnified,
	ScannerIdText,
};
use crate::Severity;

/// Human-facing finding reference, distinct from report identity and issue ID.
pub fn format_finding_id(id: i64) -> String {
	format!("LUP-{id}")
}

/// Finding content retains its actual source: local regex output is Repo,
/// while an MCP submission's designated carried fields are Agent.
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct Finding<S: Source> {
	pub scanner_id: BoundedText<ScannerIdText, S>,
	pub severity: Severity,
	pub title: BoundedText<FindingTitle, S>,
	pub description: BoundedText<FindingDescription, S>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub file_path: Option<RepoPath<S>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub line_start: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub line_end: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub cwe: Option<BoundedText<CweText, S>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub patch_unified: Option<BoundedText<PatchUnified, S>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub poc_unified: Option<BoundedText<PocUnified, S>>,
	pub fingerprint: BoundedText<FindingFingerprintText, S>,
}
record_impls!(@fields Finding {
	scanner_id,
	severity,
	title,
	description,
	file_path,
	line_start,
	line_end,
	cwe,
	patch_unified,
	poc_unified,
	fingerprint
});
impl<S: Source> std::fmt::Debug for Finding<S> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Finding")
			.field("source", &S::NAME)
			.field("severity", &self.severity)
			.field("line_start", &self.line_start)
			.field("line_end", &self.line_end)
			.field("content", &"[redacted]")
			.finish_non_exhaustive()
	}
}
#[cfg(test)]
mod tests {
	use loupe_provenance::Agent;

	use super::*;
	use crate::test_support::{path, text};

	fn sample() -> Finding<Agent> {
		Finding {
			scanner_id: text("regex-secrets").unwrap(),
			severity: Severity::High,
			title: text("AWS access key").unwrap(),
			description: text("Found AKIA-prefixed token in source").unwrap(),
			file_path: Some(path("src/config.rs").unwrap()),
			line_start: Some(42),
			line_end: Some(42),
			cwe: Some(text("CWE-798").unwrap()),
			patch_unified: None,
			poc_unified: None,
			fingerprint: text("deadbeef").unwrap(),
		}
	}

	#[test]
	fn debug_contains_only_severity_and_line_metadata() {
		let mut f = sample();
		let baseline = "Finding { source: \"agent\", severity: High, line_start: Some(42), line_end: Some(42), content: \"[redacted]\", .. }";
		for payload in ["private-repository-secret", "Finding", "redacted", ""] {
			f.scanner_id = text(payload).unwrap();
			f.title = text(payload).unwrap();
			f.description = text(payload).unwrap();
			f.file_path = (!payload.is_empty()).then(|| path(payload).unwrap());
			f.cwe = Some(text(payload).unwrap());
			f.patch_unified = Some(text(payload).unwrap());
			f.poc_unified = Some(text(payload).unwrap());
			f.fingerprint = text(payload).unwrap();
			assert_eq!(format!("{f:?}"), baseline, "Finding Debug must be independent of text");
		}
	}

	#[test]
	fn round_trips_through_json() {
		let f = sample();
		let s = serde_json::to_string(&f).unwrap();
		let back: serde_json::Value = serde_json::from_str(&s).unwrap();
		assert_eq!(
			back,
			serde_json::json!({"scanner_id":"regex-secrets", "severity":"high", "title":"AWS access key", "description":"Found AKIA-prefixed token in source", "file_path":"src/config.rs", "line_start":42, "line_end":42, "cwe":"CWE-798", "fingerprint":"deadbeef"})
		);
	}

	#[test]
	fn omits_none_fields_in_serialization() {
		let f: Finding<Agent> = Finding {
			scanner_id: text("x").unwrap(),
			severity: Severity::Info,
			title: text("t").unwrap(),
			description: text("d").unwrap(),
			file_path: None,
			line_start: None,
			line_end: None,
			cwe: None,
			patch_unified: None,
			poc_unified: None,
			fingerprint: text("fp").unwrap(),
		};
		let s = serde_json::to_string(&f).unwrap();
		assert!(!s.contains("file_path"));
		assert!(!s.contains("cwe"));
		assert!(!s.contains("patch_unified"));
		assert!(!s.contains("poc_unified"));
	}

	#[test]
	fn poc_unified_round_trips_when_present() {
		let mut f = sample();
		f.poc_unified = Some(text("--- a/src/x.rs\n+++ b/src/x.rs\n@@ ...").unwrap());
		let s = serde_json::to_string(&f).unwrap();
		assert!(s.contains("poc_unified"));
		let back: serde_json::Value = serde_json::from_str(&s).unwrap();
		assert_eq!(back["poc_unified"].as_str(), f.poc_unified.as_ref().map(|p| p.expose()));
	}
}
