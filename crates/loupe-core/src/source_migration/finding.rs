use loupe_provenance::Source;
use serde::Serialize;

use super::text::{BoundedText, RepoPath};
use crate::text::policy::{
	CweText, FindingDescription, FindingFingerprintText, FindingTitle, PatchUnified, PocUnified,
	ScannerIdText,
};
use crate::Severity;

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
record_impls!(Finding {
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
