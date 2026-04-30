//! Admin-side findings DTOs. Read-only listing / detail views.
//!
//! Distinct from `loupe_core::Finding` (which is the wire shape
//! workers push to the server). The admin DTOs expose persistence
//! state — `state`, `verification_required`, `created_at` — so an
//! operator can spot a finding stuck in `validating` or already
//! `reported` without having to read the database.

use loupe_core::Severity;
use serde::{Deserialize, Serialize};

/// Findings listing response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListFindingsResponse {
	pub protocol_version: u16,
	pub findings: Vec<FindingSummary>,
}

/// Compact view used in listings — drops `description`, `patch_unified`,
/// and `poc_unified` to keep responses small. `loupectl finding get
/// <id>` returns the full detail view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingSummary {
	pub id: i64,
	pub repo_id: i64,
	pub job_id: i64,
	pub scanner_id: String,
	pub severity: Severity,
	pub title: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub file_path: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub line_start: Option<u32>,
	pub fingerprint: String,
	pub state: String,
	pub verification_required: bool,
	pub created_at: i64,
	/// Approval audit trail. Populated when an admin runs
	/// `loupectl finding approve` on a finding parked in
	/// `awaiting_approval`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub approved_at: Option<i64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub approved_by_cn: Option<String>,
	/// Rejection audit trail. Populated when an admin runs
	/// `loupectl finding reject` on a finding parked in
	/// `awaiting_approval`. Distinct from a verifier-issued dismiss
	/// (those leave `rejected_*` NULL).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub rejected_at: Option<i64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub rejected_by_cn: Option<String>,
}

/// Full detail view for `GET /v1/findings/:id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingDetail {
	pub protocol_version: u16,
	pub id: i64,
	pub repo_id: i64,
	pub job_id: i64,
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
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub poc_unified: Option<String>,
	pub fingerprint: String,
	pub state: String,
	pub verification_required: bool,
	pub created_at: i64,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub approved_at: Option<i64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub approved_by_cn: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub rejected_at: Option<i64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub rejected_by_cn: Option<String>,
}
