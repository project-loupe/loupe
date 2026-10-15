//! Admin-side findings DTOs. Read-only listing / detail views.
//!
//! Distinct from `loupe_core::Finding` (which is the wire shape
//! workers push to the server). The admin DTOs expose persistence
//! state — `state`, `verification_required`, `created_at` — so an
//! operator can spot a finding stuck in `validating` or already
//! `reported` without having to read the database.

use loupe_core::{FindingState, Severity};
use serde::{Deserialize, Serialize};

/// Findings listing response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListFindingsResponse {
	pub protocol_version: u16,
	pub findings: Vec<FindingSummary>,
}

/// Body of `POST /v1/findings/retry-verify`.
///
/// This is an operator recovery tool for findings that still need
/// verifier work but are no longer represented correctly in the
/// queue. `dry_run = true` returns the counts that would be applied
/// without mutating findings or jobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryVerifyRequest {
	pub protocol_version: u16,
	#[serde(default)]
	pub dry_run: bool,
	/// Include findings whose verifier-produced history contains
	/// inconclusive verdicts. Deadline-reaper inconclusive rows use
	/// `job_id = NULL` and remain recoverable without this flag.
	#[serde(default)]
	pub include_inconclusive: bool,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub repo_id: Option<i64>,
	/// Optional cap on findings processed in one call. Omit to process all
	/// matching recoverable findings.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub limit: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryVerifyResponse {
	pub protocol_version: u16,
	pub dry_run: bool,
	pub matched: u64,
	pub revived: u64,
	pub requeued_jobs: u64,
	pub created_jobs: u64,
	pub left_queued_or_leased: u64,
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
	pub state: FindingState,
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
	pub state: FindingState,
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
