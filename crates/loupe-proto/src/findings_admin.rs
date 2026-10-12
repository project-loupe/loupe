//! Admin-side findings DTOs. Read-only listing / detail views.
//!
//! Distinct from `loupe_core::Finding` (which is the wire shape
//! workers push to the server). The admin DTOs expose persistence
//! state — `state`, `verification_required`, `created_at` — so an
//! operator can spot a finding stuck in `validating` or already
//! `reported` without having to read the database.

use loupe_core::text::policy::*;
use loupe_core::text::{BoundedText, RepoPath};
use loupe_core::{FindingState, Severity};
use loupe_provenance::Source;
use serde::{Deserialize, Serialize};

/// Findings listing response body.
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct ListFindingsResponse<ContentS: Source, AuditS: Source> {
	pub protocol_version: u16,
	pub findings: Vec<FindingSummary<ContentS, AuditS>>,
}
record_impls!(ListFindingsResponse<ContentS, AuditS> { protocol_version, findings });

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
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct FindingSummary<ContentS: Source, AuditS: Source> {
	pub id: i64,
	pub repo_id: i64,
	pub job_id: i64,
	pub scanner_id: BoundedText<ScannerIdText, ContentS>,
	pub severity: Severity,
	pub title: BoundedText<FindingTitle, ContentS>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub file_path: Option<RepoPath<ContentS>>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub line_start: Option<u32>,
	pub fingerprint: BoundedText<FindingFingerprintText, ContentS>,
	pub state: FindingState,
	pub verification_required: bool,
	pub created_at: i64,
	/// Approval audit trail. Populated when an admin runs
	/// `loupectl finding approve` on a finding parked in
	/// `awaiting_approval`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub approved_at: Option<i64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub approved_by_cn: Option<BoundedText<AuditName, AuditS>>,
	/// Rejection audit trail. Populated when an admin runs
	/// `loupectl finding reject` on a finding parked in
	/// `awaiting_approval`. Distinct from a verifier-issued dismiss
	/// (those leave `rejected_*` NULL).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub rejected_at: Option<i64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub rejected_by_cn: Option<BoundedText<AuditName, AuditS>>,
}
record_impls!(FindingSummary<ContentS, AuditS> { id, repo_id, job_id, scanner_id, severity, title, file_path, line_start, fingerprint, state, verification_required, created_at, approved_at, approved_by_cn, rejected_at, rejected_by_cn });

/// Full detail view for `GET /v1/findings/:id`.
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct FindingDetail<ContentS: Source, AuditS: Source> {
	pub protocol_version: u16,
	pub id: i64,
	pub repo_id: i64,
	pub job_id: i64,
	pub scanner_id: BoundedText<ScannerIdText, ContentS>,
	pub severity: Severity,
	pub title: BoundedText<FindingTitle, ContentS>,
	pub description: BoundedText<FindingDescription, ContentS>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub file_path: Option<RepoPath<ContentS>>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub line_start: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub line_end: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub cwe: Option<BoundedText<CweText, ContentS>>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub patch_unified: Option<BoundedText<PatchUnified, ContentS>>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub poc_unified: Option<BoundedText<PocUnified, ContentS>>,
	pub fingerprint: BoundedText<FindingFingerprintText, ContentS>,
	pub state: FindingState,
	pub verification_required: bool,
	pub created_at: i64,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub approved_at: Option<i64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub approved_by_cn: Option<BoundedText<AuditName, AuditS>>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub rejected_at: Option<i64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub rejected_by_cn: Option<BoundedText<AuditName, AuditS>>,
}
record_impls!(FindingDetail<ContentS, AuditS> { protocol_version, id, repo_id, job_id, scanner_id, severity, title, description, file_path, line_start, line_end, cwe, patch_unified, poc_unified, fingerprint, state, verification_required, created_at, approved_at, approved_by_cn, rejected_at, rejected_by_cn });
