//! Independent serde oracle for response admission and field ordering.
//! These private DTOs cannot construct production source-labelled values.
//! JobKind is String so the oracle preserves unknown kind spellings.
#![allow(dead_code)]
use loupe_core::{FindingState, JobState, Severity};
use serde::{Deserialize, Serialize};
type JobKind = String;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubAppSummary {
	pub app_id: u64,
	pub slug: String,
}

/// Response body of `GET /v1/github-app`. `app` is `None` until an
/// operator stores a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubAppResponse {
	pub protocol_version: u16,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub app: Option<GithubAppSummary>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListReposResponse {
	pub protocol_version: u16,
	pub repos: Vec<RepoSummary>,
}

/// Which credential a GitHub issue destination files issues with.
///
/// A listing that omits the authentication mode denotes a PAT credential.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubReportingAuth {
	/// The server-wide GitHub App; issues appear authored by `<app>[bot]`.
	App,
	/// A personal access token stored for this repo.
	#[default]
	Pat,
}

/// Non-secret view of a repo's reporting destination.
///
/// Mirrors `loupe_core::ReportingDestination` with `pat_secret_id`
/// reduced to a [`GithubReportingAuth`] mode. Clients need the reporter
/// *kind* and the auth mode to decide which actions apply — PAT rotation
/// is only meaningful for a PAT-backed `GithubIssue`, and the server 400s
/// a rotation attempt against anything else — but the storage-side secret
/// id has no meaning off the server and must never leave it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReportingSummary {
	GithubIssue {
		target_owner: String,
		target_repo: String,
		#[serde(default)]
		auth: GithubReportingAuth,
	},
	Email {
		to: Vec<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		from: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		subject_prefix: Option<String>,
	},
	Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoSummary {
	pub id: i64,
	pub clone_url: String,
	pub host: String,
	pub owner: String,
	pub repo: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub default_branch: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub scan_interval_seconds: Option<i64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub disabled_at: Option<i64>,
	pub verification_enabled: bool,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub require_approval: Option<bool>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub last_scanned_sha: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub last_scanned_at: Option<i64>,
	pub created_at: i64,
	/// Which reporter this repo is configured for, without secret
	/// material. Responses may omit the reporting field.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub reporting: Option<ReportingSummary>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobInfo {
	pub job_id: i64,
	pub repo_id: i64,
	pub kind: JobKind,
	pub state: JobState,
	pub incremental: bool,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub since_sha: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub head_sha: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub parent_job_id: Option<i64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub target_finding_id: Option<i64>,
	pub attempts: u32,
	pub enqueued_at: i64,
	/// Worker that holds the lease, or last held it. `None` while the job
	/// has never been leased; the reaper and a retry both clear it.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub worker_id: Option<i64>,
	/// When the current lease lapses. Only meaningful while `state` is
	/// `leased` — a countdown against it is how a UI spots a stalled
	/// worker before the reaper gets to it.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub lease_expires_at: Option<i64>,
	/// When the job was first leased. Paired with `finished_at` this
	/// gives the run duration.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub started_at: Option<i64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub finished_at: Option<i64>,
	/// Why a `failed` or `cancelled` job ended that way.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub error: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListFindingsResponse {
	pub protocol_version: u16,
	pub findings: Vec<FindingSummary>,
}

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
