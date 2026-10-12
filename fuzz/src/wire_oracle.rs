//! Private wire-schema oracle, independent of production decoding.
//! These raw records are never production outputs or labelled constructors.
//! Their serde attributes preserve field order/default/duplicate/unknown rules;
//! each target independently checks field policy before comparing real owners.
use loupe_core::{FindingState, Severity};
use loupe_proto::{CompleteOutcome, JobCapability};
use serde::{Deserialize, Serialize};
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictPatch {
	/// Unified diff of the proposed fix. Must apply cleanly against
	/// the worktree the verifier was reasoning over (the MCP-side
	/// `validate_patch` tool runs `git apply --check` before this
	/// reaches the server).
	pub patch_unified: String,
	/// One- or two-sentence rationale from the verifier: what the
	/// fix does and why this is the minimal correct change. Surfaced
	/// to human reviewers via `loupectl finding show`.
	pub notes: String,
}

/// Outcome of a verification job — a verifier's vote on whether a finding
/// from a prior scan is real, false-positive, or undecidable.
///
/// The server's rollup policy aggregates one or more `Verdict`s into the
/// finding's `state` (`confirmed` / `dismissed` / stays `validating`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Verdict {
	Confirmed {
		#[serde(default, skip_serializing_if = "Option::is_none")]
		notes: Option<String>,
		/// Optional candidate fix. Omitted when the verifier confirms
		/// the finding without proposing a patch.
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
pub struct RepoSpec {
	pub host: String,
	pub owner: String,
	pub repo: String,
	pub clone_url: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub branch: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRequest {
	pub protocol_version: u16,
	pub capabilities: Vec<String>,
	#[serde(default)]
	pub wait_seconds: u32,
}

/// Response body. Either a job is handed out (`Lease(LeaseEnvelope)`) or
/// the queue is empty / no job matches the worker's capabilities (`Empty`).
/// We carry the variant inside the body rather than relying on HTTP status
/// codes because intermediaries strip / mangle them often enough.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LeaseResponse {
	Lease(Box<LeaseEnvelope>),
	Empty { protocol_version: u16 },
}

/// The contents of an active lease — what the worker needs to run the job.
///
/// `payload` discriminates between scan and verify so that, for verify
/// jobs, the target finding travels alongside the repo spec without
/// inflating every scan-job response with optional finding fields.
#[derive(Debug, Serialize, Deserialize)]
pub struct LeaseEnvelope {
	pub protocol_version: u16,
	pub job_id: i64,
	pub job_capability: JobCapability,
	/// Server-side numeric id for the registered repo. Workers
	/// forward this through `ScanContext`/`VerifyContext` so LLM
	/// backends can scope MCP tool calls
	/// (e.g. `query_prior_findings`) to the repo currently under
	/// scan without piecing it together from `(host, owner, repo)`.
	pub repo_id: i64,
	pub repo: RepoSpec,
	pub head_branch: Option<String>,
	/// Lease expiry as epoch seconds. Worker must heartbeat or complete
	/// before this point or the server reaper will reclaim the job.
	pub lease_expires_at: i64,
	pub scanner_config: serde_json::Value,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub github_pat: Option<String>,
	pub payload: LeasePayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LeasePayload {
	Scan {
		#[serde(default, skip_serializing_if = "Option::is_none")]
		since_sha: Option<String>,
	},
	Verify {
		finding_id: i64,
		finding: Box<Finding>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		reviewed_sha: Option<String>,
	},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingsBatch {
	pub protocol_version: u16,
	pub findings: Vec<Finding>,
}

/// Strict single-finding shape used only by the LLM MCP broker. The
/// server supplies the scanner id and does not accept candidate fixes
/// on the discovery path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmFindingSubmission {
	pub protocol_version: u16,
	pub severity: Severity,
	pub title: String,
	pub description: String,
	pub file_path: String,
	pub line_start: u32,
	pub line_end: u32,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub cwe: Option<String>,
	pub poc_unified: String,
	pub fingerprint: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictSubmission {
	pub protocol_version: u16,
	pub verdict: Verdict,
}

/// Body of `POST /v1/jobs/:id/complete`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompleteRequest {
	pub protocol_version: u16,
	pub outcome: CompleteOutcome,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub head_sha: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub error: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReportingSetup {
	/// File issues on `target_owner/target_repo`. Without `github_pat`
	/// the server files them through its configured GitHub App and
	/// rejects the registration if no app is configured.
	GithubIssue {
		target_owner: String,
		target_repo: String,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		github_pat: Option<String>,
	},
	/// Send findings as email via the server's `sendmail` binary. No
	/// secret material is required — the binary handles transport.
	Email {
		to: Vec<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		from: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		subject_prefix: Option<String>,
	},
	/// No automatic reporter. The server runs the scan, verification,
	/// and approval pipeline as usual, but confirmed findings remain
	/// `confirmed` until an operator configures reporting and retries
	/// delivery or handles them out-of-band.
	Manual,
}

/// Body of `POST /v1/repos`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRepoRequest {
	pub protocol_version: u16,
	pub clone_url: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub branch: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub scan_interval_seconds: Option<u64>,
	pub reporting: ReportingSetup,
	#[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
	pub scanner_config: serde_json::Value,
	/// Per-repo override of the verify flow. `None` (the default on
	/// the wire) means "inherit the server's
	/// `verification_default`". `Some(true)` / `Some(false)`
	/// pin the value for this repo regardless of the server default.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub verification_enabled: Option<bool>,
	/// Per-repo override of the human-in-the-loop approval gate. `None`
	/// (the default on the wire) means "inherit the server's
	/// `require_approval_default`". `Some(true)` / `Some(false)` pin
	/// the value for this repo regardless of the server default.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub require_approval: Option<bool>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct SetRepoGithubReportingRequest {
	pub protocol_version: u16,
	pub target_owner: String,
	pub target_repo: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub github_pat: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterWorkerRequest {
	pub protocol_version: u16,
	pub name: String,
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
