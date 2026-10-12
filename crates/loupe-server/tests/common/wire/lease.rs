pub use loupe_proto::JobCapability;
use loupe_provenance::Secret;
use serde::{Deserialize, Serialize};

use super::{Finding, RepoSpec};

/// Body of `POST /v1/jobs/lease`. The worker advertises capabilities so
/// the server can match a `kind=verify` job to a worker that runs the
/// right verifier (`verify:secrets`, `verify:llm-review`, ...).
///
/// `wait_seconds` enables server-side long-polling: if the queue is
/// empty, the server holds the connection up to that many seconds
/// waiting for a job. Default `0` keeps immediate empty-queue responses
/// available for callers that prefer explicit polling.
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
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		with = "crate::common::wire::secret_serde::optional"
	)]
	pub github_pat: Option<Secret<String>>,
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
