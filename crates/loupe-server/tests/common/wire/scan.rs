use loupe_core::JobState;
use serde::{Deserialize, Serialize};

use super::JobKind;

/// Body of `POST /v1/repos/:id/scan` (admin).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRequest {
	pub protocol_version: u16,
	#[serde(default)]
	pub incremental: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanResponse {
	pub protocol_version: u16,
	pub job_id: i64,
}

/// Listing entry for `GET /v1/jobs` and `GET /v1/jobs/:id`.
///
/// Lease, timing and error fields are optional for wire compatibility.
/// They let operators inspect duration, worker ownership and failure reasons
/// without a second round-trip.
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
