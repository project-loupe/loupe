use loupe_core::text::policy::{JobDiagnostic, RevisionText};
use loupe_core::text::BoundedText;
use loupe_core::{JobKind, JobState};
use loupe_provenance::Source;
use serde::{Deserialize, Serialize};

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
/// The lease/timing/error block below is additive: every field is
/// `Option` with `skip_serializing_if`, so a client built against this
/// protocol still reads responses from a server that predates them. They
/// exist so an operator surface can answer "how long did this take, who
/// ran it, and why did it fail" without a second round-trip.
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct JobInfo<S: Source> {
	pub job_id: i64,
	pub repo_id: i64,
	pub kind: JobKind<S>,
	pub state: JobState,
	pub incremental: bool,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub since_sha: Option<BoundedText<RevisionText, S>>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub head_sha: Option<BoundedText<RevisionText, S>>,
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
	pub error: Option<BoundedText<JobDiagnostic, S>>,
}
record_impls!(JobInfo<S> { job_id, repo_id, kind, state, incremental, since_sha, head_sha, parent_job_id, target_finding_id, attempts, enqueued_at, worker_id, lease_expires_at, started_at, finished_at, error });

#[cfg(test)]
mod tests {
	use loupe_core::{JobKind, JobState};
	use loupe_provenance::Server;
	use serde_json::json;

	use super::*;
	use crate::test_support::text;
	type JobInfo = super::JobInfo<Server>;

	#[test]
	fn scan_request_defaults_incremental_false() {
		let req: ScanRequest = serde_json::from_str(r#"{"protocol_version":1}"#).unwrap();
		assert!(!req.incremental);
	}

	fn queued_job() -> JobInfo {
		JobInfo {
			job_id: 1,
			repo_id: 2,
			kind: JobKind::Scan,
			state: JobState::Queued,
			incremental: false,
			since_sha: None,
			head_sha: None,
			parent_job_id: None,
			target_finding_id: None,
			attempts: 0,
			enqueued_at: 1_700_000_000,
			worker_id: None,
			lease_expires_at: None,
			started_at: None,
			finished_at: None,
			error: None,
		}
	}

	#[test]
	fn job_info_preserves_wire_fields() {
		let info = queued_job();
		let s = serde_json::to_string(&info).unwrap();
		assert_eq!(
			serde_json::from_str::<serde_json::Value>(&s).unwrap(),
			json!({
				"job_id":1,"repo_id":2,"kind":"scan","state":"queued",
				"incremental":false,"attempts":0,"enqueued_at":1700000000
			})
		);
	}

	#[test]
	fn verify_job_carries_parentage() {
		let info = JobInfo {
			job_id: 5,
			kind: JobKind::Verify,
			state: JobState::Leased,
			head_sha: Some(text("abc123")),
			parent_job_id: Some(1),
			target_finding_id: Some(42),
			enqueued_at: 1_700_000_100,
			..queued_job()
		};
		let s = serde_json::to_string(&info).unwrap();
		assert_eq!(
			serde_json::from_str::<serde_json::Value>(&s).unwrap(),
			json!({
				"job_id":5,"repo_id":2,"kind":"verify","state":"leased","incremental":false,
				"head_sha":"abc123","parent_job_id":1,"target_finding_id":42,"attempts":0,"enqueued_at":1700000100
			})
		);
	}

	#[test]
	fn job_info_preserves_lease_and_failure_wire_detail() {
		let info = JobInfo {
			state: JobState::Failed,
			attempts: 3,
			worker_id: Some(7),
			lease_expires_at: Some(1_700_000_600),
			started_at: Some(1_700_000_010),
			finished_at: Some(1_700_000_400),
			error: Some(text("lease expired after max attempts")),
			..queued_job()
		};
		let s = serde_json::to_string(&info).unwrap();
		let back: serde_json::Value = serde_json::from_str(&s).unwrap();
		assert_eq!(
			back,
			json!({"job_id":1,"repo_id":2,"kind":"scan","state":"failed",
			"incremental":false,"attempts":3,"enqueued_at":1700000000,"worker_id":7,
			"lease_expires_at":1700000600,"started_at":1700000010,"finished_at":1700000400,
			"error":"lease expired after max attempts"})
		);
		assert_eq!(
			back["finished_at"].as_i64().unwrap() - back["started_at"].as_i64().unwrap(),
			390,
			"duration is derivable"
		);
	}

	#[test]
	fn job_info_without_lease_detail_matches_the_legacy_wire_shape() {
		// Missing-field input admission moves to the CLI's named JobInfo decoder.
		let s = r#"{"job_id":1,"repo_id":2,"kind":"scan","state":"queued",
			"incremental":false,"attempts":0,"enqueued_at":1700000000}"#;
		assert_eq!(
			serde_json::from_str::<serde_json::Value>(s).unwrap(),
			serde_json::to_value(queued_job()).unwrap()
		);
	}

	#[test]
	fn queued_job_omits_the_empty_lease_block() {
		let s = serde_json::to_string(&queued_job()).unwrap();
		for absent in ["worker_id", "lease_expires_at", "started_at", "finished_at", "error"] {
			assert!(!s.contains(absent), "{absent} should be omitted when unset: {s}");
		}
	}
}
