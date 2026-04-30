use loupe_core::{Finding, RepoSpec};
use serde::{Deserialize, Serialize};

/// Body of `POST /v1/jobs/lease`. The worker advertises capabilities so
/// the server can match a `kind=verify` job to a worker that runs the
/// right verifier (`verify:secrets`, `verify:llm-review`, ...).
///
/// `wait_seconds` enables server-side long-polling: if the queue is
/// empty, the server holds the connection up to that many seconds
/// waiting for a job. Default `0` means the legacy poll-and-return-empty
/// behaviour, so older workers don't have to opt in.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseEnvelope {
	pub protocol_version: u16,
	pub job_id: i64,
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
		finding: Finding,
	},
}

#[cfg(test)]
mod tests {
	use loupe_core::{Finding, RepoSpec, Severity};
	use serde_json::json;

	use super::*;
	use crate::version::PROTOCOL_VERSION;

	fn sample_repo() -> RepoSpec {
		RepoSpec {
			host: "github.com".into(),
			owner: "acme".into(),
			repo: "widget".into(),
			clone_url: "https://github.com/acme/widget.git".into(),
			branch: Some("main".into()),
		}
	}

	#[test]
	fn empty_response_round_trips() {
		let r = LeaseResponse::Empty { protocol_version: PROTOCOL_VERSION };
		let s = serde_json::to_string(&r).unwrap();
		assert!(s.contains(r#""kind":"empty""#));
		let back: LeaseResponse = serde_json::from_str(&s).unwrap();
		assert_eq!(r, back);
	}

	#[test]
	fn scan_lease_round_trips() {
		let env = LeaseEnvelope {
			protocol_version: PROTOCOL_VERSION,
			job_id: 1,
			repo_id: 9,
			repo: sample_repo(),
			head_branch: Some("main".into()),
			lease_expires_at: 1_700_000_600,
			scanner_config: json!({"regex": {"enabled": true}}),
			github_pat: None,
			payload: LeasePayload::Scan { since_sha: Some("abc123".into()) },
		};
		let r = LeaseResponse::Lease(Box::new(env.clone()));
		let s = serde_json::to_string(&r).unwrap();
		let back: LeaseResponse = serde_json::from_str(&s).unwrap();
		assert_eq!(r, back);
	}

	#[test]
	fn verify_lease_carries_finding() {
		let finding = Finding {
			scanner_id: "regex-secrets".into(),
			severity: Severity::High,
			title: "AWS access key".into(),
			description: "Found AKIA-prefixed token".into(),
			file_path: Some("src/x.rs".into()),
			line_start: Some(1),
			line_end: Some(1),
			cwe: None,
			patch_unified: None,
			poc_unified: None,
			fingerprint: "fp1".into(),
		};
		let env = LeaseEnvelope {
			protocol_version: PROTOCOL_VERSION,
			job_id: 7,
			repo_id: 11,
			repo: sample_repo(),
			head_branch: None,
			lease_expires_at: 1_700_000_800,
			scanner_config: serde_json::Value::Null,
			github_pat: None,
			payload: LeasePayload::Verify { finding_id: 42, finding: finding.clone() },
		};
		let s = serde_json::to_string(&env).unwrap();
		let back: LeaseEnvelope = serde_json::from_str(&s).unwrap();
		assert_eq!(env, back);
		// Sanity-check the discriminator is the verify kind.
		match back.payload {
			LeasePayload::Verify { finding_id, finding: f } => {
				assert_eq!(finding_id, 42);
				assert_eq!(f, finding);
			},
			LeasePayload::Scan { .. } => panic!("expected Verify payload"),
		}
	}
}
