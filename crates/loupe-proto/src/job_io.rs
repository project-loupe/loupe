use loupe_core::{Finding, Verdict};
use serde::{Deserialize, Serialize};

/// Body of `POST /v1/jobs/:id/heartbeat` (worker, lease holder).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatRequest {
	pub protocol_version: u16,
}

/// Response body of `POST /v1/jobs/:id/heartbeat`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatResponse {
	pub protocol_version: u16,
	pub lease_expires_at: i64,
}

/// Body of `POST /v1/jobs/:id/findings` (worker, scan-kind only). The
/// server rejects calls from a verify-kind job at the route layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingsBatch {
	pub protocol_version: u16,
	pub findings: Vec<Finding>,
}

/// Body of `POST /v1/jobs/:id/verdict` (worker, verify-kind only). One
/// verdict per verify job — that's the entire reason to split the
/// endpoint from `findings`.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompleteOutcome {
	Succeeded,
	Failed,
}

#[cfg(test)]
mod tests {
	use loupe_core::{Severity, Verdict};

	use super::*;
	use crate::version::PROTOCOL_VERSION;

	#[test]
	fn findings_batch_round_trips() {
		let batch = FindingsBatch {
			protocol_version: PROTOCOL_VERSION,
			findings: vec![Finding {
				scanner_id: "x".into(),
				severity: Severity::Low,
				title: "t".into(),
				description: "d".into(),
				file_path: None,
				line_start: None,
				line_end: None,
				cwe: None,
				patch_unified: None,
				poc_unified: None,
				fingerprint: "fp".into(),
			}],
		};
		let s = serde_json::to_string(&batch).unwrap();
		let back: FindingsBatch = serde_json::from_str(&s).unwrap();
		assert_eq!(batch, back);
	}

	#[test]
	fn verdict_submission_round_trips() {
		let v = VerdictSubmission {
			protocol_version: PROTOCOL_VERSION,
			verdict: Verdict::Confirmed { notes: Some("matches".into()), patch: None },
		};
		let s = serde_json::to_string(&v).unwrap();
		let back: VerdictSubmission = serde_json::from_str(&s).unwrap();
		assert_eq!(v, back);
	}

	#[test]
	fn heartbeat_request_round_trips() {
		let req = HeartbeatRequest { protocol_version: PROTOCOL_VERSION };
		let s = serde_json::to_string(&req).unwrap();
		let back: HeartbeatRequest = serde_json::from_str(&s).unwrap();
		assert_eq!(req, back);
	}

	#[test]
	fn complete_outcome_serializes_lowercase() {
		let req = CompleteRequest {
			protocol_version: PROTOCOL_VERSION,
			outcome: CompleteOutcome::Succeeded,
			head_sha: Some("abc".into()),
			error: None,
		};
		let s = serde_json::to_string(&req).unwrap();
		assert!(s.contains(r#""outcome":"succeeded""#), "got: {s}");
		let back: CompleteRequest = serde_json::from_str(&s).unwrap();
		assert_eq!(req, back);
	}
}
