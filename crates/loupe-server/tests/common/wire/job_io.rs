use loupe_core::Severity;
use serde::{Deserialize, Serialize};

use super::{Finding, Verdict};

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

/// Body of `POST /v1/jobs/:id/verdict` (worker, verify-kind only).
/// Each verify job submits one verdict.
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
