use std::path::{Component, Path};

use loupe_core::{Finding, Severity, Verdict};
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

pub const LLM_FINDING_TITLE_MIN_CHARS: usize = 8;
pub const LLM_FINDING_TITLE_MAX_CHARS: usize = 100;
pub const LLM_FINDING_DESCRIPTION_MIN_CHARS: usize = 80;
pub const LLM_FINDING_DESCRIPTION_MAX_CHARS: usize = 16_384;
pub const LLM_FINDING_POC_MAX_BYTES: usize = 256 * 1024;

/// Checks properties the server can verify without access to the
/// checked-out repository. The trusted broker additionally verifies
/// file existence, line bounds, and `git apply --check`.
pub fn validate_llm_finding_submission(finding: &LlmFindingSubmission) -> Result<(), String> {
	let title_len = finding.title.trim().chars().count();
	if !(LLM_FINDING_TITLE_MIN_CHARS..=LLM_FINDING_TITLE_MAX_CHARS).contains(&title_len) {
		return Err(format!(
			"title must contain {LLM_FINDING_TITLE_MIN_CHARS}..={LLM_FINDING_TITLE_MAX_CHARS} characters"
		));
	}
	let description_len = finding.description.trim().chars().count();
	if !(LLM_FINDING_DESCRIPTION_MIN_CHARS..=LLM_FINDING_DESCRIPTION_MAX_CHARS)
		.contains(&description_len)
	{
		return Err(format!(
			"description must contain {LLM_FINDING_DESCRIPTION_MIN_CHARS}..={LLM_FINDING_DESCRIPTION_MAX_CHARS} characters"
		));
	}
	if finding.line_start == 0 || finding.line_end < finding.line_start {
		return Err("line range must be positive and ordered".into());
	}
	let path = Path::new(&finding.file_path);
	if finding.file_path.trim().is_empty()
		|| path.is_absolute()
		|| path.components().any(|component| !matches!(component, Component::Normal(_)))
	{
		return Err("file_path must be a normalized repo-relative path".into());
	}
	if let Some(cwe) = &finding.cwe {
		let digits = cwe.strip_prefix("CWE-").unwrap_or_default();
		if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
			return Err("cwe must have the form CWE-<digits>".into());
		}
	}
	if finding.fingerprint.len() != 64
		|| !finding
			.fingerprint
			.bytes()
			.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
	{
		return Err("fingerprint must be 64 lowercase hexadecimal characters".into());
	}
	validate_llm_poc(&finding.poc_unified)
}

fn validate_llm_poc(poc: &str) -> Result<(), String> {
	if poc.len() > LLM_FINDING_POC_MAX_BYTES {
		return Err(format!("poc_unified exceeds {LLM_FINDING_POC_MAX_BYTES} bytes"));
	}
	let mut has_old_file = false;
	let mut has_new_file = false;
	let mut in_hunk = false;
	let mut has_substantive_addition = false;
	for line in poc.lines() {
		if line.starts_with("@@ ") {
			in_hunk = true;
			continue;
		}
		// Headers only count ahead of the first hunk. Inside a hunk the
		// same prefixes are ordinary added or removed content.
		if !in_hunk {
			has_old_file |= line.starts_with("--- ");
			has_new_file |= line.starts_with("+++ ");
		}
		if in_hunk
			&& line.starts_with('+')
			&& !line.starts_with("+++")
			&& !line[1..].trim().is_empty()
		{
			has_substantive_addition = true;
		}
	}
	if !has_old_file || !has_new_file || !in_hunk || !has_substantive_addition {
		return Err(
			"poc_unified must be a unified diff with a hunk and a non-whitespace added line".into(),
		);
	}
	Ok(())
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

	fn valid_llm_submission() -> LlmFindingSubmission {
		LlmFindingSubmission {
			protocol_version: PROTOCOL_VERSION,
			severity: Severity::High,
			title: "Unchecked index permits denial of service".into(),
			description: "An attacker-controlled index reaches the slice operation without a bounds check and can reliably terminate the service process.".into(),
			file_path: "src/lib.rs".into(),
			line_start: 4,
			line_end: 7,
			cwe: Some("CWE-129".into()),
			poc_unified: "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,1 +1,2 @@\n old\n+#[test] fn triggers_bug() {}\n".into(),
			fingerprint: "a".repeat(64),
		}
	}

	#[test]
	fn strict_llm_submission_requires_headers_before_the_first_hunk() {
		// A unified diff carries its ---/+++ headers ahead of the first
		// hunk. Accepting them anywhere let hunk-body text that merely
		// looks like a header stand in for the real thing.
		let mut finding = valid_llm_submission();
		finding.poc_unified =
			"@@ -1,1 +1,2 @@\n--- not a header\n+++ also not a header\n+real addition\n".into();
		assert!(validate_llm_finding_submission(&finding).is_err());
	}

	#[test]
	fn strict_llm_submission_rejects_placeholder_content() {
		let mut finding = valid_llm_submission();
		finding.description = "test".into();
		assert!(validate_llm_finding_submission(&finding).is_err());
		finding = valid_llm_submission();
		finding.poc_unified = "--- a/x\n+++ b/x\n@@ -1 +1,2 @@\n x\n+\n".into();
		assert!(validate_llm_finding_submission(&finding).is_err());
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
