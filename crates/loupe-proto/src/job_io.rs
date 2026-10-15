use std::path::{Component, Path};

use loupe_core::text::policy::*;
use loupe_core::text::{BoundedText, RepoPath};
use loupe_core::{Finding, Severity, Verdict};
use loupe_provenance::Source;
use serde::{Deserialize, Serialize};

/// Body of `POST /v1/jobs/:id/heartbeat` (worker, lease holder).
// debug-ok: heartbeat request contains only a numeric protocol version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatRequest {
	pub protocol_version: u16,
}

/// Response body of `POST /v1/jobs/:id/heartbeat`.
// debug-ok: heartbeat response contains only protocol and numeric expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatResponse {
	pub protocol_version: u16,
	pub lease_expires_at: i64,
}

/// Body of `POST /v1/jobs/:id/findings` (worker, scan-kind only). The
/// server rejects calls from a verify-kind job at the route layer.
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct FindingsBatch<S: Source> {
	pub protocol_version: u16,
	pub findings: Vec<Finding<S>>,
}
record_impls!(FindingsBatch<S> { protocol_version, findings });

/// Strict single-finding shape used only by the LLM MCP broker. The
/// server supplies the scanner id and does not accept candidate fixes
/// on the discovery path.
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct LlmFindingSubmission<S: Source> {
	pub protocol_version: u16,
	pub severity: Severity,
	pub title: BoundedText<FindingTitle, S>,
	pub description: BoundedText<FindingDescription, S>,
	pub file_path: RepoPath<S>,
	pub line_start: u32,
	pub line_end: u32,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub cwe: Option<BoundedText<CweText, S>>,
	pub poc_unified: BoundedText<PocUnified, S>,
	pub fingerprint: BoundedText<FindingFingerprintText, S>,
}
record_impls!(LlmFindingSubmission<S> { protocol_version, severity, title, description, file_path, line_start, line_end, cwe, poc_unified, fingerprint });

pub const LLM_FINDING_TITLE_MIN_CHARS: usize = 8;
pub const LLM_FINDING_TITLE_MAX_CHARS: usize = 100;
pub const LLM_FINDING_DESCRIPTION_MIN_CHARS: usize = 80;
pub const LLM_FINDING_DESCRIPTION_MAX_CHARS: usize = 16_384;
pub const LLM_FINDING_POC_MAX_BYTES: usize = 256 * 1024;

/// Checks properties the server can verify without access to the
/// checked-out repository. The trusted broker additionally verifies
/// file existence, line bounds, and `git apply --check`.
pub fn validate_llm_finding_submission<S: Source>(
	finding: &LlmFindingSubmission<S>,
) -> Result<(), String> {
	validate_llm_finding(&LlmFindingValidation {
		title: &finding.title,
		description: &finding.description,
		file_path: &finding.file_path,
		line_start: finding.line_start,
		line_end: finding.line_end,
		cwe: finding.cwe.as_ref(),
		poc_unified: &finding.poc_unified,
		fingerprint: finding.fingerprint.expose(),
	})
}

/// Borrowed strict-submission checks shared by the server DTO and the worker's
/// mixed-source submission. The independently computed fingerprint is checked
/// only for its hexadecimal shape; this view neither labels nor owns
/// it and is not a serialization or raw-content construction API.
pub struct LlmFindingValidation<'a, S: Source> {
	pub title: &'a BoundedText<FindingTitle, S>,
	pub description: &'a BoundedText<FindingDescription, S>,
	pub file_path: &'a RepoPath<S>,
	pub line_start: u32,
	pub line_end: u32,
	pub cwe: Option<&'a BoundedText<CweText, S>>,
	pub poc_unified: &'a BoundedText<PocUnified, S>,
	pub fingerprint: &'a str,
}

pub fn validate_llm_finding<S: Source>(
	finding: &LlmFindingValidation<'_, S>,
) -> Result<(), String> {
	loupe_core::report_limits::validate_report_content(
		finding.description.expose(),
		Some(finding.poc_unified.expose()),
		None,
	)?;
	let title_len = finding.title.expose().trim().chars().count();
	if !(LLM_FINDING_TITLE_MIN_CHARS..=LLM_FINDING_TITLE_MAX_CHARS).contains(&title_len) {
		return Err(format!(
			"title must contain {LLM_FINDING_TITLE_MIN_CHARS}..={LLM_FINDING_TITLE_MAX_CHARS} characters"
		));
	}
	let description_len = finding.description.expose().trim().chars().count();
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
	if !llm_path_is_normalized(finding.file_path.expose()) {
		return Err("file_path must be a normalized repo-relative path".into());
	}
	if let Some(cwe) = &finding.cwe {
		let digits = cwe.expose().strip_prefix("CWE-").unwrap_or_default();
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
	validate_llm_poc(finding.poc_unified.expose())
}

pub(crate) fn llm_path_is_normalized(raw: &str) -> bool {
	let path = Path::new(raw);
	!raw.trim().is_empty()
		&& !path.is_absolute()
		&& path.components().all(|component| matches!(component, Component::Normal(_)))
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
			&& line.strip_prefix('+').is_some_and(|added| !added.trim().is_empty())
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

/// Body of `POST /v1/jobs/:id/verdict` (worker, verify-kind only).
/// Each verify job submits one verdict.
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct VerdictSubmission<S: Source> {
	pub protocol_version: u16,
	pub verdict: Verdict<S>,
}
record_impls!(VerdictSubmission<S> { protocol_version, verdict });

/// Body of `POST /v1/jobs/:id/complete`.
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct CompleteRequest<RevisionS: Source, DiagnosticS: Source> {
	pub protocol_version: u16,
	pub outcome: CompleteOutcome,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub head_sha: Option<BoundedText<RevisionText, RevisionS>>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub error: Option<BoundedText<JobDiagnostic, DiagnosticS>>,
}
record_impls!(CompleteRequest<RevisionS, DiagnosticS> { protocol_version, outcome, head_sha, error });

// debug-ok: completion is a closed enum of unit variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompleteOutcome {
	Succeeded,
	Failed,
}

#[cfg(test)]
mod tests {
	use loupe_core::{Severity, Verdict};
	use loupe_provenance::Server;

	use super::*;
	use crate::test_support::{path, text};
	use crate::version::PROTOCOL_VERSION;

	#[test]
	fn findings_batch_preserves_wire_fields() {
		let batch = FindingsBatch {
			protocol_version: PROTOCOL_VERSION,
			findings: vec![Finding {
				scanner_id: text("x"),
				severity: Severity::Low,
				title: text("t"),
				description: text("d"),
				file_path: None,
				line_start: None,
				line_end: None,
				cwe: None,
				patch_unified: None,
				poc_unified: None,
				fingerprint: text("fp"),
			}],
		};
		let s = serde_json::to_string(&batch).unwrap();
		let back: serde_json::Value = serde_json::from_str(&s).unwrap();
		assert_eq!(
			back,
			serde_json::json!({"protocol_version":PROTOCOL_VERSION,"findings":[{
				"scanner_id":"x","severity":"low","title":"t","description":"d","fingerprint":"fp"
			}]})
		);
	}

	fn valid_llm_submission() -> LlmFindingSubmission<Server> {
		LlmFindingSubmission {
			protocol_version: PROTOCOL_VERSION,
			severity: Severity::High,
			title: text("Unchecked index permits denial of service"),
			description: text("An attacker-controlled index reaches the slice operation without a bounds check and can reliably terminate the service process."),
			file_path: path("src/lib.rs"),
			line_start: 4,
			line_end: 7,
			cwe: Some(text("CWE-129")),
			poc_unified: text("--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,1 +1,2 @@\n old\n+#[test] fn triggers_bug() {}\n"),
			fingerprint: text(&"a".repeat(64)),
		}
	}

	#[test]
	fn borrowed_llm_validation_accepts_independently_owned_computed_fingerprint() {
		let finding = valid_llm_submission();
		let computed = "0123456789abcdef".repeat(4);
		let mut view = LlmFindingValidation {
			title: &finding.title,
			description: &finding.description,
			file_path: &finding.file_path,
			line_start: finding.line_start,
			line_end: finding.line_end,
			cwe: finding.cwe.as_ref(),
			poc_unified: &finding.poc_unified,
			fingerprint: &computed,
		};
		assert_eq!(validate_llm_finding(&view), Ok(()));
		view.fingerprint = "not-computed-hex";
		assert_eq!(
			validate_llm_finding(&view).unwrap_err(),
			"fingerprint must be 64 lowercase hexadecimal characters"
		);
		assert_eq!(computed, "0123456789abcdef".repeat(4));
	}

	#[test]
	fn strict_llm_view_compatibility_order_and_exact_borrowed_inputs() {
		let valid = valid_llm_submission();
		assert_eq!(validate_llm_finding_submission(&valid), Ok(()));
		let mut value = valid.clone();
		value.title = text("  eight-ok  ");
		value.description = text(&format!("  {}  ", "d".repeat(80)));
		assert_eq!(validate_llm_finding_submission(&value), Ok(()));
		assert_eq!(value.title.expose(), "  eight-ok  ");
		assert_eq!(value.description.expose(), format!("  {}  ", "d".repeat(80)));
		for title in ["x".repeat(7), "x".repeat(101)] {
			value = valid.clone();
			value.title = text(&title);
			value.description = text("short");
			value.line_start = 0;
			assert_eq!(
				validate_llm_finding_submission(&value).unwrap_err(),
				"title must contain 8..=100 characters"
			);
		}
		for description in ["d".repeat(79), "d".repeat(16_385)] {
			value = valid.clone();
			value.description = text(&description);
			value.line_start = 0;
			assert_eq!(
				validate_llm_finding_submission(&value).unwrap_err(),
				"description must contain 80..=16384 characters"
			);
		}
		for lines in [(0, 7), (4, 3)] {
			value = valid.clone();
			value.line_start = lines.0;
			value.line_end = lines.1;
			value.cwe = Some(text("wrong"));
			assert_eq!(
				validate_llm_finding_submission(&value).unwrap_err(),
				"line range must be positive and ordered"
			);
		}
		for cwe in ["", "CWE-", "CWE-12x", "cwe-129"] {
			value = valid.clone();
			value.cwe = Some(text(cwe));
			value.fingerprint = text("short");
			assert_eq!(
				validate_llm_finding_submission(&value).unwrap_err(),
				"cwe must have the form CWE-<digits>"
			);
		}
		for fingerprint in ["a".repeat(63), "a".repeat(65), "A".repeat(64), "g".repeat(64)] {
			value = valid.clone();
			value.fingerprint = text(&fingerprint);
			value.poc_unified = text("bad");
			assert_eq!(
				validate_llm_finding_submission(&value).unwrap_err(),
				"fingerprint must be 64 lowercase hexadecimal characters"
			);
		}
		value = valid.clone();
		value.cwe = None;
		value.fingerprint = text(&"0123456789abcdef".repeat(4));
		assert_eq!(validate_llm_finding_submission(&value), Ok(()));
		value.poc_unified = text("--- a/x\n+++ b/x\n@@ -1 +1 @@\n+   \n");
		assert_eq!(
			validate_llm_finding_submission(&value).unwrap_err(),
			"poc_unified must be a unified diff with a hunk and a non-whitespace added line"
		);
		value.title = text("bad");
		value.description = text(&"d".repeat(60_001));
		assert!(validate_llm_finding_submission(&value)
			.unwrap_err()
			.starts_with("report content is too long:"));
	}

	#[test]
	fn strict_llm_submission_requires_headers_before_the_first_hunk() {
		// Header-like hunk content cannot substitute for the ---/+++ headers
		// required ahead of the first hunk.
		let mut finding = valid_llm_submission();
		finding.poc_unified =
			text("@@ -1,1 +1,2 @@\n--- not a header\n+++ also not a header\n+real addition\n");
		assert!(validate_llm_finding_submission(&finding).is_err());
	}

	#[test]
	fn strict_llm_submission_rejects_placeholder_content() {
		let mut finding = valid_llm_submission();
		finding.description = text("test");
		assert!(validate_llm_finding_submission(&finding).is_err());
		finding = valid_llm_submission();
		finding.poc_unified = text("--- a/x\n+++ b/x\n@@ -1 +1,2 @@\n x\n+\n");
		assert!(validate_llm_finding_submission(&finding).is_err());
	}

	#[test]
	fn strict_llm_submission_rejects_oversized_combined_report() {
		let mut finding = valid_llm_submission();
		let overhead = finding.description.expose().chars().count()
			+ finding.poc_unified.expose().chars().count();
		let mut poc = finding.poc_unified.expose().to_owned();
		poc.push_str(&"é".repeat(60_000 - overhead));
		finding.poc_unified = text(&poc);
		validate_llm_finding_submission(&finding).expect("exact content budget is allowed");
		poc.push('é');
		finding.poc_unified = text(&poc);
		let error = validate_llm_finding_submission(&finding)
			.expect_err("oversized combined report must be rejected");
		assert!(error.contains("60001"), "actual character count: {error}");
		assert!(error.contains("60000") && error.contains("retry"), "actionable error: {error}");
	}

	#[test]
	fn verdict_submission_preserves_wire_fields() {
		let v = VerdictSubmission {
			protocol_version: PROTOCOL_VERSION,
			verdict: Verdict::Confirmed { notes: Some(text("matches")), patch: None },
		};
		let s = serde_json::to_string(&v).unwrap();
		assert_eq!(
			serde_json::from_str::<serde_json::Value>(&s).unwrap(),
			serde_json::json!({
				"protocol_version":PROTOCOL_VERSION,"verdict":{"outcome":"confirmed","notes":"matches"}
			})
		);
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
		let req: CompleteRequest<Server, Server> = CompleteRequest {
			protocol_version: PROTOCOL_VERSION,
			outcome: CompleteOutcome::Succeeded,
			head_sha: Some(text("abc")),
			error: None,
		};
		let s = serde_json::to_string(&req).unwrap();
		assert!(s.contains(r#""outcome":"succeeded""#), "got: {s}");
		assert_eq!(
			serde_json::from_str::<serde_json::Value>(&s).unwrap(),
			serde_json::json!({
				"protocol_version":PROTOCOL_VERSION,"outcome":"succeeded","head_sha":"abc"
			})
		);
	}
}
