//! Actual six Worker, eight Operator and three query validators. Legacy DTOs
//! supply schema compatibility only; exact policies and field outputs are
//! independently checked. Authentication and collection have separate targets.
use http::Uri;
use loupe_server::fuzz_support::{self as actual, CarriedSpan, OperatorRequest, WorkerRequest};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use unicode_general_category::{get_general_category, GeneralCategory};

use crate::server_request_parsers::clone_url_shape;
use crate::utils::test_logger;

const TEXT_CAP: usize = 2 * 1024 * 1024;
const RAW_LIMIT: usize = 64 * 1024;

fn text_admitted(text: &str, multiline: bool) -> bool {
	text.len() <= TEXT_CAP
		&& text.chars().all(|c| {
			if multiline && matches!(c, '\r' | '\n' | '\t') {
				return true;
			}
			let point = u32::from(c);
			!matches!(
				get_general_category(c),
				GeneralCategory::Control
					| GeneralCategory::Format
					| GeneralCategory::Unassigned
					| GeneralCategory::PrivateUse
					| GeneralCategory::LineSeparator
					| GeneralCategory::ParagraphSeparator
			) && !(0xfdd0..=0xfdef).contains(&point)
				&& !matches!(point & 0xffff, 0xfffe | 0xffff)
		})
}

fn path_admitted(path: &str) -> bool {
	path.len() <= 512
		&& text_admitted(path, false)
		&& !path.contains('\\')
		&& path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

fn texts(value: &Value, fields: &[&str], multiline: bool) -> bool {
	fields.iter().all(|field| {
		value.get(*field).is_none_or(|value| {
			value.is_null() || value.as_str().is_some_and(|text| text_admitted(text, multiline))
		})
	})
}
fn paths(value: &Value) -> bool {
	value.get("file_path").is_none_or(|v| v.is_null() || v.as_str().is_some_and(path_admitted))
}
fn secrets(value: &Value, field: &str) -> bool {
	value.get(field).is_none_or(|v| v.is_null() || v.as_str().is_some_and(|s| s.len() <= TEXT_CAP))
}
fn defaults(value: &mut Value, fields: &[&str]) {
	for field in fields {
		if value.get(*field).is_none() {
			value[*field] = Value::Null;
		}
	}
}
fn finding_policy(value: &mut Value) -> bool {
	defaults(
		value,
		&["file_path", "line_start", "line_end", "cwe", "patch_unified", "poc_unified"],
	);
	texts(value, &["scanner_id", "title", "cwe", "fingerprint"], false)
		&& texts(value, &["description", "patch_unified", "poc_unified"], true)
		&& paths(value)
}

fn legacy<T: DeserializeOwned + Serialize>(body: &[u8]) -> Option<Value> {
	serde_json::from_slice::<T>(body).ok().map(|value| {
		serde_json::to_value(value).unwrap_or_else(|error| panic!("wire DTO serializes: {error}"))
	})
}

fn worker_expected(kind: usize, body: &[u8]) -> Option<Value> {
	let mut value = match kind {
		0 if body.is_empty() => return Some(Value::Null),
		0 => legacy::<loupe_proto::HeartbeatRequest>(body)?,
		1 => legacy::<loupe_proto::CompleteRequest>(body)?,
		2 => legacy::<loupe_proto::FindingsBatch>(body)?,
		3 => legacy::<loupe_proto::LlmFindingSubmission>(body)?,
		4 => legacy::<loupe_proto::VerdictSubmission>(body)?,
		_ => legacy::<loupe_proto::LeaseRequest>(body)?,
	};
	let valid = match kind {
		0 => true,
		1 => {
			defaults(&mut value, &["head_sha", "error"]);
			texts(&value, &["head_sha"], false) && texts(&value, &["error"], true)
		},
		2 => value["findings"].as_array_mut()?.iter_mut().all(finding_policy),
		3 => {
			defaults(&mut value, &["cwe"]);
			texts(&value, &["title", "cwe", "fingerprint"], false)
				&& texts(&value, &["description", "poc_unified"], true)
				&& paths(&value)
		},
		4 => {
			let verdict = &mut value["verdict"];
			match verdict["outcome"].as_str()? {
				"confirmed" => {
					defaults(verdict, &["notes", "patch"]);
					texts(verdict, &["notes"], true)
						&& (verdict["patch"].is_null()
							|| texts(&verdict["patch"], &["patch_unified", "notes"], true))
				},
				"dismissed" => {
					defaults(verdict, &["notes"]);
					texts(verdict, &["notes"], true)
				},
				"inconclusive" => {
					if verdict.get("terminal").is_none() {
						verdict["terminal"] = false.into();
					}
					texts(verdict, &["reason"], true)
				},
				_ => return None,
			}
		},
		_ => value["capabilities"]
			.as_array()?
			.iter()
			.all(|v| v.as_str().is_some_and(|s| text_admitted(s, false))),
	};
	valid.then_some(value)
}

fn operator_expected(kind: usize, body: &[u8]) -> Option<Value> {
	let mut value = match kind {
		0 => legacy::<loupe_proto::RegisterRepoRequest>(body)?,
		1 => legacy::<loupe_proto::UpdateRepoRequest>(body)?,
		2 => legacy::<loupe_proto::ScanRequest>(body)?,
		3 => legacy::<loupe_proto::RetryVerifyRequest>(body)?,
		4 => legacy::<loupe_proto::RegisterWorkerRequest>(body)?,
		5 => legacy::<loupe_proto::RotateRepoPatRequest>(body)?,
		6 => legacy::<loupe_proto::SetGithubAppRequest>(body)?,
		_ => legacy::<loupe_proto::SetRepoGithubReportingRequest>(body)?,
	};
	let valid = match kind {
		0 => {
			defaults(
				&mut value,
				&[
					"branch",
					"scan_interval_seconds",
					"scanner_config",
					"verification_enabled",
					"require_approval",
				],
			);
			if !texts(&value, &["clone_url", "branch"], false) {
				return None;
			}
			let derived = clone_url_shape(value["clone_url"].as_str()?);
			if derived
				.as_ref()
				.is_some_and(|(h, o, r)| ![h, o, r].iter().all(|v| text_admitted(v, false)))
			{
				return None;
			}
			let reporting = &mut value["reporting"];
			let admitted = match reporting["kind"].as_str()? {
				"manual" => true,
				"github_issue" => {
					defaults(reporting, &["github_pat"]);
					texts(reporting, &["target_owner", "target_repo"], false)
						&& secrets(reporting, "github_pat")
				},
				"email" => {
					defaults(reporting, &["from", "subject_prefix"]);
					texts(reporting, &["from", "subject_prefix"], false)
						&& reporting["to"]
							.as_array()?
							.iter()
							.all(|v| v.as_str().is_some_and(|s| text_admitted(s, false)))
				},
				_ => return None,
			};
			value = json!({"request":value, "derived":derived});
			admitted
		},
		1..=3 => true,
		4 => texts(&value, &["name"], false),
		5 => secrets(&value, "github_pat"),
		6 => secrets(&value, "private_key_pem"),
		_ => {
			defaults(&mut value, &["github_pat"]);
			texts(&value, &["target_owner", "target_repo"], false) && secrets(&value, "github_pat")
		},
	};
	valid.then_some(value)
}

const WORKER: [WorkerRequest; 6] = [
	WorkerRequest::Heartbeat,
	WorkerRequest::Complete,
	WorkerRequest::Findings,
	WorkerRequest::LlmFinding,
	WorkerRequest::Verdict,
	WorkerRequest::Lease,
];
const OPERATOR: [OperatorRequest; 8] = [
	OperatorRequest::RegisterRepo,
	OperatorRequest::UpdateRepo,
	OperatorRequest::EnqueueScan,
	OperatorRequest::RetryVerify,
	OperatorRequest::RegisterWorker,
	OperatorRequest::RotatePat,
	OperatorRequest::SetApp,
	OperatorRequest::SetReporting,
];

fn compare(result: actual::Decoded, expected: Option<Value>, selector: usize) {
	assert_eq!(result.is_ok(), expected.is_some(), "selector {selector}: admission differs");
	match result {
		Ok(value) => assert_eq!(Some(value), expected, "selector {selector}: exact fields differ"),
		Err((status, reason)) => {
			assert!(matches!(status, 400 | 422));
			// Every error is closed metadata, never an echoed body or serde cause.
			assert!(closed_diagnostic(&reason), "unexpected diagnostic: {reason}");
			assert!(!reason.contains("private_body_sentinel"));
			assert!(reason.len() < 256, "unexpected unbounded diagnostic");
		},
	}
}

fn closed_diagnostic(reason: &str) -> bool {
	if matches!(
		reason,
		"Failed to parse the request body as JSON: invalid syntax"
			| "Failed to deserialize query string: invalid query"
			| "state must name at least one job state"
			| "unknown job state; expected any of queued, leased, succeeded, failed, cancelled"
			| "unknown job kind; expected scan, verify, survey or drilldown"
			| "limit must be positive"
	) {
		return true;
	}
	if let Some(category) =
		reason.strip_prefix("Failed to deserialize the JSON body into the target type: ")
	{
		return matches!(
			category,
			"missing field"
				| "duplicate field"
				| "invalid type"
				| "unknown field"
				| "unknown variant"
				| "invalid data"
		);
	}
	let Some((field, rule)) = reason.split_once(": ") else { return false };
	if !matches!(
		field,
		"finding_title"
			| "finding_description"
			| "poc_unified"
			| "patch_unified"
			| "verdict_notes"
			| "verdict_reason"
			| "patch_notes"
			| "scanner_id"
			| "cwe"
			| "finding_fingerprint"
			| "repo_path"
			| "path"
			| "revision"
			| "job_diagnostic"
			| "worker_name"
			| "lease_capability_name"
			| "repo_host"
			| "repo_owner"
			| "repo_name"
			| "clone_url"
			| "git_branch"
			| "mail_address"
			| "mail_subject_prefix"
			| "credential"
			| "finding_search"
	) {
		return false;
	}
	if matches!(rule, "Bytes" | "Chars" | "JsonSyntax" | "Path" | "Empty") {
		return true;
	}
	let Some(point) = rule.strip_prefix("Character (U+").and_then(|s| s.strip_suffix(')')) else {
		return false;
	};
	(4..=6).contains(&point.len())
		&& point.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
		&& u32::from_str_radix(point, 16).is_ok_and(|n| n <= 0x10ffff)
}

#[derive(Deserialize)]
struct SearchShape {
	q: String,
	#[serde(default)]
	limit: Option<i64>,
}
#[derive(Deserialize)]
struct JobsShape {
	#[serde(default)]
	limit: Option<i64>,
	#[serde(default)]
	state: Option<String>,
	#[serde(default)]
	kind: Option<String>,
}

fn query_expected(selector: usize, uri: &Uri) -> Option<Value> {
	let text = uri.query().unwrap_or_default();
	if selector < 16 {
		let value: SearchShape = serde_urlencoded::from_str(text).ok()?;
		return text_admitted(&value.q, true).then(|| json!({"q":value.q, "limit":value.limit}));
	}
	let value: JobsShape = serde_urlencoded::from_str(text).ok()?;
	if value.limit.is_some_and(|n| n <= 0) {
		return None;
	}
	if value
		.kind
		.as_deref()
		.is_some_and(|k| !["scan", "verify", "survey", "drilldown"].contains(&k))
	{
		return None;
	}
	let mut states = Vec::new();
	if let Some(raw) = &value.state {
		for state in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
			if !["queued", "leased", "succeeded", "failed", "cancelled"].contains(&state) {
				return None;
			}
			if !states.contains(&state) {
				states.push(state);
			}
		}
		if states.is_empty() {
			return None;
		}
	}
	Some(json!({"states":states, "kind":value.kind, "limit":value.limit}))
}

fn check(selector: usize, body: &[u8]) -> Vec<CarriedSpan> {
	if selector < 6 {
		let (result, spans) = actual::worker_request(WORKER[selector], body);
		compare(result, worker_expected(selector, body), selector);
		return spans;
	}
	if selector < 14 {
		compare(
			actual::operator_request(OPERATOR[selector - 6], body),
			operator_expected(selector - 6, body),
			selector,
		);
	} else if let Ok(uri) = Uri::try_from(body) {
		let result = match selector {
			14 => actual::worker_search(&uri),
			15 => actual::operator_search(&uri),
			_ => actual::job_query(&uri),
		};
		compare(result, query_expected(selector, &uri), selector);
	}
	Vec::new()
}

// The expected token locations are recorded while appending bytes, without
// looking up text or repeating the production pointer/offset calculation.
#[derive(Default)]
struct Message {
	bytes: Vec<u8>,
	spans: Vec<CarriedSpan>,
}
impl Message {
	fn append(&mut self, text: &str) {
		self.bytes.extend_from_slice(text.as_bytes());
	}
	fn token(&mut self, name: &str, field: &'static str, encoded: &str) {
		self.append(name);
		let start = self.bytes.len();
		self.append(encoded);
		self.spans.push(CarriedSpan { field, start, end: self.bytes.len() });
	}
}

fn span_recipe(mode: u8) {
	let encoded = match mode / 3 % 4 {
		0 => r#""same""#,
		1 => r#""\u0073ame""#,
		2 => r#""Cafe\u0301""#,
		_ => r#""\uD83D\uDE80""#,
	};
	let selector = usize::from(mode % 3) + 2;
	let mut body = Message::default();
	body.append("{\"spare\":");
	body.append(encoded);
	body.append(",\"protocol_version\":2,");
	match selector {
		2 => {
			body.append("\"findings\":[");
			for index in 0..2 {
				if index != 0 {
					body.append(",");
				}
				body.append("{");
				body.token(r#""scann\u0065r_id":"#, "AgentScanner", encoded);
				body.append(",\"severity\":\"high\"");
				for (name, field) in [
					("title", "AgentTitle"),
					("description", "AgentDescription"),
					("file_path", "AgentPath"),
					("cwe", "AgentCwe"),
					("patch_unified", "AgentPatch"),
					("poc_unified", "AgentPoc"),
					("fingerprint", "AgentFingerprint"),
				] {
					body.token(&format!(",\"{name}\":"), field, encoded);
				}
				body.append(",\"line_start\":1,\"line_end\":2}");
			}
			body.append("]}");
		},
		3 => {
			body.append("\"severity\":\"high\",\"line_start\":1,\"line_end\":2");
			for (name, field) in [
				("title", "AgentTitle"),
				("description", "AgentDescription"),
				("file_path", "AgentPath"),
				("cwe", "AgentCwe"),
				("poc_unified", "AgentPoc"),
				("fingerprint", "AgentFingerprint"),
			] {
				body.token(&format!(",\"{name}\":"), field, encoded);
			}
			body.append("}");
		},
		_ => match mode / 12 % 3 {
			0 => {
				body.append("\"verdict\":{\"outcome\":\"confirmed\"");
				body.token(",\"notes\":", "AgentNotes", encoded);
				body.append(",\"patch\":{");
				body.token("\"patch_unified\":", "AgentPatch", encoded);
				body.token(",\"notes\":", "AgentPatchNotes", encoded);
				body.append("}}}");
			},
			1 => {
				body.append("\"verdict\":{\"outcome\":\"dismissed\"");
				body.token(",\"notes\":", "AgentNotes", encoded);
				body.append("}}");
			},
			_ => {
				body.append("\"verdict\":{\"outcome\":\"inconclusive\",\"terminal\":true");
				body.token(",\"reason\":", "AgentReason", encoded);
				body.append("}}");
			},
		},
	}
	let expected = worker_expected(selector, &body.bytes);
	assert!(expected.is_some(), "span recipe must be admitted");
	let (result, mut observed) = actual::worker_request(WORKER[selector], &body.bytes);
	compare(result, expected, selector);
	observed.sort();
	body.spans.sort();
	assert_eq!(observed, body.spans, "original Agent spans differ from append ledger");
	// A separate invocation must start empty, even after a carried message.
	let (result, spans) = actual::worker_request(WorkerRequest::Heartbeat, b"");
	assert_eq!(result, Ok(Value::Null));
	assert!(spans.is_empty(), "span observer leaked across invocations");
}

fn boundary_recipe(field: u8, edge: u8, escaped: bool) {
	let path = field % 4 == 3;
	let cap = if path { 512 } else { TEXT_CAP };
	let count = cap - 1 + usize::from(edge % 3);
	let token = if escaped { "\\u0061" } else { "a" }.repeat(count);
	let (selector, body) = match field % 4 {
		0 => (5, format!(r#"{{"protocol_version":2,"capabilities":["{token}"]}}"#)),
		1 => (10, format!(r#"{{"protocol_version":2,"name":"{token}"}}"#)),
		2 => (11, format!(r#"{{"protocol_version":2,"github_pat":"{token}"}}"#)),
		_ => (
			3,
			format!(
				r#"{{"protocol_version":2,"severity":"high","title":"title","description":"description","file_path":"{token}","line_start":1,"line_end":1,"poc_unified":"","fingerprint":"fp"}}"#
			),
		),
	};
	assert!(body.len() < 16 * 1024 * 1024);
	check(selector, body.as_bytes());
}

pub fn do_test(data: &[u8]) {
	match data {
		[255, b'S', mode, ..] => {
			span_recipe(*mode);
			return;
		},
		[255, b'B', field, edge, encoding, ..] => {
			boundary_recipe(*field, *edge, encoding & 1 != 0);
			return;
		},
		_ => {},
	}
	let Some((&selector, body)) = data.split_first() else { return };
	// This is a harness bound only; compact recipes below separately reach
	// production field caps. It adds no runtime request admission limit.
	if body.len() > RAW_LIMIT {
		return;
	}
	check(usize::from(selector) % 17, body);
}

pub fn server_ingress_requests_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes during this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn server_ingress_requests_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller supplies the readable buffer documented above.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests;
