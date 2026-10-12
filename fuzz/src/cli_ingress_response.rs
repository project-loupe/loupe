//! Same-source CLI response decoders. Selector byte, mode byte, bounded payload.
//! Mode 0: raw JSON; 1: append-ledger finding tokens; 2: compact text/path caps;
//! 3: reporting/schema recipes; 4: positional DTOs. Fixtures bypass HTTP.
use loupe_cli::fuzz_support::{self, ResponseCase, ResponseObservation};
use serde_json::{json, Value};

use crate::utils::test_logger;
use crate::{cli_common as limits, cli_response_oracle as oracle};
const CONSTRUCTED_LIMIT: usize = 16 * 1024 * 1024;
fn encoded(value: &str) -> String {
	serde_json::to_string(value).unwrap_or_else(|e| panic!("fixture encoding: {e}"))
}
fn bytes(value: &Value) -> Vec<u8> {
	serde_json::to_vec(value).unwrap_or_else(|e| panic!("fixture encoding: {e}"))
}
fn summary() -> Value {
	json!({"id":1,"repo_id":-2,"job_id":3,"scanner_id":"same","severity":"high","title":"same","file_path":"src/a.rs","line_start":0,"fingerprint":"same","state":"confirmed","verification_required":false,"created_at":i64::MIN,"approved_at":1,"approved_by_cn":"same","rejected_at":2,"rejected_by_cn":"same"})
}
fn job() -> Value {
	json!({"job_id":1,"repo_id":-2,"kind":"future-kind","state":"queued","incremental":true,"since_sha":" since ","head_sha":"head","parent_job_id":3,"target_finding_id":4,"attempts":u32::MAX,"enqueued_at":i64::MIN,"worker_id":5,"lease_expires_at":6,"started_at":7,"finished_at":8,"error":" exact\r\nerror "})
}
fn repo() -> Value {
	json!({"id":-1,"clone_url":" local é ","host":"host","owner":"owner","repo":"repo","default_branch":" branch ","scan_interval_seconds":-1,"disabled_at":0,"verification_enabled":true,"require_approval":false,"last_scanned_sha":" sha ","last_scanned_at":1,"created_at":i64::MAX,"reporting":{"kind":"github_issue","target_owner":"owner","target_repo":"repo"}})
}
pub fn fixture(case: ResponseCase) -> Value {
	use ResponseCase as C;
	match case {
		C::ShowApp => json!({"protocol_version":65535,"app":{"app_id":u64::MAX,"slug":" slug "}}),
		C::RegisterRepo => json!({"protocol_version":65535,"repo_id":i64::MIN}),
		C::ListRepos => json!({"protocol_version":2,"repos":[repo()]}),
		C::ScanRepo => json!({"protocol_version":1,"job_id":i64::MAX}),
		C::RegisterWorker => {
			json!({"protocol_version":2,"worker_id":-1,"client_cert_pem":" cert\n ","client_key_pem":"KEY\"\\\r\n\t\u{0}","ca_cert_pem":" CAé "})
		},
		C::ListJobs => json!([job(), job()]),
		C::GetJob | C::RetryJob | C::CancelJob => job(),
		C::ListFindings | C::SearchFindings => {
			json!({"protocol_version":2,"findings":[summary(),summary()]})
		},
		C::GetFinding => {
			let mut d = summary();
			d["protocol_version"] = 2.into();
			d["description"] = " exact e\u{301}\r\n\t ".into();
			d["line_end"] = u32::MAX.into();
			d["cwe"] = "".into();
			d["patch_unified"] = " patch\n\n\n ".into();
			d["poc_unified"] = "poc\r\n".into();
			d
		},
		C::RetryVerification => {
			json!({"protocol_version":2,"dry_run":true,"matched":u64::MAX,"revived":1,"requeued_jobs":2,"created_jobs":3,"left_queued_or_leased":4})
		},
		C::DiscardSuccess => Value::Null,
	}
}
pub fn check(case: ResponseCase, raw: &[u8]) -> ResponseObservation {
	assert!(raw.len() <= CONSTRUCTED_LIMIT, "fixture cap is separate from HTTP collection");
	let old = oracle::legacy(case, raw);
	let expected = old.as_ref().is_ok_and(oracle::policies);
	let mut actual = fuzz_support::observe_response(case, raw);
	assert_eq!(actual.case, case);
	use fuzz_support::Entry as E;
	let expected_entry = match case {
		ResponseCase::ShowApp => E::ShowApp,
		ResponseCase::RegisterRepo => E::RegisterRepo,
		ResponseCase::ListRepos => E::ListRepos,
		ResponseCase::ScanRepo => E::ScanRepo,
		ResponseCase::RegisterWorker => E::RegisterWorker,
		ResponseCase::ListJobs => E::ListJobs,
		ResponseCase::GetJob => E::GetJob,
		ResponseCase::RetryJob => E::RetryJob,
		ResponseCase::CancelJob => E::CancelJob,
		ResponseCase::ListFindings => E::ListFindings,
		ResponseCase::SearchFindings => E::SearchFindings,
		ResponseCase::GetFinding => E::GetFinding,
		ResponseCase::RetryVerification => E::RetryVerification,
		ResponseCase::DiscardSuccess => E::DiscardSuccess,
	};
	let mut expected_entries = vec![expected_entry];
	if case == ResponseCase::SearchFindings {
		expected_entries.push(E::ListFindings);
	}
	assert_eq!(actual.entries, expected_entries, "actual response entry reached");
	assert_eq!(
		actual.result.is_ok(),
		expected,
		"{case:?}: legacy schema / independent policy mismatch"
	);
	for &(start, end) in &actual.spans {
		assert!(start <= end && end <= raw.len());
	}
	if expected {
		let old = old.unwrap_or_else(|e| panic!("old admitted result: {e}"));
		let expected_fields = oracle::typed_fields(&old);
		actual.typed.sort();
		assert_eq!(actual.typed, expected_fields, "typed observations before legacy exit");
		let result =
			std::mem::replace(&mut actual.result, Err(fuzz_support::Rejection::SchemaOrPolicy))
				.unwrap_or_else(|_| panic!("missing actual admitted value"));
		oracle::compare(old, result);
		// Caller's ledger only needs admission and observations, not a duplicate
		// secret-bearing output. Return the closed discard witness for success.
		actual.result = Ok(fuzz_support::ResponseValue::Discard);
	}
	actual
}

pub struct Ledger {
	pub raw: Vec<u8>,
	pub ranges: Vec<(usize, usize)>,
	pub decoded: Vec<String>,
}
impl Ledger {
	fn new() -> Self {
		Self { raw: Vec::new(), ranges: Vec::new(), decoded: Vec::new() }
	}
	fn append(&mut self, s: &str) {
		self.raw.extend_from_slice(s.as_bytes());
	}
	fn token(&mut self, token: &str, agent: bool) {
		let start = self.raw.len();
		self.append(token);
		let end = self.raw.len();
		if agent {
			self.ranges.push((start, end));
			self.decoded
				.push(serde_json::from_str(token).unwrap_or_else(|e| panic!("ledger token: {e}")));
		}
	}
	fn field(&mut self, name: &str, token: &str, agent: bool) {
		self.append(",");
		self.append(name);
		self.append(":");
		self.token(token, agent);
	}
}
pub fn ledger(detail: bool, payload: &str, flags: u8) -> Ledger {
	let token = if flags & 64 != 0 {
		// Force UTF-16 escape spelling, including actual high/low surrogate pairs.
		let mut token = String::from("\"");
		for unit in payload.encode_utf16() {
			use std::fmt::Write;
			write!(&mut token, "\\u{unit:04x}").unwrap_or_else(|_| unreachable!());
		}
		token.push('"');
		token
	} else if flags & 1 == 0 {
		encoded(payload)
	} else {
		encoded(payload).replace("/", "\\/")
	};
	let mut out = Ledger::new();
	if !detail {
		out.append("{\"protocol_version\":2,\"findings\":[");
	}
	for index in 0..if detail { 1 } else { 2 } {
		if index > 0 {
			out.append(",")
		}
		out.append("{\"id\":1,\"repo_id\":2,\"job_id\":3,\"severity\":\"high\",\"state\":\"confirmed\",\"verification_required\":false,\"created_at\":0");
		if detail {
			out.append(",\"protocol_version\":2");
		}
		// Equal Server audit / ignored tokens surround the Agent tokens. Their
		// offsets are known when appended, never obtained by content search.
		out.field("\"approved_by_cn\"", &token, false);
		let names = if flags & 2 == 0 {
			["\"scanner_id\"", "\"title\"", "\"fingerprint\""]
		} else {
			["\"fingerprint\"", "\"ti\\u0074le\"", "\"scanner_id\""]
		};
		for name in names {
			out.field(name, &token, true);
		}
		if flags & 4 != 0 {
			out.field("\"file_path\"", "\"src/a.rs\"", true);
		} else if flags & 8 != 0 {
			out.field("\"file_path\"", "null", false);
		}
		if detail {
			out.field("\"description\"", &token, true);
			for name in ["\"cwe\"", "\"patch_unified\"", "\"poc_unified\""] {
				if flags & 16 == 0 {
					out.field(name, &token, true);
				} else if flags & 8 != 0 {
					out.field(name, "null", false);
				} else {
					out.field(name, "\"\"", true);
				}
			}
		}
		out.field("\"rejected_by_cn\"", &token, false);
		out.field("\"ignored\"", &token, false);
		out.append("}");
	}
	if !detail {
		out.append("]}");
	}
	out
}
pub fn check_ledger(detail: bool, payload: &str, flags: u8) {
	let ledger = ledger(detail, payload, flags);
	let case = if detail {
		ResponseCase::GetFinding
	} else if flags & 32 == 0 {
		ResponseCase::ListFindings
	} else {
		ResponseCase::SearchFindings
	};
	let actual = check(case, &ledger.raw);
	if actual.result.is_ok() {
		let mut expected = ledger.ranges.clone();
		expected.sort();
		let mut actual = actual.spans;
		actual.sort();
		assert_eq!(
			actual, expected,
			"original-token append ledger differs (including equal-token offsets)"
		);
		for ((start, end), expected) in ledger.ranges.into_iter().zip(ledger.decoded) {
			let actual: String = serde_json::from_slice(&ledger.raw[start..end])
				.unwrap_or_else(|e| panic!("original token: {e}"));
			assert_eq!(actual, expected);
		}
	}
}
fn array(object: &Value, names: &[&str]) -> Value {
	Value::Array(
		names.iter().map(|name| object.get(*name).cloned().unwrap_or(Value::Null)).collect(),
	)
}
const SUMMARY: &[&str] = &[
	"id",
	"repo_id",
	"job_id",
	"scanner_id",
	"severity",
	"title",
	"file_path",
	"line_start",
	"fingerprint",
	"state",
	"verification_required",
	"created_at",
	"approved_at",
	"approved_by_cn",
	"rejected_at",
	"rejected_by_cn",
];
const JOB: &[&str] = &[
	"job_id",
	"repo_id",
	"kind",
	"state",
	"incremental",
	"since_sha",
	"head_sha",
	"parent_job_id",
	"target_finding_id",
	"attempts",
	"enqueued_at",
	"worker_id",
	"lease_expires_at",
	"started_at",
	"finished_at",
	"error",
];
const REPO: &[&str] = &[
	"id",
	"clone_url",
	"host",
	"owner",
	"repo",
	"default_branch",
	"scan_interval_seconds",
	"disabled_at",
	"verification_enabled",
	"require_approval",
	"last_scanned_sha",
	"last_scanned_at",
	"created_at",
	"reporting",
];
const DETAIL: &[&str] = &[
	"protocol_version",
	"id",
	"repo_id",
	"job_id",
	"scanner_id",
	"severity",
	"title",
	"description",
	"file_path",
	"line_start",
	"line_end",
	"cwe",
	"patch_unified",
	"poc_unified",
	"fingerprint",
	"state",
	"verification_required",
	"created_at",
	"approved_at",
	"approved_by_cn",
	"rejected_at",
	"rejected_by_cn",
];
pub fn positional(case: ResponseCase) -> Value {
	use ResponseCase as C;
	let value = fixture(case);
	match case {
		C::ShowApp => json!([value["protocol_version"], array(&value["app"], &["app_id", "slug"])]),
		C::RegisterRepo => array(&value, &["protocol_version", "repo_id"]),
		C::ScanRepo => array(&value, &["protocol_version", "job_id"]),
		C::RegisterWorker => array(
			&value,
			&["protocol_version", "worker_id", "client_cert_pem", "client_key_pem", "ca_cert_pem"],
		),
		C::ListRepos => json!([2, [array(&repo(), REPO)]]),
		C::ListJobs => json!([array(&job(), JOB), array(&job(), JOB)]),
		C::GetJob | C::RetryJob | C::CancelJob => array(&value, JOB),
		C::ListFindings | C::SearchFindings => {
			json!([2, [array(&summary(), SUMMARY), array(&summary(), SUMMARY)]])
		},
		C::GetFinding => array(&value, DETAIL),
		C::RetryVerification => array(
			&value,
			&[
				"protocol_version",
				"dry_run",
				"matched",
				"revived",
				"requeued_jobs",
				"created_jobs",
				"left_queued_or_leased",
			],
		),
		C::DiscardSuccess => Value::Null,
	}
}
pub fn reporting(raw: &str) -> Vec<u8> {
	format!(r#"{{"protocol_version":2,"repos":[{{"id":1,"clone_url":"x","host":"h","owner":"o","repo":"r","verification_enabled":true,"created_at":0,"reporting":{raw}}}]}}"#).into_bytes()
}
fn schema_recipe(recipe: u8) -> Vec<u8> {
	let fixed = [
		r#"{"kind":"manual"}"#,
		r#"{"target_repo":"r","target_owner":"o","k\u0069nd":"github_issue"}"#,
		r#"{"kind":"github_issue","target_owner":"o","target_repo":"r","auth":{"app":null}}"#,
		r#"{"kind":{"manual":null}}"#,
		r#"{"kind":"email","to":["b","a"],"from":"","subject_prefix":null}"#,
		r#"{"kind":"manual","ignored":1,"ignored":2}"#,
		r#"{"kind":"manual","kind":"manual"}"#,
		r#"{"kind":"github_issue","target_owner":"a","target_owner":"b","target_repo":"r"}"#,
		r#"["github_issue","o","r","pat"]"#,
		r#"["manual"]"#,
		r#"["email",["b","a"],null,""]"#,
		r#"{"kind":"manual","ignored":1e400}"#,
		r#"{"kind":"manual","ignored":"\uD800"}"#,
	];
	if let Some(raw) = fixed.get(usize::from(recipe)) {
		return reporting(raw);
	}
	if recipe == 13 {
		return format!(
			r#"{{"protocol_version":2,"repos":[],"ignored":{}0{}}}"#,
			"[".repeat(140),
			"]".repeat(140)
		)
		.into_bytes();
	}
	let depth = 120 + usize::from(recipe - 14) % 11;
	reporting(&format!(
		r#"{{"kind":"manual","ignored":{}0{}}}"#,
		"[".repeat(depth),
		"]".repeat(depth)
	))
}
fn boundary_recipe(recipe: u8) -> Vec<u8> {
	let path = recipe & 16 != 0;
	let text = if path {
		"x".repeat(if recipe & 1 == 0 { 512 } else { 513 })
	} else {
		limits::boundary(recipe % 7)
	};
	let token = if recipe & 8 != 0 {
		let mut s = String::from("\"");
		for c in text.chars() {
			for unit in c.encode_utf16(&mut [0; 2]) {
				use std::fmt::Write;
				write!(&mut s, "\\u{unit:04x}").unwrap_or_else(|_| unreachable!());
			}
		}
		s.push('"');
		s
	} else {
		encoded(&text)
	};
	let mut row = summary();
	row.as_object_mut().unwrap_or_else(|| unreachable!()).remove(if path {
		"file_path"
	} else {
		"title"
	});
	let row = serde_json::to_string(&row).unwrap_or_else(|_| unreachable!());
	let prefix = row.strip_suffix('}').unwrap_or_else(|| unreachable!());
	format!(
		"{{\"protocol_version\":2,\"findings\":[{prefix},\"{}\":{token}}}]}}",
		if path { "file_path" } else { "title" }
	)
	.into_bytes()
}
pub fn do_test(data: &[u8]) {
	let data = &data[..data.len().min(limits::INPUT_LIMIT)];
	let Some(&selector) = data.first() else { return };
	let case = ResponseCase::ALL[usize::from(selector) % ResponseCase::ALL.len()];
	let mode = data.get(1).copied().unwrap_or(0) % 5;
	let payload = data.get(2..).unwrap_or_default();
	match mode {
		0 => {
			check(case, payload);
		},
		1 => {
			let flags = payload.first().copied().unwrap_or(0);
			let text = String::from_utf8_lossy(payload.get(1..).unwrap_or_default());
			check_ledger(selector % 2 == 0, &text, flags);
		},
		2 => {
			check(
				ResponseCase::ListFindings,
				&boundary_recipe(payload.first().copied().unwrap_or(0)),
			);
		},
		3 => {
			check(
				ResponseCase::ListRepos,
				&schema_recipe(payload.first().copied().unwrap_or(0) % 25),
			);
		},
		_ => {
			check(case, &bytes(&positional(case)));
		},
	}
}
pub fn cli_ingress_response_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data)
}
/// # Safety
/// The caller provides `datalen` readable bytes for this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cli_ingress_response_run(data: *const u8, datalen: usize) {
	// SAFETY: the C runner supplies readable bytes for the lifetime of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn every_response_entry_reaches_admitted_rejected_and_exact_oracles() {
		for case in ResponseCase::ALL {
			assert!(check(case, &bytes(&fixture(case))).result.is_ok(), "{case:?}");
			assert!(check(case, &bytes(&positional(case))).result.is_ok(), "{case:?} sequence");
			let rejected = check(case, b"not JSON\xff").result.is_err();
			assert_eq!(rejected, case != ResponseCase::DiscardSuccess);
		}
	}
	#[test]
	fn append_ledger_covers_equal_tokens_array_indices_audit_and_optional_fields() {
		for detail in [false, true] {
			for flags in [0, 1, 2, 4, 8, 16, 24, 32, 63, 64, 127] {
				for text in ["same", "e\u{301}\"\\😀", "a/b", ""] {
					check_ledger(detail, text, flags);
				}
			}
		}
	}
	#[test]
	fn reporting_uses_legacy_tags_defaults_duplicate_and_envelope_depth() {
		for recipe in 0..25 {
			check(ResponseCase::ListRepos, &schema_recipe(recipe));
		}
	}
	#[test]
	fn exact_byte_path_and_escaped_caps_are_not_transport_tests() {
		for recipe in [0, 1, 2, 4, 5, 6, 8, 9, 10, 16, 17] {
			let raw = boundary_recipe(recipe);
			assert!(raw.len() <= CONSTRUCTED_LIMIT);
			check(ResponseCase::ListFindings, &raw);
		}
	}
	#[test]
	fn raw_scalar_optional_duplicate_and_trailing_matrix() {
		for case in ResponseCase::ALL {
			let raw = bytes(&fixture(case));
			let mut trailing = raw.clone();
			trailing.push(b'x');
			check(case, &trailing);
			check(case, b"{}");
			check(case, b"[]");
		}
		for raw in
			[b"[2]".as_slice(), b"[2,null]", b"[2,[1,\"\"]]", br#"{"protocol_version":65536}"#]
		{
			check(ResponseCase::ShowApp, raw);
		}
		for raw in [
			br#"{"protocol_version":2,"repo_id":9223372036854775808}"#.as_slice(),
			br#"{"protocol_version":2,"repo_id":1,"repo_id":2}"#,
		] {
			check(ResponseCase::RegisterRepo, raw);
		}
		for key in [
			"file_path",
			"line_start",
			"line_end",
			"cwe",
			"patch_unified",
			"poc_unified",
			"approved_by_cn",
			"rejected_by_cn",
		] {
			for mode in 0..3 {
				let mut value = fixture(ResponseCase::GetFinding);
				if mode == 0 {
					value.as_object_mut().unwrap_or_else(|| unreachable!()).remove(key);
				} else {
					value[key] = if mode == 1 { Value::Null } else { "".into() };
				}
				check(ResponseCase::GetFinding, &bytes(&value));
			}
		}
	}
}
