//! Fixed Server schema/output/field/carry oracles. Bytes 0/1 select operation
//! and raw (0), ledger (1), field-boundary (2), or body-boundary (3) recipe.
pub(crate) mod oracle;

use loupe_worker::client::fuzz_support::{self, HostCase, ResponseCase};
use loupe_worker::host_outcome::CheckoutFailure;
use serde_json::{json, Value};

use crate::utils::test_logger;

fn case(value: u8) -> ResponseCase {
	match value {
		0 => ResponseCase::Lease,
		1 => ResponseCase::Heartbeat,
		2 => ResponseCase::Search,
		3 => ResponseCase::Detail,
		4 => ResponseCase::ErrorDiagnostic,
		_ => ResponseCase::Submission,
	}
}

pub(crate) fn closed_error(error: &str) -> bool {
	if [
		"fixture exceeds response byte limit",
		"invalid JSON syntax",
		"expected string",
		"unknown lease kind",
		"unknown payload kind",
		"unknown response kind",
	]
	.contains(&error)
	{
		return true;
	}
	for prefix in
		["invalid JSON syntax at line ", "invalid response data at line ", "missing field at line "]
	{
		if let Some(tail) = error.strip_prefix(prefix) {
			return tail.split_once(" column ").is_some_and(|(line, column)| {
				line.parse::<usize>().is_ok() && column.parse::<usize>().is_ok()
			});
		}
	}
	let Some((field, rest)) = error.split_once(": ") else { return false };
	if ![
		"finding_title",
		"finding_description",
		"poc_unified",
		"patch_unified",
		"scanner_id",
		"cwe",
		"finding_fingerprint",
		"repo_path",
		"revision",
		"audit_name",
		"repo_host",
		"repo_owner",
		"repo_name",
		"clone_url",
		"git_branch",
		"scanner_extension",
		"scanner_exclude_pattern",
		"credential",
		"job_capability",
		"kind",
	]
	.contains(&field)
	{
		return false;
	}
	let (rule, point) =
		rest.split_once(" (U+").map_or((rest, None), |(rule, point)| (rule, Some(point)));
	["Character", "Chars", "Bytes", "Whitespace", "Empty", "Path", "JsonSyntax"].contains(&rule)
		&& point.is_none_or(|point| {
			point.strip_suffix(')').is_some_and(|digits| u32::from_str_radix(digits, 16).is_ok())
		})
}

fn host(choice: u8) -> HostCase {
	use CheckoutFailure::*;
	if choice.is_multiple_of(14) {
		HostCase::Scanner
	} else if choice % 14 == 1 {
		HostCase::Missing
	} else {
		HostCase::Checkout(
			[
				CreateWorktree,
				OpenRepository,
				LocateBranch,
				LocateHead,
				ResolveReference,
				ParseRevision,
				LocateRevision,
				ResolveRevision,
				ResolveTree,
				AttachWorktree,
				CheckoutTree,
				Task,
			][usize::from(choice % 14 - 2)],
		)
	}
}

fn check_host(choice: u8, expected: &Value, actual: &fuzz_support::Observation) {
	let revision =
		expected.get("payload").and_then(|v| v.get("reviewed_sha")).and_then(Value::as_str);
	assert_eq!(
		actual.reviewed_revision.as_deref(),
		revision,
		"closed revision fact differs from original lease"
	);
	let Some(submission) = &actual.host_submission else { panic!("lease host observation absent") };
	let (reason, terminal) = if choice.is_multiple_of(14) {
		("scanner does not verify".to_owned(), false)
	} else if choice % 14 == 1 || revision.is_none() {
		("original reviewed revision is unavailable: verify lease did not carry the original reviewed revision".to_owned(),true)
	} else {
		let revision = revision.unwrap_or_default();
		let operation = [
			"creating temp worktree dir",
			"opening bare repository",
			"locating branch reference",
			"locating HEAD reference",
			"resolving ref to commit",
			"parsing reviewed revision",
			"locating reviewed revision",
			"resolving reviewed revision to commit",
			"resolving commit tree",
			"attaching temporary worktree to bare repo",
			"checking out tree into worktree dir",
			"checkout task failed",
		][usize::from(choice % 14 - 2)];
		let detail = if matches!(choice % 14, 7 | 8) {
			format!("{operation} {revision}")
		} else {
			operation.to_owned()
		};
		(format!("original reviewed revision {revision} is unavailable after refreshing and re-cloning the repository: {detail}"),true)
	};
	let mut expected =
		json!({"protocol_version":2,"verdict":{"outcome":"inconclusive","reason":reason}});
	if terminal {
		expected["verdict"]["terminal"] = json!(true);
	}
	assert_eq!(
		serde_json::to_value(submission).unwrap_or_else(|error| panic!("host output: {error}")),
		expected
	);
}

pub fn do_test(data: &[u8]) {
	exercise(data);
}
fn exercise(data: &[u8]) {
	if data.len() > 65_536 {
		return;
	}
	let kind = data.first().copied().unwrap_or(0) % 6;
	let mode = data.get(1).copied().unwrap_or(0) % 4;
	let payload = data.get(2..).unwrap_or_default();
	let choice = payload.first().copied().unwrap_or(0);
	let (body, ledger) = match mode {
		1 => {
			let ledger = ledger_fixture(kind, choice);
			(ledger.bytes, Some(ledger.agent))
		},
		2 => (boundary_fixture(kind, choice), None),
		3 => (vec![b' '; oracle::BODY_LIMIT + usize::from(choice % 2)], None),
		_ => (payload.to_vec(), None),
	};
	let expected = oracle::client(kind, &body);
	let observe = || fuzz_support::observe(case(kind), &body, host(choice));
	let actual = if kind == 0 {
		oracle::lease_logs(&body, expected.is_some(), observe).0
	} else {
		oracle::without_logs(observe)
	};
	assert_eq!(
		actual.result.is_ok(),
		expected.is_some(),
		"client schema/field admission differs, kind={kind}, mode={mode}"
	);
	match (&actual.result, expected) {
		(Ok(value), Some(expected)) => {
			assert_eq!(value, &expected, "client admitted output changed");
			if let Some(mut ledger) = ledger {
				let mut spans = actual.agent_spans.clone();
				spans.sort_by_key(|range| (range.start, range.end));
				ledger.sort_by_key(|range| (range.start, range.end));
				assert_eq!(spans, ledger, "actual Agent carry selected a different original token");
			}
			for span in &actual.agent_spans {
				let token = body
					.get(span.clone())
					.unwrap_or_else(|| panic!("carry escaped original owner"));
				assert!(
					serde_json::from_slice::<String>(token).is_ok(),
					"Agent carry did not select a whole original string token"
				);
			}
			if kind == 0 {
				check_host(choice, &expected, &actual);
			}
		},
		(Err(error), None) => {
			assert!(closed_error(error), "validator error is not closed metadata: {error}")
		},
		_ => unreachable!(),
	}
}

fn finding_fields(ledger: &mut oracle::Ledger, detail: bool, token: &str) {
	for (index, key) in ["scanner_id", "title", "fingerprint", "file_path"].into_iter().enumerate()
	{
		if index > 0 {
			ledger.raw(",");
		}
		ledger.raw(&format!("\"{key}\":"));
		ledger.token(token, true);
	}
	if detail {
		for key in ["description", "cwe", "poc_unified", "patch_unified"] {
			ledger.raw(&format!(",\"{key}\":"));
			ledger.token(token, true);
		}
	}
	ledger.raw(",\"severity\":\"high\",\"line_start\":1,\"line_end\":1");
}
fn summary(ledger: &mut oracle::Ledger, token: &str) {
	ledger.raw("{\"id\":1,\"repo_id\":2,\"job_id\":3,");
	finding_fields(ledger, false, token);
	ledger.raw(",\"state\":\"validating\",\"verification_required\":true,\"created_at\":1,\"approved_by_cn\":");
	ledger.token(token, false);
	ledger.raw("}");
}
fn ledger_fixture(kind: u8, choice: u8) -> oracle::Ledger {
	let token = if choice.is_multiple_of(2) { r#""same""# } else { r#""\u0073ame""# };
	let mut ledger = oracle::Ledger::default();
	match kind {
		0 => {
			ledger.raw(r#"{"kind":"lease","protocol_version":1,"job_id":1,"job_capability":"fixture","repo_id":2,"repo":{"host":"same","owner":"same","repo":"same","clone_url":"same"},"lease_expires_at":1,"scanner_config":{},"payload":{"kind":"verify","finding_id":3,"reviewed_sha":" same ","finding":{"#);
			finding_fields(&mut ledger, true, token);
			ledger.raw("}}}");
		},
		1 => ledger.raw(r#"{"protocol_version":1,"lease_expires_at":-1}"#),
		2 => {
			ledger.raw(r#"{"protocol_version":1,"findings":["#);
			summary(&mut ledger, token);
			ledger.raw(",");
			summary(&mut ledger, token);
			ledger.raw("]}");
		},
		3 => {
			ledger.raw(r#"{"protocol_version":1,"id":1,"repo_id":2,"job_id":3,"ignored":"same","#);
			finding_fields(&mut ledger, true, token);
			ledger.raw(",\"state\":\"validating\",\"verification_required\":true,\"created_at\":1,\"approved_by_cn\":");
			ledger.token(token, false);
			ledger.raw("}");
		},
		4 => ledger.raw(" diagnostic \n"),
		_ => ledger.raw("arbitrary non-JSON success"),
	}
	ledger
}
fn boundary_fixture(kind: u8, choice: u8) -> Vec<u8> {
	let length = [0, 1, oracle::TEXT_LIMIT - 1, oracle::TEXT_LIMIT, oracle::TEXT_LIMIT + 1]
		[usize::from(choice % 5)];
	let unit = if choice & 8 == 0 { "a" } else { "\\u0061" };
	let text = unit.repeat(length);
	if kind == 0 && choice & 16 != 0 {
		let unit = if choice & 8 == 0 { " " } else { "\\u0020" };
		let fixture = String::from_utf8(ledger_fixture(0, 0).bytes).unwrap_or_default();
		return fixture
			.replace(
				"\"reviewed_sha\":\" same \"",
				&format!("\"reviewed_sha\":\"{}\"", unit.repeat(length)),
			)
			.into_bytes();
	}
	match kind {
		0=>format!(r#"{{"kind":"lease","protocol_version":1,"job_id":1,"job_capability":"fixture","repo_id":1,"repo":{{"host":"h","owner":"o","repo":"r","clone_url":"c"}},"lease_expires_at":1,"scanner_config":{{"include_extensions":["{text}"]}},"payload":{{"kind":"scan"}}}}"#).into_bytes(),
		2|3=>{
			let mut ledger=ledger_fixture(kind,0);
			// Fixture-only construction replaces the first recorded token before
			// any production decode. Carry-ledger mode itself never uses replacement.
			let range=ledger.agent.remove(0);
			ledger.bytes.splice(range,format!("\"{text}\"").bytes()); ledger.bytes
		},
		_=>ledger_fixture(kind,0).bytes,
	}
}

pub fn worker_client_ingress_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}
/// # Safety
/// The caller supplies `len` readable bytes at `data` for this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_client_ingress_run(data: *const u8, len: usize) {
	// SAFETY: the C runner guarantees the readable input buffer.
	do_test(unsafe { std::slice::from_raw_parts(data, len) });
}

#[cfg(test)]
mod tests {
	fn log_case(record: &str, admitted: bool, warnings: usize) {
		let expected = super::oracle::client(0, record.as_bytes());
		assert_eq!(expected.is_some(), admitted, "independent fixture admission changed");
		let (actual, count) = super::oracle::lease_logs(record.as_bytes(), admitted, || {
			super::fuzz_support::observe(super::case(0), record.as_bytes(), super::host(0))
		});
		assert_eq!(actual.result.is_ok(), admitted);
		assert_eq!(count, warnings, "fixed warning moved across the expected validation stage");
	}

	#[test]
	fn scanner_warning_is_fixed_and_only_emitted_at_its_projection_stage() {
		let fixture = String::from_utf8(super::ledger_fixture(0, 0).bytes)
			.unwrap_or_else(|e| panic!("lease fixture: {e}"));
		for (scanner, admitted, warnings) in [
			("null", true, 0),
			("{}", true, 0),
			(r#"[1,2,3,["rs"],["target"]]"#, true, 0),
			("7", true, 1),
			(r#"{"include_extensions":3}"#, true, 1),
			(r#"{"include_extensions":[7,"rs"]}"#, true, 1),
			(r#"{"include_extensions":["bad\u0001"]}"#, false, 0),
			(r#"{"include_extensions":3,"include_extensions":["rs"]}"#, true, 0),
			(r#"{"include_extensions":["rs"],"include_extensions":3}"#, true, 1),
		] {
			let record =
				fixture.replace("\"scanner_config\":{}", &format!("\"scanner_config\":{scanner}"));
			log_case(&record, admitted, warnings);
		}
		let malformed = fixture.replace("\"scanner_config\":{}", "\"scanner_config\":7");
		// Repo policy is checked before scanner projection, PAT and the complete
		// envelope's ignored content afterward. All three refusals remain fixed.
		log_case(&malformed.replace(r#""host":"same""#, r#""host":"bad\u0001""#), false, 0);
		log_case(&malformed.replace("\"payload\":", "\"github_pat\":7,\"payload\":"), false, 1);
		log_case(&malformed.replace("\"payload\":", "\"ignored\":1e400,\"payload\":"), false, 1);
		for kind in 1..6 {
			super::do_test(&[kind, 1, 0]);
		}
	}

	#[test]
	fn every_response_schema_has_admitted_rejected_and_exact_output_controls() {
		for kind in 0..6 {
			for choice in 0..14 {
				super::do_test(&[kind, 1, choice]);
			}
			super::do_test(&[kind, 0, b'!']);
		}
	}
	#[test]
	fn response_text_boundaries_preserve_escaped_decoded_limits() {
		for kind in [0, 2, 3] {
			for choice in [2, 3, 4, 10, 11, 12] {
				super::do_test(&[kind, 2, choice]);
			}
		}
		for choice in [18, 19, 28, 29] {
			super::do_test(&[0, 2, choice]);
		}
	}
	#[test]
	fn original_lease_scanner_shapes_last_wins_and_depth_are_preserved() {
		let fixture = String::from_utf8(super::ledger_fixture(0, 0).bytes).unwrap_or_default();
		for scanner in [
			r#"null"#,
			r#"7"#,
			r#"{"include_extensions":["rs"],"include_extensions":["go","go"],"forward":{"nested":"exact"}}"#,
			r#"{"include_extensions":["bad\u0001"],"include_extensions":["rs"]}"#,
			r#"{"include_extensions":["rs"],"include_extensions":["bad\u0001"]}"#,
			r#"{"include_extensions":[7,"bad\u0001"]}"#,
			r#"{"include_extensions":3,"exclude_path_substrings":[" unchanged "]}"#,
			r#"[1,2,3,["rs"],["unchanged"],null]"#,
			r#"{"include_\u0065xtensions":["rs"]}"#,
		] {
			let record =
				fixture.replace("\"scanner_config\":{}", &format!("\"scanner_config\":{scanner}"));
			let mut input = vec![0, 0];
			input.extend_from_slice(record.as_bytes());
			super::do_test(&input);
		}
		for depth in 123..130 {
			let scanner = format!("{}1{}", "[".repeat(depth), "]".repeat(depth));
			let record =
				fixture.replace("\"scanner_config\":{}", &format!("\"scanner_config\":{scanner}"));
			let mut input = vec![0, 0];
			input.extend_from_slice(record.as_bytes());
			super::do_test(&input);
		}
	}
}
