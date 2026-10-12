//! Actual bounded framer and original Sandbox decoder, with independent
//! record/schema/policy/output oracles and append-time Agent token ledgers.
pub(crate) mod oracle;
use std::sync::OnceLock;

use loupe_worker::mcp::fuzz_support::{observe_records, RecordObservation};

use crate::utils::test_logger;
use crate::worker_client_ingress::oracle::{Ledger, BODY_LIMIT, TEXT_LIMIT};

fn closed_argument(error: &str) -> bool {
	if crate::worker_client_ingress::closed_error(error) {
		return true;
	}
	if [
		"record does not dispatch tool arguments",
		"unknown tool",
		"unknown severity",
		"unknown verdict; must be one of `confirmed`, `dismissed`, `inconclusive`",
		"protocol_version must be an integer",
		"`id` must be a finding reference such as LUP-1234 or a positive integer",
		"`file` must not be empty",
		"`file` must be repo-relative or under /workdir",
		"`file` must not contain `..` components",
		"`file` must name a file inside the workdir",
	]
	.contains(&error)
	{
		return true;
	}
	for field in [
		"severity",
		"title",
		"file",
		"description",
		"poc_unified",
		"patch_unified",
		"notes",
		"verdict",
		"query",
	] {
		if error == format!("`{field}` argument is required and must be a string") {
			return true;
		}
	}
	for field in ["line_start", "line_end"] {
		if error == format!("`{field}` argument is required and must be a positive integer") {
			return true;
		}
	}
	if let Some(version) = error
		.strip_prefix("unsupported Loupe MCP protocol_version ")
		.and_then(|s| s.strip_suffix("; worker supports 1"))
	{
		return version.parse::<u64>().is_ok();
	}
	if let Some((field, tail)) = error.split_once(": ") {
		return ["query", "verdict_notes", "verdict_reason", "patch_notes", "finding_id"]
			.contains(&field)
			&& crate::worker_client_ingress::closed_error(&format!("finding_title: {tail}"));
	}
	false
}

pub fn do_test(data: &[u8]) {
	crate::worker_client_ingress::oracle::without_logs(|| exercise(data));
}
fn exercise(data: &[u8]) {
	if data.len() > 65_536 {
		return;
	}
	let mode = data.first().copied().unwrap_or(0) % 4;
	let choice = data.get(1).copied().unwrap_or(0);
	let payload = data.get(2..).unwrap_or_default();
	let (body, ledger) = match mode {
		1 => {
			let ledger = ledger_fixture(choice);
			(ledger.bytes, Some(ledger.agent))
		},
		2 => (field_fixture(choice), None),
		3 => (framing_fixture(choice), None),
		_ => (payload.to_vec(), None),
	};
	let chunk = if body.len() > TEXT_LIMIT {
		if choice % 2 == 0 {
			8192
		} else {
			511
		}
	} else {
		[1, 2, 7, 8192][usize::from(choice % 4)]
	};
	static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
	let runtime = RUNTIME.get_or_init(|| {
		tokio::runtime::Builder::new_current_thread()
			.build()
			.unwrap_or_else(|error| panic!("ingress runtime: {error}"))
	});
	let actual = runtime.block_on(observe_records(&body, chunk, BODY_LIMIT));
	let mut records = actual.iter();
	let mut remaining = body.as_slice();
	let mut index = 0;
	while !remaining.is_empty() {
		let newline = remaining.iter().position(|byte| *byte == b'\n');
		let (record, rest) = match newline {
			Some(end) => (&remaining[..end], &remaining[end + 1..]),
			None => (remaining, &[][..]),
		};
		remaining = rest;
		let record =
			if newline.is_some() { record.strip_suffix(b"\r").unwrap_or(record) } else { record };
		let observed = records.next().unwrap_or_else(|| panic!("framer lost record {index}"));
		if record.len() > BODY_LIMIT {
			assert!(matches!(observed, RecordObservation::Framing));
			break;
		}
		let text = match std::str::from_utf8(record) {
			Ok(text) => text,
			Err(_) => {
				assert!(
					matches!(observed,RecordObservation::Utf8{length} if *length==record.len())
				);
				break;
			},
		};
		if text.trim().is_empty() {
			assert!(matches!(observed,RecordObservation::Blank{length} if *length==record.len()));
			continue;
		}
		match oracle::request(text) {
			Err(()) => {
				let RecordObservation::Syntax { length, error } = observed else {
					panic!("original JSON syntax/id/depth changed: {observed:?}")
				};
				assert_eq!(*length, record.len());
				assert!(
					crate::worker_client_ingress::closed_error(error),
					"record error is not fixed metadata: {error}"
				);
			},
			Ok(expected) => {
				let RecordObservation::Request { length, request, agent_spans } = observed else {
					panic!("admitted original record was rejected: {observed:?}")
				};
				assert_eq!(*length, record.len());
				assert_eq!(request.id, expected.id, "original reply id changed");
				assert_eq!(request.method, expected.method);
				assert_eq!(request.tool, expected.tool);
				assert_eq!(
					request.arguments.is_ok(),
					expected.arguments.is_ok(),
					"MCP field admission differs"
				);
				match (&request.arguments, expected.arguments) {
					(Ok(actual), Ok(expected)) => {
						assert_eq!(actual, &expected, "MCP admitted exact output changed")
					},
					(Err(error), Err(_)) => assert!(
						closed_argument(error),
						"argument error retained uncontrolled data: {error}"
					),
					_ => unreachable!(),
				}
				if index == 0
					&& let Some(ledger) = &ledger
				{
					assert_eq!(
						agent_spans, ledger,
						"Agent carry chose another original token, including equal-content tokens"
					);
				}
				for span in agent_spans {
					assert!(
						record.get(span.clone()).is_some(),
						"Agent carry escaped original record"
					);
				}
			},
		}
		index += 1;
	}
	assert!(records.next().is_none(), "framer invented a record or consumed past fatal failure");
}

fn ledger_fixture(choice: u8) -> Ledger {
	let tool = [
		"query_prior_findings",
		"get_finding_by_id",
		"submit_finding",
		"validate_poc",
		"submit_verdict",
		"submit_patch",
		"validate_patch",
		"unknown",
	][usize::from(choice % 8)];
	let mut out = Ledger::default();
	out.raw(&format!(r#"{{"jsonrpc":"unchecked","id":73,"method":"tools/call","params":{{"name":"{tool}","same":"same","arguments":{{"#));
	let token = if choice & 8 == 0 { r#""same""# } else { r#""\u0073ame""# };
	match choice % 8 {
		0 => {
			out.raw(r#""query":"#);
			out.token(token, true);
			out.raw(r#", "limit":101"#);
		},
		1 => {
			out.raw(r#""id":"#);
			out.token(r#""LUP-1""#, true);
		},
		2 => {
			out.raw(r#""severity":"high","title":"#);
			out.token(token, true);
			out.raw(r#", "file":"#);
			out.token(token, true);
			out.raw(r#", "line_start":0,"line_end":18446744073709551615,"description":"#);
			out.token(token, true);
			out.raw(r#", "poc_unified":"#);
			out.token(token, true);
			out.raw(r#", "cwe":"#);
			out.token(token, true);
		},
		3 => {
			out.raw(r#""poc_unified":"#);
			out.token(token, true);
		},
		4 => {
			out.raw(r#""verdict":"confirmed","notes":"#);
			out.token(token, true);
		},
		5 => {
			out.raw(r#""patch_unified":"#);
			out.token(token, true);
			out.raw(r#", "notes":"#);
			out.token(token, true);
		},
		6 => {
			out.raw(r#""patch_unified":"#);
			out.token(token, true);
		},
		_ => {
			out.raw(r#""ignored":"#);
			out.token(token, false);
		},
	}
	out.raw("}}}\r\n");
	out
}
fn field_fixture(choice: u8) -> Vec<u8> {
	let length = [0, 1, TEXT_LIMIT - 1, TEXT_LIMIT, TEXT_LIMIT + 1][usize::from(choice % 5)];
	let unit = if choice & 8 == 0 { "a" } else { "\\u0061" };
	let mut text = unit.repeat(length);
	if choice & 16 != 0 {
		text.push_str("\\uD800");
	}
	let later = if choice & 32 != 0 { ",\"later\":1e400" } else { "" };
	format!(r#"{{"jsonrpc":"2.0","id":73,"method":"tools/call","params":{{"name":"submit_verdict","arguments":{{"verdict":"confirmed","notes":"{text}"{later}}}}}}}"#).into_bytes()
}
fn framing_fixture(choice: u8) -> Vec<u8> {
	let length = [BODY_LIMIT - 1, BODY_LIMIT, BODY_LIMIT + 1][usize::from(choice % 3)];
	let mut body = vec![b' '; length];
	match choice % 4 {
		0 => body.push(b'\n'),
		1 => body.extend_from_slice(b"\r\n"),
		2 => {},
		_ => body.push(b'\r'),
	}
	body
}

pub fn worker_mcp_ingress_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}
/// # Safety
/// The caller supplies `len` readable bytes at `data` for this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_mcp_ingress_run(data: *const u8, len: usize) {
	// SAFETY: the C runner guarantees the readable input buffer.
	do_test(unsafe { std::slice::from_raw_parts(data, len) });
}
#[cfg(test)]
mod tests {
	#[test]
	fn all_concrete_tools_have_original_token_and_exact_output_controls() {
		for choice in 0..16 {
			super::do_test(&[1, choice]);
		}
	}
	#[test]
	fn json_syntax_and_new_policy_keep_distinct_precedence() {
		for notes in [
			r#""\uD800""#,
			r#""\uDC00""#,
			r#""\uD800\u0041""#,
			r#""\uD83D\uDE00""#,
			r#""\u0001""#,
			r#""same""#,
		] {
			for id in ["73", "null"] {
				let record = format!(
					r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"submit_verdict","arguments":{{"verdict":"confirmed","notes":{notes},"later":1e400}}}}}}"#
				);
				let mut data = vec![0, 1];
				data.extend_from_slice(record.as_bytes());
				super::do_test(&data);
			}
		}
		for choice in [3, 4, 11, 12, 44, 60] {
			super::do_test(&[2, choice]);
		}
	}
	#[test]
	fn original_id_and_params_depth_are_not_reset() {
		for depth in 123..130 {
			for field in ["id", "params"] {
				let nested = format!("{}1{}", "[".repeat(depth), "]".repeat(depth));
				let record = if field == "id" {
					format!(r#"{{"jsonrpc":"2.0","id":{nested},"method":"ping"}}"#)
				} else {
					format!(r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":{nested}}}"#)
				};
				let mut input = vec![0, 0];
				input.extend_from_slice(record.as_bytes());
				super::do_test(&input);
			}
		}
	}
	#[test]
	fn records_preserve_delimiters_utf8_and_exact_caps() {
		for body in [b"\n\r\n".as_slice(), b"\xff\n{}\n", b"\r", b" \n{}\r\n"] {
			let mut data = vec![0, 0];
			data.extend_from_slice(body);
			super::do_test(&data);
		}
		for choice in 0..12 {
			super::do_test(&[3, choice]);
		}
	}
}
