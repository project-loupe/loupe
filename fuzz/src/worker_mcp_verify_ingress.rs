//! The actual verify-catalog MCP decoder over original Sandbox records: Agent
//! carries stay inside the record, rejected arguments never echo their
//! content, every field the host supplies is refused as an argument and holds
//! its fixed value in the request, and admitted arguments always serialize as
//! a valid phase request.
use loupe_worker::mcp::fuzz_support::observe_verify_record;
use serde_json::Value;

use crate::phase_ingress_common as common;
use crate::utils::test_logger;

const FOREIGN: [&str; 4] = [
	"query_same_project_lead_candidates",
	"submit_sibling_lead",
	"finalize_drilldown",
	"submit_verdict",
];
const TOOLS: [&str; 6] =
	["finalize_verification", "get_job_limits", FOREIGN[0], FOREIGN[1], FOREIGN[2], FOREIGN[3]];
const FIELDS: [&str; 14] = [
	"verdict",
	"e2e_rationale",
	"evidence",
	"counterargument",
	"continuation",
	"blocker",
	"partial_evidence",
	"retry_explanation",
	"revalidation",
	"notes",
	"version",
	"established_rung",
	"e2e_applicability",
	"protocol_version",
];
const VERDICTS: [&str; 3] = ["verified", "rejected", "inconclusive"];
const CONTINUATIONS: [&str; 4] = [
	"awaiting_proof_infrastructure",
	"source_analysis_remaining",
	"external_dependency",
	"requires_successor",
];
const HOST_FIELDS: [&str; 3] = ["version", "established_rung", "e2e_applicability"];
const BLOCKER: &str = "awaiting proof infrastructure";

/// A field value of the given shape, its strings carrying `text`.
fn value(text: &str, shape: u8) -> String {
	let pick = usize::from(shape / 10);
	match shape % 10 {
		0 => format!("{text:?}"),
		1 => format!("{{\"argument\":{text:?},\"source_refs\":[{{\"path\":\"a.rs\"}}]}}"),
		2 => format!("{{\"current_source_refs\":[{{\"path\":\"a.rs\"}}],\"rationale\":{text:?}}}"),
		3 => format!("{:?}", VERDICTS[pick % VERDICTS.len()]),
		4 => format!("{:?}", CONTINUATIONS[pick % CONTINUATIONS.len()]),
		5 => evidence(text, shape / 10),
		6 => format!("{:?}", ["L2", "not_applicable", BLOCKER][pick % 3]),
		7 => "2".to_owned(),
		8 => "1".to_owned(),
		_ => "null".to_owned(),
	}
}

/// An evidence object, complete except for one variation chosen by `pick`.
fn evidence(text: &str, pick: u8) -> String {
	let extra = match pick % 3 {
		0 => "",
		1 => ",\"version\":1",
		_ => ",\"owner\":1",
	};
	format!(
		r#"{{"l2_argument":{{"attacker_source":{text:?},"control":"c","sink":"k","reachable_path":"p","trust_boundary":"b"}},"material_locations":[{{"role":"sink","file":"a.rs","line_start":{},"line_end":2}}],"counterevidence":"c","assumptions_gaps":"g","confidence":"low"{extra}}}"#,
		pick % 2 + 1
	)
}

/// An admitted finalize holds the host's values, and none of them came from
/// the agent's arguments.
fn check_host_values(record: &[u8], request: &[u8]) {
	let request: Value =
		serde_json::from_slice(request).unwrap_or_else(|_| panic!("request is not JSON"));
	assert_eq!(request["protocol_version"], 3);
	let payload = &request["payload"];
	let record: Value =
		serde_json::from_slice(record).unwrap_or_else(|_| panic!("decoded record is not JSON"));
	let Some(arguments) = record["params"]["arguments"].as_object() else {
		panic!("finalize without arguments")
	};
	for field in HOST_FIELDS {
		assert!(!arguments.contains_key(field), "the agent supplied `{field}`");
	}
	assert_eq!(payload["version"], 1);
	match payload["verdict"].as_str() {
		Some("verified") => {
			assert_eq!(payload["established_rung"], "L2");
			assert_eq!(payload["e2e_applicability"], "not_applicable");
			assert_eq!(payload["evidence"]["version"], 1);
			assert!(arguments["evidence"].get("version").is_none());
		},
		Some("rejected") => {},
		Some("inconclusive") => {
			if payload["continuation"] == "awaiting_proof_infrastructure" {
				assert_eq!(payload["blocker"], BLOCKER);
				assert!(!arguments.contains_key("blocker"), "the agent supplied the blocker");
			} else {
				assert!(arguments.contains_key("blocker"), "the host supplied a free blocker");
			}
		},
		_ => panic!("unknown verdict"),
	}
}

/// Checks one record; whether it decoded as an admitted tool call.
fn check(record: &[u8]) -> bool {
	common::check(record, &FOREIGN, observe_verify_record);
	let Some((tool, Ok(request))) = observe_verify_record(record).decoded else { return false };
	if tool == "finalize_verification" {
		check_host_values(record, &request);
	}
	true
}

pub fn do_test(data: &[u8]) {
	if let Some(record) = common::record(data, &TOOLS, &FIELDS, value) {
		check(&record);
	}
}

pub fn worker_mcp_verify_ingress_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}
/// # Safety
/// The caller supplies `len` readable bytes at `data` for this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_mcp_verify_ingress_run(data: *const u8, len: usize) {
	// SAFETY: the C runner guarantees the readable input buffer.
	do_test(unsafe { std::slice::from_raw_parts(data, len) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn structured_records_cover_every_tool() {
		for tool in 0..6u8 {
			for field in 0..14u8 {
				for shape in 0..40u8 {
					for verdict in [3, 13, 23] {
						do_test(&[1, tool, 0, 0, verdict, field, 1, shape]);
					}
				}
			}
		}
	}

	fn call(arguments: &str) -> Vec<u8> {
		format!(
			r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"finalize_verification","arguments":{arguments}}}}}"#
		)
		.into_bytes()
	}

	#[test]
	fn every_verdict_is_admitted_with_host_values() {
		let verified = format!(
			r#"{{"verdict":"verified","e2e_rationale":"r","evidence":{}}}"#,
			evidence("t", 0)
		);
		for arguments in [
			verified.as_str(),
			r#"{"verdict":"rejected","counterargument":{"argument":"a","source_refs":[{"path":"a.rs"}]}}"#,
			r#"{"verdict":"inconclusive","continuation":"awaiting_proof_infrastructure"}"#,
			r#"{"verdict":"inconclusive","continuation":"external_dependency","blocker":"b"}"#,
		] {
			assert!(check(&call(arguments)), "{arguments}");
		}
	}

	#[test]
	fn host_values_and_malformed_arguments_are_refused() {
		for arguments in [
			r#"{"verdict":"inconclusive","continuation":"awaiting_proof_infrastructure","blocker":"awaiting proof infrastructure"}"#,
			r#"{"verdict":"inconclusive","continuation":"zq9sentinel-long","blocker":"b"}"#,
			r#"{"verdict":"rejected","version":1,"counterargument":{"argument":"a","source_refs":[{"path":"a.rs"}]}}"#,
			r#"{"verdict":"zq9sentinel-long-verdict"}"#,
		] {
			assert!(!check(&call(arguments)), "{arguments}");
		}
	}
}
