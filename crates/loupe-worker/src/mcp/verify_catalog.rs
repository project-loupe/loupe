//! The verify tool catalog (Loupe MCP protocol 2), SPEC-02 §3. The
//! `finalize_verification` schema holds the members of the server's tagged
//! terminal payload without the fields the host supplies. Model tool APIs
//! may refuse a combinator at a schema's root, so descriptions state what
//! each verdict requires, and the host enforces it.

use serde_json::{json, Value};

use super::evidence_schema::{argument, finding_evidence, revalidation, CONTINUATIONS};
use super::survey_catalog::{defs, text};
use super::{add_tool_protocol_version, VERIFY_LOUPE_MCP_PROTOCOL_VERSION};

/// The continuation class whose blocker the host supplies.
pub(super) const HOST_BLOCKED: &str = "awaiting_proof_infrastructure";

fn described(mut schema: Value, description: String) -> Value {
	schema["description"] = json!(description);
	schema
}

/// A member that only `verdict` takes.
fn member(verdict: &str, schema: Value) -> Value {
	described(schema, format!("With verdict {verdict} only."))
}

pub(super) fn tools() -> Value {
	let finalize = json!({
		"type":"object",
		"required":["verdict"],
		"additionalProperties":false,
		"$defs": defs(),
		"properties":{
			"verdict":described(
				json!({"enum":["verified","rejected","inconclusive"]}),
				format!(
					"verified requires e2e_rationale and evidence. rejected requires \
					 counterargument. inconclusive requires continuation, and blocker unless \
					 continuation is {HOST_BLOCKED}; partial_evidence and retry_explanation are \
					 optional with it. A member of another verdict is refused; revalidation and \
					 notes are optional with every verdict."
				),
			),
			"e2e_rationale":member("verified", text(2000)),
			"evidence":member("verified", finding_evidence()),
			"counterargument":member("rejected", argument(8000)),
			"continuation":member("inconclusive", json!({"enum":CONTINUATIONS})),
			"blocker":described(
				text(2000),
				format!(
					"What blocks a verdict. With verdict inconclusive only: required with every \
					 continuation except {HOST_BLOCKED}, and refused with {HOST_BLOCKED}."
				),
			),
			"partial_evidence":member("inconclusive", argument(4000)),
			"retry_explanation":member("inconclusive", text(1000)),
			"revalidation":revalidation("finding"),
			"notes":text(4000)},
	});
	let mut tools = vec![
		json!({
			"name": "get_job_limits",
			"description": "Read this verification's deadlines and campaign capacity.",
			"inputSchema": {"type":"object","properties":{}},
		}),
		json!({
			"name": "finalize_verification",
			"description":
				"End the verification with exactly one verdict; always reachable until it succeeds. \
				 verified: your own L2 evidence, and an e2e_rationale for why end-to-end proof does \
				 not apply. rejected: a source-backed counterargument. inconclusive: unfinished or \
				 blocked, with a continuation class (source_analysis_remaining when out of time) and \
				 the blocker; with awaiting_proof_infrastructure leave `blocker` out and put the \
				 argument in partial_evidence. Every path must exist in the pinned checkout exactly \
				 as written. After success, end the session.",
			"inputSchema": finalize,
		}),
	];
	add_tool_protocol_version(&mut tools, VERIFY_LOUPE_MCP_PROTOCOL_VERSION);
	Value::Array(tools)
}
