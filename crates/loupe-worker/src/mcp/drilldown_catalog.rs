//! The drilldown tool catalog (Loupe MCP protocol 2), SPEC-02 §3. The
//! `finalize_drilldown` schema is the server's tagged terminal payload
//! without its `version` fields, which the host supplies.

use serde_json::{json, Value};

use super::evidence_schema::{argument, finding_evidence, revalidation, CONTINUATIONS};
use super::survey_catalog::{defs, source_refs, text, KEY_PATTERN};
use super::{add_tool_protocol_version, DRILLDOWN_LOUPE_MCP_PROTOCOL_VERSION};

fn promotion() -> Value {
	json!({"type":"object",
		"required":["severity","title","description","identity_family","identity_anchor",
			"evidence"],
		"additionalProperties":false,
		"properties":{
			"severity":{"enum":["info","low","medium","high","critical"]},
			"title":text(100),
			"description":text(16384),
			"identity_family":{"type":"string","pattern":"^[a-z0-9-]{3,64}$"},
			"identity_anchor":text(300),
			"identity_instance_key":text(200),
			"cwe":{"type":"string","pattern":"^CWE-[1-9][0-9]{0,5}$"},
			"evidence":finding_evidence()}})
}

/// One `oneOf` branch per disposition: the members it requires. Members of
/// other dispositions are refused by the host.
fn variant(disposition: &str, required: &[&str]) -> Value {
	let mut all = vec!["disposition"];
	all.extend_from_slice(required);
	json!({"required":all,"properties":{"disposition":{"const":disposition}}})
}

pub(super) fn tools() -> Value {
	let mut tools = vec![json!({
		"name": "get_job_limits",
		"description":
			"Read this drilldown's deadlines and remaining sibling-lead and candidate-query \
			 capacity.",
		"inputSchema": {"type":"object","properties":{}},
	})];
	tools.push(json!({
		"name": "query_same_project_lead_candidates",
		"description":
			"Search same-project leads and findings whose identity family or anchor contains the \
			 query text. A duplicate finalize may name only a lead or finding returned here. \
			 Repeating an earlier query replays its earlier answer. Open until the job is \
			 finalized.",
		"inputSchema": {"type":"object","required":["query"],
			"properties":{"query":text(500),
				"limit":{"type":"integer","minimum":1,"maximum":20}}},
	}));
	tools.push(json!({
		"name": "submit_sibling_lead",
		"description":
			"Checkpoint one further suspicion found while investigating, as soon as you find it; \
			 it becomes its own lead with its own drilldown. Never report it as a side finding. \
			 Reusing a key with identical content replays it. Closed after submit_by.",
		"inputSchema": {"type":"object",
			"required":["client_lead_key","identity_family","identity_anchor","hypothesis",
				"source_refs","next_proof_step","counterevidence","proof_gaps"],
			"$defs": defs(),
			"properties":{
				"client_lead_key":{"type":"string","pattern":KEY_PATTERN},
				"identity_family":{"type":"string","pattern":"^[a-z0-9-]{3,64}$"},
				"identity_anchor":text(300),
				"identity_instance_key":text(200),
				"hypothesis":text(4000),
				"invariant_or_boundary":text(1000),
				"source_refs":source_refs(1, 16),
				"next_proof_step":text(1000),
				"counterevidence":text(2000),
				"proof_gaps":text(2000),
				"priority_proposal":{"type":"object",
					"required":["impact","access","reachability","boundary_refs","rationale"],
					"additionalProperties":false,
					"properties":{
						"impact":{"enum":["low","medium","high","critical"]},
						"access":{"enum":["privileged","local","remote"]},
						"reachability":{"enum":["plausible","traced"]},
						"boundary_refs":source_refs(0, 16),
						"rationale":text(1000)}},
				"duplicate_of_lead_id":{"type":"integer","minimum":1},
				"duplicate_rationale":text(1000)}},
	}));
	let finalize = json!({
		"type":"object",
		"required":["disposition"],
		"$defs": defs(),
		"properties":{
			"disposition":{"enum":["promote","reject","duplicate","hardening","defer"]},
			"promotion":promotion(),
			"counterargument":argument(8000),
			"target":{"type":"object","required":["kind","id"],"additionalProperties":false,
				"properties":{"kind":{"enum":["lead","finding"]},
					"id":{"type":"integer","minimum":1}}},
			"rationale":text(1000),
			"explanation":argument(8000),
			"reason":text(1000),
			"continuation":{"enum":CONTINUATIONS},
			"retry_explanation":text(1000),
			"revalidation":revalidation("lead")},
		"oneOf":[
			variant("promote", &["promotion"]),
			variant("reject", &["counterargument"]),
			variant("duplicate", &["target", "rationale"]),
			variant("hardening", &["explanation"]),
			variant("defer", &["reason", "continuation"]),
		],
	});
	tools.push(json!({
		"name": "finalize_drilldown",
		"description":
			"End the drilldown with exactly one disposition; always reachable until it succeeds. \
			 promote: an L2 argument with material locations. reject: a source-backed \
			 counterargument. duplicate: a lead or finding returned by your own candidate \
			 queries. hardening: defensive improvement, not a vulnerability. defer: unfinished, \
			 with a continuation class (source_analysis_remaining when out of time). Every \
			 path must exist in the pinned checkout exactly as written. After success, end the \
			 session.",
		"inputSchema": finalize,
	}));
	add_tool_protocol_version(&mut tools, DRILLDOWN_LOUPE_MCP_PROTOCOL_VERSION);
	Value::Array(tools)
}
