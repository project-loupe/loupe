//! The drilldown tool catalog (Loupe MCP protocol 2), SPEC-02 §3. The
//! `finalize_drilldown` schema is the server's tagged terminal payload
//! without its `version` fields, which the host supplies. Model tool APIs
//! may refuse a combinator at a schema's root, so descriptions state what
//! each disposition requires, and the host enforces it.

use serde_json::{json, Value};

use super::evidence_schema::{argument, described, finding_evidence, revalidation, CONTINUATIONS};
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

/// A member that only `disposition` takes.
fn member(disposition: &str, schema: Value) -> Value {
	described(schema, format!("With disposition {disposition} only."))
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
		"additionalProperties":false,
		"$defs": defs(),
		"properties":{
			"disposition":described(
				json!({"enum":["promote","reject","duplicate","hardening","defer"]}),
				"promote requires promotion. reject requires counterargument. duplicate requires \
				 target and rationale. hardening requires explanation. defer requires reason and \
				 continuation; retry_explanation is optional with it. A member of another \
				 disposition is refused; revalidation is optional with every disposition."
					.to_owned(),
			),
			"promotion":member("promote", promotion()),
			"counterargument":member("reject", argument(8000)),
			"target":member(
				"duplicate",
				json!({"type":"object","required":["kind","id"],"additionalProperties":false,
					"properties":{"kind":{"enum":["lead","finding"]},
						"id":{"type":"integer","minimum":1}}}),
			),
			"rationale":member("duplicate", text(1000)),
			"explanation":member("hardening", argument(8000)),
			"reason":member("defer", text(1000)),
			"continuation":member("defer", json!({"enum":CONTINUATIONS})),
			"retry_explanation":member("defer", text(1000)),
			"revalidation":revalidation("lead")},
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
