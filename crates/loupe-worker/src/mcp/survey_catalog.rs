//! The survey tool catalog (Loupe MCP protocol 2), SPEC-02 §3.

use serde_json::{json, Value};

use super::{add_tool_protocol_version, SURVEY_LOUPE_MCP_PROTOCOL_VERSION};
use crate::review::session::SurveySession;

pub(super) const KEY_PATTERN: &str = "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$";

pub(super) fn source_refs(min: usize, max: usize) -> Value {
	json!({"type":"array","minItems":min,"maxItems":max,"items":{"$ref":"#/$defs/source_ref"}})
}

pub(super) fn defs() -> Value {
	json!({"source_ref":{"type":"object","required":["path"],"additionalProperties":false,
		"properties":{"path":{"type":"string","maxLength":512},
		"symbol":{"type":"string","maxLength":256}}}})
}

pub(super) fn text(max: usize) -> Value {
	json!({"type":"string","maxLength":max})
}

fn band() -> Value {
	json!({"enum":["urgent","high","normal","background"]})
}

fn ids(max: usize) -> Value {
	json!({"type":"array","maxItems":max,"items":{"type":"integer","minimum":1}})
}

pub(super) fn tools(survey: &SurveySession) -> Value {
	let mut tools = vec![json!({
		"name": "get_job_limits",
		"description": "Read this survey's deadlines and remaining review-unit and lead capacity.",
		"inputSchema": {"type":"object","properties":{}},
	})];
	if survey.lists_publish_profile() {
		tools.push(json!({
			"name": "publish_profile",
			"description":
				"Publish the repository profile once, before any review unit, lead, result, \
				 disposition or candidate query. It cannot be replaced afterwards.",
			"inputSchema": {"type":"object","required":["profile"],
				"properties":{"profile":{"type":"object",
					"description":"Bounded JSON profile: at most 32 KiB, depth 16, 4096 nodes."}}},
		}));
	}
	tools.push(json!({
		"name": "propose_review_unit",
		"description":
			"Checkpoint one review unit: a bounded scope for later review. Reusing a key with \
			 identical content replays it; different content under the same key is rejected.",
		"inputSchema": {"type":"object",
			"required":["client_review_unit_key","title","objective","priority_band","source_refs"],
			"$defs": defs(),
			"properties":{
				"client_review_unit_key":{"type":"string","pattern":KEY_PATTERN},
				"title":text(200),
				"objective":text(2000),
				"priority_band":band(),
				"priority_rationale":text(1000),
				"source_refs":source_refs(1, 32),
				"depends_on_review_unit_ids":ids(8),
				"closure_criteria":text(1000),
				"semantic_context":text(4000)}},
	}));
	tools.push(json!({
		"name": "submit_lead",
		"description":
			"Checkpoint one L1 lead with its evidence, counterevidence and proof gaps. The host \
			 pairs review_unit_id with its assignment epoch.",
		"inputSchema": {"type":"object",
			"required":["client_lead_key","identity_family","identity_anchor","hypothesis",
				"source_refs","next_proof_step","counterevidence","proof_gaps"],
			"$defs": defs(),
			"properties":{
				"client_lead_key":{"type":"string","pattern":KEY_PATTERN},
				"identity_family":{"type":"string","pattern":"^[a-z0-9-]{3,64}$"},
				"identity_anchor":text(300),
				"identity_instance_key":text(200),
				"review_unit_id":{"type":"integer","minimum":1},
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
	tools.push(json!({
		"name": "submit_review_unit_result",
		"description":
			"Checkpoint the result of reviewing one unit. needs_follow_up requires follow_up and \
			 continuation; lead_created requires created_lead_ids.",
		"inputSchema": {"type":"object",
			"required":["client_result_key","review_unit_id","disposition","inspected_refs",
				"counterevidence","proof_gaps"],
			"$defs": defs(),
			"properties":{
				"client_result_key":{"type":"string","pattern":KEY_PATTERN},
				"review_unit_id":{"type":"integer","minimum":1},
				"disposition":{"enum":["lead_created","no_lead_found","not_applicable","needs_follow_up"]},
				"inspected_refs":source_refs(1, 64),
				"created_lead_ids":ids(16),
				"counterevidence":text(2000),
				"proof_gaps":text(2000),
				"follow_up":text(2000),
				"notes":text(4000),
				"continuation":{"enum":["source_analysis_remaining","awaiting_proof_infrastructure",
					"external_dependency","requires_successor"]}}},
	}));
	tools.push(json!({
		"name": "submit_inventory_disposition",
		"description":
			"Checkpoint one inventory entry's disposition. mapped requires mapped_review_unit_ids; \
			 context and excluded require a reason. The host supplies the entry revision and \
			 unit epochs; a revision conflict is reported, not retried.",
		"inputSchema": {"type":"object",
			"required":["client_inventory_disposition_key","path","disposition"],
			"properties":{
				"client_inventory_disposition_key":{"type":"string","pattern":KEY_PATTERN},
				"path":{"type":"string","maxLength":512},
				"disposition":{"enum":["mapped","context","excluded","unresolved"]},
				"reason":text(500),
				"mapped_review_unit_ids":ids(8)}},
	}));
	tools.push(json!({
		"name": "query_same_project_lead_candidates",
		"description": "Search same-project leads and findings for duplicates of a lead you consider.",
		"inputSchema": {"type":"object","required":["query"],
			"properties":{"query":text(500),
				"limit":{"type":"integer","minimum":1,"maximum":20}}},
	}));
	tools.push(json!({
		"name": "finalize_survey",
		"description":
			"End the survey. Always reachable; call it when done, when capacity is exhausted or \
			 after the soft stop. Coverage is derived by the server.",
		"inputSchema": {"type":"object","required":["terminal_reason"],
			"properties":{
				"terminal_reason":{"enum":["completed","partial","deferred"]},
				"continuation":text(4000),
				"security_model_notes":text(8000)}},
	}));
	add_tool_protocol_version(&mut tools, SURVEY_LOUPE_MCP_PROTOCOL_VERSION);
	Value::Array(tools)
}
