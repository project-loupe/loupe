//! Schemas of the evidence objects and closed values the drilldown and
//! verification terminal payloads share.

use serde_json::{json, Value};

use super::survey_catalog::{source_refs, text};

pub(super) const CONTINUATIONS: [&str; 4] = [
	"source_analysis_remaining",
	"awaiting_proof_infrastructure",
	"external_dependency",
	"requires_successor",
];

/// `subject` is what the job re-inspects, as its description names it.
pub(super) fn revalidation(subject: &str) -> Value {
	json!({"type":"object","required":["current_source_refs","rationale"],
		"additionalProperties":false,
		"description": format!(
			"Only when finalizing was refused as revalidation required: the {subject} \
			 re-inspected on this checkout."
		),
		"properties":{"current_source_refs":source_refs(1, 16),"rationale":text(2000)}})
}

pub(super) fn argument(max: usize) -> Value {
	json!({"type":"object","required":["argument","source_refs"],"additionalProperties":false,
		"properties":{"argument":text(max),"source_refs":source_refs(1, 16)}})
}

pub(super) fn finding_evidence() -> Value {
	json!({"type":"object",
		"required":["l2_argument","material_locations","counterevidence",
			"assumptions_gaps","confidence"],
		"additionalProperties":false,
		"properties":{
			"l2_argument":{"type":"object",
				"required":["attacker_source","control","sink","reachable_path",
					"trust_boundary"],
				"additionalProperties":false,
				"properties":{
					"attacker_source":text(2000),
					"control":text(2000),
					"sink":text(2000),
					"reachable_path":text(4000),
					"trust_boundary":text(1000)}},
			"material_locations":{"type":"array","minItems":1,"maxItems":16,
				"items":{"type":"object","required":["role","file"],
					"additionalProperties":false,
					"properties":{
						"role":{"enum":["root_control","entry_point","wrapper","sink",
							"implementation"]},
						"file":{"type":"string","maxLength":512},
						"symbol":text(200),
						"line_start":{"type":"integer","minimum":1},
						"line_end":{"type":"integer","minimum":1}}}},
			"counterevidence":text(4000),
			"assumptions_gaps":text(4000),
			"confidence":{"enum":["low","medium","high"]}}})
}
