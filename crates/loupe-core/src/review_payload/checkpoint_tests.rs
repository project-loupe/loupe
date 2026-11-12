use loupe_provenance::Agent;
use serde_json::{json, Value};

use super::*;

#[test]
fn checkpoint_traits_require_only_source_and_debug_redacts_content() {
	fn traits<T: Clone + Eq + serde::Serialize + std::fmt::Debug>() {}
	fn check<S: loupe_provenance::Source>() {
		traits::<LeadEvidenceV1<S>>();
		traits::<UnitResultPayloadV1<S>>();
		traits::<PriorityProposal<S>>();
		traits::<DuplicateLeadHint<S>>();
	}
	check::<loupe_provenance::Agent>();
	check::<loupe_provenance::Worker>();
	let payload = parse_lead(&lead().to_string()).unwrap();
	assert!(!format!("{payload:?}").contains(payload.hypothesis.expose()));
}
use crate::marked;
fn parse_lead(raw: &str) -> Result<LeadEvidenceV1<Agent>, Error> {
	marked::fixture(raw, |raw, mark| LeadEvidenceV1::from_json(mark, raw))
}
fn parse_result(raw: &str) -> Result<UnitResultPayloadV1<Agent>, Error> {
	marked::fixture(raw, |raw, mark| UnitResultPayloadV1::from_json(mark, raw))
}
fn text<P: crate::text::TextPolicy>(
	raw: &str,
) -> Result<BoundedText<P, Agent>, crate::text::Error> {
	marked::fixture(raw, |raw, mark| BoundedText::new(mark, raw))
}
fn path(raw: &str) -> Result<RepoPath<Agent>, crate::text::Error> {
	marked::fixture(raw, |raw, mark| RepoPath::new(mark, raw))
}

fn lead() -> Value {
	json!({
		"format":"loupe.lead_evidence", "version":1,
		"identity_family":"auth-bypass", "identity_anchor":"token boundary",
		"review_unit_id":31, "assignment_epoch":0,
		"hypothesis":"untrusted token reaches a privileged sink",
		"invariant_or_boundary":"authentication boundary",
		"source_refs":[{"path":"cafe\u{301}.rs"}],
		"next_proof_step":"trace the wrapper", "counterevidence":"wrapper checks exist",
		"proof_gaps":"attacker control is not traced",
		"priority_proposal":{"impact":"high","access":"remote","reachability":"traced",
			"boundary_refs":[{"path":"cafe\u{301}.rs"}],"rationale":"reachable boundary"},
		"duplicate_hint":{"lead_id":9,"rationale":"same boundary"}
	})
}
fn result() -> Value {
	json!({
		"format":"loupe.unit_result", "version":1,"review_unit_id":31,"assignment_epoch":0,
		"disposition":"no_lead_found","inspected_refs":[{"path":"cafe\u{301}.rs"}],
		"created_lead_ids":[],"counterevidence":"checked the guard","proof_gaps":"no gaps"
	})
}

#[test]
fn checkpoint_payload_paths_remain_exact_and_digests_distinguish_them() {
	let lead = parse_lead(&lead().to_string()).unwrap();
	let raw = String::from_utf8(lead.canonical_bytes().unwrap()).unwrap();
	assert_eq!(parse_lead(&raw).unwrap(), lead);
	assert_eq!(lead.source_refs[0].path.expose(), "cafe\u{301}.rs");
	assert_eq!(
		lead.priority_proposal.as_ref().unwrap().boundary_refs[0].path.expose(),
		"cafe\u{301}.rs"
	);
	let normalized = parse_lead(&raw.replace("cafe\u{301}.rs", "café.rs")).unwrap();
	assert_ne!(lead.digest().unwrap(), normalized.digest().unwrap());
	let result = parse_result(&result().to_string()).unwrap();
	assert_eq!(result.inspected_refs[0].path.expose(), "cafe\u{301}.rs");
	assert_eq!(
		parse_result(&String::from_utf8(result.canonical_bytes().unwrap()).unwrap()).unwrap(),
		result
	);
}

#[test]
fn checkpoint_payloads_reject_unknown_duplicate_fields_and_future_versions() {
	{
		let baseline = lead();
		let parse = parse_lead;
		let mut value = baseline.clone();
		value["unexpected"] = json!(true);
		assert!(parse(&value.to_string()).is_err());
		value = baseline.clone();
		value["version"] = json!(2);
		assert!(parse(&value.to_string()).is_err());
		value = baseline.clone();
		value["priority_proposal"]["unexpected"] = json!(true);
		assert!(parse(&value.to_string()).is_err());
		let raw = baseline.to_string();
		assert!(parse(&format!("{{\"version\":1,{}", &raw[1..])).is_err());
	}
	let mut value = result();
	value["unexpected"] = json!(true);
	assert!(parse_result(&value.to_string()).is_err());
	value = result();
	value["version"] = json!(2);
	assert!(parse_result(&value.to_string()).is_err());
	let raw = result().to_string();
	assert!(parse_result(&format!("{{\"version\":1,{}", &raw[1..])).is_err());
}

#[test]
fn lead_checkpoint_bounds_validate_both_deserialization_and_serialization() {
	for (field, bad) in [
		("review_unit_id", json!(0)),
		("assignment_epoch", json!(-1)),
		("source_refs", json!([])),
		("source_refs", json!(vec![json!({"path":"a.rs"}); 17])),
		("duplicate_hint", json!({"lead_id":0,"rationale":"same"})),
	] {
		let mut value = lead();
		value[field] = bad;
		assert!(parse_lead(&value.to_string()).is_err(), "{field}");
	}
	for field in ["review_unit_id", "assignment_epoch"] {
		let mut value = lead();
		value.as_object_mut().unwrap().remove(field);
		assert!(parse_lead(&value.to_string()).is_err(), "paired {field}");
	}
	let mut value = lead();
	value["priority_proposal"]["boundary_refs"] = json!(vec![json!({"path":"a.rs"}); 17]);
	assert!(parse_lead(&value.to_string()).is_err());
	let mut typed = parse_lead(&lead().to_string()).unwrap();
	typed.source_refs.clear();
	assert!(serde_json::to_string(&typed).is_err());
	assert!(typed.canonical_bytes().is_err());
}

#[test]
fn unit_result_disposition_rules_are_bidirectional() {
	for disposition in ["no_lead_found", "not_applicable", "lead_created", "needs_follow_up"] {
		let mut value = result();
		value["disposition"] = json!(disposition);
		match disposition {
			"lead_created" => value["created_lead_ids"] = json!([1, 2]),
			"needs_follow_up" => {
				value["follow_up"] = json!("trace next");
				value["continuation"] = json!("source_analysis_remaining");
			},
			_ => {},
		}
		let parsed = parse_result(&value.to_string()).unwrap();
		assert!(serde_json::to_string(&parsed).is_ok());
		if disposition == "lead_created" {
			value["created_lead_ids"] = json!([]);
		} else {
			value["created_lead_ids"] = json!([1]);
		}
		assert!(parse_result(&value.to_string()).is_err());
	}
	for (field, bad) in [
		("review_unit_id", json!(0)),
		("assignment_epoch", json!(-1)),
		("inspected_refs", json!([])),
		("inspected_refs", json!(vec![json!({"path":"a.rs"}); 65])),
		("follow_up", json!("later")),
		("continuation", json!("requires_successor")),
	] {
		let mut value = result();
		value[field] = bad;
		assert!(parse_result(&value.to_string()).is_err(), "{field}");
	}
	for ids in [json!([1, 1]), json!([0]), json!((1..=17).collect::<Vec<_>>())] {
		let mut value = result();
		value["disposition"] = json!("lead_created");
		value["created_lead_ids"] = ids;
		assert!(parse_result(&value.to_string()).is_err());
	}
	for omitted in ["follow_up", "continuation"] {
		let mut value = result();
		value["disposition"] = json!("needs_follow_up");
		value["follow_up"] = json!("trace next");
		value["continuation"] = json!("source_analysis_remaining");
		value.as_object_mut().unwrap().remove(omitted);
		assert!(parse_result(&value.to_string()).is_err());
	}
}

#[test]
fn checkpoint_payloads_enforce_aggregate_budget() {
	let reference = SourceRef {
		path: path(&"\"".repeat(512)).unwrap(),
		symbol: Some(text(&"\"".repeat(256)).unwrap()),
	};
	let mut result = parse_result(&result().to_string()).unwrap();
	result.inspected_refs = vec![reference.clone(); 64];
	assert!(matches!(result.canonical_bytes(), Err(Error::Bytes { max_bytes: 65536, .. })));
	assert!(serde_json::to_string(&result).is_err());
	result.inspected_refs.truncate(32);
	assert!(
		result.canonical_bytes().is_ok(),
		"same individually valid fields fit below the aggregate cap"
	);
	let mut lead = parse_lead(&lead().to_string()).unwrap();
	lead.source_refs = vec![reference.clone(); 16];
	lead.priority_proposal.as_mut().unwrap().boundary_refs = vec![reference; 16];
	lead.hypothesis = text(&"\"".repeat(4000)).unwrap();
	lead.counterevidence = text(&"\"".repeat(2000)).unwrap();
	lead.proof_gaps = text(&"\"".repeat(2000)).unwrap();
	lead.next_proof_step = text(&"\"".repeat(1000)).unwrap();
	assert!(matches!(lead.canonical_bytes(), Err(Error::Bytes { max_bytes: 65536, .. })));
	assert!(serde_json::to_string(&lead).is_err());
	lead.source_refs.truncate(1);
	assert!(lead.canonical_bytes().is_ok());
}

#[test]
fn unit_result_decoder_accepts_its_distinct_sixty_four_reference_budget() {
	for count in [17, 64] {
		let mut value = result();
		value["inspected_refs"] = json!(vec![json!({"path":"exact.rs"}); count]);
		let parsed = parse_result(&value.to_string())
			.expect("unit results accept up to 64 inspected references");
		assert_eq!(parsed.inspected_refs.len(), count);
	}
}

#[test]
fn closed_values_decode_only_from_json_strings() {
	assert!(parse_lead(&lead().to_string()).is_ok());
	for (field, word) in [("impact", "high"), ("access", "remote"), ("reachability", "traced")] {
		let mut map_form = lead();
		map_form["priority_proposal"][field] = json!({ word: null });
		assert!(parse_lead(&map_form.to_string()).is_err(), "{field} accepted a map encoding");
	}
	for (field, word) in [("format", "loupe.unit_result"), ("disposition", "no_lead_found")] {
		let mut map_form = result();
		map_form[field] = json!({ word: null });
		assert!(parse_result(&map_form.to_string()).is_err(), "{field} accepted a map encoding");
	}
	let survey = |reason: Value| {
		let raw = json!({"version":1,"terminal_reason":reason}).to_string();
		marked::fixture(&raw, |raw, mark| SurveyTerminalV1::<Agent>::from_json(mark, raw))
	};
	assert!(survey(json!("partial")).is_ok());
	assert!(survey(json!({"partial":null})).is_err(), "terminal_reason accepted a map encoding");
	let duplicate = json!({"disposition":"duplicate","version":1,
		"target":{"kind":"lead","id":4},"rationale":"same sink"});
	let drilldown = |raw: &str| {
		marked::fixture(raw, |raw, mark| DrilldownTerminalV1::<Agent>::from_json(mark, raw))
	};
	assert!(drilldown(&duplicate.to_string()).is_ok(), "object-valued fields stay objects");
}

#[test]
fn shared_severity_decodes_only_from_a_json_string_in_evidence() {
	let promotion = |severity: Value| {
		let mut value = json!({"version":1,"severity":"high","title":"t","description":"d",
			"identity_family":"auth-bypass","identity_anchor":"token boundary",
			"evidence":{"version":1,"l2_argument":{"attacker_source":"a","control":"c","sink":"s",
				"reachable_path":"p","trust_boundary":"b"},
				"material_locations":[{"role":"sink","file":"src/lib.rs"}],
				"counterevidence":"n","assumptions_gaps":"n","confidence":"low"}});
		value["severity"] = severity;
		let raw = value.to_string();
		marked::fixture(&raw, |raw, mark| PromotionV1::<Agent>::from_json(mark, raw))
	};
	assert!(promotion(json!("high")).is_ok());
	assert!(promotion(json!({"high":null})).is_err(), "severity accepted a map encoding");
}
