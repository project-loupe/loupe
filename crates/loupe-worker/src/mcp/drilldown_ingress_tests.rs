use serde_json::{json, Value};

use super::ingress::fuzz_support::{drilldown_arguments_fixture, survey_arguments_fixture};
use super::ingress::Arguments;

fn err(name: &str, args: Value) -> String {
	match drilldown_arguments_fixture(name, &args) {
		Ok(_) => panic!("{name} accepted invalid arguments"),
		Err(error) => format!("{error:#}"),
	}
}

fn source_ref() -> Value {
	json!({"path": "src/lib.rs", "symbol": "parse"})
}

fn sibling() -> Value {
	json!({
		"client_lead_key": "sibling-1",
		"identity_family": "memory-safety",
		"identity_anchor": "parse header",
		"hypothesis": "Header length is unchecked.",
		"source_refs": [source_ref()],
		"next_proof_step": "Trace the header length.",
		"counterevidence": "None found.",
		"proof_gaps": "Reachability.",
	})
}

fn evidence() -> Value {
	json!({
		"l2_argument": {
			"attacker_source": "Remote request body",
			"control": "Length field",
			"sink": "Vec::with_capacity",
			"reachable_path": "handler -> parse -> allocate",
			"trust_boundary": "Network to process memory",
		},
		"material_locations": [
			{"role": "sink", "file": "src/lib.rs", "symbol": "parse", "line_start": 3, "line_end": 9},
			{"role": "entry_point", "file": "src/main.rs"},
		],
		"counterevidence": "No dominating bound check.",
		"assumptions_gaps": "Assumes default limits.",
		"confidence": "medium",
	})
}

fn promotion() -> Value {
	json!({
		"severity": "high",
		"title": "Unbounded allocation",
		"description": "A request length reaches an allocation.",
		"identity_family": "memory-safety",
		"identity_anchor": "parse allocation",
		"identity_instance_key": "header",
		"cwe": "CWE-789",
		"evidence": evidence(),
	})
}

fn revalidation() -> Value {
	json!({"current_source_refs": [source_ref()], "rationale": "Re-read on this checkout."})
}

fn finalize(args: Value) -> Value {
	let Arguments::FinalizeDrilldown(terminal) =
		drilldown_arguments_fixture("finalize_drilldown", &args).unwrap()
	else {
		panic!("finalize")
	};
	serde_json::from_slice(&terminal.canonical_bytes().unwrap()).unwrap()
}

#[test]
fn shared_tools_decode_in_the_drilldown_catalog() {
	assert!(matches!(
		drilldown_arguments_fixture("get_job_limits", &json!({})),
		Ok(Arguments::JobLimits)
	));
	let Arguments::Candidates(query) = drilldown_arguments_fixture(
		"query_same_project_lead_candidates",
		&json!({"query": "parse allocation", "limit": 5}),
	)
	.unwrap() else {
		panic!("candidates")
	};
	assert_eq!((query.query.expose(), query.limit), ("parse allocation", 5));
}

#[test]
fn a_sibling_lead_decodes_like_a_lead_without_a_unit() {
	let mut args = sibling();
	args["duplicate_of_lead_id"] = json!(9);
	args["duplicate_rationale"] = json!("Same sink.");
	let Arguments::SiblingLead(lead) =
		drilldown_arguments_fixture("submit_sibling_lead", &args).unwrap()
	else {
		panic!("sibling")
	};
	assert_eq!(lead.key.expose(), "sibling-1");
	assert!(lead.review_unit_id.is_none());
	assert_eq!(lead.evidence.identity_anchor.expose(), "parse header");
	assert_eq!(lead.evidence.source_refs[0].symbol.as_ref().unwrap().expose(), "parse");
	assert_eq!(lead.evidence.duplicate_hint.as_ref().unwrap().lead_id, 9);
	assert!(lead.evidence.review_unit_id.is_none() && lead.evidence.assignment_epoch.is_none());

	let mut with_unit = sibling();
	with_unit["review_unit_id"] = json!(4);
	assert_eq!(err("submit_sibling_lead", with_unit), "unknown argument for this tool");
	let mut epoch = sibling();
	epoch["assignment_epoch"] = json!(1);
	assert_eq!(err("submit_sibling_lead", epoch), "unknown argument for this tool");
}

#[test]
fn a_promotion_gets_host_versions_at_every_level() {
	let value = finalize(json!({
		"disposition": "promote",
		"promotion": promotion(),
		"revalidation": revalidation(),
	}));
	let mut expected_promotion = promotion();
	expected_promotion["version"] = json!(1);
	expected_promotion["evidence"]["version"] = json!(1);
	assert_eq!(
		value,
		json!({
			"version": 1,
			"disposition": "promote",
			"promotion": expected_promotion,
			"revalidation": revalidation(),
		})
	);
}

#[test]
fn every_other_disposition_decodes_with_exact_text() {
	let counterargument = json!({"argument": "The bound is checked.\nAll callers enforce it.", "source_refs": [source_ref()]});
	assert_eq!(
		finalize(json!({"disposition": "reject", "counterargument": counterargument})),
		json!({"version": 1, "disposition": "reject", "counterargument": counterargument})
	);
	let explanation = json!({"argument": "Defensive only.", "source_refs": [{"path": "a.rs"}]});
	assert_eq!(
		finalize(json!({"disposition": "hardening", "explanation": explanation})),
		json!({"version": 1, "disposition": "hardening", "explanation":
			{"argument": "Defensive only.", "source_refs": [{"path": "a.rs", "symbol": null}]}})
	);
	assert_eq!(
		finalize(json!({"disposition": "duplicate", "target": {"kind": "finding", "id": 12},
			"rationale": "Same root cause."})),
		json!({"version": 1, "disposition": "duplicate", "target": {"kind": "finding", "id": 12},
			"rationale": "Same root cause."})
	);
	assert_eq!(
		finalize(json!({"disposition": "defer", "reason": "Out of time.",
			"continuation": "source_analysis_remaining", "retry_explanation": "Trace callers.",
			"revalidation": revalidation()})),
		json!({"version": 1, "disposition": "defer", "reason": "Out of time.",
			"continuation": "source_analysis_remaining", "retry_explanation": "Trace callers.",
			"revalidation": revalidation()})
	);
}

#[test]
fn host_owned_and_unknown_fields_are_refused_at_every_level() {
	const UNKNOWN: &str = "unknown argument for this tool";
	let promote = |promotion: Value| json!({"disposition": "promote", "promotion": promotion});
	let mut versioned = promotion();
	versioned["version"] = json!(1);
	let mut evidence_versioned = promotion();
	evidence_versioned["evidence"]["version"] = json!(1);
	let mut l2_extra = promotion();
	l2_extra["evidence"]["l2_argument"]["owner"] = json!("x");
	let mut location_extra = promotion();
	location_extra["evidence"]["material_locations"][0]["owner"] = json!("x");
	for args in [
		json!({"disposition": "reject", "version": 1,
			"counterargument": {"argument": "a", "source_refs": [source_ref()]}}),
		json!({"disposition": "reject",
			"counterargument": {"argument": "a", "source_refs": [source_ref()], "owner": 1}}),
		json!({"disposition": "reject", "reason": "wrong variant",
			"counterargument": {"argument": "a", "source_refs": [source_ref()]}}),
		json!({"disposition": "defer", "reason": "r", "continuation": "external_dependency",
			"revalidation": {"current_source_refs": [source_ref()], "rationale": "r", "x": 1}}),
		promote(versioned),
		promote(evidence_versioned),
		promote(l2_extra),
		promote(location_extra),
	] {
		assert_eq!(err("finalize_drilldown", args), UNKNOWN);
	}
}

#[test]
fn nested_objects_refuse_a_protocol_version() {
	const UNKNOWN: &str = "unknown argument for this tool";
	let promote = |promotion: Value| json!({"disposition": "promote", "promotion": promotion});
	let mut nested = promotion();
	nested["protocol_version"] = json!(2);
	let mut evidence = promotion();
	evidence["evidence"]["protocol_version"] = json!(2);
	let mut l2 = promotion();
	l2["evidence"]["l2_argument"]["protocol_version"] = json!(2);
	let mut location = promotion();
	location["evidence"]["material_locations"][0]["protocol_version"] = json!(2);
	let mut revalidated = revalidation();
	revalidated["protocol_version"] = json!(2);
	for args in [
		promote(nested),
		promote(evidence),
		promote(l2),
		promote(location),
		json!({"disposition": "reject",
			"counterargument": {"argument": "a", "source_refs": [source_ref()], "protocol_version": 2}}),
		json!({"disposition": "hardening",
			"explanation": {"argument": "a", "source_refs": [source_ref()], "protocol_version": 2}}),
		json!({"disposition": "defer", "reason": "r", "continuation": "external_dependency",
			"revalidation": revalidated}),
	] {
		assert_eq!(err("finalize_drilldown", args), UNKNOWN);
	}
	finalize(json!({"disposition": "promote", "promotion": promotion(), "protocol_version": 2}));
}

#[test]
fn malformed_finalize_arguments_name_the_field() {
	assert!(err("finalize_drilldown", json!({})).contains("`disposition`"));
	assert!(err("finalize_drilldown", json!({"disposition": "promoted"})).contains("`disposition`"));
	assert!(
		err("finalize_drilldown", json!({"disposition": "reject"})).contains("`counterargument`")
	);
	assert!(err(
		"finalize_drilldown",
		json!({"disposition": "reject", "counterargument": {"argument": "a", "source_refs": []}})
	)
	.contains("`source_refs`"));
	assert!(err(
		"finalize_drilldown",
		json!({"disposition": "duplicate", "target": {"kind": "unit", "id": 1}, "rationale": "r"})
	)
	.contains("`target`"));
	assert!(err(
		"finalize_drilldown",
		json!({"disposition": "duplicate", "target": {"kind": "lead", "id": 0}, "rationale": "r"})
	)
	.contains("`target`"));
	assert!(err(
		"finalize_drilldown",
		json!({"disposition": "defer", "reason": "r", "continuation": "later"})
	)
	.contains("`continuation`"));
	let long = "x".repeat(1001);
	assert!(err(
		"finalize_drilldown",
		json!({"disposition": "defer", "reason": long, "continuation": "external_dependency"})
	)
	.contains("defer_reason"));
	let mut lines = promotion();
	lines["evidence"]["material_locations"][0]["line_start"] = json!(10);
	assert!(!err("finalize_drilldown", json!({"disposition": "promote", "promotion": lines}))
		.is_empty());
	let mut evidence = promotion();
	evidence["evidence"] = json!("not an object");
	assert!(err("finalize_drilldown", json!({"disposition": "promote", "promotion": evidence}))
		.contains("`evidence`"));
}

#[test]
fn rejected_arguments_never_echo_agent_text() {
	let sentinel = "zq9sentinel-drilldown";
	for args in [
		json!({"disposition": "defer", "reason": sentinel.repeat(80),
			"continuation": "external_dependency"}),
		json!({"disposition": "reject",
			"counterargument": {"argument": sentinel, "source_refs": [{"path": sentinel, "x": 1}]}}),
		json!({"disposition": sentinel}),
	] {
		assert!(!err("finalize_drilldown", args).contains("zq9sentinel"));
	}
}

#[test]
fn catalogs_do_not_share_phase_specific_tools() {
	for name in ["submit_lead", "finalize_survey", "publish_profile", "submit_finding"] {
		assert_eq!(err(name, json!({})), "unknown tool", "{name}");
	}
	for name in ["submit_sibling_lead", "finalize_drilldown"] {
		let Err(error) = survey_arguments_fixture(name, &json!({})) else {
			panic!("{name} decoded in the survey catalog")
		};
		assert_eq!(format!("{error:#}"), "unknown tool", "{name}");
	}
}
