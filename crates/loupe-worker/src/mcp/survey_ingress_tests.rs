use serde_json::json;

use super::ingress::fuzz_support::{arguments_fixture, survey_arguments_fixture};
use super::ingress::Arguments;

fn err(name: &str, args: serde_json::Value) -> String {
	match survey_arguments_fixture(name, &args) {
		Ok(_) => panic!("{name} accepted invalid arguments"),
		Err(error) => format!("{error:#}"),
	}
}

fn source_ref() -> serde_json::Value {
	json!({"path": "src/lib.rs", "symbol": "parse"})
}

fn unit() -> serde_json::Value {
	json!({
		"client_review_unit_key": "unit-1",
		"title": "Parser core",
		"objective": "Review the parser.",
		"priority_band": "high",
		"source_refs": [source_ref()],
		"depends_on_review_unit_ids": [3],
	})
}

fn lead() -> serde_json::Value {
	json!({
		"client_lead_key": "lead-1",
		"identity_family": "memory-safety",
		"identity_anchor": "parse",
		"review_unit_id": 4,
		"hypothesis": "Length is unchecked.",
		"source_refs": [source_ref()],
		"next_proof_step": "Write a test.",
		"counterevidence": "None found.",
		"proof_gaps": "Reachability.",
		"duplicate_of_lead_id": 9,
		"duplicate_rationale": "Same sink.",
	})
}

fn result() -> serde_json::Value {
	json!({
		"client_result_key": "result-1",
		"review_unit_id": 4,
		"disposition": "no_lead_found",
		"inspected_refs": [source_ref()],
		"counterevidence": "Checked bounds.",
		"proof_gaps": "None.",
	})
}

#[test]
fn every_survey_tool_decodes_to_agent_values_with_exact_text() {
	assert!(matches!(
		survey_arguments_fixture("get_job_limits", &json!({})),
		Ok(Arguments::JobLimits)
	));

	let Arguments::PublishProfile(profile) =
		survey_arguments_fixture("publish_profile", &json!({"profile": {"languages": ["rust"]}}))
			.unwrap()
	else {
		panic!("profile")
	};
	assert_eq!(profile.expose(), r#"{"languages":["rust"]}"#);

	let Arguments::ProposeUnit(unit) =
		survey_arguments_fixture("propose_review_unit", &unit()).unwrap()
	else {
		panic!("unit")
	};
	assert_eq!(unit.client_review_unit_key.expose(), "unit-1");
	assert_eq!(unit.title.expose(), "Parser core");
	assert_eq!(unit.source_refs.as_slice()[0].path.expose(), "src/lib.rs");
	assert_eq!(i64::from(unit.depends_on_review_unit_ids.as_slice()[0]), 3);

	let Arguments::Lead(lead) = survey_arguments_fixture("submit_lead", &lead()).unwrap() else {
		panic!("lead")
	};
	assert_eq!(lead.key.expose(), "lead-1");
	assert_eq!(lead.review_unit_id.map(i64::from), Some(4));
	// The host pairs the unit with its epoch at dispatch.
	assert_eq!(lead.evidence.review_unit_id, None);
	assert_eq!(lead.evidence.assignment_epoch, None);
	assert_eq!(lead.evidence.duplicate_hint.as_ref().map(|hint| hint.lead_id), Some(9));

	let Arguments::UnitResult(result) =
		survey_arguments_fixture("submit_review_unit_result", &result()).unwrap()
	else {
		panic!("result")
	};
	assert_eq!(result.key.expose(), "result-1");
	assert_eq!(result.result.review_unit_id, 4);
	assert_eq!(result.result.counterevidence.expose(), "Checked bounds.");

	let Arguments::Disposition(disposition) = survey_arguments_fixture(
		"submit_inventory_disposition",
		&json!({"client_inventory_disposition_key": "d-1", "path": "src/lib.rs",
			"disposition": "mapped", "mapped_review_unit_ids": [4, 5]}),
	)
	.unwrap() else {
		panic!("disposition")
	};
	assert_eq!(disposition.path.expose(), "src/lib.rs");
	assert_eq!(disposition.mapped_review_unit_ids.len(), 2);

	let Arguments::Candidates(query) = survey_arguments_fixture(
		"query_same_project_lead_candidates",
		&json!({"query": "parse length"}),
	)
	.unwrap() else {
		panic!("candidates")
	};
	assert_eq!((query.query.expose(), query.limit), ("parse length", 10));

	let Arguments::Finalize(terminal) = survey_arguments_fixture(
		"finalize_survey",
		&json!({"terminal_reason": "partial", "continuation": "More parsers.", "protocol_version": 2}),
	)
	.unwrap() else {
		panic!("finalize")
	};
	assert_eq!(terminal.continuation.as_ref().map(|c| c.expose()), Some("More parsers."));
}

#[test]
fn over_long_fields_are_rejected_on_the_host_with_field_and_rule() {
	let mut long = unit();
	long["title"] = json!("t".repeat(201));
	let error = err("propose_review_unit", long);
	assert!(error.starts_with("title: "), "{error}");

	let mut long = lead();
	long["hypothesis"] = json!("h".repeat(4001));
	let error = err("submit_lead", long);
	assert!(error.starts_with("argument: "), "{error}");

	let error = err("query_same_project_lead_candidates", json!({"query": "q".repeat(501)}));
	assert!(error.starts_with("query: "), "{error}");

	let error = err(
		"submit_inventory_disposition",
		json!({"client_inventory_disposition_key": "d-1", "path": "a",
			"disposition": "excluded", "reason": "r".repeat(501)}),
	);
	assert!(error.starts_with("reason: "), "{error}");

	let error = err("propose_review_unit", {
		let mut bad = unit();
		bad["client_review_unit_key"] = json!("-leading-dash");
		bad
	});
	assert!(error.starts_with("client_key: "), "{error}");

	let profile = json!({"profile": {"blob": "x".repeat(33 * 1024)}});
	let error = err("publish_profile", profile);
	assert!(error.starts_with("generated_profile: "), "{error}");
}

#[test]
fn survey_schemas_reject_shapes_the_server_would_reject() {
	let error = err("propose_review_unit", {
		let mut bad = unit();
		bad["source_refs"] = json!([]);
		bad
	});
	assert!(error.contains("`source_refs`"), "{error}");
	assert!(err("propose_review_unit", {
		let mut bad = unit();
		bad["priority_band"] = json!("whenever");
		bad
	})
	.contains("`priority_band`"));
	assert_eq!(
		err("propose_review_unit", {
			let mut bad = unit();
			bad["extra"] = json!(1);
			bad
		}),
		"unknown argument for this tool"
	);
	assert!(err("submit_lead", {
		let mut bad = lead();
		bad.as_object_mut().unwrap().remove("duplicate_rationale");
		bad
	})
	.contains("together"));
	assert!(err(
		"submit_inventory_disposition",
		json!({"client_inventory_disposition_key": "d-1", "path": "a", "disposition": "mapped"}),
	)
	.contains("`mapped_review_unit_ids`"));
	assert!(err(
		"submit_inventory_disposition",
		json!({"client_inventory_disposition_key": "d-1", "path": "a", "disposition": "excluded"}),
	)
	.contains("`reason`"));
	assert!(err("submit_review_unit_result", {
		let mut bad = result();
		bad["disposition"] = json!("needs_follow_up");
		bad
	})
	.starts_with("follow_up: "));
	assert!(err("query_same_project_lead_candidates", json!({"query": "q", "limit": 21}))
		.contains("`limit`"));
	assert!(err("publish_profile", json!({"profile": "text"})).contains("`profile`"));
	assert!(
		err("finalize_survey", json!({"terminal_reason": "done"})).contains("`terminal_reason`")
	);
	assert!(err("get_job_limits", json!({"protocol_version": 1})).contains("worker supports 2"));
}

#[test]
fn each_catalog_decodes_only_its_own_tools() {
	for name in [
		"get_job_limits",
		"publish_profile",
		"propose_review_unit",
		"submit_lead",
		"submit_review_unit_result",
		"submit_inventory_disposition",
		"query_same_project_lead_candidates",
		"finalize_survey",
	] {
		let error = arguments_fixture(name, &json!({})).err().unwrap();
		assert!(error.is::<super::ingress::UnknownTool>(), "{name} decoded in a legacy session");
	}
	for name in ["query_prior_findings", "get_finding_by_id", "submit_finding", "submit_verdict"] {
		let error = survey_arguments_fixture(name, &json!({})).err().unwrap();
		assert!(error.is::<super::ingress::UnknownTool>(), "{name} decoded in a survey session");
	}
}
