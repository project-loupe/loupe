use loupe_core::review_payload::AWAITING_PROOF_INFRASTRUCTURE;
use serde_json::{json, Value};

use super::ingress::fuzz_support::{
	arguments_fixture, drilldown_arguments_fixture, survey_arguments_fixture,
	verify_arguments_fixture,
};
use super::ingress::Arguments;

const UNKNOWN: &str = "unknown argument for this tool";

fn err(name: &str, args: Value) -> String {
	match verify_arguments_fixture(name, &args) {
		Ok(_) => panic!("{name} accepted invalid arguments: {args}"),
		Err(error) => format!("{error:#}"),
	}
}

fn finalize_err(args: Value) -> String {
	err("finalize_verification", args)
}

fn finalize(args: &Value) -> Value {
	let Arguments::FinalizeVerification(terminal) =
		verify_arguments_fixture("finalize_verification", args).unwrap()
	else {
		panic!("finalize")
	};
	serde_json::from_slice(&terminal.canonical_bytes().unwrap()).unwrap()
}

fn source_ref() -> Value {
	json!({"path": "src/lib.rs", "symbol": "parse"})
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
		],
		"counterevidence": "No dominating bound check.",
		"assumptions_gaps": "Assumes default limits.",
		"confidence": "medium",
	})
}

fn verified() -> Value {
	json!({"verdict": "verified", "e2e_rationale": "Pure library with no runtime surface.",
		"evidence": evidence()})
}

fn argument() -> Value {
	json!({"argument": "The bound is checked.\nAll callers enforce it.",
		"source_refs": [source_ref()]})
}

fn rejected() -> Value {
	json!({"verdict": "rejected", "counterargument": argument()})
}

fn inconclusive(continuation: &str) -> Value {
	let mut args = json!({"verdict": "inconclusive", "continuation": continuation});
	if continuation != "awaiting_proof_infrastructure" {
		args["blocker"] = json!("Two callers remain unread.");
	}
	args
}

fn revalidation() -> Value {
	json!({"current_source_refs": [source_ref()], "rationale": "Re-read on this checkout."})
}

const FREE_BLOCKER: [&str; 3] =
	["source_analysis_remaining", "external_dependency", "requires_successor"];

fn every_verdict() -> Vec<Value> {
	let mut all = vec![verified(), rejected(), inconclusive("awaiting_proof_infrastructure")];
	all.extend(FREE_BLOCKER.map(inconclusive));
	all
}

fn with(mut args: Value, pointer: &str, name: &str, value: Value) -> Value {
	let object = args.pointer_mut(pointer).and_then(Value::as_object_mut).unwrap();
	object.insert(name.to_owned(), value);
	args
}

fn without(mut args: Value, name: &str) -> Value {
	args.as_object_mut().unwrap().remove(name).unwrap();
	args
}

#[test]
fn the_verify_catalog_decodes_its_two_tools_only() {
	assert!(matches!(
		verify_arguments_fixture("get_job_limits", &json!({})),
		Ok(Arguments::JobLimits)
	));
	assert_eq!(err("get_job_limits", json!({"owner": 1})), UNKNOWN);
	assert!(verify_arguments_fixture("get_job_limits", &json!({"protocol_version": 2})).is_ok());
	assert!(err("get_job_limits", json!({"protocol_version": 1, "owner": 1}))
		.contains("unsupported Loupe MCP protocol_version"));
	for name in [
		"query_same_project_lead_candidates",
		"submit_sibling_lead",
		"finalize_drilldown",
		"finalize_survey",
		"submit_lead",
		"submit_verdict",
		"submit_patch",
		"validate_patch",
		"query_prior_findings",
		"get_finding_by_id",
	] {
		assert_eq!(err(name, json!({})), "unknown tool", "{name}");
	}
}

#[test]
fn finalize_verification_is_unknown_in_every_other_catalog() {
	for fixture in [arguments_fixture, survey_arguments_fixture, drilldown_arguments_fixture] {
		let Err(error) = fixture("finalize_verification", &rejected()) else {
			panic!("finalize_verification decoded outside the verify catalog")
		};
		assert_eq!(format!("{error:#}"), "unknown tool");
	}
}

#[test]
fn a_verified_verdict_gets_every_host_value() {
	let args = with(verified(), "", "notes", json!("Checked twice."));
	let args = with(args, "", "revalidation", revalidation());
	let mut expected = args.clone();
	expected["version"] = json!(1);
	expected["established_rung"] = json!("L2");
	expected["e2e_applicability"] = json!("not_applicable");
	expected["evidence"]["version"] = json!(1);
	assert_eq!(finalize(&args), expected);
}

#[test]
fn a_rejected_verdict_decodes_with_exact_text() {
	let args = with(rejected(), "", "notes", json!("No path."));
	let expected = with(args.clone(), "", "version", json!(1));
	assert_eq!(finalize(&args), expected);
}

#[test]
fn an_inconclusive_verdict_decodes_with_its_own_blocker() {
	for class in FREE_BLOCKER {
		let args = with(inconclusive(class), "", "partial_evidence", argument());
		let args = with(args, "", "retry_explanation", json!("Trace the callers."));
		let args = with(args, "", "revalidation", revalidation());
		let expected = with(args.clone(), "", "version", json!(1));
		assert_eq!(finalize(&args), expected);
		// Optional members may be absent.
		let bare = finalize(&inconclusive(class));
		assert_eq!(bare, with(inconclusive(class), "", "version", json!(1)));
		assert_eq!(
			finalize_err(without(inconclusive(class), "blocker")),
			"`blocker` argument is required"
		);
	}
}

#[test]
fn awaiting_proof_infrastructure_gets_the_canonical_blocker() {
	let args = inconclusive("awaiting_proof_infrastructure");
	let args = with(args, "", "partial_evidence", argument());
	let expected = with(args.clone(), "", "version", json!(1));
	let expected = with(expected, "", "blocker", json!(AWAITING_PROOF_INFRASTRUCTURE));
	assert_eq!(finalize(&args), expected);
	for blocker in [json!(AWAITING_PROOF_INFRASTRUCTURE), json!("mine"), Value::Null] {
		assert_eq!(finalize_err(with(args.clone(), "", "blocker", blocker)), UNKNOWN);
	}
}

#[test]
fn host_values_are_refused_in_every_verdict() {
	for args in every_verdict() {
		finalize(&args);
		for (name, value) in [
			("version", json!(1)),
			("established_rung", json!("L2")),
			("e2e_applicability", json!("not_applicable")),
		] {
			for value in [value, Value::Null] {
				assert_eq!(
					finalize_err(with(args.clone(), "", name, value)),
					UNKNOWN,
					"{name} in {args}"
				);
			}
		}
	}
	assert_eq!(finalize_err(with(verified(), "/evidence", "version", json!(1))), UNKNOWN);
}

#[test]
fn each_verdict_admits_only_its_own_members() {
	let members = [
		("e2e_rationale", json!("r")),
		("evidence", evidence()),
		("counterargument", argument()),
		("continuation", json!("requires_successor")),
		("blocker", json!("b")),
		("partial_evidence", argument()),
		("retry_explanation", json!("r")),
		("owner", json!(1)),
		("finding_id", json!(1)),
		("proof", json!({})),
	];
	for (args, own) in [
		(verified(), &["e2e_rationale", "evidence"][..]),
		(rejected(), &["counterargument"]),
		(
			inconclusive("external_dependency"),
			&["continuation", "blocker", "partial_evidence", "retry_explanation"],
		),
	] {
		for (name, value) in &members {
			if !own.contains(name) {
				assert_eq!(
					finalize_err(with(args.clone(), "", name, value.clone())),
					UNKNOWN,
					"{name} in {args}"
				);
			}
		}
	}
}

#[test]
fn nested_objects_are_closed_and_refuse_a_protocol_version() {
	let revalidated = with(rejected(), "", "revalidation", revalidation());
	let partial =
		with(inconclusive("awaiting_proof_infrastructure"), "", "partial_evidence", argument());
	for (args, pointer) in [
		(verified(), "/evidence"),
		(verified(), "/evidence/l2_argument"),
		(verified(), "/evidence/material_locations/0"),
		(rejected(), "/counterargument"),
		(revalidated, "/revalidation"),
		(partial, "/partial_evidence"),
	] {
		finalize(&args);
		for (name, value) in [("owner", json!(1)), ("protocol_version", json!(2))] {
			assert_eq!(
				finalize_err(with(args.clone(), pointer, name, value)),
				UNKNOWN,
				"{pointer}"
			);
		}
	}
	for args in every_verdict() {
		finalize(&with(args.clone(), "", "protocol_version", json!(2)));
		assert!(finalize_err(with(args, "", "protocol_version", json!(1)))
			.contains("unsupported Loupe MCP protocol_version"));
	}
}

#[test]
fn malformed_finalize_arguments_name_the_field() {
	for (args, field) in [
		(json!({}), "`verdict`"),
		(json!({"verdict": "confirmed"}), "`verdict`"),
		(without(verified(), "e2e_rationale"), "`e2e_rationale`"),
		(without(verified(), "evidence"), "`evidence`"),
		(with(verified(), "", "evidence", json!("text")), "`evidence`"),
		(without(rejected(), "counterargument"), "`counterargument`"),
		(with(rejected(), "/counterargument", "source_refs", json!([])), "`source_refs`"),
		(without(inconclusive("external_dependency"), "continuation"), "`continuation`"),
		(
			with(inconclusive("external_dependency"), "", "continuation", json!("later")),
			"`continuation`",
		),
		(with(inconclusive("external_dependency"), "", "continuation", json!(1)), "`continuation`"),
		(
			with(
				inconclusive("external_dependency"),
				"",
				"partial_evidence",
				json!({"argument": "a", "source_refs": []}),
			),
			"`source_refs`",
		),
		(with(verified(), "", "e2e_rationale", json!("x".repeat(2001))), "rationale"),
		(
			with(inconclusive("external_dependency"), "", "blocker", json!("x".repeat(2001))),
			"blocker",
		),
		(with(rejected(), "", "notes", json!("x".repeat(4001))), "notes"),
	] {
		let error = finalize_err(args);
		assert!(error.contains(field), "{field}: {error}");
	}
	let lines = with(verified(), "/evidence/material_locations/0", "line_start", json!(10));
	assert!(!finalize_err(lines).is_empty());
}

#[test]
fn rejected_arguments_never_echo_agent_text() {
	let sentinel = "zq9sentinel-verify";
	for args in [
		json!({"verdict": sentinel}),
		json!({"verdict": "inconclusive", "continuation": sentinel, "blocker": "b"}),
		with(inconclusive("external_dependency"), "", "blocker", json!(sentinel.repeat(200))),
		json!({"verdict": "rejected",
			"counterargument": {"argument": sentinel, "source_refs": [{"path": sentinel, "x": 1}]}}),
	] {
		assert!(!finalize_err(args).contains("zq9sentinel"));
	}
}
