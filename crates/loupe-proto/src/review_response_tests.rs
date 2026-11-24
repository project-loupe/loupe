use loupe_provenance::{Agent, Server, Validate, ValidateCarrying};
use serde::Serialize;
use serde_json::{json, Value};

use crate::review_api::*;
use crate::review_drilldown::DrilldownTerminalResponseDecoder;
use crate::review_evidence::{LeadCheckpointResponseDecoder, UnitResultCheckpointResponseDecoder};
use crate::review_inventory::InventoryDispositionResponseDecoder;
use crate::review_lifecycle::PhaseControlResponseDecoder;
use crate::review_terminal::SurveyTerminalResponseDecoder;
use crate::review_units::ReviewUnitResponseDecoder;
use crate::review_verification::VerificationTerminalResponseDecoder;
use crate::test_support::server_response;

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn plain<V>(decoder: V, raw: &str) -> Result<Value, ReviewResponseDecodeError>
where
	V: for<'a> Validate<&'a [u8], Server, Error = ReviewResponseDecodeError>,
	for<'a> <V as Validate<&'a [u8], Server>>::Output: Serialize,
{
	let value = server_response(raw.as_bytes()).validate(decoder)?;
	Ok(serde_json::to_value(&value).unwrap())
}
fn carried<V>(decoder: V, raw: &str) -> Result<Value, ReviewResponseDecodeError>
where
	V: for<'a> ValidateCarrying<&'a [u8], Server, Error = ReviewResponseDecodeError>,
	for<'a> <V as ValidateCarrying<&'a [u8], Server>>::Output: Serialize,
{
	let value = server_response(raw.as_bytes()).validate_carrying(decoder)?;
	Ok(serde_json::to_value(&value).unwrap())
}

/// Each valid fixture re-serializes to itself; every mutation is refused.
fn check(decode: &dyn Fn(&str) -> Result<Value, ReviewResponseDecodeError>, valid: Value) {
	let raw = valid.to_string();
	assert_eq!(decode(&raw).unwrap(), valid, "{raw}");
	let first = raw.find(':').unwrap();
	let key = &raw[2..first - 1];
	let mut invalid = vec![
		raw.replacen("{", "{\"unexpected\":0,", 1),
		raw.replacen(&format!("\"{key}\":"), &format!("\"{key}\":0,\"{key}\":"), 1),
		raw.replace("\"protocol_version\":3", "\"protocol_version\":2"),
		raw.replace(",\"protocol_version\":3", "").replace("\"protocol_version\":3,", ""),
		format!("[{raw}]"),
		raw[..raw.len() - 1].to_owned(),
	];
	if let Value::Object(map) = &valid {
		for (field, value) in map {
			let mut changed = valid.clone();
			changed.as_object_mut().unwrap().remove(field);
			invalid.push(changed.to_string());
			if let Value::String(text) = value {
				let mut changed = valid.clone();
				changed[field] = json!({ text.as_str(): null });
				invalid.push(changed.to_string());
			}
			if let Value::Object(nested) = value {
				let mut changed = valid.clone();
				changed[field] = Value::Array(nested.values().cloned().collect());
				invalid.push(changed.to_string());
			}
		}
	}
	for raw in invalid {
		let error = match decode(&raw) {
			Ok(_) => panic!("accepted malformed response {raw}"),
			Err(error) => error,
		};
		assert!(!format!("{error:?} {error}").contains("unexpected"));
	}
}

#[test]
fn metadata_responses_round_trip_and_refuse_noncanonical_forms() {
	check(
		&|raw| plain(PhaseLimitsResponseDecoder, raw),
		json!({"protocol_version":3,"soft_deadline_at":100,"submit_by":100,"hard_deadline_at":200,
			"remaining_seconds":60,"new_units":{"limit":32,"remaining":30},
			"leads":{"limit":16,"remaining":16},"siblings":{"limit":4,"remaining":4},
			"candidate_queries":{"limit":8,"remaining":7},"campaign_jobs_limit":10,
			"campaign_jobs_admitted":2,"campaign_general_remaining":5,
			"campaign_urgent_remaining":1,"campaign_verification_remaining":2,
			"proof_capacity":"unavailable","artifact_capacity":"unavailable",
			"output_capacity":"unavailable",
			"tokens":{"status":"host_enforced","limit":1000,"spent":"unknown"}}),
	);
	check(
		&|raw| plain(ManifestProgressDecoder, raw),
		json!({"protocol_version":3,"expected_entry_count":2,"expected_digest":DIGEST,
			"received_entry_count":1,"received_canonical_bytes":80,"sealed":false}),
	);
	check(
		&|raw| plain(PublishedProfileDecoder, raw),
		json!({"protocol_version":3,"profile_version":1,"profile_digest":DIGEST}),
	);
	check(
		&|raw| plain(ReviewUnitResponseDecoder, raw),
		json!({"protocol_version":3,"review_unit_id":5,"assignment_epoch":0,
			"accepted_priority_band":"normal"}),
	);
	check(
		&|raw| plain(LeadCheckpointResponseDecoder, raw),
		json!({"protocol_version":3,"lead_id":4,"outcome":"created","observation_id":null,
			"accepted_priority":{"band":"urgent","score":90}}),
	);
	check(
		&|raw| plain(UnitResultCheckpointResponseDecoder, raw),
		json!({"protocol_version":3,"result_id":9,"review_unit_id":5,"assignment_epoch":0,
			"disposition":"no_lead_found"}),
	);
	check(
		&|raw| plain(InventoryDispositionResponseDecoder, raw),
		json!({"protocol_version":3,"inventory_entry_id":3,"revision":1}),
	);
	check(
		&|raw| plain(PhaseControlResponseDecoder, raw),
		json!({"protocol_version":3,"job_id":7,"state":"queued","eligible_at":30}),
	);
	check(
		&|raw| plain(SurveyTerminalResponseDecoder, raw),
		json!({"protocol_version":3,"receipt":{"receipt_id":1,"job_id":7,"commit_sha":SHA,
			"result_digest":DIGEST,"terminal_reason":"completed","summary":{"version":1,
			"coverage":"complete","corroboration_satisfied":true,"missing_results":0,
			"needs_follow_up":0,"unresolved_inventory":0,"follow_up_batches":0,
			"follow_up_units":0}}}),
	);
}

#[test]
fn tagged_and_closed_values_accept_only_their_string_spelling() {
	let limits = |tokens: Value| {
		let mut value = json!({"protocol_version":3,"soft_deadline_at":1,"submit_by":1,
			"hard_deadline_at":2,"remaining_seconds":1,"new_units":{"limit":1,"remaining":1},
			"leads":{"limit":1,"remaining":1},"siblings":{"limit":1,"remaining":1},
			"candidate_queries":{"limit":1,"remaining":1},"campaign_jobs_limit":1,
			"campaign_jobs_admitted":1,"campaign_general_remaining":1,
			"campaign_urgent_remaining":1,"campaign_verification_remaining":1,
			"proof_capacity":"unavailable","artifact_capacity":"unavailable",
			"output_capacity":"unavailable","tokens":{"status":"none"}});
		value["tokens"] = tokens;
		plain(PhaseLimitsResponseDecoder, &value.to_string())
	};
	assert!(limits(json!({"status":"none"})).is_ok());
	assert!(limits(json!({"status":0})).is_err());
	assert!(limits(json!({"status":{"none":null}})).is_err());
	let control = |state: Value| {
		plain(
			PhaseControlResponseDecoder,
			&json!({"protocol_version":3,"job_id":7,"state":state,"eligible_at":null}).to_string(),
		)
	};
	assert!(control(json!("failed")).is_ok());
	assert!(control(json!({"failed":null})).is_err());
	assert!(control(json!("succeeded")).is_err());
}

fn assignment() -> Value {
	json!({"review_unit_id":5,"assignment_epoch":2,"title":"Review parser",
		"objective":"Check input bounds","source_refs":[{"path":"src/lib.rs","symbol":"parse"}],
		"depends_on":[4],"closure_criteria":null})
}

#[test]
fn pin_responses_carry_profile_and_assignments_and_keep_metadata_server() {
	let decode = |raw: &str| carried(PinTargetResponseDecoder, raw);
	let ordinary = json!({"outcome":"prepared","protocol_version":3,
		"generation":{"generation_id":3,"commit_sha":SHA},
		"profile":{"profile_version":1,"profile_digest":DIGEST,"profile":{"purpose":"test"}},
		"assignments":[assignment()]});
	check(&decode, ordinary.clone());
	check(
		&decode,
		json!({"outcome":"prepared","protocol_version":3,
			"generation":{"generation_id":3,"commit_sha":SHA},"profile":null,"assignments":null}),
	);
	check(
		&decode,
		json!({"outcome":"deferred","protocol_version":3,
			"receipt":{"receipt_id":2,"commit_sha":SHA,"reason":"unsupported_recipe"}}),
	);
	let response = server_response(ordinary.to_string().as_bytes())
		.validate_carrying(PinTargetResponseDecoder)
		.unwrap();
	let PinTargetResponse::Prepared { generation, profile, assignments, .. } = &response else {
		panic!("prepared")
	};
	let _: &crate::review_lease::ReviewGeneration<Server> = generation;
	let _: &crate::review_lease::FrozenReviewProfile<Agent, Server> = profile.as_ref().unwrap();
	let _: &crate::review_lease::ReviewAssignments<Agent> = assignments.as_ref().unwrap();
	assert!(!format!("{response:?}").contains("Review parser"));
	for (field, value) in [
		("outcome", json!(0)),
		("outcome", json!({"prepared":null})),
		("outcome", json!("pinned")),
		("generation", json!({"generation_id":3,"commit_sha":"zz"})),
		("assignments", json!([assignment(), assignment()])),
	] {
		let mut invalid = ordinary.clone();
		invalid[field] = value;
		assert!(decode(&invalid.to_string()).is_err(), "{invalid}");
	}
	let deferred = json!({"outcome":"deferred","protocol_version":3,
		"receipt":{"receipt_id":2,"commit_sha":SHA,"reason":{"unsupported_recipe":null}}});
	assert!(decode(&deferred.to_string()).is_err());
}

#[test]
fn candidate_identity_is_carried_and_bounded() {
	let decode = |raw: &str| carried(CandidatesResponseDecoder, raw);
	let candidate = json!({"kind":"lead","id":4,"producer_job_id":7,"commit_sha":SHA,
		"created_at":10,"identity_family":"allocation","identity_anchor":"handler",
		"identity_instance_key":null});
	check(&decode, json!({"protocol_version":3,"candidates":[candidate.clone()]}));
	check(&decode, json!({"protocol_version":3,"candidates":[]}));
	let response = server_response(
		json!({"protocol_version":3,"candidates":[candidate.clone()]}).to_string().as_bytes(),
	)
	.validate_carrying(CandidatesResponseDecoder)
	.unwrap();
	let _: &loupe_core::review_candidates::Candidate<Agent, Server> =
		&response.candidates.as_slice()[0];
	for (field, value) in [
		("kind", json!({"lead":null})),
		("kind", json!("unit")),
		("id", json!(0)),
		("unexpected", json!(1)),
	] {
		let mut invalid = candidate.clone();
		invalid[field] = value;
		let raw = json!({"protocol_version":3,"candidates":[invalid]}).to_string();
		assert!(decode(&raw).is_err(), "{raw}");
	}
	let many = json!({"protocol_version":3,"candidates":vec![candidate; 21]});
	assert!(decode(&many.to_string()).is_err());
}

#[test]
fn error_envelope_classifies_known_and_unknown_codes() {
	let decode = |raw: &str| server_response(raw.as_bytes()).validate(ReviewErrorResponseDecoder);
	for code in ReviewErrorCode::KNOWN {
		let current_revision = (code == ReviewErrorCode::InventoryRevisionConflict).then_some(4);
		let expected = ReviewErrorResponse { code, current_revision };
		let raw = serde_json::to_string(&expected).unwrap();
		assert_eq!(decode(&raw).unwrap(), expected, "{raw}");
	}
	// The router's fallback codes for statuses no handler produced.
	for spelling in ["unauthenticated", "method_not_allowed", "request_failed"] {
		let raw =
			format!(r#"{{"protocol_version":3,"error":{{"code":"{spelling}","detail":null}}}}"#);
		let code = decode(&raw).unwrap().code;
		assert_ne!(code, ReviewErrorCode::Other, "{spelling}");
		assert_eq!(serde_json::to_value(code).unwrap(), spelling);
	}
	let other = decode(r#"{"protocol_version":3,"error":{"code":"brand_new","detail":null}}"#);
	assert_eq!(other.unwrap().code, ReviewErrorCode::Other);
	let long = format!(
		r#"{{"protocol_version":3,"error":{{"code":"{}","detail":null}}}}"#,
		"x".repeat(1000)
	);
	assert_eq!(decode(&long).unwrap().code, ReviewErrorCode::Other);
	let revised =
		r#"{"protocol_version":3,"error":{"code":"brand_new","detail":null,"current_revision":2}}"#;
	assert_eq!(decode(revised).unwrap().current_revision, Some(2));
	for raw in [
		r#"{"protocol_version":3,"error":{"code":"denied","detail":"private"}}"#,
		r#"{"protocol_version":3,"error":{"code":"denied"}}"#,
		r#"{"protocol_version":3,"error":{"code":1,"detail":null}}"#,
		r#"{"protocol_version":3,"error":{"code":["denied"],"detail":null}}"#,
		r#"{"protocol_version":3,"error":{"code":"denied","detail":null,"extra":1}}"#,
		r#"{"protocol_version":3,"error":{"code":"denied","detail":null},"extra":1}"#,
		r#"{"protocol_version":3,"error":{"code":"denied","detail":null,"current_revision":1}}"#,
		r#"{"protocol_version":3,"error":{"code":"inventory_revision_conflict","detail":null}}"#,
		r#"{"protocol_version":3,"error":["denied",null]}"#,
		r#"{"protocol_version":2,"error":{"code":"denied","detail":null}}"#,
		r#"{"error":{"code":"denied","detail":null}}"#,
		"denied",
	] {
		let error = decode(raw).expect_err(raw);
		assert!(!format!("{error:?} {error}").contains("private"));
	}
}

fn drilldown(summary: Value) -> Value {
	json!({"protocol_version":3,"receipt":{"receipt_id":2,"job_id":8,"commit_sha":SHA,
		"result_digest":DIGEST,"summary":summary}})
}

#[test]
fn drilldown_receipts_round_trip_for_every_summary_shape() {
	let decode = |raw: &str| plain(DrilldownTerminalResponseDecoder, raw);
	check(
		&decode,
		drilldown(json!({"version":1,"lead_id":4,"disposition":"promoted",
			"promoted_finding_id":11})),
	);
	check(
		&decode,
		drilldown(json!({"version":1,"lead_id":4,"disposition":"deferred","continuation":{
			"state":"pending","class":"source_analysis_remaining","revision":1,
			"logical_sequence":2,"not_before":60}})),
	);
	check(
		&decode,
		drilldown(json!({"version":1,"lead_id":4,"disposition":"deferred","continuation":{
			"state":"blocked","class":"external_dependency","revision":1,"logical_sequence":1,
			"reason":"external_dependency"}})),
	);
	for disposition in ["rejected", "duplicate", "hardening"] {
		check(&decode, drilldown(json!({"version":1,"lead_id":4,"disposition":disposition})));
	}
}

#[test]
fn drilldown_receipts_refuse_malformed_summaries_and_metadata() {
	let decode = |value: Value| plain(DrilldownTerminalResponseDecoder, &value.to_string());
	let summary = json!({"version":1,"lead_id":4,"disposition":"rejected"});
	assert!(decode(drilldown(summary.clone())).is_ok());
	let mut bad = vec![];
	for (key, value) in [
		("unexpected", json!(0)),
		("version", json!(2)),
		("disposition", json!("reject")),
		("disposition", json!("promote")),
		("promoted_finding_id", json!("11")),
		("continuation", json!({"state":"pending"})),
		(
			"continuation",
			json!({"state":"blocked","class":"external_dependency","revision":1,
			"logical_sequence":1,"reason":"source_analysis_remaining"}),
		),
	] {
		let mut changed = summary.clone();
		changed[key] = value;
		bad.push(drilldown(changed));
	}
	for (key, value) in [
		("commit_sha", json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")),
		("commit_sha", json!("aaaa")),
		("result_digest", json!(SHA)),
		("receipt_id", json!(-1)),
		("terminal_reason", json!("completed")),
	] {
		let mut changed = drilldown(summary.clone());
		changed["receipt"][key] = value;
		bad.push(changed);
	}
	let mut wrong_protocol = drilldown(summary.clone());
	wrong_protocol["protocol_version"] = json!(4);
	bad.push(wrong_protocol);
	for value in bad {
		assert!(decode(value.clone()).is_err(), "accepted {value}");
	}
}

fn verification(summary: Value) -> Value {
	json!({"protocol_version":3,"receipt":{"receipt_id":2,"job_id":8,"commit_sha":SHA,
		"result_digest":DIGEST,"summary":summary}})
}
fn verification_summary(verdict: &str, state: &str) -> Value {
	json!({"version":1,"finding_id":4,"verification_id":7,"verdict":verdict,
		"finding_state":state})
}
fn inconclusive(continuation: Value) -> Value {
	let mut summary = verification_summary("inconclusive", "validating");
	summary["continuation"] = continuation;
	summary
}

#[test]
fn verification_receipts_round_trip_for_every_summary_shape() {
	let decode = |raw: &str| plain(VerificationTerminalResponseDecoder, raw);
	for (verdict, state) in
		[("verified", "confirmed"), ("verified", "awaiting_approval"), ("rejected", "dismissed")]
	{
		check(&decode, verification(verification_summary(verdict, state)));
	}
	check(
		&decode,
		verification(inconclusive(json!({"state":"pending","class":"source_analysis_remaining",
			"revision":1,"logical_sequence":2,"not_before":60}))),
	);
	for reason in ["awaiting_proof_infrastructure", "external_dependency", "requires_successor"] {
		check(
			&decode,
			verification(inconclusive(json!({"state":"blocked","class":reason,"revision":1,
				"logical_sequence":1,"reason":reason}))),
		);
	}
}

#[test]
fn verification_receipts_refuse_malformed_summaries_and_metadata() {
	let decode = |value: Value| plain(VerificationTerminalResponseDecoder, &value.to_string());
	let summary = inconclusive(json!({"state":"pending","class":"source_analysis_remaining",
		"revision":1,"logical_sequence":2,"not_before":60}));
	assert!(decode(verification(summary.clone())).is_ok());
	let mut bad = vec![];
	for (key, value) in [
		("unexpected", json!(0)),
		("version", json!(2)),
		("finding_id", json!(0)),
		("finding_id", json!("4")),
		("verification_id", json!(-1)),
		("verdict", json!("confirmed")),
		("verdict", json!({"inconclusive":null})),
		("finding_state", json!("open")),
		("finding_state", json!({"validating":null})),
		("continuation", json!(null)),
		("continuation", json!({"state":"pending"})),
		(
			"continuation",
			json!({"state":"blocked","class":"external_dependency","revision":1,
			"logical_sequence":1,"reason":"source_analysis_remaining"}),
		),
		(
			"continuation",
			json!({"state":"blocked","class":"external_dependency","revision":1,
			"logical_sequence":1,"reason":"external_dependency","not_before":60}),
		),
		("continuation", json!(["pending", "source_analysis_remaining", 1, 2, 60])),
	] {
		let mut changed = summary.clone();
		changed[key] = value;
		bad.push(verification(changed));
	}
	for key in ["version", "finding_id", "verification_id", "verdict", "finding_state"] {
		let mut changed = summary.clone();
		changed.as_object_mut().unwrap().remove(key);
		bad.push(verification(changed));
	}
	for (key, value) in [
		("commit_sha", json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")),
		("commit_sha", json!("aaaa")),
		("result_digest", json!(SHA)),
		("receipt_id", json!(-1)),
		("terminal_reason", json!("completed")),
		("summary", json!([1, 4, 7, "rejected", "dismissed"])),
	] {
		let mut changed = verification(summary.clone());
		changed["receipt"][key] = value;
		bad.push(changed);
	}
	let mut wrong_protocol = verification(summary);
	wrong_protocol["protocol_version"] = json!(4);
	bad.push(wrong_protocol);
	for value in bad {
		assert!(decode(value.clone()).is_err(), "accepted {value}");
	}
}

#[test]
fn verification_receipts_refuse_nested_duplicate_and_unknown_members() {
	let valid = verification(inconclusive(json!({"state":"pending",
		"class":"source_analysis_remaining","revision":1,"logical_sequence":2,"not_before":60})));
	let raw = valid.to_string();
	assert!(plain(VerificationTerminalResponseDecoder, &raw).is_ok());
	let receipt = &valid["receipt"];
	let summary = &receipt["summary"];
	let continuation = &summary["continuation"];
	for (object, name) in
		[(receipt, "receipt"), (summary, "summary"), (continuation, "continuation")]
	{
		let opening = format!("\"{name}\":{{");
		assert_eq!(raw.matches(&opening).count(), 1);
		let unknown = raw.replace(&opening, &format!("{opening}\"unexpected\":0,"));
		assert!(plain(VerificationTerminalResponseDecoder, &unknown).is_err(), "{unknown}");
		for (key, value) in object.as_object().unwrap() {
			let duplicate = raw.replace(&opening, &format!("{opening}\"{key}\":{value},"));
			assert!(plain(VerificationTerminalResponseDecoder, &duplicate).is_err(), "{duplicate}");
		}
	}
}

#[test]
fn verification_responses_stop_at_the_route_response_cap() {
	let raw = verification(verification_summary("rejected", "dismissed")).to_string();
	let boundary = format!("{raw}{}", " ".repeat(16 * 1024 - raw.len()));
	assert!(plain(VerificationTerminalResponseDecoder, &boundary).is_ok());
	assert!(plain(VerificationTerminalResponseDecoder, &(boundary + " ")).is_err());
}
