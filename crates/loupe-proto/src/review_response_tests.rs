use loupe_provenance::{Agent, Server, Validate, ValidateCarrying};
use serde::Serialize;
use serde_json::{json, Value};

use crate::review_api::*;
use crate::review_evidence::{LeadCheckpointResponseDecoder, UnitResultCheckpointResponseDecoder};
use crate::review_inventory::InventoryDispositionResponseDecoder;
use crate::review_lifecycle::PhaseControlResponseDecoder;
use crate::review_terminal::SurveyTerminalResponseDecoder;
use crate::review_units::ReviewUnitResponseDecoder;
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
