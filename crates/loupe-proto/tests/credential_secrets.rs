use std::fmt::Debug;

use loupe_proto::{
	JobCapability, LeaseEnvelope, LeaseResponse, RegisterRepoRequest, ReportingSetup,
	RotateRepoPatRequest, SetRepoGithubReportingRequest, PROTOCOL_VERSION,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

const PAT: &str = "ghp_protocol_debug_sentinel_7b3980";
const CAPABILITY: &str = "protocol-capability-fixture";

fn reporting_wire() -> Value {
	json!({
		"kind": "github_issue",
		"target_owner": "acme",
		"target_repo": "security",
		"github_pat": PAT,
	})
}

fn registration_wire() -> Value {
	json!({
		"protocol_version": PROTOCOL_VERSION,
		"clone_url": "https://github.com/acme/widget.git",
		"branch": "main",
		"scan_interval_seconds": 3600,
		"reporting": reporting_wire(),
		"scanner_config": {"regex": {"enabled": true}},
		"verification_enabled": true,
		"require_approval": false,
	})
}

fn rotation_wire() -> Value {
	json!({"protocol_version": PROTOCOL_VERSION, "github_pat": PAT})
}

fn reporting_update_wire() -> Value {
	json!({
		"protocol_version": PROTOCOL_VERSION,
		"target_owner": "acme",
		"target_repo": "security",
		"github_pat": PAT,
	})
}

fn lease_wire() -> Value {
	json!({
		"protocol_version": PROTOCOL_VERSION,
		"job_id": 17,
		"job_capability": CAPABILITY,
		"repo_id": 23,
		"repo": {
			"host": "github.com",
			"owner": "acme",
			"repo": "widget",
			"clone_url": "https://github.com/acme/widget.git",
			"branch": "main",
		},
		"head_branch": "review",
		"lease_expires_at": 1_700_000_600,
		"scanner_config": {"regex": {"enabled": true}},
		"github_pat": PAT,
		"payload": {"kind": "scan", "since_sha": "abc123"},
	})
}

fn assert_pat_debug_redacted<T: Debug>(value: &T) {
	for rendered in [format!("{value:?}"), format!("{value:#?}")] {
		assert!(!rendered.contains(PAT), "populated credential DTO Debug disclosed the PAT");
		assert!(rendered.contains("[redacted]"), "PAT Debug must retain a redaction marker");
	}
}

fn assert_wire_roundtrip<T: DeserializeOwned + Serialize>(expected: Value) {
	let decoded: T = serde_json::from_value(expected.clone()).unwrap();
	let encoded = serde_json::to_value(&decoded).unwrap();
	assert_eq!(encoded, expected, "credential wire fields changed");
	let back: T = serde_json::from_value(encoded).unwrap();
	assert_eq!(serde_json::to_value(&back).unwrap(), expected, "credential round trip changed");
}

#[test]
fn reporting_setup_debug_redacts_populated_pat() {
	let setup: ReportingSetup = serde_json::from_value(reporting_wire()).unwrap();
	assert_pat_debug_redacted(&setup);
}

#[test]
fn register_repo_debug_redacts_populated_pat() {
	let request: RegisterRepoRequest = serde_json::from_value(registration_wire()).unwrap();
	assert_pat_debug_redacted(&request);
}

#[test]
fn rotate_pat_debug_redacts_populated_pat() {
	let request: RotateRepoPatRequest = serde_json::from_value(rotation_wire()).unwrap();
	assert_pat_debug_redacted(&request);
}

#[test]
fn reporting_update_debug_redacts_populated_pat() {
	let request: SetRepoGithubReportingRequest =
		serde_json::from_value(reporting_update_wire()).unwrap();
	assert_pat_debug_redacted(&request);
}

#[test]
fn lease_debug_redacts_populated_pat() {
	let lease: LeaseEnvelope = serde_json::from_value(lease_wire()).unwrap();
	assert_pat_debug_redacted(&lease);
}

#[test]
fn lease_response_debug_redacts_populated_pat() {
	let lease: LeaseEnvelope = serde_json::from_value(lease_wire()).unwrap();
	assert_pat_debug_redacted(&LeaseResponse::Lease(Box::new(lease)));
}

#[test]
fn capability_debug_uses_exact_redaction_contract() {
	let capability = JobCapability::from_secret(CAPABILITY);
	assert_eq!(format!("{capability:?}"), "[redacted]");
	assert_eq!(format!("{capability:#?}"), "[redacted]");
}

#[test]
fn capability_display_uses_exact_redaction_contract() {
	let capability = JobCapability::from_secret(CAPABILITY);
	assert_eq!(format!("{capability}"), "[redacted]");
	assert_eq!(format!("{capability:#}"), "[redacted]");
}

#[test]
fn credential_wire_roundtrips_preserve_every_field() {
	assert_wire_roundtrip::<JobCapability>(json!(CAPABILITY));
	assert_wire_roundtrip::<ReportingSetup>(reporting_wire());
	assert_wire_roundtrip::<RegisterRepoRequest>(registration_wire());
	assert_wire_roundtrip::<RotateRepoPatRequest>(rotation_wire());
	assert_wire_roundtrip::<SetRepoGithubReportingRequest>(reporting_update_wire());
	assert_wire_roundtrip::<LeaseEnvelope>(lease_wire());
	let mut response = lease_wire();
	response.as_object_mut().unwrap().insert("kind".into(), json!("lease"));
	assert_wire_roundtrip::<LeaseResponse>(response);
	assert_wire_roundtrip::<LeaseResponse>(
		json!({"kind": "empty", "protocol_version": PROTOCOL_VERSION}),
	);
}

#[test]
fn optional_pat_wire_fields_preserve_omission_and_null_defaults() {
	fn check<T: DeserializeOwned + Serialize>(mut expected: Value) {
		expected.as_object_mut().unwrap().remove("github_pat");
		assert_wire_roundtrip::<T>(expected.clone());
		let mut with_null = expected.clone();
		with_null.as_object_mut().unwrap().insert("github_pat".into(), Value::Null);
		let decoded: T = serde_json::from_value(with_null).unwrap();
		assert_eq!(serde_json::to_value(decoded).unwrap(), expected);
	}

	check::<ReportingSetup>(reporting_wire());
	check::<SetRepoGithubReportingRequest>(reporting_update_wire());
	check::<LeaseEnvelope>(lease_wire());
}
