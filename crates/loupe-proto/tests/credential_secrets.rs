use std::fmt::Debug;

#[path = "support/fixtures.rs"]
#[allow(dead_code)] // Each integration test uses a subset of the shared fixtures.
mod fixtures;
use fixtures::{scanner, text};
use loupe_core::RepoSpec;
use loupe_proto::{
	JobCapability, LeasePayload, RegisterRepoRequest, ReportingSetup, RotateRepoPatRequest,
	SetRepoGithubReportingRequest, PROTOCOL_VERSION,
};
use loupe_provenance::{Secret, Server};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

const PAT: &str = "ghp_protocol_debug_sentinel_7b3980";
const CAPABILITY: &str = "protocol-capability-fixture";

type LeaseEnvelope = loupe_proto::LeaseEnvelope<Server, Server>;
type LeaseResponse = loupe_proto::LeaseResponse<Server, Server>;

fn reporting(pat: Option<&str>) -> ReportingSetup<Server> {
	ReportingSetup::GithubIssue {
		target_owner: text("acme"),
		target_repo: text("security"),
		github_pat: pat.map(|p| Secret::new(p.to_owned())),
	}
}

fn registration() -> RegisterRepoRequest<Server> {
	RegisterRepoRequest {
		protocol_version: PROTOCOL_VERSION,
		clone_url: text("https://github.com/acme/widget.git"),
		branch: Some(text("main")),
		scan_interval_seconds: Some(3600),
		reporting: reporting(Some(PAT)),
		scanner_config: Some(scanner(json!({"regex":{"enabled":true}}))),
		verification_enabled: Some(true),
		require_approval: Some(false),
	}
}

fn reporting_update(pat: Option<&str>) -> SetRepoGithubReportingRequest<Server> {
	SetRepoGithubReportingRequest {
		protocol_version: PROTOCOL_VERSION,
		target_owner: text("acme"),
		target_repo: text("security"),
		github_pat: pat.map(|p| Secret::new(p.to_owned())),
	}
}

fn lease(pat: Option<&str>) -> LeaseEnvelope {
	LeaseEnvelope {
		protocol_version: PROTOCOL_VERSION,
		job_id: 17,
		job_capability: JobCapability::from_secret(CAPABILITY),
		repo_id: 23,
		repo: RepoSpec {
			host: text("github.com"),
			owner: text("acme"),
			repo: text("widget"),
			clone_url: text("https://github.com/acme/widget.git"),
			branch: Some(text("main")),
		},
		head_branch: Some(text("review")),
		lease_expires_at: 1700000600,
		scanner_config: scanner(json!({"regex":{"enabled":true}})),
		github_pat: pat.map(|p| Secret::new(p.to_owned())),
		payload: LeasePayload::Scan { since_sha: Some(text("abc123")) },
	}
}

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
	let setup = reporting(Some(PAT));
	assert_pat_debug_redacted(&setup);
}

#[test]
fn register_repo_debug_redacts_populated_pat() {
	let request = registration();
	assert_pat_debug_redacted(&request);
}

#[test]
fn rotate_pat_debug_redacts_populated_pat() {
	let request: RotateRepoPatRequest = serde_json::from_value(rotation_wire()).unwrap();
	assert_pat_debug_redacted(&request);
}

#[test]
fn reporting_update_debug_redacts_populated_pat() {
	let request = reporting_update(Some(PAT));
	assert_pat_debug_redacted(&request);
}

#[test]
fn lease_debug_redacts_populated_pat() {
	let lease = lease(Some(PAT));
	assert_pat_debug_redacted(&lease);
}

#[test]
fn lease_response_debug_redacts_populated_pat() {
	let lease = lease(Some(PAT));
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
fn credential_wire_serialization_preserves_every_field() {
	assert_wire_roundtrip::<JobCapability>(json!(CAPABILITY));
	assert_eq!(serde_json::to_value(reporting(Some(PAT))).unwrap(), reporting_wire());
	assert_eq!(serde_json::to_value(registration()).unwrap(), registration_wire());
	assert_wire_roundtrip::<RotateRepoPatRequest>(rotation_wire());
	assert_eq!(serde_json::to_value(reporting_update(Some(PAT))).unwrap(), reporting_update_wire());
	assert_eq!(serde_json::to_value(lease(Some(PAT))).unwrap(), lease_wire());
	let mut response = lease_wire();
	response.as_object_mut().unwrap().insert("kind".into(), json!("lease"));
	assert_eq!(
		serde_json::to_value(LeaseResponse::Lease(Box::new(lease(Some(PAT))))).unwrap(),
		response
	);
	assert_eq!(
		serde_json::to_value(LeaseResponse::Empty { protocol_version: PROTOCOL_VERSION }).unwrap(),
		json!({"kind":"empty","protocol_version":PROTOCOL_VERSION})
	);
}

#[test]
fn optional_pat_wire_fields_are_omitted_when_absent() {
	// Missing/null input admission is retained at the named server and worker
	// decoders; source-bearing DTOs only expose serialization here.
	fn check<T: Serialize>(value: T, mut expected: Value) {
		expected.as_object_mut().unwrap().remove("github_pat");
		assert_eq!(serde_json::to_value(value).unwrap(), expected);
	}

	check(reporting(None), reporting_wire());
	check(reporting_update(None), reporting_update_wire());
	check(lease(None), lease_wire());
}
