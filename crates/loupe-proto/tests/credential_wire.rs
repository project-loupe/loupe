//! Compatibility controls for the closed credential-bearing wire DTOs.

use loupe_core::{Finding, RepoSpec, Severity};
use loupe_proto::*;
use loupe_provenance::{Secret, Server};
use serde::Serialize;
use serde_json::{json, Value};

#[path = "support/fixtures.rs"]
#[allow(dead_code)] // Each integration test uses a subset of the shared fixtures.
mod fixtures;
use fixtures::{scanner, text};
type LeaseResponse = loupe_proto::LeaseResponse<Server, Server>;
type RegisterRepoRequest = loupe_proto::RegisterRepoRequest<Server>;
type SetRepoGithubReportingRequest = loupe_proto::SetRepoGithubReportingRequest<Server>;

trait TestWire {
	fn wire(&self) -> loupe_provenance::Secret<Vec<u8>>;
}

macro_rules! wire {
	($($ty:ty),+ $(,)?) => { $(
		impl TestWire for $ty {
			fn wire(&self) -> loupe_provenance::Secret<Vec<u8>> {
				self.credential_json().unwrap()
			}
		}
	)+ };
}
wire!(
	LeaseResponse,
	RegisterWorkerResponse,
	SetGithubAppRequest,
	RotateRepoPatRequest,
	SetRepoGithubReportingRequest,
	RegisterRepoRequest
);

fn check<T: Serialize + TestWire>(value: &T, expected: &Value) {
	let bytes = value.wire();
	assert_eq!(bytes.expose(), &serde_json::to_vec(value).unwrap());
	assert_eq!(&serde_json::from_slice::<Value>(bytes.expose()).unwrap(), expected);
}

#[test]
fn credential_requests_preserve_escaped_values_and_optional_fields() {
	let sentinel = "FAKE_WIRE_\"\\\n\r\t\0é秘密";
	let app = json!({"protocol_version": 2, "app_id": 42, "private_key_pem": sentinel});
	check(&serde_json::from_value::<SetGithubAppRequest>(app.clone()).unwrap(), &app);
	let rotate = json!({"protocol_version": 2, "github_pat": sentinel});
	check(&serde_json::from_value::<RotateRepoPatRequest>(rotate.clone()).unwrap(), &rotate);
	for pat in [None, Some(sentinel)] {
		let mut reporting =
			json!({"protocol_version": 2, "target_owner": "acme", "target_repo": "issues"});
		if let Some(pat) = pat {
			reporting["github_pat"] = pat.into();
		}
		check(
			&SetRepoGithubReportingRequest {
				protocol_version: 2,
				target_owner: text("acme"),
				target_repo: text("issues"),
				github_pat: pat.map(|p| Secret::new(p.to_owned())),
			},
			&reporting,
		);
		reporting.as_object_mut().unwrap().remove("protocol_version");
		reporting["kind"] = "github_issue".into();
		let repo = json!({"protocol_version": 2, "clone_url": "https://example.test/repo", "reporting": reporting});
		let request = RegisterRepoRequest::new(
			text("https://example.test/repo"),
			ReportingSetup::GithubIssue {
				target_owner: text("acme"),
				target_repo: text("issues"),
				github_pat: pat.map(|p| Secret::new(p.to_owned())),
			},
			Some(scanner(Value::Null)),
		);
		check(&request, &repo);
	}
	let manual =
		json!({"protocol_version": 2, "clone_url": "local", "reporting": {"kind":"manual"}});
	check(&RegisterRepoRequest::new(text("local"), ReportingSetup::Manual, None), &manual);
}

#[test]
fn worker_bundle_preserves_compact_and_pretty_pem_bytes() {
	let bundle = json!({"protocol_version":2,"worker_id":7,"client_cert_pem":"CERT\n", "client_key_pem":"FAKE_KEY_\"\\\n\r\té", "ca_cert_pem":"CA\n"});
	let value = serde_json::from_value::<RegisterWorkerResponse>(bundle.clone()).unwrap();
	check(&value, &bundle);
	let pretty = value.credential_json_pretty().unwrap();
	assert_eq!(pretty.expose(), &serde_json::to_vec_pretty(&value).unwrap());
	assert_eq!(serde_json::from_slice::<Value>(pretty.expose()).unwrap(), bundle);
	assert!(pretty.expose().starts_with(b"{\n  \"protocol_version\": 2,"));
	assert!(!pretty.expose().ends_with(b"\n"));
}

#[test]
fn lease_variants_preserve_capability_pat_and_payload() {
	let empty = json!({"kind":"empty", "protocol_version":2});
	check(&LeaseResponse::Empty { protocol_version: 2 }, &empty);
	for (payload, expected_payload) in [
		(LeasePayload::Scan { since_sha: None }, json!({"kind":"scan"})),
		(
			LeasePayload::Scan { since_sha: Some(text("abc")) },
			json!({"kind":"scan", "since_sha":"abc"}),
		),
		(
			LeasePayload::Verify {
				finding_id: 3,
				reviewed_sha: None,
				finding: Box::new(Finding {
					scanner_id: text("regex-secrets"),
					severity: Severity::High,
					title: text("fixture"),
					description: text("fixture description"),
					fingerprint: text("fp"),
					file_path: None,
					line_start: None,
					line_end: None,
					cwe: None,
					patch_unified: None,
					poc_unified: None,
				}),
			},
			json!({"kind":"verify", "finding_id":3, "finding": {
				"scanner_id":"regex-secrets", "severity":"high", "title":"fixture",
				"description":"fixture description", "fingerprint":"fp"
			}}),
		),
	] {
		let wire = json!({"kind":"lease", "protocol_version":2, "job_id":1,
			"job_capability":"FAKE_CAP_\"\\\né", "repo_id":2,
			"repo":{"host":"example.test","owner":"acme","repo":"repo","clone_url":"local"},
			"head_branch":null,"lease_expires_at":10,"scanner_config":null,
			"github_pat":"FAKE_PAT_\"\\\né", "payload":expected_payload});
		let value = LeaseResponse::Lease(Box::new(LeaseEnvelope {
			protocol_version: 2,
			job_id: 1,
			job_capability: JobCapability::from_secret("FAKE_CAP_\"\\\né"),
			repo_id: 2,
			repo: RepoSpec {
				host: text("example.test"),
				owner: text("acme"),
				repo: text("repo"),
				clone_url: text("local"),
				branch: None,
			},
			head_branch: None,
			lease_expires_at: 10,
			scanner_config: scanner(Value::Null),
			github_pat: Some(Secret::new("FAKE_PAT_\"\\\né".into())),
			payload,
		}));
		check(&value, &wire);
	}
}
