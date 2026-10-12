//! Compatibility controls for the closed credential-bearing wire DTOs.

use loupe_proto::*;
use serde::Serialize;
use serde_json::{json, Value};

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
			&serde_json::from_value::<SetRepoGithubReportingRequest>(reporting.clone()).unwrap(),
			&reporting,
		);
		reporting.as_object_mut().unwrap().remove("protocol_version");
		reporting["kind"] = "github_issue".into();
		let repo = json!({"protocol_version": 2, "clone_url": "https://example.test/repo", "reporting": reporting});
		check(&serde_json::from_value::<RegisterRepoRequest>(repo.clone()).unwrap(), &repo);
	}
	let manual =
		json!({"protocol_version": 2, "clone_url": "local", "reporting": {"kind":"manual"}});
	check(&serde_json::from_value::<RegisterRepoRequest>(manual.clone()).unwrap(), &manual);
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
	check(&serde_json::from_value::<LeaseResponse>(empty.clone()).unwrap(), &empty);
	for payload in [
		json!({"kind":"scan"}),
		json!({"kind":"scan", "since_sha":"abc"}),
		json!({"kind":"verify", "finding_id":3, "finding": {
			"scanner_id":"regex-secrets", "severity":"high", "title":"fixture",
			"description":"fixture description", "fingerprint":"fp"
		}}),
	] {
		let wire = json!({"kind":"lease", "protocol_version":2, "job_id":1,
			"job_capability":"FAKE_CAP_\"\\\né", "repo_id":2,
			"repo":{"host":"example.test","owner":"acme","repo":"repo","clone_url":"local","branch":null},
			"head_branch":null,"lease_expires_at":10,"scanner_config":null,
			"github_pat":"FAKE_PAT_\"\\\né", "payload":payload});
		let value = serde_json::from_value::<LeaseResponse>(wire.clone()).unwrap();
		// Finding has legacy default fields; pin its canonical DTO form too.
		let canonical = serde_json::to_value(&value).unwrap();
		check(&value, &canonical);
		assert_eq!(canonical["job_capability"], wire["job_capability"]);
		assert_eq!(canonical["github_pat"], wire["github_pat"]);
		assert_eq!(canonical["payload"]["kind"], wire["payload"]["kind"]);
	}
}
