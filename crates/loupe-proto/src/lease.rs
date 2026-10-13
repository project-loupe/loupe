use std::sync::Arc;

use loupe_core::text::policy::{GitBranch, LeaseCapabilityName, RevisionText};
use loupe_core::text::BoundedText;
use loupe_core::{Finding, RepoSpec};
use loupe_provenance::{Secret, Source};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Opaque, single-lease capability issued by loupe-server.
///
/// Cloning shares one secret owner across the lease's host tasks. Formatting
/// is redacted; serialization deliberately delivers the bearer over mTLS.
///
/// Security events accept closed decisions and scalar context, not this bearer:
/// ```
/// use loupe_core::security_event::*;
/// let capability = loupe_proto::JobCapability::from_secret("fixture");
/// let context = EventContext::default();
/// let operation = Operation::Heartbeat;
/// let requested = RequestedTarget::Job(1);
/// let reason = CapabilityDenial::InactiveLease;
/// emit(SecurityEvent::CapabilityDenied { context, operation, requested, reason });
/// drop(capability);
/// ```
/// ```compile_fail,E0308
/// use loupe_core::security_event::emit;
/// emit(loupe_proto::JobCapability::from_secret("fixture"));
/// ```
pub struct JobCapability(Arc<Secret<String>>);

impl JobCapability {
	pub fn from_secret(value: impl Into<String>) -> Self {
		Self(Arc::new(Secret::new(value.into())))
	}

	pub fn expose_secret(&self) -> &str {
		self.0.expose()
	}
}

impl Clone for JobCapability {
	fn clone(&self) -> Self {
		Self(Arc::clone(&self.0))
	}
}

impl std::fmt::Debug for JobCapability {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("[redacted]")
	}
}

impl std::fmt::Display for JobCapability {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("[redacted]")
	}
}

impl Serialize for JobCapability {
	fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		serializer.serialize_str(self.expose_secret())
	}
}

impl<'de> Deserialize<'de> for JobCapability {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		String::deserialize(deserializer).map(Self::from_secret)
	}
}

/// Body of `POST /v1/jobs/lease`. The worker advertises capabilities so
/// the server can match a `kind=verify` job to a worker that runs the
/// right verifier (`verify:secrets`, `verify:llm-review`, ...).
///
/// `wait_seconds` enables server-side long-polling: if the queue is
/// empty, the server holds the connection up to that many seconds
/// waiting for a job. Default `0` keeps immediate empty-queue responses
/// available for callers that prefer explicit polling.
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct LeaseRequest<S: Source> {
	pub protocol_version: u16,
	pub capabilities: Vec<BoundedText<LeaseCapabilityName, S>>,
	#[serde(default)]
	pub wait_seconds: u32,
}
record_impls!(LeaseRequest<S> { protocol_version, capabilities, wait_seconds });

/// Response body. Either a job is handed out (`Lease(LeaseEnvelope)`) or
/// the queue is empty / no job matches the worker's capabilities (`Empty`).
/// We carry the variant inside the body rather than relying on HTTP status
/// codes because intermediaries strip / mangle them often enough.
// debug-ok: lease fields delegate to redacted owners; empty has only protocol.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", bound(serialize = ""))]
pub enum LeaseResponse<ContentS: Source, MetaS: Source> {
	Lease(Box<LeaseEnvelope<ContentS, MetaS>>),
	Empty { protocol_version: u16 },
}

/// The contents of an active lease — what the worker needs to run the job.
///
/// `payload` discriminates between scan and verify so that, for verify
/// jobs, the target finding travels alongside the repo spec without
/// inflating every scan-job response with optional finding fields.
// debug-ok: capability, credentials and all text delegate to redacted owners.
#[derive(Debug, Serialize)]
#[serde(bound(serialize = ""))]
pub struct LeaseEnvelope<ContentS: Source, MetaS: Source> {
	pub protocol_version: u16,
	pub job_id: i64,
	pub job_capability: JobCapability,
	/// Server-side numeric id for the registered repo. Workers
	/// forward this through `ScanContext`/`VerifyContext` so LLM
	/// backends can scope MCP tool calls
	/// (e.g. `query_prior_findings`) to the repo currently under
	/// scan without piecing it together from `(host, owner, repo)`.
	pub repo_id: i64,
	pub repo: RepoSpec<MetaS>,
	pub head_branch: Option<BoundedText<GitBranch, MetaS>>,
	/// Lease expiry as epoch seconds. Worker must heartbeat or complete
	/// before this point or the server reaper will reclaim the job.
	pub lease_expires_at: i64,
	pub scanner_config: crate::ScannerDocument<MetaS>,
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		with = "crate::secret_serde::optional"
	)]
	pub github_pat: Option<Secret<String>>,
	pub payload: LeasePayload<ContentS, MetaS>,
}

// debug-ok: finding and revision owners redact content; remaining field is ID.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", bound(serialize = ""))]
pub enum LeasePayload<ContentS: Source, MetaS: Source> {
	Scan {
		#[serde(default, skip_serializing_if = "Option::is_none")]
		since_sha: Option<BoundedText<RevisionText, MetaS>>,
	},
	Verify {
		finding_id: i64,
		finding: Box<Finding<ContentS>>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		reviewed_sha: Option<BoundedText<RevisionText, MetaS>>,
	},
}
impl<ContentS: Source, MetaS: Source> Clone for LeasePayload<ContentS, MetaS> {
	fn clone(&self) -> Self {
		match self {
			Self::Scan { since_sha } => Self::Scan { since_sha: since_sha.clone() },
			Self::Verify { finding_id, finding, reviewed_sha } => Self::Verify {
				finding_id: *finding_id,
				finding: finding.clone(),
				reviewed_sha: reviewed_sha.clone(),
			},
		}
	}
}
impl<ContentS: Source, MetaS: Source> PartialEq for LeasePayload<ContentS, MetaS> {
	fn eq(&self, other: &Self) -> bool {
		match (self, other) {
			(Self::Scan { since_sha: a }, Self::Scan { since_sha: b }) => a == b,
			(
				Self::Verify { finding_id: a, finding: b, reviewed_sha: c },
				Self::Verify { finding_id: x, finding: y, reviewed_sha: z },
			) => a == x && b == y && c == z,
			_ => false,
		}
	}
}
impl<ContentS: Source, MetaS: Source> Eq for LeasePayload<ContentS, MetaS> {}

#[cfg(test)]
mod tests {
	use loupe_core::{Finding, RepoSpec, Severity};
	use loupe_provenance::Server;
	use serde_json::json;

	use super::*;
	use crate::test_support::{path, scanner, text};
	use crate::version::PROTOCOL_VERSION;
	type LeaseResponse = super::LeaseResponse<Server, Server>;
	type LeaseEnvelope = super::LeaseEnvelope<Server, Server>;

	fn sample_repo() -> RepoSpec<Server> {
		RepoSpec {
			host: text("github.com"),
			owner: text("acme"),
			repo: text("widget"),
			clone_url: text("https://github.com/acme/widget.git"),
			branch: Some(text("main")),
		}
	}

	#[test]
	fn empty_response_preserves_wire_fields() {
		let r = LeaseResponse::Empty { protocol_version: PROTOCOL_VERSION };
		let s = serde_json::to_string(&r).unwrap();
		assert!(s.contains(r#""kind":"empty""#));
		assert_eq!(
			serde_json::from_str::<serde_json::Value>(&s).unwrap(),
			json!({"kind":"empty", "protocol_version":PROTOCOL_VERSION})
		);
	}

	#[test]
	fn scan_lease_preserves_every_wire_field() {
		let env: LeaseEnvelope = LeaseEnvelope {
			protocol_version: PROTOCOL_VERSION,
			job_id: 1,
			job_capability: JobCapability::from_secret("scan-capability"),
			repo_id: 9,
			repo: sample_repo(),
			head_branch: Some(text("main")),
			lease_expires_at: 1_700_000_600,
			scanner_config: scanner(json!({"regex": {"enabled": true}})),
			github_pat: None,
			payload: LeasePayload::Scan { since_sha: Some(text("abc123")) },
		};
		let r = LeaseResponse::Lease(Box::new(env));
		let s = serde_json::to_string(&r).unwrap();
		assert_eq!(
			serde_json::from_str::<serde_json::Value>(&s).unwrap(),
			json!({
				"kind":"lease", "protocol_version":PROTOCOL_VERSION, "job_id":1,
				"job_capability":"scan-capability", "repo_id":9,
				"repo":{"host":"github.com","owner":"acme","repo":"widget",
					"clone_url":"https://github.com/acme/widget.git","branch":"main"},
				"head_branch":"main", "lease_expires_at":1700000600,
				"scanner_config":{"regex":{"enabled":true}},
				"payload":{"kind":"scan","since_sha":"abc123"}
			})
		);
	}

	#[test]
	fn verify_lease_carries_finding() {
		let finding = Finding {
			scanner_id: text("regex-secrets"),
			severity: Severity::High,
			title: text("AWS access key"),
			description: text("Found AKIA-prefixed token"),
			file_path: Some(path("src/x.rs")),
			line_start: Some(1),
			line_end: Some(1),
			cwe: None,
			patch_unified: None,
			poc_unified: None,
			fingerprint: text("fp1"),
		};
		let env = LeaseEnvelope {
			protocol_version: PROTOCOL_VERSION,
			job_id: 7,
			job_capability: JobCapability::from_secret("verify-capability"),
			repo_id: 11,
			repo: sample_repo(),
			head_branch: None,
			lease_expires_at: 1_700_000_800,
			scanner_config: scanner(serde_json::Value::Null),
			github_pat: None,
			payload: LeasePayload::Verify {
				finding_id: 42,
				finding: Box::new(finding.clone()),
				reviewed_sha: Some(text("abc123")),
			},
		};
		let s = serde_json::to_string(&env).unwrap();
		assert_eq!(
			serde_json::from_str::<serde_json::Value>(&s).unwrap(),
			json!({
				"protocol_version":PROTOCOL_VERSION, "job_id":7, "job_capability":"verify-capability",
				"repo_id":11, "repo":{"host":"github.com","owner":"acme","repo":"widget",
					"clone_url":"https://github.com/acme/widget.git","branch":"main"},
				"head_branch":null, "lease_expires_at":1700000800,"scanner_config":null,
				"payload":{"kind":"verify","finding_id":42,"reviewed_sha":"abc123",
					"finding":{"scanner_id":"regex-secrets","severity":"high","title":"AWS access key",
						"description":"Found AKIA-prefixed token","file_path":"src/x.rs",
						"line_start":1,"line_end":1,"fingerprint":"fp1"}}
			})
		);
		match env.payload {
			LeasePayload::Verify { finding_id, finding: f, reviewed_sha } => {
				assert_eq!(finding_id, 42);
				assert_eq!(*f, finding);
				assert_eq!(reviewed_sha.as_ref().map(|sha| sha.expose()), Some("abc123"));
			},
			LeasePayload::Scan { .. } => panic!("expected Verify payload"),
		}
	}

	#[test]
	fn verify_lease_omits_unset_reviewed_sha() {
		// Missing-field input admission is checked by the worker's named lease
		// decoder; this fixture checks output serialization.
		let raw = r#"{
			"protocol_version":2,
			"job_id":7,
			"job_capability":"test-capability",
			"repo_id":11,
			"repo":{
				"host":"github.com",
				"owner":"acme",
				"repo":"widget",
				"clone_url":"https://github.com/acme/widget.git",
				"branch":"main"
			},
			"head_branch":null,
			"lease_expires_at":1700000800,
			"scanner_config":null,
			"payload":{
				"kind":"verify",
				"finding_id":42,
				"finding":{
					"scanner_id":"regex-secrets",
					"severity":"high",
					"title":"AWS access key",
					"description":"Found AKIA-prefixed token",
					"fingerprint":"fp1"
				}
			}
		}"#;
		let env = LeaseEnvelope {
			protocol_version: 2,
			job_id: 7,
			job_capability: JobCapability::from_secret("test-capability"),
			repo_id: 11,
			repo: sample_repo(),
			head_branch: None,
			lease_expires_at: 1700000800,
			scanner_config: scanner(serde_json::Value::Null),
			github_pat: None,
			payload: LeasePayload::Verify {
				finding_id: 42,
				reviewed_sha: None,
				finding: Box::new(Finding {
					scanner_id: text("regex-secrets"),
					severity: Severity::High,
					title: text("AWS access key"),
					description: text("Found AKIA-prefixed token"),
					fingerprint: text("fp1"),
					file_path: None,
					line_start: None,
					line_end: None,
					cwe: None,
					patch_unified: None,
					poc_unified: None,
				}),
			},
		};
		assert_eq!(
			serde_json::to_value(env).unwrap(),
			serde_json::from_str::<serde_json::Value>(raw).unwrap()
		);
	}
}
