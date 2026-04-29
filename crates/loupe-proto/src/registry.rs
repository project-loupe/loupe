use serde::{Deserialize, Serialize};

use crate::version::PROTOCOL_VERSION;

/// Wire-only reporting setup. Carries the GitHub PAT inline so the
/// admin can register a repo in a single round-trip; the server moves
/// the PAT into the `secrets` table and persists a
/// `loupe_core::ReportingDestination` referencing the resulting
/// `pat_secret_id`. PAT material never travels back out of the server
/// in any response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReportingSetup {
	GithubIssue {
		target_owner: String,
		target_repo: String,
		github_pat: String,
	},
	/// Send findings as email via the server's `sendmail` binary. No
	/// secret material is required — the binary handles transport.
	Email {
		to: Vec<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		from: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		subject_prefix: Option<String>,
	},
}

/// Body of `POST /v1/repos`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRepoRequest {
	pub protocol_version: u16,
	pub clone_url: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub branch: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub scan_interval_seconds: Option<u64>,
	pub reporting: ReportingSetup,
	#[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
	pub scanner_config: serde_json::Value,
	/// When `true`, scan findings for this repo go through the verify
	/// flow before being dispatched. Defaults to `false` so simple
	/// scanners that don't have a verifier worker pool to back them
	/// dispatch immediately.
	#[serde(default)]
	pub verification_enabled: bool,
}

impl RegisterRepoRequest {
	pub fn new(clone_url: impl Into<String>, reporting: ReportingSetup) -> Self {
		Self {
			protocol_version: PROTOCOL_VERSION,
			clone_url: clone_url.into(),
			branch: None,
			scan_interval_seconds: None,
			reporting,
			scanner_config: serde_json::Value::Null,
			verification_enabled: false,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRepoResponse {
	pub protocol_version: u16,
	pub repo_id: i64,
}

/// Response body of `GET /v1/repos`. `RepoSummary` deliberately omits
/// the storage-only `reporting` JSON — clients don't need it, and it
/// would leak `pat_secret_id` references that have no meaning to them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListReposResponse {
	pub protocol_version: u16,
	pub repos: Vec<RepoSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoSummary {
	pub id: i64,
	pub clone_url: String,
	pub host: String,
	pub owner: String,
	pub repo: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub default_branch: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub scan_interval_seconds: Option<i64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub last_scanned_sha: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub last_scanned_at: Option<i64>,
	pub created_at: i64,
}

/// Body of `POST /v1/workers` (admin-only). Returns the freshly-minted
/// client cert + key + the CA cert; this is the **only** time the client
/// key leaves the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterWorkerRequest {
	pub protocol_version: u16,
	pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterWorkerResponse {
	pub protocol_version: u16,
	pub worker_id: i64,
	pub client_cert_pem: String,
	pub client_key_pem: String,
	pub ca_cert_pem: String,
}

#[cfg(test)]
mod tests {
	use serde_json::json;

	use super::*;

	#[test]
	fn register_repo_request_round_trips() {
		let req = RegisterRepoRequest {
			protocol_version: PROTOCOL_VERSION,
			clone_url: "https://github.com/acme/widget.git".into(),
			branch: Some("main".into()),
			scan_interval_seconds: Some(3600),
			reporting: ReportingSetup::GithubIssue {
				target_owner: "acme".into(),
				target_repo: "security".into(),
				github_pat: "ghp_xxx".into(),
			},
			scanner_config: json!({"regex": {"enabled": true}}),
			verification_enabled: true,
		};
		let s = serde_json::to_string(&req).unwrap();
		let back: RegisterRepoRequest = serde_json::from_str(&s).unwrap();
		assert_eq!(req, back);
		// Sanity check: the wire form does not leak `pat_secret_id`.
		assert!(!s.contains("pat_secret_id"));
	}

	#[test]
	fn register_worker_response_carries_pem_triple() {
		let resp = RegisterWorkerResponse {
			protocol_version: PROTOCOL_VERSION,
			worker_id: 17,
			client_cert_pem: "-----BEGIN CERTIFICATE-----\n...".into(),
			client_key_pem: "-----BEGIN PRIVATE KEY-----\n...".into(),
			ca_cert_pem: "-----BEGIN CERTIFICATE-----\n...".into(),
		};
		let s = serde_json::to_string(&resp).unwrap();
		let back: RegisterWorkerResponse = serde_json::from_str(&s).unwrap();
		assert_eq!(resp, back);
	}
}
