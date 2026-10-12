use loupe_proto::PROTOCOL_VERSION;
use loupe_provenance::Secret;
use serde::{Deserialize, Serialize};

use super::ReportingDestination;

/// Wire-only reporting setup. May carry a GitHub PAT inline so the
/// admin can register a repo in a single round-trip; the server moves
/// the PAT into the `secrets` table and persists a
/// `loupe_core::ReportingDestination` referencing the resulting
/// `pat_secret_id`. PAT material never travels back out of the server
/// in any response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReportingSetup {
	/// File issues on `target_owner/target_repo`. Without `github_pat`
	/// the server files them through its configured GitHub App and
	/// rejects the registration if no app is configured.
	GithubIssue {
		target_owner: String,
		target_repo: String,
		#[serde(
			default,
			skip_serializing_if = "Option::is_none",
			with = "crate::common::wire::secret_serde::optional"
		)]
		github_pat: Option<Secret<String>>,
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
	/// No automatic reporter. The server runs the scan, verification,
	/// and approval pipeline as usual, but confirmed findings remain
	/// `confirmed` until an operator configures reporting and retries
	/// delivery or handles them out-of-band.
	Manual,
}

/// Body of `POST /v1/repos`.
#[derive(Debug, Serialize, Deserialize)]
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
	/// Per-repo override of the verify flow. `None` (the default on
	/// the wire) means "inherit the server's
	/// `verification_default`". `Some(true)` / `Some(false)`
	/// pin the value for this repo regardless of the server default.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub verification_enabled: Option<bool>,
	/// Per-repo override of the human-in-the-loop approval gate. `None`
	/// (the default on the wire) means "inherit the server's
	/// `require_approval_default`". `Some(true)` / `Some(false)` pin
	/// the value for this repo regardless of the server default.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub require_approval: Option<bool>,
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
			verification_enabled: None,
			require_approval: None,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRepoResponse {
	pub protocol_version: u16,
	pub repo_id: i64,
}

/// Body of `POST /v1/repos/:id/reporting/github-pat`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RotateRepoPatRequest {
	pub protocol_version: u16,
	#[serde(with = "crate::common::wire::secret_serde::string")]
	pub github_pat: Secret<String>,
}

/// Body of `PUT /v1/repos/:id/reporting/github`. Omitting `github_pat`
/// switches the repo to the server's GitHub App.
#[derive(Debug, Serialize, Deserialize)]
pub struct SetRepoGithubReportingRequest {
	pub protocol_version: u16,
	pub target_owner: String,
	pub target_repo: String,
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		with = "crate::common::wire::secret_serde::optional"
	)]
	pub github_pat: Option<Secret<String>>,
}

/// Body of `PUT /v1/github-app`. Carries the app's private key inline,
/// the same way repo registration carries a PAT; the server verifies it
/// against GitHub and moves it into the `secrets` table. The key never
/// travels back out in any response.
#[derive(Serialize, Deserialize)]
pub struct SetGithubAppRequest {
	pub protocol_version: u16,
	pub app_id: u64,
	#[serde(with = "crate::common::wire::secret_serde::string")]
	pub private_key_pem: Secret<String>,
}

impl std::fmt::Debug for SetGithubAppRequest {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("SetGithubAppRequest")
			.field("protocol_version", &self.protocol_version)
			.field("app_id", &self.app_id)
			.field("private_key_pem", &self.private_key_pem)
			.finish()
	}
}

/// Non-secret view of the configured GitHub App.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubAppSummary {
	pub app_id: u64,
	pub slug: String,
}

/// Response body of `GET /v1/github-app`. `app` is `None` until an
/// operator stores a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubAppResponse {
	pub protocol_version: u16,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub app: Option<GithubAppSummary>,
}

/// Body of `PATCH /v1/repos/:id`. All fields are optional — only the
/// ones present in the JSON are applied. `disabled = Some(true)` stamps
/// `disabled_at = now`; `disabled = Some(false)` clears it. The repo's
/// reporting destination, clone URL, and PAT cannot be patched: those
/// are register-time inputs, and changing them would silently affect
/// where new findings get filed. Re-register the repo for that.
///
/// `require_approval` is tri-state on the wire: omitted = leave the
/// existing per-repo override alone; `Some(true)` / `Some(false)` =
/// pin per-repo. To clear the per-repo override back to "inherit
/// server default", set `inherit_require_approval = true` instead.
/// The server rejects requests that set both at once.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UpdateRepoRequest {
	pub protocol_version: u16,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub disabled: Option<bool>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub scan_interval_seconds: Option<u64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub verification_enabled: Option<bool>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub require_approval: Option<bool>,
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub inherit_require_approval: bool,
}

/// Response body of `GET /v1/repos`. `RepoSummary` carries a sanitized
/// [`ReportingSummary`] rather than the storage-only
/// `loupe_core::ReportingDestination`, so clients learn *which* reporter
/// a repo uses without ever seeing `pat_secret_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListReposResponse {
	pub protocol_version: u16,
	pub repos: Vec<RepoSummary>,
}

/// Which credential a GitHub issue destination files issues with.
///
/// A listing that omits the authentication mode denotes a PAT credential.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubReportingAuth {
	/// The server-wide GitHub App; issues appear authored by `<app>[bot]`.
	App,
	/// A personal access token stored for this repo.
	#[default]
	Pat,
}

/// Non-secret view of a repo's reporting destination.
///
/// Mirrors `loupe_core::ReportingDestination` with `pat_secret_id`
/// reduced to a [`GithubReportingAuth`] mode. Clients need the reporter
/// *kind* and the auth mode to decide which actions apply — PAT rotation
/// is only meaningful for a PAT-backed `GithubIssue`, and the server 400s
/// a rotation attempt against anything else — but the storage-side secret
/// id has no meaning off the server and must never leave it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReportingSummary {
	GithubIssue {
		target_owner: String,
		target_repo: String,
		#[serde(default)]
		auth: GithubReportingAuth,
	},
	Email {
		to: Vec<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		from: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		subject_prefix: Option<String>,
	},
	Manual,
}

impl From<&ReportingDestination> for ReportingSummary {
	fn from(dest: &ReportingDestination) -> Self {
		// Destructured field-by-field on purpose: no `..` rest pattern, so
		// adding a field to `ReportingDestination` fails to compile here
		// and forces a deliberate "does this belong on the wire?" call
		// rather than silently leaking or silently dropping it.
		match dest {
			ReportingDestination::GithubIssue { target_owner, target_repo, pat_secret_id } => {
				Self::GithubIssue {
					target_owner: target_owner.clone(),
					target_repo: target_repo.clone(),
					auth: match pat_secret_id {
						Some(_) => GithubReportingAuth::Pat,
						None => GithubReportingAuth::App,
					},
				}
			},
			ReportingDestination::Email { to, from, subject_prefix } => Self::Email {
				to: to.clone(),
				from: from.clone(),
				subject_prefix: subject_prefix.clone(),
			},
			ReportingDestination::Manual => Self::Manual,
		}
	}
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
	pub disabled_at: Option<i64>,
	pub verification_enabled: bool,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub require_approval: Option<bool>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub last_scanned_sha: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub last_scanned_at: Option<i64>,
	pub created_at: i64,
	/// Which reporter this repo is configured for, without secret
	/// material. Responses may omit the reporting field.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub reporting: Option<ReportingSummary>,
}

/// Body of `POST /v1/workers` (admin-only). Returns the freshly-minted
/// client cert + key + the CA cert; this is the **only** time the client
/// key leaves the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterWorkerRequest {
	pub protocol_version: u16,
	pub name: String,
}

/// The registration's private key has a single owning allocation.
///
/// ```compile_fail,E0599
/// fn duplicate(response: loupe_proto::RegisterWorkerResponse) {
///     let _copy = response.clone();
/// }
/// ```
///
/// ```
/// let metadata: fn(&loupe_proto::RegisterWorkerResponse) -> i64 = |response| response.worker_id;
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterWorkerResponse {
	pub protocol_version: u16,
	pub worker_id: i64,
	pub client_cert_pem: String,
	#[serde(with = "crate::common::wire::secret_serde::string")]
	pub client_key_pem: loupe_provenance::Secret<String>,
	#[serde(with = "crate::common::wire::secret_serde::string")]
	pub ca_cert_pem: loupe_provenance::Secret<String>,
}
