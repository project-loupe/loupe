use loupe_core::text::policy::*;
use loupe_core::text::BoundedText;
use loupe_core::ReportingDestination;
use loupe_provenance::{Secret, Source};
use serde::{Deserialize, Serialize};

use crate::version::PROTOCOL_VERSION;

/// Wire-only reporting setup. May carry a GitHub PAT inline so the
/// admin can register a repo in a single round-trip; the server moves
/// the PAT into the `secrets` table and persists a
/// `loupe_core::ReportingDestination` referencing the resulting
/// `pat_secret_id`. PAT material never travels back out of the server
/// in any response.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", bound(serialize = ""))]
pub enum ReportingSetup<S: Source> {
	/// File issues on `target_owner/target_repo`. Without `github_pat`
	/// the server files them through its configured GitHub App and
	/// rejects the registration if no app is configured.
	GithubIssue {
		target_owner: BoundedText<RepoOwner, S>,
		target_repo: BoundedText<RepoName, S>,
		#[serde(
			default,
			skip_serializing_if = "Option::is_none",
			with = "crate::secret_serde::optional"
		)]
		github_pat: Option<Secret<String>>,
	},
	/// Send findings as email via the server's `sendmail` binary. No
	/// secret material is required — the binary handles transport.
	Email {
		to: Vec<BoundedText<MailAddress, S>>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		from: Option<BoundedText<MailAddress, S>>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		subject_prefix: Option<BoundedText<MailSubjectPrefix, S>>,
	},
	/// No automatic reporter. The server runs the scan, verification,
	/// and approval pipeline as usual, but confirmed findings remain
	/// `confirmed` until an operator configures reporting and retries
	/// delivery or handles them out-of-band.
	Manual,
}

/// Body of `POST /v1/repos`.
#[derive(Debug, Serialize)]
#[serde(bound(serialize = ""))]
pub struct RegisterRepoRequest<S: Source> {
	pub protocol_version: u16,
	pub clone_url: BoundedText<CloneUrl, S>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub branch: Option<BoundedText<GitBranch, S>>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub scan_interval_seconds: Option<u64>,
	pub reporting: ReportingSetup<S>,
	#[serde(skip_serializing_if = "scanner_document_is_absent")]
	pub scanner_config: Option<crate::ScannerDocument<S>>,
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

fn scanner_document_is_absent<S: Source>(document: &Option<crate::ScannerDocument<S>>) -> bool {
	document.as_ref().is_none_or(crate::ScannerDocument::is_null)
}

impl<S: Source> RegisterRepoRequest<S> {
	pub fn new(
		clone_url: BoundedText<CloneUrl, S>, reporting: ReportingSetup<S>,
		scanner_config: Option<crate::ScannerDocument<S>>,
	) -> Self {
		Self {
			protocol_version: PROTOCOL_VERSION,
			clone_url,
			branch: None,
			scan_interval_seconds: None,
			reporting,
			scanner_config,
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
	#[serde(with = "crate::secret_serde::string")]
	pub github_pat: Secret<String>,
}

/// Body of `PUT /v1/repos/:id/reporting/github`. Omitting `github_pat`
/// switches the repo to the server's GitHub App.
#[derive(Debug, Serialize)]
#[serde(bound(serialize = ""))]
pub struct SetRepoGithubReportingRequest<S: Source> {
	pub protocol_version: u16,
	pub target_owner: BoundedText<RepoOwner, S>,
	pub target_repo: BoundedText<RepoName, S>,
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		with = "crate::secret_serde::optional"
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
	#[serde(with = "crate::secret_serde::string")]
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
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct GithubAppSummary<S: Source> {
	pub app_id: u64,
	pub slug: BoundedText<GithubAppSlug, S>,
}
record_impls!(GithubAppSummary<S> { app_id, slug });

/// Response body of `GET /v1/github-app`. `app` is `None` until an
/// operator stores a credential.
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct GithubAppResponse<S: Source> {
	pub protocol_version: u16,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub app: Option<GithubAppSummary<S>>,
}
record_impls!(GithubAppResponse<S> { protocol_version, app });

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
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct ListReposResponse<S: Source> {
	pub protocol_version: u16,
	pub repos: Vec<RepoSummary<S>>,
}
record_impls!(ListReposResponse<S> { protocol_version, repos });

/// Which credential a GitHub issue destination files issues with.
///
/// Defaults to `Pat` because that is the only mode servers predating
/// GitHub App support had; a listing without the field is one of theirs.
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
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", bound(serialize = ""))]
pub enum ReportingSummary<S: Source> {
	GithubIssue {
		target_owner: BoundedText<RepoOwner, S>,
		target_repo: BoundedText<RepoName, S>,
		#[serde(default)]
		auth: GithubReportingAuth,
	},
	Email {
		to: Vec<BoundedText<MailAddress, S>>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		from: Option<BoundedText<MailAddress, S>>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		subject_prefix: Option<BoundedText<MailSubjectPrefix, S>>,
	},
	Manual,
}

impl<S: Source> Clone for ReportingSummary<S> {
	fn clone(&self) -> Self {
		match self {
			Self::GithubIssue { target_owner, target_repo, auth } => Self::GithubIssue {
				target_owner: target_owner.clone(),
				target_repo: target_repo.clone(),
				auth: *auth,
			},
			Self::Email { to, from, subject_prefix } => Self::Email {
				to: to.clone(),
				from: from.clone(),
				subject_prefix: subject_prefix.clone(),
			},
			Self::Manual => Self::Manual,
		}
	}
}
impl<S: Source> PartialEq for ReportingSummary<S> {
	fn eq(&self, other: &Self) -> bool {
		match (self, other) {
			(
				Self::GithubIssue { target_owner: a, target_repo: b, auth: c },
				Self::GithubIssue { target_owner: x, target_repo: y, auth: z },
			) => a == x && b == y && c == z,
			(
				Self::Email { to: a, from: b, subject_prefix: c },
				Self::Email { to: x, from: y, subject_prefix: z },
			) => a == x && b == y && c == z,
			(Self::Manual, Self::Manual) => true,
			_ => false,
		}
	}
}
impl<S: Source> Eq for ReportingSummary<S> {}

impl<S: Source> From<&ReportingDestination<S>> for ReportingSummary<S> {
	fn from(dest: &ReportingDestination<S>) -> Self {
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

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct RepoSummary<S: Source> {
	pub id: i64,
	pub clone_url: BoundedText<CloneUrl, S>,
	pub host: BoundedText<RepoHost, S>,
	pub owner: BoundedText<RepoOwner, S>,
	pub repo: BoundedText<RepoName, S>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub default_branch: Option<BoundedText<GitBranch, S>>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub scan_interval_seconds: Option<i64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub disabled_at: Option<i64>,
	pub verification_enabled: bool,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub require_approval: Option<bool>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub last_scanned_sha: Option<BoundedText<RevisionText, S>>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub last_scanned_at: Option<i64>,
	pub created_at: i64,
	/// Which reporter this repo is configured for, without secret
	/// material. `Option` because the field is additive: a client built
	/// against a newer protocol must still deserialize responses from a
	/// server that predates it.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub reporting: Option<ReportingSummary<S>>,
}
record_impls!(RepoSummary<S> { id, clone_url, host, owner, repo, default_branch, scan_interval_seconds, disabled_at, verification_enabled, require_approval, last_scanned_sha, last_scanned_at, created_at, reporting });

/// Body of `POST /v1/workers` (admin-only). Returns the freshly-minted
/// client cert + key + the CA cert; this is the **only** time the client
/// key leaves the server.
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct RegisterWorkerRequest<S: Source> {
	pub protocol_version: u16,
	pub name: BoundedText<WorkerName, S>,
}
record_impls!(RegisterWorkerRequest<S> { protocol_version, name });

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
	#[serde(with = "crate::secret_serde::string")]
	pub client_key_pem: loupe_provenance::Secret<String>,
	#[serde(with = "crate::secret_serde::string")]
	pub ca_cert_pem: loupe_provenance::Secret<String>,
}

#[cfg(test)]
mod tests {
	use loupe_provenance::Server;
	use serde_json::json;

	use super::*;
	use crate::test_support::{scanner, text};
	type RepoSummary = super::RepoSummary<Server>;
	type ReportingSummary = super::ReportingSummary<Server>;
	type ReportingSetup = super::ReportingSetup<Server>;
	type ReportingDestination = loupe_core::ReportingDestination<Server>;

	#[test]
	fn credential_app_request_debug_redacts_private_pem() {
		let request: super::SetGithubAppRequest = serde_json::from_str(
			r#"{"protocol_version":1,"app_id":42,"private_key_pem":"FAKE_APP_REQUEST_SENTINEL"}"#,
		)
		.unwrap();
		for formatted in [format!("{request:?}"), format!("{request:#?}")] {
			assert!(
				!formatted.contains("FAKE_APP_REQUEST_SENTINEL"),
				"App request Debug must not expose private PEM"
			);
		}
	}

	#[test]
	fn app_request_wire_roundtrip_preserves_all_fields() {
		let wire = serde_json::json!({
			"protocol_version": super::PROTOCOL_VERSION,
			"app_id": 42,
			"private_key_pem": "FAKE_APP_WIRE_SENTINEL\n",
		});
		let request: super::SetGithubAppRequest = serde_json::from_value(wire.clone()).unwrap();
		assert_eq!(serde_json::to_value(&request).unwrap(), wire);
	}
	#[test]
	fn register_repo_request_preserves_every_wire_field() {
		let req = RegisterRepoRequest {
			protocol_version: PROTOCOL_VERSION,
			clone_url: text("https://github.com/acme/widget.git"),
			branch: Some(text("main")),
			scan_interval_seconds: Some(3600),
			reporting: ReportingSetup::GithubIssue {
				target_owner: text("acme"),
				target_repo: text("security"),
				github_pat: Some(loupe_provenance::Secret::new("ghp_xxx".into())),
			},
			scanner_config: Some(scanner(json!({"regex": {"enabled": true}}))),
			verification_enabled: Some(true),
			require_approval: Some(false),
		};
		let s = serde_json::to_string(&req).unwrap();
		assert_eq!(
			serde_json::from_str::<serde_json::Value>(&s).unwrap(),
			json!({
				"protocol_version":PROTOCOL_VERSION,"clone_url":"https://github.com/acme/widget.git",
				"branch":"main","scan_interval_seconds":3600,
				"reporting":{"kind":"github_issue","target_owner":"acme","target_repo":"security","github_pat":"ghp_xxx"},
				"scanner_config":{"regex":{"enabled":true}},"verification_enabled":true,"require_approval":false
			})
		);
		// Sanity check: the wire form does not leak `pat_secret_id`.
		assert!(!s.contains("pat_secret_id"));
	}

	#[test]
	fn register_repo_request_omits_inherited_verification_default() {
		let req = RegisterRepoRequest::new(
			text("https://github.com/acme/widget.git"),
			ReportingSetup::Manual,
			None,
		);
		let s = serde_json::to_string(&req).unwrap();
		assert!(
			!s.contains("verification_enabled"),
			"verification default should be inherited unless pinned: {s}"
		);
		assert_eq!(req.verification_enabled, None);
		assert_eq!(
			serde_json::from_str::<serde_json::Value>(&s).unwrap(),
			json!({
				"protocol_version":PROTOCOL_VERSION,"clone_url":"https://github.com/acme/widget.git","reporting":{"kind":"manual"}
			})
		);
	}

	#[test]
	fn registration_scanner_presence_preserves_wire_omission() {
		// None represents host absence without manufacturing a source mark.
		// An explicitly sourced null document retains its existing omission;
		// other sourced JSON values must survive even when false or empty.
		for (document, expected) in [
			(None, None),
			(Some(scanner(serde_json::Value::Null)), None),
			(Some(scanner(json!({}))), Some(json!({}))),
			(Some(scanner(json!(false))), Some(json!(false))),
		] {
			let request = RegisterRepoRequest::new(
				text("https://github.com/acme/widget.git"),
				ReportingSetup::Manual,
				document,
			);
			let mut wire = json!({"protocol_version":PROTOCOL_VERSION,
				"clone_url":"https://github.com/acme/widget.git","reporting":{"kind":"manual"}});
			if let Some(value) = expected {
				wire["scanner_config"] = value;
			}
			assert_eq!(serde_json::to_value(&request).unwrap(), wire);
			assert_eq!(
				serde_json::from_slice::<serde_json::Value>(
					request.credential_json().unwrap().expose()
				)
				.unwrap(),
				wire
			);
		}
	}

	fn summary_with_reporting(reporting: Option<ReportingSummary>) -> RepoSummary {
		RepoSummary {
			id: 1,
			clone_url: text("https://github.com/acme/widget.git"),
			host: text("github.com"),
			owner: text("acme"),
			repo: text("widget"),
			default_branch: Some(text("main")),
			scan_interval_seconds: Some(3600),
			disabled_at: None,
			verification_enabled: true,
			require_approval: None,
			last_scanned_sha: None,
			last_scanned_at: None,
			created_at: 42,
			reporting,
		}
	}

	#[test]
	fn reporting_summary_drops_the_pat_secret_id() {
		let dest = ReportingDestination::GithubIssue {
			target_owner: text("acme"),
			target_repo: text("tracker"),
			pat_secret_id: Some(7),
		};
		let summary = ReportingSummary::from(&dest);
		assert_eq!(
			summary,
			ReportingSummary::GithubIssue {
				target_owner: text("acme"),
				target_repo: text("tracker"),
				auth: GithubReportingAuth::Pat,
			}
		);

		// The whole point of the type: the storage-side secret id must not
		// survive the conversion onto the wire.
		let s = serde_json::to_string(&summary).unwrap();
		assert!(s.contains(r#""kind":"github_issue""#), "kind must be tagged: {s}");
		assert!(s.contains("acme"), "non-secret target must survive: {s}");
		assert!(s.contains(r#""auth":"pat""#), "auth mode must be on the wire: {s}");
		assert!(!s.contains("pat_secret_id"), "secret id leaked onto the wire: {s}");
		assert!(!s.contains('7'), "secret id value leaked onto the wire: {s}");
	}

	#[test]
	fn reporting_summary_reports_app_mode_for_pat_less_destinations() {
		let dest = ReportingDestination::GithubIssue {
			target_owner: text("acme"),
			target_repo: text("tracker"),
			pat_secret_id: None,
		};
		let summary = ReportingSummary::from(&dest);
		assert_eq!(
			summary,
			ReportingSummary::GithubIssue {
				target_owner: text("acme"),
				target_repo: text("tracker"),
				auth: GithubReportingAuth::App,
			}
		);
		let s = serde_json::to_string(&summary).unwrap();
		assert!(s.contains(r#""auth":"app""#), "auth mode must be on the wire: {s}");
	}

	#[test]
	fn reporting_auth_default_is_pat() {
		// The CLI's named listing decoder owns omission -> default admission.
		assert_eq!(GithubReportingAuth::default(), GithubReportingAuth::Pat);
	}

	#[test]
	fn reporting_setup_without_a_pat_omits_the_wire_field() {
		// Server input omission/null behavior belongs to its named decoder.
		let setup = ReportingSetup::GithubIssue {
			target_owner: text("acme"),
			target_repo: text("t"),
			github_pat: None,
		};
		let s = serde_json::to_string(&setup).unwrap();
		assert!(!s.contains("github_pat"), "app mode must not send a null PAT: {s}");
		assert_eq!(
			serde_json::from_str::<serde_json::Value>(&s).unwrap(),
			json!({
				"kind":"github_issue","target_owner":"acme","target_repo":"t"
			})
		);
	}

	#[test]
	fn reporting_summary_preserves_email_and_manual() {
		let email = ReportingDestination::Email {
			to: vec![text("sec@acme.test")],
			from: Some(text("loupe@acme.test")),
			subject_prefix: Some(text("[loupe]")),
		};
		assert_eq!(
			ReportingSummary::from(&email),
			ReportingSummary::Email {
				to: vec![text("sec@acme.test")],
				from: Some(text("loupe@acme.test")),
				subject_prefix: Some(text("[loupe]")),
			}
		);
		assert_eq!(ReportingSummary::from(&ReportingDestination::Manual), ReportingSummary::Manual);
	}

	#[test]
	fn repo_summary_preserves_every_wire_field_with_reporting() {
		let summary = summary_with_reporting(Some(ReportingSummary::GithubIssue {
			target_owner: text("acme"),
			target_repo: text("tracker"),
			auth: GithubReportingAuth::App,
		}));
		let s = serde_json::to_string(&summary).unwrap();
		assert_eq!(
			serde_json::from_str::<serde_json::Value>(&s).unwrap(),
			json!({
				"id":1,"clone_url":"https://github.com/acme/widget.git","host":"github.com","owner":"acme","repo":"widget",
				"default_branch":"main","scan_interval_seconds":3600,"verification_enabled":true,"created_at":42,
				"reporting":{"kind":"github_issue","target_owner":"acme","target_repo":"tracker","auth":"app"}
			})
		);
		assert!(!s.contains("pat_secret_id"));
	}

	#[test]
	fn repo_summary_omits_absent_reporting() {
		// CLI input admission of missing reporting is checked by its named decoder.
		let summary = summary_with_reporting(None);
		let s = serde_json::to_string(&summary).unwrap();
		assert!(!s.contains("reporting"), "absent reporting should not be serialized: {s}");
		assert!(!serde_json::from_str::<serde_json::Value>(&s)
			.unwrap()
			.as_object()
			.unwrap()
			.contains_key("reporting"));
	}

	#[test]
	fn register_worker_response_carries_pem_triple() {
		let resp = RegisterWorkerResponse {
			protocol_version: PROTOCOL_VERSION,
			worker_id: 17,
			client_cert_pem: "-----BEGIN CERTIFICATE-----\n...".into(),
			client_key_pem: loupe_provenance::Secret::new(
				"-----BEGIN PRIVATE KEY-----\n...".into(),
			),
			ca_cert_pem: loupe_provenance::Secret::new("-----BEGIN CERTIFICATE-----\n...".into()),
		};
		let s = serde_json::to_string(&resp).unwrap();
		let back: RegisterWorkerResponse = serde_json::from_str(&s).unwrap();
		assert_eq!(resp.protocol_version, back.protocol_version);
		assert_eq!(resp.worker_id, back.worker_id);
		assert_eq!(resp.client_cert_pem, back.client_cert_pem);
		assert_eq!(resp.client_key_pem.expose(), back.client_key_pem.expose());
		assert_eq!(resp.ca_cert_pem.expose(), back.ca_cert_pem.expose());
	}

	#[test]
	fn rotate_repo_pat_request_does_not_use_storage_ids() {
		let req = RotateRepoPatRequest {
			protocol_version: PROTOCOL_VERSION,
			github_pat: loupe_provenance::Secret::new("ghp_new".into()),
		};
		let s = serde_json::to_string(&req).unwrap();
		assert!(s.contains("github_pat"));
		assert!(!s.contains("pat_secret_id"));
		let back: RotateRepoPatRequest = serde_json::from_str(&s).unwrap();
		assert_eq!(req.protocol_version, back.protocol_version);
		assert_eq!(req.github_pat.expose(), back.github_pat.expose());
	}

	#[test]
	fn set_repo_github_reporting_request_does_not_use_storage_ids() {
		let req = SetRepoGithubReportingRequest {
			protocol_version: PROTOCOL_VERSION,
			target_owner: text("acme"),
			target_repo: text("tracker"),
			github_pat: Some(loupe_provenance::Secret::new("ghp_new".into())),
		};
		let s = serde_json::to_string(&req).unwrap();
		assert!(s.contains("github_pat"));
		assert!(!s.contains("pat_secret_id"));
		assert_eq!(
			serde_json::from_str::<serde_json::Value>(&s).unwrap(),
			json!({
				"protocol_version":PROTOCOL_VERSION,"target_owner":"acme","target_repo":"tracker","github_pat":"ghp_new"
			})
		);
	}
}

#[cfg(test)]
mod tls_consumer_tests {
	use super::*;

	#[test]
	fn tls_consumer_worker_registration_debug_redacts_private_pem() {
		let response: RegisterWorkerResponse = serde_json::from_str(r#"{"protocol_version":1,"worker_id":42,"client_cert_pem":"public-client-cert","client_key_pem":"FAKE_REGISTERED_TLS_PRIVATE","ca_cert_pem":"public-ca-cert"}"#).unwrap();
		for rendered in [format!("{response:?}"), format!("{response:#?}")] {
			assert!(rendered.contains("public-client-cert"));
			assert!(rendered.contains("42"));
			assert!(
				!rendered.contains("FAKE_REGISTERED_TLS_PRIVATE"),
				"registration Debug disclosed the private key"
			);
		}
	}

	#[test]
	fn worker_registration_wire_preserves_all_pem_bytes_and_metadata() {
		let wire = serde_json::json!({"protocol_version": 1, "worker_id": 42,
			"client_cert_pem": "public-client-cert\n", "client_key_pem": "FAKE_PRIVATE_\"\\\n💡", "ca_cert_pem": "public-ca-cert\n"});
		let response: RegisterWorkerResponse = serde_json::from_value(wire.clone()).unwrap();
		assert_eq!(serde_json::to_value(&response).unwrap(), wire);
		let pretty = serde_json::to_string_pretty(&response).unwrap();
		assert_eq!(serde_json::from_str::<serde_json::Value>(&pretty).unwrap(), wire);
	}
}
