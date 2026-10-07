//! GitHub issue reporter — hand-rolled `reqwest` POST to
//! `/repos/{owner}/{repo}/issues`. Deliberately not using `octocrab` to
//! keep the dependency tree minimal; the integration we need is small
//! enough to maintain ourselves.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use loupe_core::report_limits::GITHUB_ISSUE_BODY_MAX_CHARS;
use loupe_core::{format_finding_id, Finding, ReportingDestination, Severity};
use loupe_storage::repos::RepoRow;
use reqwest::{StatusCode, Url};
use serde::Serialize;

use super::github_app::{self, GithubAppInfo, GithubAppKey, InstallationTokens};
use super::{DispatchReceipt, ReportFinding, Reporter, ReporterCredential};

const DEFAULT_API_BASE: &str = "https://api.github.com";
const MAX_TITLE_CHARS: usize = 100;
/// Upper bounds on one GitHub API call; see `with_base` for why.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub struct GithubReporter {
	http: reqwest::Client,
	api_base: Url,
	/// Installation tokens minted for app-mode repos, reused across
	/// dispatches to the same tracker until shortly before they expire.
	tokens: InstallationTokens,
}

impl GithubReporter {
	/// Build the default reporter that talks to api.github.com.
	pub fn new() -> Result<Self> {
		Self::with_base(DEFAULT_API_BASE)
	}

	/// Build a reporter pointed at a custom API root. Used by the
	/// integration tests' fake-github stub.
	pub fn with_base(base: &str) -> Result<Self> {
		let api_base = base.parse::<Url>().context("parsing GithubReporter API base URL")?;
		// Bounded waits matter here: the installation-token cache holds
		// its lock across lookup + mint so concurrent dispatches share one
		// token, which means a GitHub call that never answers would stall
		// every app-mode dispatch (and the worker `complete` handlers that
		// await them) instead of just this one.
		let http = reqwest::Client::builder()
			.user_agent("loupe-server/0.0.0")
			.use_rustls_tls()
			.connect_timeout(CONNECT_TIMEOUT)
			.timeout(REQUEST_TIMEOUT)
			.build()
			.context("building GithubReporter http client")?;
		Ok(Self { http, api_base, tokens: InstallationTokens::default() })
	}

	/// Prove a GitHub App credential works by fetching the app it belongs
	/// to. Used by the credential route so a bad key or app id fails at
	/// configuration time rather than at the first dispatch.
	pub async fn verify_app(&self, key: &GithubAppKey) -> Result<GithubAppInfo> {
		github_app::fetch_app(&self.http, &self.api_base, key).await
	}

	/// Resolve the bearer token for one dispatch: the stored PAT as-is, or
	/// a repo-scoped installation token minted from the GitHub App.
	async fn bearer_for(
		&self, credential: &ReporterCredential, target_owner: &str, target_repo: &str,
	) -> Result<String> {
		match credential {
			ReporterCredential::GithubPat(pat) => Ok(pat.clone()),
			ReporterCredential::GithubApp(key) => {
				self.tokens
					.token_for(&self.http, &self.api_base, key, target_owner, target_repo)
					.await
			},
			ReporterCredential::None => {
				anyhow::bail!("GithubReporter dispatched without a PAT or GitHub App credential")
			},
		}
	}

	/// POST `body` to `url` with the session's current bearer. In app
	/// mode a 401 means the cached installation token is no longer good
	/// (revoked, or expired ahead of the cached deadline), so it is
	/// dropped, a fresh one is minted into the session, and the request
	/// is sent once more. A second 401 is returned to the caller like any
	/// other failure. A PAT has nothing to refresh, so its 401 is
	/// returned as-is.
	async fn post_with_refresh<B: Serialize>(
		&self, url: Url, body: &B, session: &mut DispatchSession<'_>, what: &str,
	) -> Result<reqwest::Response> {
		let resp =
			self.post_json(url.clone(), body, &session.bearer).await.context(what.to_owned())?;
		let ReporterCredential::GithubApp(key) = session.credential else {
			return Ok(resp);
		};
		if resp.status() != StatusCode::UNAUTHORIZED {
			return Ok(resp);
		}
		let (owner, repo) = (session.target_owner, session.target_repo);
		tracing::warn!(
			target = %format!("{owner}/{repo}"),
			"github rejected the cached installation token; minting a fresh one and retrying"
		);
		self.tokens.invalidate(key.app_id(), owner, repo).await;
		session.bearer = self.bearer_for(session.credential, owner, repo).await?;
		self.post_json(url, body, &session.bearer).await.context(what.to_owned())
	}

	async fn post_json<B: Serialize>(
		&self, url: Url, body: &B, bearer: &str,
	) -> reqwest::Result<reqwest::Response> {
		github_app::github_request(self.http.post(url), bearer).json(body).send().await
	}
}

/// Everything one dispatch needs to authenticate against its tracker:
/// the credential it started from and the bearer currently in use,
/// which `post_with_refresh` may replace mid-dispatch.
struct DispatchSession<'a> {
	credential: &'a ReporterCredential,
	target_owner: &'a str,
	target_repo: &'a str,
	bearer: String,
}

#[derive(Serialize)]
struct CreateIssueBody<'a> {
	title: &'a str,
	body: String,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	labels: Vec<String>,
}

#[derive(Serialize)]
struct CreateLabelBody<'a> {
	name: &'a str,
	color: &'a str,
	description: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LabelSpec {
	name: &'static str,
	color: &'static str,
	description: &'static str,
}

#[async_trait]
impl Reporter for GithubReporter {
	fn kind(&self) -> &'static str {
		"github_issue"
	}

	async fn dispatch(
		&self, repo: &RepoRow, findings: &[ReportFinding], credential: &ReporterCredential,
	) -> Result<DispatchReceipt> {
		let (target_owner, target_repo) = match &repo.reporting {
			ReportingDestination::GithubIssue { target_owner, target_repo, .. } => {
				(target_owner.as_str(), target_repo.as_str())
			},
			_ => anyhow::bail!("GithubReporter dispatched against a non-github destination"),
		};
		if findings.is_empty() {
			return Ok(DispatchReceipt { kind: self.kind(), external_id: None });
		}
		// Reject oversize before any GitHub call, including app-token
		// lookup and minting. Reuse the validated bodies when posting.
		let bodies = findings
			.iter()
			.map(|report_finding| {
				let body = render_body(repo, report_finding);
				validate_body(&body).map_err(anyhow::Error::msg)?;
				Ok(body)
			})
			.collect::<Result<Vec<_>>>()?;
		// One bearer per dispatch: labels and issues share it, and an
		// app-mode dispatch mints at most one installation token up front
		// (plus one more if GitHub rejects it mid-way; see
		// `post_with_refresh`).
		let bearer = self.bearer_for(credential, target_owner, target_repo).await?;
		let mut session = DispatchSession { credential, target_owner, target_repo, bearer };

		let mut external_ids = Vec::new();
		for (report_finding, body) in findings.iter().zip(bodies) {
			let finding = &report_finding.finding;
			let severity = severity_label(finding.severity);
			self.ensure_label(&mut session, severity).await?;
			let title = render_title(finding);
			let labels = vec!["loupe".to_owned(), severity.name.to_owned()];

			let url = self
				.api_base
				.join(&format!("/repos/{target_owner}/{target_repo}/issues"))
				.map_err(|e| anyhow!("building issues URL: {e}"))?;
			let resp = self
				.post_with_refresh(
					url,
					&CreateIssueBody { title: &title, body, labels },
					&mut session,
					"posting github issue",
				)
				.await?;
			let status = resp.status();
			if !status.is_success() {
				let body = resp.text().await.unwrap_or_default();
				anyhow::bail!("github returned {} when opening issue: {}", status, body);
			}
			let json: serde_json::Value = resp.json().await.context("parsing issue response")?;
			if let Some(external_id) =
				json.get("number").and_then(|v| v.as_i64()).map(|n| n.to_string())
			{
				external_ids.push(external_id);
			}
		}
		let external_id = (!external_ids.is_empty()).then(|| external_ids.as_slice().join(","));
		Ok(DispatchReceipt { kind: self.kind(), external_id })
	}
}

impl GithubReporter {
	async fn ensure_label(
		&self, session: &mut DispatchSession<'_>, label: LabelSpec,
	) -> Result<()> {
		let url = self
			.api_base
			.join(&format!("/repos/{}/{}/labels", session.target_owner, session.target_repo))
			.map_err(|e| anyhow!("building labels URL: {e}"))?;
		let resp = self
			.post_with_refresh(
				url,
				&CreateLabelBody {
					name: label.name,
					color: label.color,
					description: label.description,
				},
				session,
				&format!("creating github label {}", label.name),
			)
			.await?;
		let status = resp.status();
		if status.is_success() {
			return Ok(());
		}
		let body = resp.text().await.unwrap_or_default();
		if status == StatusCode::UNPROCESSABLE_ENTITY && body.contains("already_exists") {
			return Ok(());
		}
		anyhow::bail!("github returned {} when creating label {}: {}", status, label.name, body);
	}
}

fn severity_label(severity: Severity) -> LabelSpec {
	match severity {
		Severity::Info => LabelSpec {
			name: "severity:info",
			color: "cfd3d7",
			description: "Loupe severity: info",
		},
		Severity::Low => {
			LabelSpec { name: "severity:low", color: "fef2c0", description: "Loupe severity: low" }
		},
		Severity::Medium => LabelSpec {
			name: "severity:medium",
			color: "fbca04",
			description: "Loupe severity: medium",
		},
		Severity::High => LabelSpec {
			name: "severity:high",
			color: "d93f0b",
			description: "Loupe severity: high",
		},
		Severity::Critical => LabelSpec {
			name: "severity:critical",
			color: "b60205",
			description: "Loupe severity: critical",
		},
	}
}

fn render_title(finding: &Finding) -> String {
	compact_title(&finding.title)
}

fn compact_title(raw: &str) -> String {
	let mut compact = String::new();
	for word in raw.split_whitespace() {
		if !compact.is_empty() {
			compact.push(' ');
		}
		compact.push_str(word);
	}
	if compact.is_empty() {
		compact.push_str("Untitled finding");
	}
	if compact.chars().count() <= MAX_TITLE_CHARS {
		return compact;
	}

	let mut truncated: String = compact.chars().take(MAX_TITLE_CHARS - 3).collect();
	while truncated.ends_with(char::is_whitespace) {
		truncated.pop();
	}
	truncated.push_str("...");
	truncated
}

pub(crate) fn validate_finding_body(
	repo: &RepoRow, report_finding: &ReportFinding,
) -> Result<(), String> {
	validate_body(&render_body(repo, report_finding))
}

fn validate_body(body: &str) -> Result<(), String> {
	let chars = body.chars().count();
	if chars > GITHUB_ISSUE_BODY_MAX_CHARS {
		return Err(format!(
			"GitHub issue body is too long: {chars} characters; maximum is \
			 {GITHUB_ISSUE_BODY_MAX_CHARS} including metadata and Markdown. \
			 Shorten the report or diffs and retry; no issue was submitted."
		));
	}
	Ok(())
}

fn render_body(repo: &RepoRow, report_finding: &ReportFinding) -> String {
	let finding = &report_finding.finding;
	let mut out = String::new();
	out.push_str(&format!("## Finding {}\n\n", format_finding_id(report_finding.id)));
	out.push_str(&format!("- repo: `{}/{}` (`{}`)\n", repo.owner, repo.repo, repo.clone_url));
	match &report_finding.reviewed_revision {
		Some(revision) => out.push_str(&format!("- reviewed revision: `{revision}`\n")),
		None => out.push_str("- reviewed revision: _not recorded_\n"),
	}
	out.push_str(&format!("- title: {}\n", finding.title));
	out.push_str(&format!("- severity: `{}`\n", finding.severity));
	if let Some(location) = render_location(finding) {
		out.push_str(&format!("- location: {location}\n"));
	}
	if let Some(cwe) = &finding.cwe {
		out.push_str(&format!("- cwe: {cwe}\n"));
	}
	out.push_str(&format!("- fingerprint: `{}`\n\n", finding.fingerprint));

	out.push_str("## Description\n\n");
	out.push_str(&finding.description);
	out.push_str("\n\n");

	if let Some(poc) = &finding.poc_unified {
		out.push_str("## Proof of Concept\n\n```diff\n");
		out.push_str(poc);
		out.push_str("\n```\n\n");
	}

	if let Some(patch) = &finding.patch_unified {
		out.push_str("## Suggested Fix\n\n```diff\n");
		out.push_str(patch);
		out.push_str("\n```\n\n");
	}

	out.push_str(
		"_This finding was discovered by [Project Loupe](https://github.com/project-loupe/loupe)._\n",
	);

	out
}

fn render_location(finding: &Finding) -> Option<String> {
	let path = finding.file_path.as_ref()?;
	let suffix = match (finding.line_start, finding.line_end) {
		(Some(start), Some(end)) if end != start => format!(":{start}-{end}"),
		(Some(start), _) => format!(":{start}"),
		_ => String::new(),
	};
	Some(format!("`{path}{suffix}`"))
}

#[cfg(test)]
mod tests {
	use loupe_core::Severity;

	use super::*;

	fn repo() -> RepoRow {
		RepoRow {
			id: 1,
			clone_url: "https://github.com/acme/widget.git".into(),
			host: "github.com".into(),
			owner: "acme".into(),
			repo: "widget".into(),
			default_branch: None,
			scan_interval_seconds: None,
			scanner_config: serde_json::Value::Null,
			reporting: ReportingDestination::GithubIssue {
				target_owner: "acme".into(),
				target_repo: "tracker".into(),
				pat_secret_id: Some(7),
			},
			verification_enabled: false,
			require_approval: None,
			last_scanned_sha: None,
			last_scanned_at: None,
			created_at: 0,
			disabled_at: None,
		}
	}

	fn finding() -> Finding {
		Finding {
			scanner_id: "llm-code-review".into(),
			severity: Severity::High,
			title: "Out-of-bounds index in idx".into(),
			description: "The idx helper indexes without checking bounds.".into(),
			file_path: Some("src/lib.rs".into()),
			line_start: Some(4),
			line_end: Some(6),
			cwe: Some("CWE-129".into()),
			patch_unified: Some("--- a/src/lib.rs\n+++ b/src/lib.rs\n".into()),
			poc_unified: Some("--- a/src/lib.rs\n+++ b/src/lib.rs\n".into()),
			fingerprint: "fp".into(),
		}
	}

	#[test]
	fn title_is_per_finding_without_loupe_or_severity_prefix() {
		assert_eq!(render_title(&finding()), "Out-of-bounds index in idx");
	}

	#[test]
	fn severity_labels_are_namespaced_and_colored_by_urgency() {
		assert_eq!(
			severity_label(Severity::Info),
			LabelSpec {
				name: "severity:info",
				color: "cfd3d7",
				description: "Loupe severity: info"
			}
		);
		assert_eq!(severity_label(Severity::Low).name, "severity:low");
		assert_eq!(severity_label(Severity::Low).color, "fef2c0");
		assert_eq!(severity_label(Severity::Medium).color, "fbca04");
		assert_eq!(severity_label(Severity::High).color, "d93f0b");
		assert_eq!(severity_label(Severity::Critical).color, "b60205");
	}

	#[tokio::test]
	async fn oversized_issue_is_rejected_before_any_github_request() {
		use std::sync::atomic::{AtomicUsize, Ordering};
		use std::sync::Arc;
		let requests = Arc::new(AtomicUsize::new(0));
		let count = requests.clone();
		let app = axum::Router::new().fallback(move || {
			let count = count.clone();
			async move {
				count.fetch_add(1, Ordering::SeqCst);
				axum::Json(serde_json::json!({"number": 7}))
			}
		});
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let reporter =
			GithubReporter::with_base(&format!("http://{}", listener.local_addr().unwrap()))
				.unwrap();
		let stub = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
		let mut report =
			ReportFinding { id: 1234, finding: finding(), reviewed_revision: Some("a".repeat(40)) };
		report.finding.description.clear();
		let overhead = render_body(&repo(), &report).chars().count();
		report.finding.description = "é".repeat(65_536 - overhead);
		assert!(
			render_body(&repo(), &report).len() > 65_536,
			"Unicode bytes must not set the limit"
		);
		reporter
			.dispatch(&repo(), &[report.clone()], &ReporterCredential::GithubPat("pat".into()))
			.await
			.expect("exact character limit is accepted");
		assert_eq!(requests.load(Ordering::SeqCst), 2);
		report.finding.description.push('é');
		let error = reporter
			.dispatch(&repo(), &[report.clone()], &ReporterCredential::GithubPat("pat".into()))
			.await
			.unwrap_err();
		assert!(error.to_string().contains("65536"), "local size rejection: {error:#}");
		assert!(error.to_string().contains("retry"), "actionable error: {error:#}");
		assert_eq!(requests.load(Ordering::SeqCst), 2, "oversize must cause no GitHub requests");
		let credential = app_credential();
		let error = reporter.dispatch(&repo(), &[report], &credential).await.unwrap_err();
		assert!(error.to_string().contains("65536"), "app-mode local size rejection: {error:#}");
		assert_eq!(
			requests.load(Ordering::SeqCst),
			2,
			"oversize must not request an installation token"
		);
		stub.abort();
	}

	#[test]
	fn body_describes_one_finding_not_a_scan_batch() {
		let body = render_body(
			&repo(),
			&ReportFinding {
				id: 1234,
				finding: finding(),
				reviewed_revision: Some("abc123".into()),
			},
		);
		assert!(body.starts_with("## Finding LUP-1234\n\n"), "body: {body}");
		assert!(body.contains("- repo: `acme/widget` (`https://github.com/acme/widget.git`)"));
		assert!(body.contains("- reviewed revision: `abc123`"));
		assert!(body.contains("- title: Out-of-bounds index in idx"));
		assert!(body.contains("- severity: `high`"));
		assert!(body.contains("- location: `src/lib.rs:4-6`"));
		assert!(body.contains("## Proof of Concept"));
		assert!(body.contains("## Suggested Fix"));
		assert!(body.ends_with(
			"_This finding was discovered by [Project Loupe](https://github.com/project-loupe/loupe)._\n"
		));
		assert!(!body.contains("This issue tracks one loupe finding"));
		assert!(!body.contains("finished a scan"));
		assert!(!body.contains("Findings:"));
	}

	#[test]
	fn body_omits_scanner_metadata() {
		let body = render_body(
			&repo(),
			&ReportFinding { id: 1234, finding: finding(), reviewed_revision: None },
		);
		assert!(!body.contains("- scanner:"), "body must omit the scanner header: {body}");
	}

	/// Stub GitHub for the dispatch path: mints numbered installation
	/// tokens and rejects issue POSTs that still carry the first one, the
	/// way GitHub does once a token has been revoked or has expired.
	mod stub {
		use std::net::SocketAddr;
		use std::sync::{Arc, Mutex};

		use axum::extract::{Path, State};
		use axum::http::{HeaderMap, StatusCode};
		use axum::routing::{get, post};
		use axum::{Json, Router};

		#[derive(Clone, Default)]
		pub struct Github {
			pub mints: Arc<Mutex<usize>>,
			/// Bearer tokens seen on label POSTs, in order.
			pub label_auths: Arc<Mutex<Vec<String>>>,
			/// Bearer tokens seen on issue POSTs, in order.
			pub issue_auths: Arc<Mutex<Vec<String>>>,
			/// Bearers the stub answers with 401.
			pub rejected: Arc<Mutex<Vec<String>>>,
		}

		fn bearer(headers: &HeaderMap) -> String {
			headers
				.get(axum::http::header::AUTHORIZATION)
				.and_then(|v| v.to_str().ok())
				.and_then(|v| v.strip_prefix("Bearer "))
				.unwrap_or("")
				.to_owned()
		}

		async fn installation() -> Json<serde_json::Value> {
			Json(serde_json::json!({"id": 777}))
		}

		async fn mint(State(gh): State<Github>) -> (StatusCode, Json<serde_json::Value>) {
			let n = {
				let mut mints = gh.mints.lock().unwrap();
				*mints += 1;
				*mints
			};
			(
				StatusCode::CREATED,
				Json(
					serde_json::json!({"token": format!("ghs_{n}"), "expires_at": "2099-01-01T00:00:00Z"}),
				),
			)
		}

		async fn label(
			State(gh): State<Github>, Path((_o, _r)): Path<(String, String)>, headers: HeaderMap,
			Json(body): Json<serde_json::Value>,
		) -> (StatusCode, Json<serde_json::Value>) {
			let auth = bearer(&headers);
			gh.label_auths.lock().unwrap().push(auth.clone());
			if gh.rejected.lock().unwrap().contains(&auth) {
				return (
					StatusCode::UNAUTHORIZED,
					Json(serde_json::json!({"message": "Bad credentials"})),
				);
			}
			(StatusCode::CREATED, Json(body))
		}

		async fn issue(
			State(gh): State<Github>, Path((_o, _r)): Path<(String, String)>, headers: HeaderMap,
		) -> (StatusCode, Json<serde_json::Value>) {
			let auth = bearer(&headers);
			gh.issue_auths.lock().unwrap().push(auth.clone());
			if gh.rejected.lock().unwrap().contains(&auth) {
				return (
					StatusCode::UNAUTHORIZED,
					Json(serde_json::json!({"message": "Bad credentials"})),
				);
			}
			(StatusCode::CREATED, Json(serde_json::json!({"number": 9})))
		}

		pub async fn spawn() -> (SocketAddr, Github) {
			let gh = Github::default();
			let app = Router::new()
				.route("/repos/{owner}/{repo}/installation", get(installation))
				.route("/app/installations/{id}/access_tokens", post(mint))
				.route("/repos/{owner}/{repo}/labels", post(label))
				.route("/repos/{owner}/{repo}/issues", post(issue))
				.with_state(gh.clone());
			let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
			let addr = listener.local_addr().unwrap();
			tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
			(addr, gh)
		}
	}

	fn app_mode_repo() -> RepoRow {
		let mut repo = repo();
		repo.reporting = ReportingDestination::GithubIssue {
			target_owner: "acme".into(),
			target_repo: "tracker".into(),
			pat_secret_id: None,
		};
		repo
	}

	fn app_credential() -> ReporterCredential {
		ReporterCredential::GithubApp(Box::new(
			GithubAppKey::from_pem(42, super::github_app::testing::APP_PRIVATE_KEY_PEM).unwrap(),
		))
	}

	fn one_finding() -> Vec<ReportFinding> {
		vec![ReportFinding { id: 1, finding: finding(), reviewed_revision: None }]
	}

	#[tokio::test]
	async fn app_mode_dispatch_mints_a_fresh_token_after_a_401_and_retries_once() {
		let (addr, gh) = stub::spawn().await;
		let reporter = GithubReporter::with_base(&format!("http://{addr}")).unwrap();
		let credential = app_credential();

		// Warm the cache, then have GitHub start rejecting that token.
		reporter.dispatch(&app_mode_repo(), &one_finding(), &credential).await.unwrap();
		assert_eq!(*gh.mints.lock().unwrap(), 1);
		gh.rejected.lock().unwrap().push("ghs_1".into());

		let receipt =
			reporter.dispatch(&app_mode_repo(), &one_finding(), &credential).await.unwrap();
		assert_eq!(receipt.external_id.as_deref(), Some("9"));
		assert_eq!(*gh.mints.lock().unwrap(), 2, "exactly one re-mint after the 401");
		// Second dispatch: the label POST got the stale token, was refused,
		// and was retried with the fresh one; the issue went straight out
		// with the fresh token.
		let label_auths = gh.label_auths.lock().unwrap().clone();
		assert_eq!(label_auths, vec!["ghs_1", "ghs_1", "ghs_2"], "label auths: {label_auths:?}");
		let issue_auths = gh.issue_auths.lock().unwrap().clone();
		assert_eq!(issue_auths, vec!["ghs_1", "ghs_2"], "issue auths: {issue_auths:?}");

		// A token that is refused even when freshly minted fails as before.
		gh.rejected.lock().unwrap().push("ghs_2".into());
		gh.rejected.lock().unwrap().push("ghs_3".into());
		let err = reporter
			.dispatch(&app_mode_repo(), &one_finding(), &credential)
			.await
			.unwrap_err()
			.to_string();
		assert!(err.contains("401"), "error: {err}");
		assert_eq!(*gh.mints.lock().unwrap(), 3, "one re-mint per dispatch, never a loop");
	}

	#[tokio::test]
	async fn pat_mode_dispatch_does_not_retry_a_401() {
		let (addr, gh) = stub::spawn().await;
		let reporter = GithubReporter::with_base(&format!("http://{addr}")).unwrap();
		gh.rejected.lock().unwrap().push("ghp_stale".into());

		let err = reporter
			.dispatch(&repo(), &one_finding(), &ReporterCredential::GithubPat("ghp_stale".into()))
			.await
			.unwrap_err()
			.to_string();
		assert!(err.contains("401"), "error: {err}");
		assert_eq!(gh.label_auths.lock().unwrap().as_slice(), ["ghp_stale"]);
		assert!(gh.issue_auths.lock().unwrap().is_empty());
		assert_eq!(*gh.mints.lock().unwrap(), 0, "a PAT never mints anything");
	}
}
