//! GitHub issue reporter — hand-rolled `reqwest` POST to
//! `/repos/{owner}/{repo}/issues`. Deliberately not using `octocrab` to
//! keep the dependency tree minimal; the integration we need is small
//! enough to maintain ourselves.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use loupe_core::{Finding, ReportingDestination, Severity};
use loupe_storage::repos::RepoRow;
use reqwest::Url;
use serde::Serialize;

use super::{DispatchReceipt, Reporter};

const DEFAULT_API_BASE: &str = "https://api.github.com";

pub struct GithubReporter {
	http: reqwest::Client,
	api_base: Url,
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
		let http = reqwest::Client::builder()
			.user_agent("loupe-server/0.0.0")
			.use_rustls_tls()
			.build()
			.context("building GithubReporter http client")?;
		Ok(Self { http, api_base })
	}
}

#[derive(Serialize)]
struct CreateIssueBody<'a> {
	title: &'a str,
	body: String,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	labels: Vec<String>,
}

#[async_trait]
impl Reporter for GithubReporter {
	fn kind(&self) -> &'static str {
		"github_issue"
	}

	async fn dispatch(
		&self, repo: &RepoRow, findings: &[Finding], pat: &str,
	) -> Result<DispatchReceipt> {
		let (target_owner, target_repo) = match &repo.reporting {
			ReportingDestination::GithubIssue { target_owner, target_repo, .. } => {
				(target_owner.as_str(), target_repo.as_str())
			},
		};
		if findings.is_empty() {
			return Ok(DispatchReceipt { kind: self.kind(), external_id: None });
		}

		let url = self
			.api_base
			.join(&format!("/repos/{target_owner}/{target_repo}/issues"))
			.map_err(|e| anyhow!("building issues URL: {e}"))?;
		let title = render_title(repo, findings);
		let body = render_body(repo, findings);
		let labels = vec!["loupe".to_owned(), max_severity(findings).as_str().to_owned()];

		let resp = self
			.http
			.post(url)
			.bearer_auth(pat)
			.header("Accept", "application/vnd.github+json")
			.header("X-GitHub-Api-Version", "2022-11-28")
			.json(&CreateIssueBody { title: &title, body, labels })
			.send()
			.await
			.context("posting github issue")?;
		let status = resp.status();
		if !status.is_success() {
			let body = resp.text().await.unwrap_or_default();
			anyhow::bail!("github returned {} when opening issue: {}", status, body);
		}
		let json: serde_json::Value = resp.json().await.context("parsing issue response")?;
		let external_id = json.get("number").and_then(|v| v.as_i64()).map(|n| n.to_string());
		Ok(DispatchReceipt { kind: self.kind(), external_id })
	}
}

fn render_title(repo: &RepoRow, findings: &[Finding]) -> String {
	let count = findings.len();
	let max_sev = max_severity(findings);
	format!("[loupe] {count} {max_sev} finding(s) in {}/{}", repo.owner, repo.repo)
}

fn render_body(repo: &RepoRow, findings: &[Finding]) -> String {
	let mut out = String::new();
	out.push_str(&format!(
		"loupe has finished a scan of `{}/{}` (clone url `{}`).\n\n",
		repo.owner, repo.repo, repo.clone_url
	));
	out.push_str(&format!("**Findings: {}**\n\n", findings.len()));
	for (i, f) in findings.iter().enumerate() {
		out.push_str(&format!("### {}. {} ({})\n", i + 1, f.title, f.severity));
		if let Some(path) = &f.file_path {
			out.push_str(&format!("- file: `{path}`"));
			if let Some(line) = f.line_start {
				out.push_str(&format!(":{line}"));
			}
			out.push('\n');
		}
		if let Some(cwe) = &f.cwe {
			out.push_str(&format!("- cwe: {cwe}\n"));
		}
		out.push_str(&format!("- scanner: `{}`\n", f.scanner_id));
		out.push_str(&format!("- fingerprint: `{}`\n\n", f.fingerprint));
		out.push_str(&f.description);
		out.push_str("\n\n");
		if let Some(patch) = &f.patch_unified {
			out.push_str("```diff\n");
			out.push_str(patch);
			out.push_str("\n```\n\n");
		}
	}
	out
}

fn max_severity(findings: &[Finding]) -> Severity {
	findings.iter().map(|f| f.severity).max().unwrap_or(Severity::Info)
}
