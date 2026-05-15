//! GitHub issue reporter — hand-rolled `reqwest` POST to
//! `/repos/{owner}/{repo}/issues`. Deliberately not using `octocrab` to
//! keep the dependency tree minimal; the integration we need is small
//! enough to maintain ourselves.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use loupe_core::{Finding, ReportingDestination};
use loupe_storage::repos::RepoRow;
use reqwest::Url;
use serde::Serialize;

use super::{DispatchReceipt, Reporter};

const DEFAULT_API_BASE: &str = "https://api.github.com";
const MAX_TITLE_CHARS: usize = 100;

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
			_ => anyhow::bail!("GithubReporter dispatched against a non-github destination"),
		};
		if findings.is_empty() {
			return Ok(DispatchReceipt { kind: self.kind(), external_id: None });
		}

		let mut external_ids = Vec::new();
		for finding in findings {
			let url = self
				.api_base
				.join(&format!("/repos/{target_owner}/{target_repo}/issues"))
				.map_err(|e| anyhow!("building issues URL: {e}"))?;
			let title = render_title(finding);
			let body = render_body(repo, finding);
			let labels = vec!["loupe".to_owned(), finding.severity.as_str().to_owned()];

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

fn render_title(finding: &Finding) -> String {
	format!("{}: {}", finding.severity, compact_title(&finding.title))
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

fn render_body(repo: &RepoRow, finding: &Finding) -> String {
	let mut out = String::new();
	out.push_str(&format!(
		"This issue tracks one loupe finding in `{}/{}` (clone url `{}`).\n\n",
		repo.owner, repo.repo, repo.clone_url
	));
	out.push_str("## Finding\n\n");
	out.push_str(&format!("- title: {}\n", finding.title));
	out.push_str(&format!("- severity: `{}`\n", finding.severity));
	if let Some(location) = render_location(finding) {
		out.push_str(&format!("- location: {location}\n"));
	}
	if let Some(cwe) = &finding.cwe {
		out.push_str(&format!("- cwe: {cwe}\n"));
	}
	out.push_str(&format!("- scanner: `{}`\n", finding.scanner_id));
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
				pat_secret_id: 7,
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
	fn title_is_per_finding_without_loupe_prefix() {
		assert_eq!(render_title(&finding()), "high: Out-of-bounds index in idx");
	}

	#[test]
	fn body_describes_one_finding_not_a_scan_batch() {
		let body = render_body(&repo(), &finding());
		assert!(body.contains("This issue tracks one loupe finding"));
		assert!(body.contains("- title: Out-of-bounds index in idx"));
		assert!(body.contains("- severity: `high`"));
		assert!(body.contains("- location: `src/lib.rs:4-6`"));
		assert!(body.contains("## Proof of Concept"));
		assert!(body.contains("## Suggested Fix"));
		assert!(!body.contains("finished a scan"));
		assert!(!body.contains("Findings:"));
	}
}
