//! LLM verifier scanner — implements `Scanner::verify` only.
//!
//! Used in the cross-model second-opinion path: a `kind=verify` job
//! lands on a worker advertising `verify:llm`, the runner's lease
//! response carries the target Finding, and this scanner asks a
//! (potentially different) LLM backend whether the finding holds up.
//!
//! The scanner intentionally returns an empty `Vec<Finding>` from
//! `scan()` — a verifier is not also a discoverer, even though the
//! trait surface allows it to be. Wiring a verifier worker to also
//! advertise `scan:*` is just a matter of pairing it with another
//! scanner in the runner's scanner list.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use loupe_core::{Finding, Verdict};
use serde::Deserialize;

use crate::llm::prompts::{self, VERIFY};
use crate::llm::{LlmBackend, LlmRequest};
use crate::scanner::{ScanContext, Scanner, VerifyContext};

const SCANNER_ID: &str = "llm-verifier";
const CAPABILITIES: &[&str] = &["verify:llm"];

pub struct LlmVerifierScanner {
	backend: Arc<dyn LlmBackend>,
}

impl LlmVerifierScanner {
	pub fn new(backend: Arc<dyn LlmBackend>) -> Self {
		Self { backend }
	}
}

#[derive(Debug, Deserialize)]
struct VerifyRaw {
	verdict: String,
	#[serde(default)]
	notes: Option<String>,
}

#[async_trait]
impl Scanner for LlmVerifierScanner {
	fn id(&self) -> &'static str {
		SCANNER_ID
	}

	fn capabilities(&self) -> &[&'static str] {
		CAPABILITIES
	}

	async fn scan(&self, _ctx: &ScanContext) -> Result<Vec<Finding>> {
		Ok(Vec::new())
	}

	async fn verify(&self, ctx: &VerifyContext) -> Result<Verdict> {
		let finding_json = serde_json::json!({
			"severity": ctx.finding.severity.as_str(),
			"title": ctx.finding.title,
			"file": ctx.finding.file_path,
			"line_start": ctx.finding.line_start,
			"line_end": ctx.finding.line_end,
			"description": ctx.finding.description,
			"cwe": ctx.finding.cwe,
		});
		let file = ctx.finding.file_path.as_deref().unwrap_or("(unknown)");
		let prompt =
			prompts::render(VERIFY, &[("file", file), ("finding_json", &finding_json.to_string())]);
		let req = LlmRequest {
			prompt,
			workdir: ctx.workdir.clone(),
			timeout: crate::llm::DEFAULT_REQUEST_TIMEOUT,
			cancel: ctx.cancel.clone(),
			repo_id: Some(ctx.repo_id),
		};
		let resp = self.backend.run(req).await?;

		let json = crate::scanners::llm_code_review::extract_json_object(&resp.text)
			.unwrap_or_else(|| resp.text.clone());
		let raw: VerifyRaw = serde_json::from_str(&json).map_err(|e| {
			anyhow::anyhow!(
				"verify response did not parse as VerifyRaw JSON: {e}; got: {}",
				resp.text
			)
		})?;
		Ok(match raw.verdict.as_str() {
			"confirmed" => Verdict::Confirmed { notes: raw.notes },
			"dismissed" => Verdict::Dismissed { notes: raw.notes },
			_ => Verdict::Inconclusive {
				reason: raw.notes.unwrap_or_else(|| "model returned inconclusive".into()),
			},
		})
	}
}

#[cfg(test)]
mod tests {
	use std::path::PathBuf;

	use loupe_core::{Finding, RepoSpec, Severity};
	use tokio_util::sync::CancellationToken;

	use super::*;
	use crate::llm::testing::StubLlmBackend;

	fn ctx() -> VerifyContext {
		VerifyContext {
			workdir: PathBuf::from("/tmp"),
			repo_id: 1,
			repo: RepoSpec {
				host: "github.com".into(),
				owner: "a".into(),
				repo: "b".into(),
				clone_url: "https://github.com/a/b.git".into(),
				branch: None,
			},
			finding: Finding {
				scanner_id: "llm-code-review".into(),
				severity: Severity::High,
				title: "OOB index".into(),
				description: "no bounds check".into(),
				file_path: Some("src/lib.rs".into()),
				line_start: Some(1),
				line_end: Some(1),
				cwe: None,
				patch_unified: None,
				poc_unified: None,
				fingerprint: "fp1".into(),
			},
			config: serde_json::Value::Null,
			cancel: CancellationToken::new(),
		}
	}

	#[tokio::test]
	async fn confirms_when_backend_says_confirmed() {
		let backend = Arc::new(StubLlmBackend::new("stub", |_req: &LlmRequest| {
			Ok(r#"{"verdict":"confirmed","notes":"reproduced"}"#.to_owned())
		}));
		let v = LlmVerifierScanner::new(backend).verify(&ctx()).await.unwrap();
		assert!(matches!(v, Verdict::Confirmed { .. }));
	}

	#[tokio::test]
	async fn dismisses_when_backend_says_dismissed() {
		let backend = Arc::new(StubLlmBackend::new("stub", |_req: &LlmRequest| {
			Ok(r#"{"verdict":"dismissed","notes":"hallucination"}"#.to_owned())
		}));
		let v = LlmVerifierScanner::new(backend).verify(&ctx()).await.unwrap();
		assert!(matches!(v, Verdict::Dismissed { .. }));
	}

	#[tokio::test]
	async fn unknown_verdict_is_treated_as_inconclusive() {
		let backend = Arc::new(StubLlmBackend::new("stub", |_req: &LlmRequest| {
			Ok(r#"{"verdict":"???","notes":"shrug"}"#.to_owned())
		}));
		let v = LlmVerifierScanner::new(backend).verify(&ctx()).await.unwrap();
		assert!(matches!(v, Verdict::Inconclusive { .. }));
	}
}
