//! LLM verifier scanner — implements `Scanner::verify` only.
//!
//! Used in the LLM second-opinion path: a `kind=verify` job lands on
//! a worker advertising `verify:llm`, the runner's lease response
//! carries the target Finding, and this scanner asks the configured
//! LLM backend whether the finding holds up.
//!
//! Two-phase MCP-driven flow. The agent is given the loupe MCP
//! server in verify mode (`--finding-id` + `--job-id` set), which
//! advertises `submit_verdict`, `submit_patch`, and `validate_patch`.
//! The agent locks a verdict first, optionally proposes a patch on
//! confirm, then exits. The MCP server's session-end flush POSTs
//! the buffered `VerdictSubmission` to `/v1/jobs/:id/verdict` —
//! the runner gets back a `VerifyOutcome::Submitted` and stays out
//! of the way (no double POST).
//!
//! The scanner intentionally returns an empty `Vec<Finding<loupe_provenance::Repo>>` from
//! `scan()` — a verifier is not also a discoverer, even though the
//! trait surface allows it to be. Wiring a verifier worker to also
//! advertise `scan:*` is just a matter of pairing it with another
//! scanner in the runner's scanner list.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use loupe_core::Finding;

use crate::llm::prompts::Prompt;
use crate::llm::{LlmBackend, LlmRequest};
use crate::scanner::{ScanContext, Scanner, VerifyContext, VerifyOutcome};

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

#[async_trait]
impl Scanner for LlmVerifierScanner {
	fn id(&self) -> &'static str {
		SCANNER_ID
	}

	fn capabilities(&self) -> &[&'static str] {
		CAPABILITIES
	}

	async fn scan(&self, _ctx: &ScanContext) -> Result<Vec<Finding<loupe_provenance::Repo>>> {
		Ok(Vec::new())
	}

	async fn verify(&self, ctx: &VerifyContext) -> Result<VerifyOutcome> {
		// Render the original finding so the agent has the context
		// it needs to decide whether the report holds up. The MCP
		// server's `query_prior_findings` / `get_finding_by_id`
		// tools cover everything else.
		let prompt = Prompt::verification(ctx.finding_id, &ctx.finding);

		// `finding_id` + `job_id` are what flip the MCP server into
		// verify mode — the verify-mode tool catalog
		// (submit_verdict / submit_patch / validate_patch) only
		// shows up when both are set. The MCP server bails at
		// startup if it sees only `--finding-id`, so passing both
		// here is load-bearing.
		let req = LlmRequest {
			prompt,
			workdir: ctx.workdir.clone(),
			timeout: crate::llm::DEFAULT_REQUEST_TIMEOUT,
			cancel: ctx.cancel.clone(),
			repo_id: Some(ctx.repo_id),
			job_id: Some(ctx.job_id),
			job_capability: Some(ctx.job_capability.clone()),
			finding_id: Some(ctx.finding_id),
		};
		let _resp = self.backend.run(req).await?;

		// The MCP server's session-end flush already POSTed the
		// verdict (with the optional patch embedded). Tell the
		// runner not to POST again.
		Ok(VerifyOutcome::Submitted)
	}
}

#[cfg(test)]
mod tests {
	use std::path::PathBuf;
	use std::sync::Mutex;

	use tokio_util::sync::CancellationToken;

	use super::*;
	use crate::llm::testing::StubLlmBackend;

	fn ctx() -> VerifyContext {
		let original = br#"{"kind":"lease","protocol_version":1,"job_id":42,"repo_id":1,"job_capability":"test-capability","repo":{"host":"github.com","owner":"a","repo":"b","clone_url":"https://github.com/a/b.git"},"scanner_config":null,"lease_expires_at":300,"payload":{"kind":"verify","finding_id":7,"finding":{"scanner_id":"llm-code-review","severity":"high","title":"OOB index","description":"no bounds check","file_path":"src/lib.rs","line_start":1,"line_end":1,"cwe":null,"patch_unified":null,"poc_unified":null,"fingerprint":"fp1"}}}"#;
		let loupe_proto::LeaseResponse::Lease(env) = crate::client::test_lease(original).response
		else {
			panic!("lease")
		};
		let loupe_proto::LeasePayload::Verify { finding, .. } = env.payload else {
			panic!("verify")
		};
		VerifyContext {
			workdir: PathBuf::from("/tmp"),
			repo_id: 1,
			job_id: 42,
			job_capability: loupe_proto::JobCapability::from_secret("test-capability"),
			finding_id: 7,
			repo: env.repo,
			finding: *finding,
			config: None,
			cancel: CancellationToken::new(),
		}
	}

	#[tokio::test]
	async fn original_report_contains_prefixed_finding_id() {
		let backend = Arc::new(StubLlmBackend::new("stub", |req: &LlmRequest| {
			assert!(
				req.prompt.for_cli_argument().contains("\"id\":\"LUP-7\""),
				"original report must identify the finding as LUP-7"
			);
			Ok(String::new())
		}));
		LlmVerifierScanner::new(backend).verify(&ctx()).await.unwrap();
	}

	#[tokio::test]
	async fn returns_submitted_outcome_so_runner_skips_its_post() {
		// MCP-driven verifier: the backend stub doesn't have to emit
		// any verdict JSON — that path is gone. The contract this
		// test pins is just "scanner returns Submitted, runner won't
		// post again." If a future refactor accidentally returns
		// `Verdict(...)` instead, the runner would POST a duplicate
		// verification row.
		let backend = Arc::new(StubLlmBackend::new("stub", |_req: &LlmRequest| Ok(String::new())));
		let outcome = LlmVerifierScanner::new(backend).verify(&ctx()).await.unwrap();
		assert!(matches!(outcome, VerifyOutcome::Submitted));
	}

	#[tokio::test]
	async fn forwards_finding_id_and_job_id_to_backend_so_mcp_enters_verify_mode() {
		// Pin the load-bearing wiring: the MCP server only flips into
		// verify mode when BOTH `--finding-id` and `--job-id` reach
		// it (via the LlmRequest fields). Capture what the backend
		// sees and assert both are populated. If a future refactor
		// drops one, the agent silently falls into discovery mode and
		// the verifier surface disappears.
		#[allow(clippy::type_complexity)]
		let captured: Arc<Mutex<Option<(Option<i64>, Option<i64>, Option<i64>)>>> =
			Arc::new(Mutex::new(None));
		let captured_for_stub = captured.clone();
		let backend = Arc::new(StubLlmBackend::new("stub", move |req: &LlmRequest| {
			*captured_for_stub.lock().unwrap() = Some((req.repo_id, req.job_id, req.finding_id));
			Ok(String::new())
		}));
		LlmVerifierScanner::new(backend).verify(&ctx()).await.unwrap();
		let seen = (*captured.lock().unwrap()).expect("backend invoked");
		assert_eq!(seen, (Some(1), Some(42), Some(7)));
	}
}
