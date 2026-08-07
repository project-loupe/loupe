//! LLM-driven code-review scanner.
//!
//! Pipeline: walk source files → fan out one agent session per file →
//! wait. Each session gets the full MCP tool surface — the agent reads
//! the file, optionally cross-checks `query_prior_findings` /
//! `get_finding_by_id` for duplicates, generates a regression-test
//! PoC, and (only if it's confident) calls `submit_finding`. The MCP
//! `submit_finding` tool POSTs straight to
//! `/v1/jobs/{job_id}/findings`, so submissions land on the server
//! before this scanner returns. The scanner's own return value is
//! always an empty `Vec<Finding>` — its job is orchestration, not
//! emission.
//!
//! Why no separate validation pass: the agent owns its own validation
//! loop (it has tools to read prior findings and the worktree, and is
//! asked to produce a regression-test PoC inline). A second worker-
//! side parse would be a poor model of what the agent already did.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use loupe_core::Finding;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::llm::prompts::{self, DISCOVERY};
use crate::llm::{LlmBackend, LlmRequest};
use crate::scanner::{ScanContext, Scanner};
use crate::source_discovery::{walk_source_files, ScannerConfig, ScannerConfigPatch};

pub const SCANNER_ID: &str = "llm-code-review";
const CAPABILITIES: &[&str] = &["scan:llm"];

pub struct LlmCodeReviewScanner {
	backend: Arc<dyn LlmBackend>,
	config: ScannerConfig,
	/// Conditional `bkb_hint` substitution string for [`prompts::DISCOVERY`].
	/// Either [`prompts::BKB_HINT_ATTACHED`] (when the worker has
	/// attached bkb-mcp to the per-call MCP config — the agent gets
	/// the bkb tool list spelled out in the prompt's "Scope of
	/// knowledge" section) or empty (no mention of bkb at all, since
	/// the agent's tool catalog won't list bkb tools either way).
	bkb_hint: &'static str,
}

impl LlmCodeReviewScanner {
	pub fn new(backend: Arc<dyn LlmBackend>) -> Self {
		Self { backend, config: ScannerConfig::default(), bkb_hint: "" }
	}

	pub fn with_config(mut self, config: ScannerConfig) -> Self {
		self.config = config;
		self
	}

	/// Mark this scanner as having `bkb-mcp` attached to its per-call
	/// MCP config. Toggles the conditional bkb section in the
	/// discovery prompt so the agent knows the bkb tools exist and
	/// how to honestly cite their output.
	pub fn with_bkb(mut self, attached: bool) -> Self {
		self.bkb_hint = if attached { prompts::BKB_HINT_ATTACHED } else { "" };
		self
	}
}

#[async_trait]
impl Scanner for LlmCodeReviewScanner {
	fn id(&self) -> &'static str {
		SCANNER_ID
	}

	fn capabilities(&self) -> &[&'static str] {
		CAPABILITIES
	}

	async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
		// Apply any per-repo overrides from the lease envelope on top
		// of our baseline config.
		let mut cfg = self.config.clone();
		if !ctx.config.is_null() {
			match serde_json::from_value::<ScannerConfigPatch>(ctx.config.clone()) {
				Ok(patch) => cfg.apply_patch(patch),
				Err(e) => {
					tracing::warn!(error = %e, "ignoring scanner_config: not a ScannerConfigPatch");
				},
			}
		}

		let files = walk_source_files(&ctx.workdir, &cfg);
		if files.is_empty() {
			return Ok(Vec::new());
		}
		tracing::info!(
			files = files.len(),
			backend = self.backend.id(),
			"llm-code-review starting agent fan-out"
		);

		let failures = self
			.run_all(
				&cfg,
				&ctx.workdir,
				&files,
				ctx.repo_id,
				ctx.job_id,
				self.bkb_hint,
				&ctx.cancel,
			)
			.await;
		let errors = failures.len();
		// Hard-fail when every agent session errored. Without this, an
		// LLM scanner that's completely broken (sandbox can't reach the
		// CLI, auth missing, network blocked) would silently complete
		// as "succeeded with 0 findings", which an operator can't tell
		// apart from "this is a clean repo." The agent producing no
		// findings on a healthy session is a success — only backend /
		// sandbox errors fail the scan.
		if errors > 0 && errors == files.len() {
			anyhow::bail!(
				"llm-code-review: every one of {n} agent sessions errored; \
				 check worker logs for the underlying error (`RUST_LOG=loupe_worker=debug` \
				 surfaces the per-call failures)",
				n = files.len(),
			);
		}
		// Partial coverage. Every one of these files is reported to the
		// operator as scanned, and contributes no findings — exactly
		// what a genuinely clean file looks like. Name them, and say
		// plainly that the repo was not fully covered, at a level that
		// shows up in a default `info` deployment.
		if errors > 0 {
			let timed_out: Vec<&str> =
				failures.iter().filter(|f| f.timed_out).map(|f| f.file.as_str()).collect();
			let other: Vec<&str> =
				failures.iter().filter(|f| !f.timed_out).map(|f| f.file.as_str()).collect();
			tracing::error!(
				errored = errors,
				total = files.len(),
				timed_out = ?timed_out,
				other_failures = ?other,
				"llm-code-review: INCOMPLETE COVERAGE — these files were not reviewed and \
				 produce no findings; do not read their absence from the findings list as clean",
			);
			if !timed_out.is_empty() {
				tracing::error!(
					count = timed_out.len(),
					per_request_timeout_secs = cfg.per_request_timeout.as_secs(),
					"llm-code-review: sessions hit the per-file timeout; raise \
					 `per_request_timeout_seconds` in scanner_config and re-scan these files",
				);
			}
		}
		tracing::info!(
			reviewed = files.len() - errors,
			total = files.len(),
			"llm-code-review finished; submissions arrived via MCP",
		);
		// The scanner's role is orchestration; agent submissions
		// already landed on the server via the MCP `submit_finding`
		// tool. The runner's `submit_findings` batch call (which
		// follows scan(...)) thus has nothing to do for this scanner.
		Ok(Vec::new())
	}
}

impl LlmCodeReviewScanner {
	/// Fan out one agent session per file with bounded concurrency.
	/// Returns the files whose sessions failed; per-session "no
	/// finding" is a success (not an error).
	#[allow(clippy::too_many_arguments)]
	async fn run_all(
		&self, cfg: &ScannerConfig, workdir: &Path, files: &[PathBuf], repo_id: i64, job_id: i64,
		bkb_hint: &'static str, cancel: &CancellationToken,
	) -> Vec<SessionFailure> {
		let sem = Arc::new(Semaphore::new(cfg.max_concurrent_files));
		let mut handles = Vec::with_capacity(files.len());
		for path in files {
			if cancel.is_cancelled() {
				break;
			}
			let permit = sem.clone().acquire_owned().await.expect("semaphore not closed");
			let backend = self.backend.clone();
			let cfg_owned = cfg.clone();
			let workdir = workdir.to_path_buf();
			let path = path.clone();
			let cancel = cancel.clone();
			handles.push(tokio::spawn(async move {
				let _permit = permit;
				run_one(backend, &workdir, &path, &cfg_owned, repo_id, job_id, bkb_hint, cancel)
					.await
			}));
		}

		let mut failures = Vec::new();
		for h in handles {
			match h.await {
				Ok(Ok(())) => {},
				Ok(Err(f)) => failures.push(f),
				Err(e) => {
					tracing::warn!(error = %e, "agent session task panicked");
					failures.push(SessionFailure {
						file: "<panicked task>".to_owned(),
						reason: e.to_string(),
						timed_out: false,
					});
				},
			}
		}
		failures
	}
}

/// Run one agent session against `file`. Returns `Err(SessionFailure)`
/// for session-level errors (sandbox / network / CLI failure /
/// timeout); the caller collects these so the scan can report which
/// files it did not actually cover. A healthy session that produced no
/// submission still returns `Ok(())` — the agent decided there was
/// nothing to report.
#[allow(clippy::too_many_arguments)]
async fn run_one(
	backend: Arc<dyn LlmBackend>, workdir: &Path, file: &Path, cfg: &ScannerConfig, repo_id: i64,
	job_id: i64, bkb_hint: &'static str, cancel: CancellationToken,
) -> Result<(), SessionFailure> {
	let rel = file.strip_prefix(workdir).unwrap_or(file).to_string_lossy().into_owned();
	let prompt = prompts::render(DISCOVERY, &[("file", &rel), ("bkb_hint", bkb_hint)]);
	tracing::info!(file = %rel, "llm-code-review: launching agent session");
	let started = std::time::Instant::now();
	let req = LlmRequest {
		prompt,
		workdir: workdir.to_path_buf(),
		timeout: cfg.per_request_timeout,
		cancel,
		repo_id: Some(repo_id),
		job_id: Some(job_id),
		finding_id: None,
	};
	match backend.run(req).await {
		Ok(r) => {
			tracing::debug!(
				file = %rel,
				elapsed_ms = started.elapsed().as_millis() as u64,
				response_chars = r.text.chars().count(),
				"agent session finished",
			);
			Ok(())
		},
		Err(e) => {
			let reason = e.to_string();
			let timed_out = reason.contains("timed out");
			tracing::warn!(file = %rel, error = %reason, timed_out, "agent session failed");
			Err(SessionFailure { file: rel, reason, timed_out })
		},
	}
}

/// One file the scanner tried and failed to review. Kept per-file
/// rather than as a bare counter so the scan can name what it missed:
/// a file whose session died is indistinguishable, in the findings
/// list, from a file the agent read and found nothing wrong with.
#[derive(Debug, Clone)]
pub(crate) struct SessionFailure {
	pub file: String,
	pub reason: String,
	pub timed_out: bool,
}

#[cfg(test)]
mod tests {
	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::sync::Arc;

	use loupe_core::RepoSpec;
	use tokio_util::sync::CancellationToken;

	use super::*;
	use crate::llm::testing::StubLlmBackend;

	fn make_ctx(workdir: &Path) -> ScanContext {
		ScanContext {
			workdir: workdir.to_path_buf(),
			repo_id: 1,
			job_id: 1,
			repo: RepoSpec {
				host: "github.com".into(),
				owner: "a".into(),
				repo: "b".into(),
				clone_url: "https://github.com/a/b.git".into(),
				branch: None,
			},
			head_sha: "deadbeef".into(),
			base_sha: None,
			config: serde_json::Value::Null,
			cancel: CancellationToken::new(),
		}
	}

	fn write_crate(root: &Path, files: &[(&str, &str)]) {
		std::fs::write(
			root.join("Cargo.toml"),
			"[package]\nname = \"x\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
		)
		.unwrap();
		std::fs::create_dir_all(root.join("src")).unwrap();
		for (path, body) in files {
			let p = root.join(path);
			if let Some(parent) = p.parent() {
				std::fs::create_dir_all(parent).unwrap();
			}
			std::fs::write(p, body).unwrap();
		}
	}

	#[tokio::test]
	async fn scanner_returns_empty_findings_and_calls_backend_per_file() {
		// Submissions go via MCP, not via the return value. The
		// scanner-level test pins the orchestration contract: every
		// matching file gets one backend call, scan returns [].
		let tmp = tempfile::tempdir().unwrap();
		write_crate(tmp.path(), &[("src/lib.rs", "// a\n"), ("src/util.rs", "// b\n")]);

		let calls = Arc::new(AtomicUsize::new(0));
		let calls_for_stub = calls.clone();
		let backend = Arc::new(StubLlmBackend::new("stub", move |_req: &LlmRequest| {
			calls_for_stub.fetch_add(1, Ordering::SeqCst);
			Ok(String::new())
		}));
		let scanner = LlmCodeReviewScanner::new(backend);

		let findings = scanner.scan(&make_ctx(tmp.path())).await.unwrap();
		assert!(findings.is_empty(), "scanner returns no findings — submissions go via MCP");
		assert_eq!(
			calls.load(Ordering::SeqCst),
			2,
			"every walked file must produce one agent session"
		);
	}

	#[tokio::test]
	async fn scanner_fails_loud_when_every_session_errors() {
		// Sandbox / network / CLI being completely broken must not
		// silently complete as "0 findings" — that's
		// indistinguishable from a clean repo.
		let tmp = tempfile::tempdir().unwrap();
		write_crate(tmp.path(), &[("src/lib.rs", "// a\n")]);
		let backend = Arc::new(StubLlmBackend::new("stub", |_req: &LlmRequest| {
			Err(anyhow::anyhow!("backend exploded"))
		}));
		let scanner = LlmCodeReviewScanner::new(backend);
		let err = scanner.scan(&make_ctx(tmp.path())).await.expect_err("must fail");
		assert!(err.to_string().contains("agent session"), "unexpected error: {err}");
	}

	#[tokio::test]
	async fn partial_failure_names_the_files_it_did_not_review() {
		// The dangerous case is not "everything broke" — that already
		// hard-fails. It's the mixed run: some files reviewed, some
		// dead, job reports success. A file whose session timed out
		// contributes no findings, which is exactly what a clean file
		// looks like, so the failure has to be carried out of run_all
		// per-file rather than as a bare count.
		let tmp = tempfile::tempdir().unwrap();
		write_crate(tmp.path(), &[("src/lib.rs", "// a\n"), ("src/big.rs", "// b\n")]);

		let backend = Arc::new(StubLlmBackend::new("stub", |req: &LlmRequest| {
			if req.prompt.contains("src/big.rs") {
				Err(anyhow::anyhow!("claude CLI timed out after 1800s"))
			} else {
				Ok(String::new())
			}
		}));
		let scanner = LlmCodeReviewScanner::new(backend);

		// Mixed outcome still succeeds — the findings that did land are
		// real and must not be thrown away.
		let findings = scanner.scan(&make_ctx(tmp.path())).await.expect("partial run succeeds");
		assert!(findings.is_empty());

		// …but the failure must be attributable to a specific file and
		// classified as a timeout, so the operator can raise the limit
		// and re-scan exactly that file.
		let failures = scanner
			.run_all(
				&ScannerConfig::default(),
				tmp.path(),
				&[tmp.path().join("src/big.rs")],
				1,
				1,
				"",
				&CancellationToken::new(),
			)
			.await;
		assert_eq!(failures.len(), 1);
		assert!(failures[0].file.ends_with("src/big.rs"), "got {:?}", failures[0].file);
		assert!(failures[0].timed_out, "a timeout must be distinguishable: {:?}", failures[0]);
	}

	#[tokio::test]
	async fn ctx_config_override_changes_walked_extensions() {
		// A C-only repo overrides include_extensions so a `.c` file
		// is picked up even without a Cargo.toml. Pinned at the
		// scanner level because the patch lookup is in scan().
		let tmp = tempfile::tempdir().unwrap();
		std::fs::write(tmp.path().join("widget.c"), "/* stub */\n").unwrap();
		let calls = Arc::new(AtomicUsize::new(0));
		let calls_for_stub = calls.clone();
		let backend = Arc::new(StubLlmBackend::new("stub", move |_req: &LlmRequest| {
			calls_for_stub.fetch_add(1, Ordering::SeqCst);
			Ok(String::new())
		}));
		let scanner = LlmCodeReviewScanner::new(backend);
		let mut ctx = make_ctx(tmp.path());
		ctx.config = serde_json::json!({"include_extensions":["c"]});
		scanner.scan(&ctx).await.unwrap();
		assert_eq!(
			calls.load(Ordering::SeqCst),
			1,
			"ctx.config override should have caught widget.c"
		);
	}
}
