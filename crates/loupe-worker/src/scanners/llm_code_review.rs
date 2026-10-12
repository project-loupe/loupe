//! LLM-driven code-review scanner.
//!
//! Pipeline: walk source files → fan out one agent session per file →
//! wait. Each session gets the full MCP tool surface — the agent reads
//! the file, optionally cross-checks `query_prior_findings` /
//! `get_finding_by_id` for duplicates, generates a regression-test
//! PoC, and (only if it's confident) calls `submit_finding`. The MCP
//! `submit_finding` tool POSTs straight to
//! `/v1/jobs/{job_id}/llm-findings`, so submissions land on the server
//! before this scanner returns. The scanner's own return value is
//! always an empty `Vec<Finding<loupe_provenance::Repo>>` — its job is orchestration, not
//! emission.
//!
//! Why no separate validation pass: the agent owns its own validation
//! loop (it has tools to read prior findings and the worktree, and is
//! asked to produce a regression-test PoC inline). A second worker-
//! side parse would be a poor model of what the agent already did.

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use loupe_core::Finding;
pub use loupe_proto::LLM_CODE_REVIEW_SCANNER_ID as SCANNER_ID;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::llm::prompts::{self, Prompt};
use crate::llm::{LlmBackend, LlmRequest};
use crate::scanner::{ScanContext, Scanner};
use crate::source_discovery::{walk_source_files, DiscoveredSourcePath, ScannerConfig};
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

	async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding<loupe_provenance::Repo>>> {
		// Apply any per-repo overrides from the lease envelope on top
		// of our baseline config.
		let mut cfg = self.config.clone();
		if let Some(patch) = &ctx.config {
			cfg.apply_patch(patch.clone());
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

		let (errors, skipped) = self
			.run_all(
				&cfg,
				&ctx.workdir,
				&files,
				ctx.repo_id,
				ctx.job_id,
				ctx.job_capability.clone(),
				self.bkb_hint,
				&ctx.cancel,
			)
			.await;
		// Hard-fail when every agent session errored. Without this, an
		// LLM scanner that's completely broken (sandbox can't reach the
		// CLI, auth missing, network blocked) would silently complete
		// as "succeeded with 0 findings", which an operator can't tell
		// apart from "this is a clean repo." The agent producing no
		// findings on a healthy session is a success — only backend /
		// sandbox errors fail the scan.
		let sessions = files.len() - skipped;
		if errors > 0 && errors == sessions {
			anyhow::bail!(
				"llm-code-review: every one of {n} agent sessions errored; \
				 check worker logs for the underlying error (`RUST_LOG=loupe_worker=debug` \
				 surfaces the per-call failures)",
				n = sessions,
			);
		}
		if errors > 0 {
			tracing::warn!(
				errored = errors,
				total = sessions,
				skipped,
				"llm-code-review: some agent sessions errored",
			);
		}
		tracing::info!("llm-code-review finished; submissions arrived via MCP");
		// The scanner's role is orchestration; agent submissions
		// already landed on the server via the MCP `submit_finding`
		// tool. The runner's `submit_findings` batch call (which
		// follows scan(...)) thus has nothing to do for this scanner.
		Ok(Vec::new())
	}
}

impl LlmCodeReviewScanner {
	/// Fan out one agent session per file with bounded concurrency.
	/// Returns session-level errors and skipped native paths; a healthy
	/// session producing no finding remains successful.
	#[allow(clippy::too_many_arguments)]
	async fn run_all(
		&self, cfg: &ScannerConfig, workdir: &Path, files: &[DiscoveredSourcePath], repo_id: i64,
		job_id: i64, job_capability: loupe_proto::JobCapability, bkb_hint: &'static str,
		cancel: &CancellationToken,
	) -> (usize, usize) {
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
			let job_capability = job_capability.clone();
			handles.push(tokio::spawn(async move {
				let _permit = permit;
				run_one(
					backend,
					&workdir,
					&path,
					&cfg_owned,
					repo_id,
					job_id,
					job_capability,
					bkb_hint,
					cancel,
				)
				.await
			}));
		}

		let mut errors = 0usize;
		let mut skipped = 0usize;
		for h in handles {
			match h.await {
				Ok(FileOutcome::Complete) => {},
				Ok(FileOutcome::SkippedNative) => skipped += 1,
				Ok(FileOutcome::Failed) => errors += 1,
				Err(e) => {
					tracing::warn!(error = %e, "agent session task panicked");
					errors += 1;
				},
			}
		}
		(errors, skipped)
	}
}

/// Run one agent session against a representable source file. Keep skipped
/// native paths distinct from failed and healthy sessions for scan accounting.
#[allow(clippy::too_many_arguments)]
async fn run_one(
	backend: Arc<dyn LlmBackend>, workdir: &Path, file: &DiscoveredSourcePath, cfg: &ScannerConfig,
	repo_id: i64, job_id: i64, job_capability: loupe_proto::JobCapability, bkb_hint: &'static str,
	cancel: CancellationToken,
) -> FileOutcome {
	let Some(path) = file.for_prompt() else {
		tracing::warn!("llm-code-review: skipped unrepresentable native source path");
		return FileOutcome::SkippedNative;
	};
	let prompt = Prompt::discovery(path, bkb_hint);
	let rel = path.expose();
	tracing::info!(file = %rel, "llm-code-review: launching agent session");
	let started = std::time::Instant::now();
	let req = LlmRequest {
		prompt,
		workdir: workdir.to_path_buf(),
		timeout: cfg.per_request_timeout,
		cancel,
		repo_id: Some(repo_id),
		job_id: Some(job_id),
		job_capability: Some(job_capability),
		finding_id: None,
	};
	match backend.run(req).await {
		Ok(r) => {
			tracing::debug!(
				file = %rel,
				elapsed_ms = started.elapsed().as_millis() as u64,
				response_chars = r.text.for_log().chars().count(),
				"agent session finished",
			);
			FileOutcome::Complete
		},
		Err(e) => {
			tracing::warn!(file = %rel, error = %e, "agent session failed");
			FileOutcome::Failed
		},
	}
}

enum FileOutcome {
	Complete,
	SkippedNative,
	Failed,
}

#[cfg(test)]
mod tests {
	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::sync::Arc;

	use super::*;
	use crate::llm::testing::StubLlmBackend;

	fn make_ctx(workdir: &Path) -> ScanContext {
		crate::test_support::scan_context(workdir, "deadbeef")
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
	#[cfg(unix)]
	async fn unrepresentable_native_file_is_skipped_without_masking_sibling_outcomes() {
		use std::os::unix::ffi::OsStringExt;
		let tmp = tempfile::tempdir().unwrap();
		write_crate(tmp.path(), &[("src/lib.rs", "// valid sibling\n")]);
		let native_dir =
			tmp.path().join("src").join(std::ffi::OsString::from_vec(b"bad-\xff".to_vec()));
		std::fs::create_dir(&native_dir).unwrap();
		std::fs::write(native_dir.join("hidden.rs"), "// native name\n").unwrap();
		let calls = Arc::new(AtomicUsize::new(0));
		let observed = calls.clone();
		let backend = Arc::new(StubLlmBackend::new("stub", move |_req: &LlmRequest| {
			observed.fetch_add(1, Ordering::SeqCst);
			Ok(String::new())
		}));
		let scanner = LlmCodeReviewScanner::new(backend);
		assert!(scanner.scan(&make_ctx(tmp.path())).await.unwrap().is_empty());
		assert_eq!(
			calls.load(Ordering::SeqCst),
			1,
			"only the valid sibling may launch an agent session"
		);

		let failing = Arc::new(StubLlmBackend::new("stub", |_req: &LlmRequest| {
			Err(anyhow::anyhow!("backend exploded"))
		}));
		let err = LlmCodeReviewScanner::new(failing)
			.scan(&make_ctx(tmp.path()))
			.await
			.expect_err("skipped native file must not mask failure of every launched session");
		assert!(err.to_string().contains("every one of 1 agent sessions errored"));

		std::fs::remove_file(tmp.path().join("src/lib.rs")).unwrap();
		assert!(scanner.scan(&make_ctx(tmp.path())).await.unwrap().is_empty());
		assert_eq!(calls.load(Ordering::SeqCst), 1, "an all-skipped scan must launch no session");
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
		ctx.config = Some(crate::test_support::patch(r#"{"include_extensions":["c"]}"#));
		scanner.scan(&ctx).await.unwrap();
		assert_eq!(
			calls.load(Ordering::SeqCst),
			1,
			"ctx.config override should have caught widget.c"
		);
	}

	#[tokio::test]
	async fn malformed_known_patch_discards_all_overrides_but_unknown_members_do_not() {
		let tmp = tempfile::tempdir().unwrap();
		for name in ["one.rs", "two.rs", "only.c", "blocked.rs"] {
			std::fs::write(tmp.path().join(name), "// source\n").unwrap();
		}
		let baseline = ScannerConfig {
			include_extensions: crate::source_discovery::ScannerList::Builtin(&["rs"]),
			exclude_path_substrings: crate::source_discovery::ScannerList::Builtin(&["blocked"]),
			..Default::default()
		};
		for (patch, expected_calls) in [
			(serde_json::Value::Null, 2),
			(serde_json::json!({}), 2),
			(serde_json::json!({"include_extensions": null}), 2),
			(serde_json::json!({"include_extensions": []}), 0),
			(serde_json::json!({"exclude_path_substrings": []}), 3),
			(serde_json::json!({"include_extensions": ["c"], "future": {"nested": [1]}}), 1),
			(serde_json::json!({"include_extensions": ["c"], "max_file_bytes": "bad"}), 2),
			(serde_json::json!({"include_extensions": ["c"], "max_concurrent_files": -1}), 2),
			(
				serde_json::json!({"include_extensions": ["c"], "per_request_timeout_seconds": false}),
				2,
			),
			(serde_json::json!({"include_extensions": ["c"], "exclude_path_substrings": [1]}), 2),
			(
				serde_json::json!({"include_extensions": ["c", null], "exclude_path_substrings": []}),
				2,
			),
			(serde_json::json!("not a patch"), 2),
			// The derived patch struct also accepts positional sequences.
			(serde_json::json!([1, 4096, 1, ["c"], []]), 1),
			(serde_json::json!([1, 4096, 1, ["c"]]), 1),
			(serde_json::json!([1, "bad", 1, ["c"], []]), 2),
			(serde_json::json!([1, 4096, 1, ["c"], [], "extra"]), 2),
			// Lease JSON has already become Value: its last duplicate wins
			// before the patch decoder can see an earlier malformed member.
			(
				serde_json::from_str(r#"{"include_extensions":["rs"],"include_extensions":["c"]}"#)
					.unwrap(),
				1,
			),
			(
				serde_json::from_str(r#"{"include_extensions":7,"include_extensions":["c"]}"#)
					.unwrap(),
				1,
			),
			(
				serde_json::from_str(r#"{"include_extensions":["c"],"include_extensions":7}"#)
					.unwrap(),
				2,
			),
			(
				serde_json::from_str(
					r#"{"include_extensions":["c"],"max_file_bytes":false,"max_file_bytes":4096}"#,
				)
				.unwrap(),
				1,
			),
		] {
			let calls = Arc::new(AtomicUsize::new(0));
			let observed = calls.clone();
			let backend = Arc::new(StubLlmBackend::new("stub", move |_req: &LlmRequest| {
				observed.fetch_add(1, Ordering::SeqCst);
				Ok(String::new())
			}));
			let scanner = LlmCodeReviewScanner::new(backend).with_config(baseline.clone());
			let mut ctx = make_ctx(tmp.path());
			ctx.config = crate::client::test_scanner_patch(&patch.to_string()).unwrap();
			let findings = scanner.scan(&ctx).await.unwrap();
			assert!(findings.is_empty());
			assert_eq!(calls.load(Ordering::SeqCst), expected_calls, "patch: {:?}", ctx.config);
		}
	}
}
