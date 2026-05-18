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
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use loupe_core::Finding;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::llm::prompts::{self, DISCOVERY};
use crate::llm::{LlmBackend, LlmRequest, DEFAULT_REQUEST_TIMEOUT};
use crate::scanner::{ScanContext, Scanner};

pub const SCANNER_ID: &str = "llm-code-review";
const CAPABILITIES: &[&str] = &["scan:llm"];

/// Config knobs operators can set via the repo's `scanner_config`
/// JSON. Defaults cover Rust, C/C++, JS/TS, Python, Go, Ruby, PHP, and
/// JVM/Swift sources, plus a broad excludelist that drops common
/// build / vendor / test dirs across those ecosystems. Tighten or
/// loosen per-repo by sending a partial JSON override (see
/// `ScannerConfigPatch`).
#[derive(Debug, Clone)]
pub struct ScannerConfig {
	pub max_concurrent_files: usize,
	pub max_file_bytes: u64,
	pub per_request_timeout: Duration,
	/// File extensions the walk will consider, lower-cased and without
	/// the leading dot (e.g. `["rs", "cpp"]`).
	pub include_extensions: Vec<String>,
	/// Substrings that disqualify a path. We match against the full
	/// path string (forward-slash form on Unix), so `/target` matches
	/// `…/target/release/foo.rs` and `node_modules` matches anywhere.
	pub exclude_path_substrings: Vec<String>,
}

impl Default for ScannerConfig {
	fn default() -> Self {
		Self {
			max_concurrent_files: 8,
			max_file_bytes: 64 * 1024,
			per_request_timeout: DEFAULT_REQUEST_TIMEOUT,
			include_extensions: default_extensions(),
			exclude_path_substrings: default_excludes(),
		}
	}
}

/// Partial override applied on top of `ScannerConfig::default()` (or a
/// constructor-supplied baseline) when the server passes a non-null
/// `scanner_config` in the lease envelope. `None` for any field means
/// "leave the baseline alone"; `Some(...)` replaces the field
/// wholesale.
///
/// Replacing rather than merging is intentional: when an operator
/// writes `{"include_extensions":["c","h"]}` for a C-only repo they
/// almost always *don't* want our default Rust/JS/Python/etc.
/// extensions silently appended.
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(default)]
pub struct ScannerConfigPatch {
	pub max_concurrent_files: Option<usize>,
	pub max_file_bytes: Option<u64>,
	pub per_request_timeout_seconds: Option<u64>,
	pub include_extensions: Option<Vec<String>>,
	pub exclude_path_substrings: Option<Vec<String>>,
}

impl ScannerConfig {
	pub(crate) fn apply_patch(&mut self, p: ScannerConfigPatch) {
		if let Some(v) = p.max_concurrent_files {
			self.max_concurrent_files = v;
		}
		if let Some(v) = p.max_file_bytes {
			self.max_file_bytes = v;
		}
		if let Some(v) = p.per_request_timeout_seconds {
			self.per_request_timeout = Duration::from_secs(v);
		}
		if let Some(v) = p.include_extensions {
			self.include_extensions = v;
		}
		if let Some(v) = p.exclude_path_substrings {
			self.exclude_path_substrings = v;
		}
	}
}

fn default_extensions() -> Vec<String> {
	[
		// Rust.
		"rs", // C / C++ / Obj-C.
		"c", "h", "cc", "hh", "cpp", "hpp", "cxx", "hxx", "m", "mm", // JS / TS.
		"js", "jsx", "mjs", "cjs", "ts", "tsx", // Python.
		"py",  // Go.
		"go",  // Ruby.
		"rb",  // PHP.
		"php", // JVM family.
		"java", "kt", "kts", "scala", "groovy", // Swift.
		"swift",  // Misc.
		"dart", "ex", "exs", "rs.in",
	]
	.into_iter()
	.map(String::from)
	.collect()
}

fn default_excludes() -> Vec<String> {
	[
		// Rust / Java / general "tests" dirs and matching filename suffixes.
		"tests",
		"/test",
		"examples",
		"__tests__",
		"/test_",
		"_test.",
		".test.",
		".spec.",
		// Build artefacts across ecosystems.
		"/target",
		"/build",
		"/dist",
		"/out",
		"/.next",
		"/.nuxt",
		"/coverage",
		// Vendored deps.
		"node_modules",
		"/vendor",
		"/.venv",
		"/venv",
		"/env",
		// Caches.
		"__pycache__",
		"/.tox",
		"/.gradle",
		"/.mypy_cache",
		"/.pytest_cache",
	]
	.into_iter()
	.map(String::from)
	.collect()
}

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

		let errors = self
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
		if errors > 0 {
			tracing::warn!(
				errored = errors,
				total = files.len(),
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
	/// Returns the count of session-level errors; per-session "no
	/// finding" is a success (not an error).
	#[allow(clippy::too_many_arguments)]
	async fn run_all(
		&self, cfg: &ScannerConfig, workdir: &Path, files: &[PathBuf], repo_id: i64, job_id: i64,
		bkb_hint: &'static str, cancel: &CancellationToken,
	) -> usize {
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

		let mut errors = 0usize;
		for h in handles {
			match h.await {
				Ok(Ok(())) => {},
				Ok(Err(())) => errors += 1,
				Err(e) => {
					tracing::warn!(error = %e, "agent session task panicked");
					errors += 1;
				},
			}
		}
		errors
	}
}

/// Run one agent session against `file`. Returns `Err(())` for
/// session-level errors (sandbox / network / CLI failure); the call
/// counts these and fails the scan when every attempt errors. A
/// healthy session that produced no submission still returns `Ok(())`
/// — the agent decided there was nothing to report.
#[allow(clippy::too_many_arguments)]
async fn run_one(
	backend: Arc<dyn LlmBackend>, workdir: &Path, file: &Path, cfg: &ScannerConfig, repo_id: i64,
	job_id: i64, bkb_hint: &'static str, cancel: CancellationToken,
) -> Result<(), ()> {
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
			tracing::warn!(file = %rel, error = %e, "agent session failed");
			Err(())
		},
	}
}

/// Walk the worktree for source files. Strategy:
/// workspace `[workspace] members` → each member's `src/`;
/// single-crate `Cargo.toml` → `src/`; otherwise the entire tree
/// under any `src/` directory. Honours the include extension
/// allowlist and the path-substring exclude list, plus the per-file
/// size cap. `.git` and any directory matching an exclude substring
/// is skipped wholesale.
pub(crate) fn walk_source_files(workdir: &Path, cfg: &ScannerConfig) -> Vec<PathBuf> {
	let mut roots: Vec<PathBuf> = Vec::new();
	let cargo_toml = workdir.join("Cargo.toml");
	if cargo_toml.exists() {
		match parse_workspace_members(&cargo_toml) {
			Some(members) => {
				for m in members {
					let p = workdir.join(m).join("src");
					if p.is_dir() {
						roots.push(p);
					}
				}
			},
			None => {
				let p = workdir.join("src");
				if p.is_dir() {
					roots.push(p);
				}
			},
		}
	}
	if roots.is_empty() {
		// Fallback: walk anything under any src/ subdir.
		roots.push(workdir.to_path_buf());
	}

	let mut out = Vec::new();
	for root in roots {
		walkdir::WalkDir::new(&root)
			.into_iter()
			.filter_entry(|e| !is_excluded_dir(e.path(), cfg))
			.filter_map(|r| r.ok())
			.filter(|e| e.file_type().is_file())
			.filter(|e| has_allowed_extension(e.path(), &cfg.include_extensions))
			.filter(|e| !is_excluded_path(e.path(), &cfg.exclude_path_substrings))
			.filter(|e| e.metadata().map(|m| m.len() <= cfg.max_file_bytes).unwrap_or(false))
			.for_each(|e| out.push(e.into_path()));
	}
	out.sort();
	out.dedup();
	out
}

/// Lightweight `[workspace] members = [...]` extractor. Returns
/// `Some(members)` when the manifest has a `[workspace]` section,
/// `None` otherwise. Deliberately not pulling in `cargo_metadata`
/// (extra dep, slow); `members` is whatever appears verbatim between
/// the opening and closing brackets, with each quoted string yielded
/// in order. Globs like `crates/*` are returned as-is — the caller
/// only uses each member to build `<workdir>/<member>/src` and skips
/// non-existent paths.
fn parse_workspace_members(cargo_toml: &Path) -> Option<Vec<String>> {
	let text = std::fs::read_to_string(cargo_toml).ok()?;
	if !text.lines().any(|l| l.trim_start().starts_with("[workspace]")) {
		return None;
	}

	// Scan section by section. We only care about the `[workspace]`
	// section; sections start with `[xxx]` lines.
	let mut in_workspace = false;
	let mut buf = String::new(); // buffer for the contents of `members = [ … ]`
	let mut collecting = false;
	for line in text.lines() {
		let trimmed = line.trim();
		if trimmed.starts_with('[') && trimmed.ends_with(']') {
			in_workspace = trimmed == "[workspace]";
			collecting = false;
			continue;
		}
		if !in_workspace {
			continue;
		}
		if collecting {
			buf.push_str(line);
			buf.push('\n');
			if line.contains(']') {
				collecting = false;
			}
			continue;
		}
		if let Some(rest) = trimmed.strip_prefix("members") {
			let rest = rest.trim_start_matches([' ', '\t', '=']).trim();
			if rest.starts_with('[') {
				buf.push_str(rest);
				buf.push('\n');
				if !rest.contains(']') {
					collecting = true;
				}
			}
		}
	}

	// Pull every "..." literal out of the buffer.
	let mut members = Vec::new();
	let mut bytes = buf.as_bytes().iter().enumerate();
	while let Some((i, &b)) = bytes.next() {
		if b != b'"' {
			continue;
		}
		// Find the closing quote (no escapes — TOML basic strings don't
		// allow newlines, and we don't expect quotes inside member paths).
		let rest = &buf.as_bytes()[i + 1..];
		if let Some(end) = rest.iter().position(|&c| c == b'"') {
			let s = std::str::from_utf8(&rest[..end]).unwrap_or("");
			if !s.is_empty() {
				members.push(s.to_owned());
			}
			// Skip past the closing quote in our outer iterator.
			for _ in 0..end + 1 {
				bytes.next();
			}
		}
	}
	Some(members)
}

fn is_excluded_dir(path: &Path, cfg: &ScannerConfig) -> bool {
	let s = path.to_string_lossy();
	if s.contains("/.git/") || s.ends_with("/.git") {
		return true;
	}
	cfg.exclude_path_substrings.iter().any(|sub| s.contains(sub.as_str()))
}

fn is_excluded_path(path: &Path, excludes: &[String]) -> bool {
	let s = path.to_string_lossy();
	excludes.iter().any(|e| s.contains(e.as_str()))
}

fn has_allowed_extension(path: &Path, exts: &[String]) -> bool {
	path.extension()
		.and_then(|e| e.to_str())
		.map(|e| exts.iter().any(|allowed| allowed.eq_ignore_ascii_case(e)))
		.unwrap_or(false)
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

	#[test]
	fn defaults_cover_common_languages() {
		let cfg = ScannerConfig::default();
		for ext in ["rs", "c", "cpp", "h", "hpp", "js", "ts", "py", "go", "java", "swift"] {
			assert!(cfg.include_extensions.iter().any(|e| e == ext), "missing: {ext}");
		}
		// node_modules and target are excluded out of the box.
		assert!(cfg.exclude_path_substrings.iter().any(|e| e == "node_modules"));
		assert!(cfg.exclude_path_substrings.iter().any(|e| e == "/target"));
	}

	#[test]
	fn patch_overrides_only_the_fields_present() {
		let mut cfg = ScannerConfig::default();
		let original_excludes = cfg.exclude_path_substrings.clone();
		let patch: ScannerConfigPatch =
			serde_json::from_str(r#"{"include_extensions":["c","h"]}"#).unwrap();
		cfg.apply_patch(patch);
		assert_eq!(cfg.include_extensions, vec!["c".to_owned(), "h".to_owned()]);
		assert_eq!(cfg.exclude_path_substrings, original_excludes);
	}

	#[test]
	fn walk_picks_up_non_rust_files_without_cargo_toml() {
		let tmp = tempfile::tempdir().unwrap();
		// No Cargo.toml here — fallback walks the workdir.
		std::fs::create_dir_all(tmp.path().join("src")).unwrap();
		std::fs::write(tmp.path().join("src/main.cpp"), "// stub\n").unwrap();
		std::fs::write(tmp.path().join("src/util.h"), "// stub\n").unwrap();
		std::fs::write(tmp.path().join("src/app.py"), "# stub\n").unwrap();
		std::fs::write(tmp.path().join("src/page.tsx"), "// stub\n").unwrap();

		let cfg = ScannerConfig::default();
		let files = walk_source_files(tmp.path(), &cfg);
		let names: Vec<String> = files
			.iter()
			.map(|p| p.strip_prefix(tmp.path()).unwrap().to_string_lossy().into_owned())
			.collect();
		for expected in ["src/main.cpp", "src/util.h", "src/app.py", "src/page.tsx"] {
			assert!(names.iter().any(|n| n == expected), "missing {expected} in {names:?}");
		}
	}

	#[test]
	fn walk_excludes_node_modules_and_build_dirs_by_default() {
		let tmp = tempfile::tempdir().unwrap();
		// Real source.
		std::fs::create_dir_all(tmp.path().join("src")).unwrap();
		std::fs::write(tmp.path().join("src/index.js"), "// real\n").unwrap();
		// Vendored deps and build artefacts that must be skipped.
		std::fs::create_dir_all(tmp.path().join("node_modules/lodash")).unwrap();
		std::fs::write(tmp.path().join("node_modules/lodash/index.js"), "// vendored\n").unwrap();
		std::fs::create_dir_all(tmp.path().join("dist")).unwrap();
		std::fs::write(tmp.path().join("dist/bundle.js"), "// built\n").unwrap();

		let files = walk_source_files(tmp.path(), &ScannerConfig::default());
		let names: Vec<String> = files
			.iter()
			.map(|p| p.strip_prefix(tmp.path()).unwrap().to_string_lossy().into_owned())
			.collect();
		assert!(names.iter().any(|n| n == "src/index.js"), "real source missing: {names:?}");
		assert!(names.iter().all(|n| !n.contains("node_modules")), "leak: {names:?}");
		assert!(names.iter().all(|n| !n.starts_with("dist/")), "leak: {names:?}");
	}

	#[test]
	fn walk_picks_up_src_rs_files_only() {
		let tmp = tempfile::tempdir().unwrap();
		write_crate(
			tmp.path(),
			&[
				("src/lib.rs", "// good\n"),
				("src/util.rs", "// good\n"),
				("README.md", "ignore\n"),
				("tests/integration.rs", "// excluded by tests dir\n"),
			],
		);
		let cfg = ScannerConfig::default();
		let files = walk_source_files(tmp.path(), &cfg);
		let names: Vec<String> = files
			.iter()
			.map(|p| p.strip_prefix(tmp.path()).unwrap().to_string_lossy().into_owned())
			.collect();
		assert!(names.iter().any(|n| n.ends_with("src/lib.rs")), "names: {names:?}");
		assert!(names.iter().any(|n| n.ends_with("src/util.rs")), "names: {names:?}");
		assert!(names.iter().all(|n| !n.contains("README")), "names: {names:?}");
		assert!(names.iter().all(|n| !n.contains("tests/")), "names: {names:?}");
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
		ctx.config = serde_json::json!({"include_extensions":["c"]});
		scanner.scan(&ctx).await.unwrap();
		assert_eq!(
			calls.load(Ordering::SeqCst),
			1,
			"ctx.config override should have caught widget.c"
		);
	}
}
