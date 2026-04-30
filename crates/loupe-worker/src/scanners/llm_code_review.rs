//! LLM-driven code-review scanner.
//!
//! Pipeline: walk → discovery → dedup (no-op) → validation → emit.
//! Each stage in its own helper so the dedup slot can be filled in
//! without restructuring the rest. See `LOUPE.md` for the design.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use loupe_core::{Finding, Severity};
use serde::Deserialize;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::llm::prompts::{self, DISCOVERY, VALIDATE};
use crate::llm::{LlmBackend, LlmRequest, LlmResponse, DEFAULT_REQUEST_TIMEOUT};
use crate::scanner::{ScanContext, Scanner};

const SCANNER_ID: &str = "llm-code-review";
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
}

impl LlmCodeReviewScanner {
	pub fn new(backend: Arc<dyn LlmBackend>) -> Self {
		Self { backend, config: ScannerConfig::default() }
	}

	pub fn with_config(mut self, config: ScannerConfig) -> Self {
		self.config = config;
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
			"llm-code-review starting discovery"
		);

		let (discovered, discovery_errors) =
			self.discover_all(&cfg, &ctx.workdir, &files, &ctx.cancel).await;
		// Hard-fail when every discovery call errored. Without this, an
		// LLM scanner that's completely broken (sandbox can't reach the
		// CLI, auth missing, network blocked) silently completes as
		// "succeeded with 0 findings", which an operator can't tell
		// apart from "this is a clean repo." Parse failures count as
		// successes here (the call ran, the model just said nothing
		// usable) — only backend / sandbox errors fail the scan.
		if discovery_errors > 0 && discovery_errors == files.len() {
			anyhow::bail!(
				"llm-code-review: every one of {n} discovery calls errored; \
				 check worker logs for the underlying error (`RUST_LOG=loupe_worker=debug` \
				 surfaces the per-call failures)",
				n = files.len(),
			);
		}
		if discovery_errors > 0 {
			tracing::warn!(
				errored = discovery_errors,
				total = files.len(),
				"llm-code-review: some discovery calls errored",
			);
		}
		// Dedup slot: no-op for now. When server-side prior-findings
		// arrive (see LOUPE.md), this is where we'd drop matches.
		let after_dedup = discovered;
		tracing::info!(candidates = after_dedup.len(), "llm-code-review entering validation");

		let n_candidates = after_dedup.len();
		let (validated, validation_errors) =
			self.validate_all(&cfg, &ctx.workdir, after_dedup, &ctx.cancel).await;
		// Same fail-loud logic for validation, gated on the candidate
		// count so a zero-candidate run (clean repo) doesn't trip it.
		if validation_errors > 0 && validation_errors == n_candidates {
			anyhow::bail!("llm-code-review: every one of {n_candidates} validation calls errored",);
		}
		if validation_errors > 0 {
			tracing::warn!(
				errored = validation_errors,
				total = n_candidates,
				"llm-code-review: some validation calls errored",
			);
		}
		tracing::info!(emitted = validated.len(), "llm-code-review finished");

		Ok(validated.into_iter().map(|v| build_finding(&self.backend, v, &ctx.head_sha)).collect())
	}
}

/// One discovered (but un-validated) finding, post-JSON-parse.
#[derive(Debug, Clone)]
struct Discovered {
	severity: Severity,
	title: String,
	file: String,
	line_start: u32,
	line_end: u32,
	description: String,
	cwe: Option<String>,
}

/// One validated finding, ready to emit.
#[derive(Debug, Clone)]
struct Validated {
	d: Discovered,
	poc_unified: String,
	notes: Option<String>,
}

impl LlmCodeReviewScanner {
	/// Returns `(discovered, error_count)`. `error_count` is the number
	/// of per-file backend / sandbox call errors — distinct from
	/// "call succeeded but the model returned no finding" (which
	/// counts as a success). The caller fails the scan loud if every
	/// attempt errored.
	async fn discover_all(
		&self, cfg: &ScannerConfig, workdir: &Path, files: &[PathBuf], cancel: &CancellationToken,
	) -> (Vec<Discovered>, usize) {
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
				discover_one(backend, &workdir, &path, &cfg_owned, cancel).await
			}));
		}

		let mut out = Vec::new();
		let mut errors = 0usize;
		for h in handles {
			match h.await {
				Ok(Ok(Some(d))) => out.push(d),
				Ok(Ok(None)) => {},
				Ok(Err(())) => errors += 1,
				Err(e) => {
					tracing::warn!(error = %e, "discovery task panicked");
					errors += 1;
				},
			}
		}
		(out, errors)
	}

	/// Returns `(validated, error_count)`. Same semantics as
	/// `discover_all` for the error count.
	async fn validate_all(
		&self, cfg: &ScannerConfig, workdir: &Path, discovered: Vec<Discovered>,
		cancel: &CancellationToken,
	) -> (Vec<Validated>, usize) {
		let sem = Arc::new(Semaphore::new(cfg.max_concurrent_files));
		let mut handles = Vec::with_capacity(discovered.len());
		for d in discovered {
			if cancel.is_cancelled() {
				break;
			}
			let permit = sem.clone().acquire_owned().await.expect("semaphore not closed");
			let backend = self.backend.clone();
			let cfg_owned = cfg.clone();
			let workdir = workdir.to_path_buf();
			let cancel = cancel.clone();
			handles.push(tokio::spawn(async move {
				let _permit = permit;
				validate_one(backend, &workdir, d, &cfg_owned, cancel).await
			}));
		}
		let mut out = Vec::new();
		let mut errors = 0usize;
		for h in handles {
			match h.await {
				Ok(Ok(Some(v))) => out.push(v),
				Ok(Ok(None)) => {},
				Ok(Err(())) => errors += 1,
				Err(e) => {
					tracing::warn!(error = %e, "validation task panicked");
					errors += 1;
				},
			}
		}
		(out, errors)
	}
}

/// How many leading characters of an LLM response to log at debug
/// level. Long enough that a JSON parse failure usually prints the
/// offending shape; short enough that GBs of model output don't
/// drown the terminal.
const RESPONSE_PREVIEW_CHARS: usize = 240;

/// `Ok(Some(_))` = call ran, model produced a valid finding.
/// `Ok(None)` = call ran, model said "no finding here" (or output was
/// unparseable — we lump unparseable in with "no finding" because the
/// call itself worked, the model just emitted garbage). `Err(())` =
/// the backend / sandbox / network call itself failed; the caller
/// counts these and fails the scan if every attempt errors.
async fn discover_one(
	backend: Arc<dyn LlmBackend>, workdir: &Path, file: &Path, cfg: &ScannerConfig,
	cancel: CancellationToken,
) -> Result<Option<Discovered>, ()> {
	let rel = file.strip_prefix(workdir).unwrap_or(file).to_string_lossy().into_owned();
	let prompt = prompts::render(DISCOVERY, &[("file", &rel)]);
	tracing::info!(file = %rel, "llm-code-review: running discovery");
	let started = std::time::Instant::now();
	let req = LlmRequest {
		prompt,
		workdir: workdir.to_path_buf(),
		timeout: cfg.per_request_timeout,
		cancel,
	};
	let resp = match backend.run(req).await {
		Ok(r) => r,
		Err(e) => {
			tracing::warn!(file = %rel, error = %e, "discovery call failed");
			return Err(());
		},
	};
	tracing::debug!(
		file = %rel,
		elapsed_ms = started.elapsed().as_millis() as u64,
		response_chars = resp.text.chars().count(),
		preview = %resp.text.chars().take(RESPONSE_PREVIEW_CHARS).collect::<String>(),
		"discovery response",
	);
	Ok(parse_discovery(&resp, &rel))
}

async fn validate_one(
	backend: Arc<dyn LlmBackend>, workdir: &Path, d: Discovered, cfg: &ScannerConfig,
	cancel: CancellationToken,
) -> Result<Option<Validated>, ()> {
	let finding_json = serde_json::json!({
		"severity": d.severity.as_str(),
		"title": d.title,
		"file": d.file,
		"line_start": d.line_start,
		"line_end": d.line_end,
		"description": d.description,
		"cwe": d.cwe,
	});
	let prompt = prompts::render(
		VALIDATE,
		&[("file", &d.file), ("finding_json", &finding_json.to_string())],
	);
	tracing::info!(file = %d.file, title = %d.title, "llm-code-review: running validation");
	let started = std::time::Instant::now();
	let req = LlmRequest {
		prompt,
		workdir: workdir.to_path_buf(),
		timeout: cfg.per_request_timeout,
		cancel,
	};
	let resp = match backend.run(req).await {
		Ok(r) => r,
		Err(e) => {
			tracing::warn!(file = %d.file, error = %e, "validation call failed");
			return Err(());
		},
	};
	tracing::debug!(
		file = %d.file,
		elapsed_ms = started.elapsed().as_millis() as u64,
		response_chars = resp.text.chars().count(),
		preview = %resp.text.chars().take(RESPONSE_PREVIEW_CHARS).collect::<String>(),
		"validation response",
	);
	Ok(parse_validation(&resp, d))
}

#[derive(Debug, Deserialize)]
struct DiscoveryRaw {
	#[serde(default)]
	found: bool,
	#[serde(default)]
	severity: Option<String>,
	#[serde(default)]
	title: Option<String>,
	#[serde(default)]
	file: Option<String>,
	#[serde(default)]
	line_start: Option<u32>,
	#[serde(default)]
	line_end: Option<u32>,
	#[serde(default)]
	description: Option<String>,
	#[serde(default)]
	cwe: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ValidationRaw {
	verdict: String,
	#[serde(default)]
	notes: Option<String>,
	#[serde(default)]
	poc_unified: Option<String>,
}

fn parse_discovery(resp: &LlmResponse, expected_file: &str) -> Option<Discovered> {
	let json = extract_json_object(&resp.text)?;
	let raw: DiscoveryRaw = match serde_json::from_str(&json) {
		Ok(r) => r,
		Err(e) => {
			tracing::warn!(file = %expected_file, error = %e, "discovery JSON parse failed");
			return None;
		},
	};
	if !raw.found {
		return None;
	}
	let severity = raw.severity.as_deref().and_then(|s| s.parse().ok()).unwrap_or(Severity::Medium);
	Some(Discovered {
		severity,
		title: raw.title.unwrap_or_else(|| "Possible vulnerability".into()),
		file: raw.file.unwrap_or_else(|| expected_file.to_owned()),
		line_start: raw.line_start.unwrap_or(1),
		line_end: raw.line_end.unwrap_or(raw.line_start.unwrap_or(1)),
		description: raw.description.unwrap_or_default(),
		cwe: raw.cwe.filter(|s| !s.is_empty()),
	})
}

fn parse_validation(resp: &LlmResponse, d: Discovered) -> Option<Validated> {
	let json = extract_json_object(&resp.text)?;
	let raw: ValidationRaw = match serde_json::from_str(&json) {
		Ok(r) => r,
		Err(e) => {
			tracing::warn!(file = %d.file, error = %e, "validation JSON parse failed");
			return None;
		},
	};
	match raw.verdict.as_str() {
		"confirmed" => {
			let poc = raw.poc_unified.filter(|s| !s.trim().is_empty())?;
			Some(Validated { d, poc_unified: poc, notes: raw.notes })
		},
		_ => None,
	}
}

/// Pull the first balanced JSON object out of a possibly noisy text
/// response. Tolerates prose before/after the object and a single
/// markdown fence around it. Returns the slice as a `String` rather
/// than a `&str` because the model occasionally emits trailing junk
/// after the closing brace; we feed only what's inside the braces.
pub(crate) fn extract_json_object(text: &str) -> Option<String> {
	let bytes = text.as_bytes();
	// Find first '{'.
	let start = bytes.iter().position(|b| *b == b'{')?;
	// Walk to the matching '}', respecting string literals.
	let mut depth = 0i32;
	let mut in_str = false;
	let mut escape = false;
	for (i, b) in bytes.iter().enumerate().skip(start) {
		if in_str {
			if escape {
				escape = false;
			} else if *b == b'\\' {
				escape = true;
			} else if *b == b'"' {
				in_str = false;
			}
			continue;
		}
		match *b {
			b'"' => in_str = true,
			b'{' => depth += 1,
			b'}' => {
				depth -= 1;
				if depth == 0 {
					return std::str::from_utf8(&bytes[start..=i]).ok().map(|s| s.to_owned());
				}
			},
			_ => {},
		}
	}
	None
}

fn build_finding(backend: &Arc<dyn LlmBackend>, v: Validated, head_sha: &str) -> Finding {
	let mut hasher = blake3::Hasher::new();
	hasher.update(SCANNER_ID.as_bytes());
	hasher.update(b"|");
	hasher.update(v.d.file.as_bytes());
	hasher.update(b"|");
	hasher.update(v.d.line_start.to_string().as_bytes());
	hasher.update(b"|");
	hasher.update(v.d.title.as_bytes());
	let fingerprint = hasher.finalize().to_hex().to_string();

	let description = if let Some(notes) = v.notes {
		format!("{}\n\n_validation notes ({}): {}_", v.d.description, backend.id(), notes)
	} else {
		v.d.description
	};
	let _ = head_sha; // not currently part of the fingerprint; M2-deferred dedup may reference it
	Finding {
		scanner_id: SCANNER_ID.into(),
		severity: v.d.severity,
		title: v.d.title,
		description,
		file_path: Some(v.d.file),
		line_start: Some(v.d.line_start),
		line_end: Some(v.d.line_end),
		cwe: v.d.cwe,
		patch_unified: None,
		poc_unified: Some(v.poc_unified),
		fingerprint,
	}
}

/// Walk the worktree for source files following the strategy from
/// `claude-ctf.sh`: workspace `[workspace] members` → each member's
/// `src/`; single-crate `Cargo.toml` → `src/`; otherwise the entire
/// tree under any `src/` directory. Honours the include extension
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

	#[tokio::test]
	async fn ctx_config_override_changes_walked_extensions() {
		// A C-only repo overrides include_extensions so a `.c` file is
		// picked up even though the project has no Cargo.toml.
		let tmp = tempfile::tempdir().unwrap();
		std::fs::write(tmp.path().join("widget.c"), "/* stub */\n").unwrap();

		// Stub backend that always reports a finding so we can tell
		// whether the file was visited.
		let backend = Arc::new(StubLlmBackend::new("stub", |req: &LlmRequest| {
			if req.prompt.contains("validating a vulnerability report") {
				Ok(r#"{"verdict":"confirmed","notes":"x","poc_unified":"--- diff ---"}"#.to_owned())
			} else {
				Ok(r#"{"found":true,"severity":"low","title":"stub","file":"widget.c","line_start":1,"line_end":1,"description":"d"}"#.to_owned())
			}
		}));
		let scanner = LlmCodeReviewScanner::new(backend);

		let mut ctx = make_ctx(tmp.path());
		ctx.config = serde_json::json!({"include_extensions":["c"]});
		let findings = scanner.scan(&ctx).await.unwrap();
		assert_eq!(findings.len(), 1, "ctx.config override should have caught widget.c");
		assert_eq!(findings[0].file_path.as_deref(), Some("widget.c"));
	}

	#[test]
	fn extract_json_object_from_prose() {
		let text = "Sure! Here you go:\n\n```json\n{\n  \"found\": true\n}\n```\nLet me know.";
		let s = extract_json_object(text).unwrap();
		assert!(s.contains("\"found\""));
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
	async fn scanner_emits_validated_findings_via_stub() {
		let tmp = tempfile::tempdir().unwrap();
		write_crate(
			tmp.path(),
			&[("src/lib.rs", "pub fn idx(arr: &[u8], i: usize) -> u8 { arr[i] }\n")],
		);

		// Stub returns a discovery JSON for any DISCOVERY-style prompt
		// and a confirmed validation with a PoC for any VALIDATE prompt.
		// We tell them apart by looking for distinct phrases in the prompt.
		let backend = Arc::new(StubLlmBackend::new("stub", |req: &LlmRequest| {
			if req.prompt.contains("validating a vulnerability report") {
				Ok(r#"{"verdict":"confirmed","notes":"reproduced","poc_unified":"--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -0,0 +1 @@\n+#[test] fn oob() { idx(&[], 0); }\n"}"#.to_owned())
			} else {
				Ok(r#"{"found":true,"severity":"high","title":"oob index","file":"src/lib.rs","line_start":1,"line_end":1,"description":"unchecked index","cwe":"CWE-129"}"#.to_owned())
			}
		}));
		let scanner = LlmCodeReviewScanner::new(backend);
		let findings = scanner.scan(&make_ctx(tmp.path())).await.unwrap();
		assert_eq!(findings.len(), 1);
		let f = &findings[0];
		assert_eq!(f.scanner_id, SCANNER_ID);
		assert_eq!(f.severity, Severity::High);
		assert_eq!(f.file_path.as_deref(), Some("src/lib.rs"));
		assert_eq!(f.line_start, Some(1));
		assert!(f.poc_unified.as_deref().unwrap().contains("#[test]"), "got: {:?}", f.poc_unified);
		assert!(f.description.contains("validation notes"));
	}

	#[tokio::test]
	async fn scanner_drops_rejected_findings() {
		let tmp = tempfile::tempdir().unwrap();
		write_crate(tmp.path(), &[("src/lib.rs", "// nothing to see\n")]);
		let backend = Arc::new(StubLlmBackend::new("stub", |req: &LlmRequest| {
			if req.prompt.contains("validating a vulnerability report") {
				Ok(r#"{"verdict":"rejected","notes":"hallucination","poc_unified":null}"#
					.to_owned())
			} else {
				Ok(r#"{"found":true,"severity":"medium","title":"x","file":"src/lib.rs","line_start":1,"line_end":1,"description":"d"}"#.to_owned())
			}
		}));
		let scanner = LlmCodeReviewScanner::new(backend);
		let findings = scanner.scan(&make_ctx(tmp.path())).await.unwrap();
		assert!(findings.is_empty(), "rejected verdicts must not emit findings");
	}

	#[tokio::test]
	async fn scanner_drops_unparseable_discovery() {
		let tmp = tempfile::tempdir().unwrap();
		write_crate(tmp.path(), &[("src/lib.rs", "// content\n")]);
		let calls = Arc::new(AtomicUsize::new(0));
		let calls_for_stub = calls.clone();
		let backend = Arc::new(StubLlmBackend::new("stub", move |req: &LlmRequest| {
			calls_for_stub.fetch_add(1, Ordering::SeqCst);
			if req.prompt.contains("validating a vulnerability report") {
				panic!("validation should not run when discovery fails to parse");
			}
			Ok("not actually json".to_owned())
		}));
		let scanner = LlmCodeReviewScanner::new(backend);
		let findings = scanner.scan(&make_ctx(tmp.path())).await.unwrap();
		assert!(findings.is_empty());
		assert_eq!(calls.load(Ordering::SeqCst), 1, "only the discovery call should have run");
	}
}
