//! Production source-file discovery for the LLM code-review scanner.
//!
//! The regex secrets scanner intentionally keeps its own broad tree walk:
//! secrets can appear in tests, docs, or config. This module is for the
//! expensive per-source-file LLM fan-out, where we prefer production code
//! and common project layouts over exhaustive repository traversal.

use std::path::{Path, PathBuf};
use std::time::Duration;

use glob::Pattern;
use serde::Deserialize;

use crate::llm::DEFAULT_REQUEST_TIMEOUT;

/// Config knobs operators can set via the repo's `scanner_config`
/// JSON. Defaults cover Rust, C/C++, JS/TS, Python, Go, Ruby, PHP, and
/// JVM/Swift sources, plus an excludelist that drops common build /
/// vendor / test dirs across those ecosystems. Tighten or loosen
/// per-repo by sending a partial JSON override (see
/// `ScannerConfigPatch`).
#[derive(Debug, Clone)]
pub struct ScannerConfig {
	pub max_concurrent_files: usize,
	pub max_file_bytes: u64,
	pub per_request_timeout: Duration,
	/// File extensions the walk will consider, lower-cased and without
	/// the leading dot (e.g. `["rs", "cpp"]`).
	pub include_extensions: Vec<String>,
	/// Exclusion patterns that disqualify a path. Built-in patterns
	/// use `dir:<name>` for exact path components and `file:<glob>`
	/// for basename matches. Legacy custom strings still match as
	/// path substrings, except `/name` matches an exact component.
	pub exclude_path_substrings: Vec<String>,
}

impl Default for ScannerConfig {
	fn default() -> Self {
		Self {
			max_concurrent_files: 8,
			max_file_bytes: 2 * 1024 * 1024,
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
#[derive(Debug, Default, Clone, Deserialize)]
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
		"dir:tests",
		"dir:test",
		"dir:examples",
		"dir:__tests__",
		"file:test_*.*",
		"file:*_test.*",
		"file:*_tests.*",
		"file:*.test.*",
		"file:*.spec.*",
		// Build artefacts across ecosystems.
		"dir:target",
		"dir:build",
		"dir:dist",
		"dir:out",
		"dir:.next",
		"dir:.nuxt",
		"dir:coverage",
		// Vendored deps.
		"dir:node_modules",
		"dir:vendor",
		"dir:.venv",
		"dir:venv",
		"dir:env",
		// Caches.
		"dir:__pycache__",
		"dir:.tox",
		"dir:.gradle",
		"dir:.mypy_cache",
		"dir:.pytest_cache",
	]
	.into_iter()
	.map(String::from)
	.collect()
}

/// Walk the worktree for production source files. Strategy:
///
/// - Rust Cargo package roots from the root package/workspace, including
///   `workspace.members` globs and `workspace.exclude`.
/// - JS/TS roots under directories containing `package.json`.
/// - C/C++ roots under directories containing common build-system markers.
/// - Fallback to the whole worktree if no project roots are discovered.
///
/// All walks honour the extension allowlist, exclude patterns, and
/// per-file size cap. `.git` and any excluded directory is skipped
/// wholesale.
pub(crate) fn walk_source_files(workdir: &Path, cfg: &ScannerConfig) -> Vec<PathBuf> {
	let roots = discover_roots(workdir, cfg);
	let mut out = Vec::new();

	if roots.roots.is_empty() && roots.files.is_empty() {
		collect_from_root(workdir, cfg, &mut out);
	} else {
		for file in roots.files {
			collect_file(&file, cfg, &mut out);
		}
		for root in roots.roots {
			collect_from_root(&root, cfg, &mut out);
		}
	}

	out.sort();
	out.dedup();
	out
}

#[derive(Default)]
struct DiscoveryRoots {
	roots: Vec<PathBuf>,
	files: Vec<PathBuf>,
}

fn discover_roots(workdir: &Path, cfg: &ScannerConfig) -> DiscoveryRoots {
	let mut roots = DiscoveryRoots::default();
	add_cargo_roots(workdir, &mut roots);
	add_marker_roots(workdir, cfg, &mut roots);
	roots.roots.sort();
	roots.roots.dedup();
	roots.files.sort();
	roots.files.dedup();
	roots
}

fn add_cargo_roots(workdir: &Path, roots: &mut DiscoveryRoots) {
	let cargo_toml = workdir.join("Cargo.toml");
	if !cargo_toml.exists() {
		return;
	}

	match parse_workspace(&cargo_toml) {
		Some(workspace) => {
			for member in expand_workspace_members(workdir, &workspace.members, &workspace.exclude)
			{
				add_rust_package_roots(&member, roots);
			}
		},
		None => add_rust_package_roots(workdir, roots),
	}
}

fn add_rust_package_roots(package: &Path, roots: &mut DiscoveryRoots) {
	let src = package.join("src");
	if src.is_dir() {
		roots.roots.push(src);
	}
	let build_rs = package.join("build.rs");
	if build_rs.is_file() {
		roots.files.push(build_rs);
	}
}

#[derive(Debug, Default)]
struct WorkspaceManifest {
	members: Vec<String>,
	exclude: Vec<String>,
}

fn parse_workspace(cargo_toml: &Path) -> Option<WorkspaceManifest> {
	let text = std::fs::read_to_string(cargo_toml).ok()?;
	let manifest: toml::Value = toml::from_str(&text).ok()?;
	let workspace = manifest.get("workspace")?;
	let members = read_string_array(workspace, "members");
	let exclude = read_string_array(workspace, "exclude");
	Some(WorkspaceManifest { members, exclude })
}

fn read_string_array(table: &toml::Value, key: &str) -> Vec<String> {
	table
		.get(key)
		.and_then(|value| value.as_array())
		.into_iter()
		.flatten()
		.filter_map(|value| value.as_str())
		.map(str::to_owned)
		.collect()
}

fn expand_workspace_members(
	workdir: &Path, members: &[String], excludes: &[String],
) -> Vec<PathBuf> {
	let mut out = Vec::new();
	for member in members {
		for path in expand_relative_pattern(workdir, member) {
			if !path.is_dir() {
				continue;
			}
			let rel = path.strip_prefix(workdir).unwrap_or(&path);
			if matches_workspace_exclude(rel, excludes) {
				continue;
			}
			if path.join("Cargo.toml").is_file() {
				out.push(path);
			}
		}
	}
	out.sort();
	out.dedup();
	out
}

fn expand_relative_pattern(base: &Path, pattern: &str) -> Vec<PathBuf> {
	if !has_glob_meta(pattern) {
		return vec![base.join(pattern)];
	}
	let Some(abs_pattern) = base.join(pattern).to_str().map(str::to_owned) else {
		return Vec::new();
	};
	let mut out: Vec<PathBuf> =
		glob::glob(&abs_pattern).into_iter().flatten().filter_map(Result::ok).collect();
	out.sort();
	out
}

fn matches_workspace_exclude(rel: &Path, excludes: &[String]) -> bool {
	excludes.iter().any(|exclude| {
		if exclude == rel.to_string_lossy().as_ref() {
			return true;
		}
		Pattern::new(exclude).map(|pattern| pattern.matches_path(rel)).unwrap_or(false)
	})
}

fn has_glob_meta(pattern: &str) -> bool {
	pattern.as_bytes().iter().any(|b| matches!(b, b'*' | b'?' | b'['))
}

fn add_marker_roots(workdir: &Path, cfg: &ScannerConfig, roots: &mut DiscoveryRoots) {
	for marker_dir in marker_dirs(workdir, cfg, "package.json") {
		add_existing_dirs(
			&marker_dir,
			&["src", "lib", "app", "server", "client", "packages"],
			&mut roots.roots,
		);
	}

	for marker in ["CMakeLists.txt", "meson.build", "Makefile", "compile_commands.json"] {
		for marker_dir in marker_dirs(workdir, cfg, marker) {
			roots.roots.push(marker_dir.clone());
			add_existing_dirs(
				&marker_dir,
				&["src", "include", "lib", "app", "server", "client"],
				&mut roots.roots,
			);
		}
	}
}

fn marker_dirs(workdir: &Path, cfg: &ScannerConfig, marker: &str) -> Vec<PathBuf> {
	walkdir::WalkDir::new(workdir)
		.max_depth(5)
		.into_iter()
		.filter_entry(|entry| !is_excluded_dir(entry.path(), cfg))
		.filter_map(Result::ok)
		.filter(|entry| entry.file_type().is_file() && entry.file_name() == marker)
		.filter_map(|entry| entry.path().parent().map(Path::to_path_buf))
		.collect()
}

fn add_existing_dirs(base: &Path, names: &[&str], out: &mut Vec<PathBuf>) {
	for name in names {
		let path = base.join(name);
		if path.is_dir() {
			out.push(path);
		}
	}
}

fn collect_from_root(root: &Path, cfg: &ScannerConfig, out: &mut Vec<PathBuf>) {
	walkdir::WalkDir::new(root)
		.into_iter()
		.filter_entry(|entry| !is_excluded_dir(entry.path(), cfg))
		.filter_map(Result::ok)
		.filter(|entry| entry.file_type().is_file())
		.for_each(|entry| collect_file(entry.path(), cfg, out));
}

fn collect_file(path: &Path, cfg: &ScannerConfig, out: &mut Vec<PathBuf>) {
	if !has_allowed_extension(path, &cfg.include_extensions) {
		return;
	}
	if is_excluded_path(path, &cfg.exclude_path_substrings) {
		return;
	}
	if !path.metadata().map(|m| m.len() <= cfg.max_file_bytes).unwrap_or(false) {
		return;
	}
	out.push(path.to_path_buf());
}

fn is_excluded_dir(path: &Path, cfg: &ScannerConfig) -> bool {
	if has_component(path, ".git") {
		return true;
	}
	cfg.exclude_path_substrings.iter().any(|pattern| matches_exclude(path, pattern))
}

fn is_excluded_path(path: &Path, excludes: &[String]) -> bool {
	excludes.iter().any(|pattern| matches_exclude(path, pattern))
}

fn matches_exclude(path: &Path, pattern: &str) -> bool {
	if let Some(component) = pattern.strip_prefix("dir:") {
		return has_component(path, component);
	}
	if let Some(glob) = pattern.strip_prefix("file:") {
		return path
			.file_name()
			.and_then(|name| name.to_str())
			.map(|name| Pattern::new(glob).map(|p| p.matches(name)).unwrap_or(false))
			.unwrap_or(false);
	}
	if let Some(component) = pattern.strip_prefix('/') {
		if !component.contains('/') {
			return has_component(path, component);
		}
	}
	path.to_string_lossy().contains(pattern)
}

fn has_component(path: &Path, needle: &str) -> bool {
	path.components().any(|component| component.as_os_str() == needle)
}

fn has_allowed_extension(path: &Path, exts: &[String]) -> bool {
	let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
		return false;
	};
	exts.iter().any(|allowed| {
		path.extension()
			.and_then(|e| e.to_str())
			.map(|e| allowed.eq_ignore_ascii_case(e))
			.unwrap_or(false)
			|| file_name
				.to_ascii_lowercase()
				.ends_with(&format!(".{}", allowed.to_ascii_lowercase()))
	})
}

#[cfg(test)]
mod tests {
	use std::path::Path;

	use super::*;

	fn write_crate(root: &Path, files: &[(&str, &str)]) {
		std::fs::create_dir_all(root).unwrap();
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

	fn rel_names(root: &Path, files: Vec<PathBuf>) -> Vec<String> {
		files.iter().map(|p| p.strip_prefix(root).unwrap().to_string_lossy().into_owned()).collect()
	}

	#[test]
	fn defaults_cover_common_languages() {
		let cfg = ScannerConfig::default();
		assert_eq!(cfg.max_file_bytes, 2 * 1024 * 1024);
		for ext in ["rs", "c", "cpp", "h", "hpp", "js", "ts", "tsx", "py", "go", "java", "swift"] {
			assert!(cfg.include_extensions.iter().any(|e| e == ext), "missing: {ext}");
		}
		assert!(cfg.exclude_path_substrings.iter().any(|e| e == "dir:node_modules"));
		assert!(cfg.exclude_path_substrings.iter().any(|e| e == "dir:target"));
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
		std::fs::create_dir_all(tmp.path().join("src")).unwrap();
		std::fs::write(tmp.path().join("src/main.cpp"), "// stub\n").unwrap();
		std::fs::write(tmp.path().join("src/util.h"), "// stub\n").unwrap();
		std::fs::write(tmp.path().join("src/app.py"), "# stub\n").unwrap();
		std::fs::write(tmp.path().join("src/page.tsx"), "// stub\n").unwrap();

		let names = rel_names(tmp.path(), walk_source_files(tmp.path(), &ScannerConfig::default()));
		for expected in ["src/main.cpp", "src/util.h", "src/app.py", "src/page.tsx"] {
			assert!(names.iter().any(|n| n == expected), "missing {expected} in {names:?}");
		}
	}

	#[test]
	fn cargo_workspace_member_globs_are_expanded() {
		let tmp = tempfile::tempdir().unwrap();
		std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]\nmembers = [\"crates/*\"]\n")
			.unwrap();
		write_crate(&tmp.path().join("crates/api"), &[("src/lib.rs", "// api\n")]);
		write_crate(&tmp.path().join("crates/worker"), &[("src/main.rs", "// worker\n")]);

		let names = rel_names(tmp.path(), walk_source_files(tmp.path(), &ScannerConfig::default()));
		assert!(names.iter().any(|n| n == "crates/api/src/lib.rs"), "names: {names:?}");
		assert!(names.iter().any(|n| n == "crates/worker/src/main.rs"), "names: {names:?}");
	}

	#[test]
	fn cargo_workspace_exclude_skips_matching_member_globs() {
		let tmp = tempfile::tempdir().unwrap();
		std::fs::write(
			tmp.path().join("Cargo.toml"),
			"[workspace]\nmembers = [\"crates/*\"]\nexclude = [\"crates/private-*\"]\n",
		)
		.unwrap();
		write_crate(&tmp.path().join("crates/public"), &[("src/lib.rs", "// public\n")]);
		write_crate(&tmp.path().join("crates/private-api"), &[("src/lib.rs", "// private\n")]);

		let names = rel_names(tmp.path(), walk_source_files(tmp.path(), &ScannerConfig::default()));
		assert!(names.iter().any(|n| n == "crates/public/src/lib.rs"), "names: {names:?}");
		assert!(names.iter().all(|n| !n.contains("private-api")), "names: {names:?}");
	}

	#[test]
	fn mixed_rust_cpp_js_and_typescript_sources_are_discovered() {
		let tmp = tempfile::tempdir().unwrap();
		std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]\nmembers = [\"crates/*\"]\n")
			.unwrap();
		write_crate(&tmp.path().join("crates/core"), &[("src/lib.rs", "// rust\n")]);
		std::fs::write(tmp.path().join("package.json"), "{}\n").unwrap();
		std::fs::write(tmp.path().join("CMakeLists.txt"), "project(x)\n").unwrap();
		std::fs::create_dir_all(tmp.path().join("src")).unwrap();
		std::fs::write(tmp.path().join("src/index.ts"), "// ts\n").unwrap();
		std::fs::write(tmp.path().join("src/view.tsx"), "// tsx\n").unwrap();
		std::fs::write(tmp.path().join("src/widget.cpp"), "// cpp\n").unwrap();
		std::fs::write(tmp.path().join("src/widget.test.ts"), "// test\n").unwrap();
		std::fs::write(tmp.path().join("main.cc"), "// top-level cpp\n").unwrap();

		let names = rel_names(tmp.path(), walk_source_files(tmp.path(), &ScannerConfig::default()));
		for expected in
			["crates/core/src/lib.rs", "src/index.ts", "src/view.tsx", "src/widget.cpp", "main.cc"]
		{
			assert!(names.iter().any(|n| n == expected), "missing {expected} in {names:?}");
		}
		assert!(names.iter().all(|n| n != "src/widget.test.ts"), "names: {names:?}");
	}

	#[test]
	fn walk_excludes_node_modules_and_build_dirs_by_default() {
		let tmp = tempfile::tempdir().unwrap();
		std::fs::create_dir_all(tmp.path().join("src")).unwrap();
		std::fs::write(tmp.path().join("src/index.js"), "// real\n").unwrap();
		std::fs::create_dir_all(tmp.path().join("node_modules/lodash")).unwrap();
		std::fs::write(tmp.path().join("node_modules/lodash/index.js"), "// vendored\n").unwrap();
		std::fs::create_dir_all(tmp.path().join("dist")).unwrap();
		std::fs::write(tmp.path().join("dist/bundle.js"), "// built\n").unwrap();

		let names = rel_names(tmp.path(), walk_source_files(tmp.path(), &ScannerConfig::default()));
		assert!(names.iter().any(|n| n == "src/index.js"), "real source missing: {names:?}");
		assert!(names.iter().all(|n| !n.contains("node_modules")), "leak: {names:?}");
		assert!(names.iter().all(|n| !n.starts_with("dist/")), "leak: {names:?}");
	}

	#[test]
	fn directory_excludes_match_exact_components_not_prefixes() {
		let tmp = tempfile::tempdir().unwrap();
		write_crate(
			tmp.path(),
			&[
				("src/outbound_payment.rs", "// production source\n"),
				("src/out/generated.rs", "// generated output\n"),
				("src/distill.rs", "// production source\n"),
				("src/dist/bundle.rs", "// generated output\n"),
			],
		);

		let names = rel_names(tmp.path(), walk_source_files(tmp.path(), &ScannerConfig::default()));
		assert!(names.iter().any(|n| n == "src/outbound_payment.rs"), "names: {names:?}");
		assert!(names.iter().any(|n| n == "src/distill.rs"), "names: {names:?}");
		assert!(names.iter().all(|n| !n.starts_with("src/out/")), "names: {names:?}");
		assert!(names.iter().all(|n| !n.starts_with("src/dist/")), "names: {names:?}");
	}

	#[test]
	fn file_test_patterns_match_common_test_names() {
		let tmp = tempfile::tempdir().unwrap();
		write_crate(
			tmp.path(),
			&[
				("src/lib.rs", "// production source\n"),
				("src/test_utils.rs", "// test helper\n"),
				("src/accountable_tests.rs", "// test module\n"),
				("src/payment.test.ts", "// js-style test\n"),
				("src/payment.spec.ts", "// js-style test\n"),
			],
		);

		let names = rel_names(tmp.path(), walk_source_files(tmp.path(), &ScannerConfig::default()));
		assert_eq!(names, vec!["src/lib.rs"]);
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
		let names = rel_names(tmp.path(), walk_source_files(tmp.path(), &ScannerConfig::default()));
		assert!(names.iter().any(|n| n.ends_with("src/lib.rs")), "names: {names:?}");
		assert!(names.iter().any(|n| n.ends_with("src/util.rs")), "names: {names:?}");
		assert!(names.iter().all(|n| !n.contains("README")), "names: {names:?}");
		assert!(names.iter().all(|n| !n.contains("tests/")), "names: {names:?}");
	}

	#[test]
	fn includes_build_rs_and_multi_part_extensions() {
		let tmp = tempfile::tempdir().unwrap();
		write_crate(
			tmp.path(),
			&[("build.rs", "// build script\n"), ("src/generated.rs.in", "// template\n")],
		);

		let names = rel_names(tmp.path(), walk_source_files(tmp.path(), &ScannerConfig::default()));
		assert!(names.iter().any(|n| n == "build.rs"), "names: {names:?}");
		assert!(names.iter().any(|n| n == "src/generated.rs.in"), "names: {names:?}");
	}
}
