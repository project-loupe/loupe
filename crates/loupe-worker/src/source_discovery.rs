//! Production source-file discovery for the LLM code-review scanner.
//!
//! The regex secrets scanner intentionally keeps its own broad tree walk:
//! secrets can appear in tests, docs, or config. This module is for the
//! expensive per-source-file LLM fan-out, where we prefer production code
//! and common project layouts over exhaustive repository traversal.

use std::path::{Path, PathBuf};
use std::time::Duration;

use glob::Pattern;
use loupe_core::source_migration::text::{BoundedText, RepoPath};
use loupe_provenance::{Ingress, Mark, Repo, Untrusted, Unvalidated, Validate};
use serde::Deserialize;

use crate::ingress_text::ScannerExcludePattern;
use crate::llm::DEFAULT_REQUEST_TIMEOUT;

/// Config knobs operators can set via the repo's `scanner_config`
/// JSON. Defaults cover Rust, C/C++, JS/TS, Python, Go, Ruby, PHP,
/// JVM/Swift, and .NET sources, plus an excludelist that drops common
/// build / vendor / test dirs across those ecosystems. Tighten or loosen
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
	/// use `dir:<name>` for exact path components, `file:<glob>` for
	/// basename matches, and `dotnet-output:<name>` for .NET build
	/// output directories. Legacy custom strings still match as path
	/// substrings, except `/name` matches an exact component.
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
		"swift",  // .NET.
		"cs", "fs", "fsi", "fsx", "vb", // Misc.
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
		"dir:fuzz",
		// Build artefacts across ecosystems.
		"dir:target",
		"dotnet-output:bin",
		"dotnet-output:obj",
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
/// - Rust Cargo package roots from non-excluded `Cargo.toml` manifests
///   with a `[package]` table. This intentionally includes in-repo
///   packages that are path dependencies but not workspace members.
/// - JS/TS roots under directories containing `package.json`.
/// - C/C++ roots under directories containing common build-system markers.
/// - .NET roots under directories containing solution or project files.
/// - Fallback to the whole worktree if no project roots are discovered.
///
/// All walks honour the extension allowlist, exclude patterns, and
/// per-file size cap. `.git` and any excluded directory is skipped
/// wholesale.
pub(crate) fn walk_source_files(workdir: &Path, cfg: &ScannerConfig) -> Vec<PathBuf> {
	let Ok(canonical_workdir) = workdir.canonicalize() else {
		return Vec::new();
	};
	let roots = discover_roots(workdir, cfg);
	let mut out = Vec::new();

	if roots.roots.is_empty() && roots.files.is_empty() {
		collect_from_root(workdir, workdir, cfg, &mut out);
	} else {
		for file in roots.files {
			if is_within_workdir(&file, &canonical_workdir) {
				collect_file(workdir, &file, cfg, &mut out);
			}
		}
		for root in roots.roots {
			if is_within_workdir(&root, &canonical_workdir) {
				collect_from_root(workdir, &root, cfg, &mut out);
			}
		}
	}

	out.sort();
	out.dedup();
	out
}

// WalkDir does not follow nested symlinks, but it follows a symlink used as
// its root. Package src directories and direct build.rs files therefore need
// this check before traversal or collection. Preserve in-workdir symlinks.
fn is_within_workdir(path: &Path, canonical_workdir: &Path) -> bool {
	path.canonicalize().map(|path| path.starts_with(canonical_workdir)).unwrap_or(false)
}

#[derive(Default)]
struct DiscoveryRoots {
	roots: Vec<PathBuf>,
	files: Vec<PathBuf>,
}

fn discover_roots(workdir: &Path, cfg: &ScannerConfig) -> DiscoveryRoots {
	let mut roots = DiscoveryRoots::default();
	add_cargo_roots(workdir, cfg, &mut roots);
	add_marker_roots(workdir, cfg, &mut roots);
	add_dotnet_roots(workdir, cfg, &mut roots);
	roots.roots.sort();
	roots.roots.dedup();
	roots.files.sort();
	roots.files.dedup();
	roots
}

fn add_cargo_roots(workdir: &Path, cfg: &ScannerConfig, roots: &mut DiscoveryRoots) {
	let workspace_exclude = parse_workspace(&workdir.join("Cargo.toml"))
		.map(|workspace| workspace.exclude)
		.unwrap_or_default();

	for manifest in cargo_package_manifests(workdir, cfg, &workspace_exclude) {
		if let Some(package_dir) = manifest.parent() {
			add_rust_package_roots(package_dir, roots);
		}
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
	exclude: Vec<String>,
}

fn parse_workspace(cargo_toml: &Path) -> Option<WorkspaceManifest> {
	let manifest = parse_manifest(cargo_toml)?;
	manifest.legacy_discovery()
}

fn cargo_package_manifests(
	workdir: &Path, cfg: &ScannerConfig, workspace_exclude: &[String],
) -> Vec<PathBuf> {
	let mut out: Vec<PathBuf> = walkdir::WalkDir::new(workdir)
		.into_iter()
		.filter_entry(|entry| {
			!is_excluded_dir(entry.path(), cfg)
				&& !is_workspace_excluded_descendant(workdir, entry.path(), workspace_exclude)
		})
		.filter_map(Result::ok)
		.filter(|entry| entry.file_type().is_file() && entry.file_name() == "Cargo.toml")
		.map(|entry| entry.into_path())
		.filter(|manifest| manifest_has_package(manifest))
		.collect();
	out.sort();
	out.dedup();
	out
}

fn manifest_has_package(cargo_toml: &Path) -> bool {
	let Some(manifest) = parse_manifest(cargo_toml) else {
		return false;
	};
	manifest.has_package
}

fn parse_manifest(cargo_toml: &Path) -> Option<CargoDiscoveryManifest> {
	let bytes = std::fs::read(cargo_toml).ok()?;
	// SAFETY: original repository Cargo.toml bytes, before UTF-8/TOML parsing.
	#[allow(unsafe_code)]
	let bytes = Untrusted::new(bytes, unsafe { Ingress::<Repo>::new() });
	bytes.as_bytes().validate(CargoDiscoveryManifestDecoder).ok().flatten()
}

struct CargoDiscoveryManifest {
	has_package: bool,
	exclude: Option<Vec<BoundedText<ScannerExcludePattern, Repo>>>,
	#[cfg(fuzzing)]
	original: toml::Value,
}
struct CargoDiscoveryManifestDecoder;
impl Validate<&[u8], Repo> for CargoDiscoveryManifestDecoder {
	type Output = Option<CargoDiscoveryManifest>;
	type Error = std::convert::Infallible;
	fn validate<'view>(
		self, u: Unvalidated<'view, &[u8]>, mark: Mark<'view, Repo>,
	) -> Result<Self::Output, Self::Error> {
		let Some(manifest) = std::str::from_utf8(u.get())
			.ok()
			.and_then(|text| toml::from_str::<toml::Value>(text).ok())
		else {
			return Ok(None);
		};
		let exclude = match manifest.get("workspace") {
			None => None,
			Some(workspace) => {
				let values = workspace
					.get("exclude")
					.and_then(toml::Value::as_array)
					.into_iter()
					.flatten()
					.filter_map(toml::Value::as_str);
				let mut exclude = Vec::new();
				for value in values {
					let Ok(value) = BoundedText::new(&mark, value) else { return Ok(None) };
					exclude.push(value);
				}
				Some(exclude)
			},
		};
		Ok(Some(CargoDiscoveryManifest {
			has_package: manifest.get("package").is_some(),
			exclude,
			#[cfg(fuzzing)]
			original: manifest,
		}))
	}
}
impl CargoDiscoveryManifest {
	/// Temporary marked Repo exclusion projection into the legacy selector.
	fn legacy_discovery(self) -> Option<WorkspaceManifest> {
		self.exclude.map(|values| WorkspaceManifest {
			exclude: values.into_iter().map(|v| v.expose().to_owned()).collect(),
		})
	}
}

/// Fuzz-only access to production manifest parsing and source selection.
#[cfg(fuzzing)]
pub mod fuzz_support {
	use std::path::{Path, PathBuf};

	pub fn parse_manifest(path: &Path) -> Option<toml::Value> {
		// Fuzz-only original syntax oracle; no production generic Value exit.
		super::parse_manifest(path).map(|manifest| manifest.original)
	}

	pub fn workspace_excludes(path: &Path) -> Option<Vec<String>> {
		super::parse_workspace(path).map(|workspace| workspace.exclude)
	}

	pub fn walk(workdir: &Path, excludes: &[String]) -> Vec<PathBuf> {
		let mut cfg = super::ScannerConfig::default();
		cfg.exclude_path_substrings.extend_from_slice(excludes);
		super::walk_source_files(workdir, &cfg)
	}
}

fn matches_workspace_exclude(rel: &Path, excludes: &[String]) -> bool {
	excludes.iter().any(|exclude| {
		if exclude == rel.to_string_lossy().as_ref() {
			return true;
		}
		Pattern::new(exclude).map(|pattern| pattern.matches_path(rel)).unwrap_or(false)
	})
}

fn is_workspace_excluded_descendant(workdir: &Path, path: &Path, excludes: &[String]) -> bool {
	if excludes.is_empty() {
		return false;
	}
	let rel = path.strip_prefix(workdir).unwrap_or(path);
	rel.ancestors()
		.take_while(|candidate| !candidate.as_os_str().is_empty())
		.any(|candidate| matches_workspace_exclude(candidate, excludes))
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

fn add_dotnet_roots(workdir: &Path, cfg: &ScannerConfig, roots: &mut DiscoveryRoots) {
	for marker_dir in
		dotnet_marker_dirs(workdir, cfg, &["sln", "slnx", "csproj", "fsproj", "vbproj"])
	{
		roots.roots.push(marker_dir);
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

fn dotnet_marker_dirs(workdir: &Path, cfg: &ScannerConfig, exts: &[&str]) -> Vec<PathBuf> {
	walkdir::WalkDir::new(workdir)
		.into_iter()
		.filter_entry(|entry| !is_excluded_dir(entry.path(), cfg))
		.filter_map(Result::ok)
		.filter(|entry| {
			entry.file_type().is_file()
				&& entry
					.path()
					.extension()
					.and_then(|ext| ext.to_str())
					.map(|ext| exts.iter().any(|allowed| allowed.eq_ignore_ascii_case(ext)))
					.unwrap_or(false)
		})
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

fn collect_from_root(workdir: &Path, root: &Path, cfg: &ScannerConfig, out: &mut Vec<PathBuf>) {
	walkdir::WalkDir::new(root)
		.into_iter()
		.filter_entry(|entry| !is_excluded_dir(entry.path(), cfg))
		.filter_map(Result::ok)
		.filter(|entry| entry.file_type().is_file())
		.for_each(|entry| collect_file(workdir, entry.path(), cfg, out));
}

fn collect_file(workdir: &Path, path: &Path, cfg: &ScannerConfig, out: &mut Vec<PathBuf>) {
	// SAFETY: native file path from an actual walk entry or the observed
	// package build.rs file, before file-name interpretation here.
	#[allow(unsafe_code)]
	let path = Untrusted::new(path.to_owned(), unsafe { Ingress::<Repo>::new() });
	if let Some(path) = path
		.validate(DiscoveredSourcePathDecoder { workdir, cfg })
		.expect("infallible path selection")
	{
		out.push(path.legacy_discovery_path());
	}
}

enum SourcePathRepresentation {
	Relative(RepoPath<Repo>),
	UnrepresentableNative,
}
struct DiscoveredSourcePath {
	native: PathBuf,
	representation: SourcePathRepresentation,
}
struct DiscoveredSourcePathDecoder<'a> {
	workdir: &'a Path,
	cfg: &'a ScannerConfig,
}
impl Validate<PathBuf, Repo> for DiscoveredSourcePathDecoder<'_> {
	type Output = Option<DiscoveredSourcePath>;
	type Error = std::convert::Infallible;
	fn validate<'view>(
		self, u: Unvalidated<'view, PathBuf>, mark: Mark<'view, Repo>,
	) -> Result<Self::Output, Self::Error> {
		let path = u.get();
		if !has_allowed_extension(path, &self.cfg.include_extensions)
			|| is_excluded_path(path, &self.cfg.exclude_path_substrings)
			|| !path.metadata().map(|m| m.len() <= self.cfg.max_file_bytes).unwrap_or(false)
		{
			return Ok(None);
		}
		let representation = path
			.strip_prefix(self.workdir)
			.ok()
			.and_then(Path::to_str)
			.and_then(|v| RepoPath::new(&mark, v).ok())
			.map(SourcePathRepresentation::Relative)
			.unwrap_or(SourcePathRepresentation::UnrepresentableNative);
		Ok(Some(DiscoveredSourcePath { native: path.clone(), representation }))
	}
}
impl DiscoveredSourcePath {
	/// Temporary native operational exit for the existing prompt consumer.
	/// Unrepresentable names stay native; they are never lossy RepoPath text.
	fn legacy_discovery_path(self) -> PathBuf {
		match self.representation {
			SourcePathRepresentation::Relative(path) => {
				let _ = path;
			},
			SourcePathRepresentation::UnrepresentableNative => {},
		}
		self.native
	}
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
	if let Some(component) = pattern.strip_prefix("dotnet-output:") {
		return is_dotnet_output_path(path, component);
	}
	if let Some(component) = pattern.strip_prefix('/')
		&& !component.contains('/')
	{
		return has_component(path, component);
	}
	path.to_string_lossy().contains(pattern)
}

fn has_component(path: &Path, needle: &str) -> bool {
	path.components().any(|component| component.as_os_str() == needle)
}

fn is_dotnet_output_path(path: &Path, output_dir: &str) -> bool {
	path.ancestors().any(|candidate| {
		candidate.file_name().and_then(|name| name.to_str()) == Some(output_dir)
			&& candidate.parent().map(has_dotnet_project_marker).unwrap_or(false)
	})
}

fn has_dotnet_project_marker(dir: &Path) -> bool {
	let Ok(entries) = std::fs::read_dir(dir) else {
		return false;
	};
	entries.filter_map(Result::ok).any(|entry| {
		entry.file_type().map(|file_type| file_type.is_file()).unwrap_or(false)
			&& entry
				.path()
				.extension()
				.and_then(|ext| ext.to_str())
				.map(|ext| {
					["csproj", "fsproj", "vbproj"]
						.iter()
						.any(|allowed| allowed.eq_ignore_ascii_case(ext))
				})
				.unwrap_or(false)
	})
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

	#[test]
	fn cargo_repo_excludes_reject_new_text_policy_before_discovery() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("Cargo.toml");
		std::fs::write(&path, "[workspace]\nexclude = [\"bad\\u0001\"]\n").unwrap();
		assert!(parse_workspace(&path).is_none(), "Repo Cargo exclude control bytes were admitted");
		std::fs::write(&path, "[workspace]\nexclude = [\" exact \" , 7, \"exact\"]\n").unwrap();
		assert_eq!(parse_workspace(&path).unwrap().exclude, vec![" exact ", "exact"]);
	}

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

	#[cfg(unix)]
	#[test]
	fn rejects_build_files_symlinked_outside_workdir() {
		let tree = tempfile::tempdir().unwrap();
		let root = tree.path().join("repo");
		let outside = tree.path().join("outside");
		write_crate(&root, &[("src/local.rs", "fn local() {}")]);
		std::fs::create_dir(&outside).unwrap();
		std::fs::write(outside.join("secret.rs"), "private source").unwrap();
		std::fs::write(outside.join("build.rs"), "private build script").unwrap();
		std::os::unix::fs::symlink(outside.join("build.rs"), root.join("build.rs")).unwrap();
		let files = walk_source_files(&root, &ScannerConfig::default());
		assert!(files.contains(&root.join("src/local.rs")), "retain legitimate source");
		assert!(
			files.iter().all(|path| path.canonicalize().unwrap().starts_with(&root)),
			"source discovery selected a build script outside the workdir"
		);
	}

	#[cfg(unix)]
	#[test]
	fn rejects_source_roots_symlinked_outside_workdir() {
		let tree = tempfile::tempdir().unwrap();
		let root = tree.path().join("repo");
		let outside = tree.path().join("outside");
		write_crate(&root, &[]);
		std::fs::create_dir(&outside).unwrap();
		std::fs::write(outside.join("secret.rs"), "private source").unwrap();
		std::fs::remove_dir(root.join("src")).unwrap();
		std::os::unix::fs::symlink(&outside, root.join("src")).unwrap();
		let files = walk_source_files(&root, &ScannerConfig::default());
		assert!(
			files.iter().all(|path| path.canonicalize().unwrap().starts_with(&root)),
			"source discovery selected a source root outside the workdir"
		);
	}

	#[cfg(unix)]
	#[test]
	fn retains_source_roots_and_build_files_symlinked_inside_workdir() {
		let tree = tempfile::tempdir().unwrap();
		let root = tree.path();
		write_crate(root, &[]);
		std::fs::create_dir(root.join("internal")).unwrap();
		std::fs::write(root.join("internal/local.rs"), "fn local() {}").unwrap();
		std::fs::write(root.join("internal/build.rs"), "fn main() {}").unwrap();
		std::fs::remove_dir(root.join("src")).unwrap();
		std::os::unix::fs::symlink(root.join("internal"), root.join("src")).unwrap();
		std::os::unix::fs::symlink(root.join("internal/build.rs"), root.join("build.rs")).unwrap();
		let files = walk_source_files(root, &ScannerConfig::default());
		assert!(files.contains(&root.join("src/local.rs")));
		assert!(files.contains(&root.join("build.rs")));
	}

	#[test]
	fn defaults_cover_common_languages() {
		let cfg = ScannerConfig::default();
		assert_eq!(cfg.max_file_bytes, 2 * 1024 * 1024);
		for ext in [
			"rs", "c", "cpp", "h", "hpp", "js", "ts", "tsx", "py", "go", "java", "swift", "cs",
			"fs", "fsi", "fsx", "vb",
		] {
			assert!(cfg.include_extensions.iter().any(|e| e == ext), "missing: {ext}");
		}
		assert!(cfg.exclude_path_substrings.iter().any(|e| e == "dir:node_modules"));
		assert!(cfg.exclude_path_substrings.iter().any(|e| e == "dir:target"));
		assert!(cfg.exclude_path_substrings.iter().any(|e| e == "dotnet-output:bin"));
		assert!(cfg.exclude_path_substrings.iter().any(|e| e == "dotnet-output:obj"));
		assert!(cfg.exclude_path_substrings.iter().any(|e| e == "dir:fuzz"));
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
	fn patch_preserves_exact_lists_and_accepts_zero_scalars() {
		let extensions = vec!["RS", "cafe\u{301}", "RS", "", " rs "];
		let excludes = vec!["dir:Tests", "cafe\u{301}", "file:[", "", "dir:Tests"];
		let patch: ScannerConfigPatch = serde_json::from_value(serde_json::json!({
			"max_concurrent_files": 0,
			"max_file_bytes": 0,
			"per_request_timeout_seconds": 0,
			"include_extensions": extensions,
			"exclude_path_substrings": excludes,
			"future_option": {"arbitrary": [false, null, {"x": 1}]}
		}))
		.unwrap();
		let mut cfg = ScannerConfig::default();
		cfg.apply_patch(patch);
		assert_eq!(cfg.max_concurrent_files, 0);
		assert_eq!(cfg.max_file_bytes, 0);
		assert_eq!(cfg.per_request_timeout, Duration::ZERO);
		assert_eq!(cfg.include_extensions, extensions);
		assert_eq!(cfg.exclude_path_substrings, excludes);
	}

	#[test]
	fn patch_null_fields_preserve_baseline_but_empty_lists_replace_it() {
		let mut cfg = ScannerConfig::default();
		let baseline = cfg.clone();
		cfg.apply_patch(
			serde_json::from_str(
				r#"{"max_concurrent_files":null,"max_file_bytes":null,"per_request_timeout_seconds":null,"include_extensions":null,"exclude_path_substrings":null}"#,
			)
			.unwrap(),
		);
		assert_eq!(cfg.max_concurrent_files, baseline.max_concurrent_files);
		assert_eq!(cfg.max_file_bytes, baseline.max_file_bytes);
		assert_eq!(cfg.per_request_timeout, baseline.per_request_timeout);
		assert_eq!(cfg.include_extensions, baseline.include_extensions);
		assert_eq!(cfg.exclude_path_substrings, baseline.exclude_path_substrings);
		cfg.apply_patch(
			serde_json::from_str(r#"{"include_extensions":[],"exclude_path_substrings":[]}"#)
				.unwrap(),
		);
		assert!(cfg.include_extensions.is_empty());
		assert!(cfg.exclude_path_substrings.is_empty());
	}

	#[test]
	fn legacy_patch_decoder_accepts_embedded_controls_without_rewriting() {
		// Baseline evidence for the deliberate new single-line admission rule;
		// this acceptance is not a requirement of the future marked decoder.
		let raw = "case\r\ncafe\u{301}\t\0";
		let patch: ScannerConfigPatch = serde_json::from_value(serde_json::json!({
			"include_extensions": [raw], "exclude_path_substrings": [raw]
		}))
		.unwrap();
		assert_eq!(patch.include_extensions.unwrap()[0].as_bytes(), raw.as_bytes());
		assert_eq!(patch.exclude_path_substrings.unwrap()[0].as_bytes(), raw.as_bytes());
	}

	#[test]
	fn exclusion_patterns_and_extension_comparison_keep_distinct_semantics() {
		for (path, pattern, expected) in [
			("src/tests/helper.rs", "dir:tests", true),
			("src/tests_extra/helper.rs", "dir:tests", false),
			("src/Tests/helper.rs", "dir:tests", false),
			("src/tests/helper.rs", "/tests", true),
			("src/tests_extra/helper.rs", "/tests", false),
			("src/tests_extra/helper.rs", "tests", true),
			("src/tests/helper.rs", "src/tests", true),
			("src/test_one.rs", "file:test_*.rs", true),
			("src/test_one.rs", "test_*.rs", false),
			("src/test_one.rs", "file:src/*", false),
			("src/[.rs", "file:[", false),
			("src/anything.rs", "", true),
			("src/cafe\u{301}.rs", "caf\u{e9}", false),
			("src/cafe\u{301}.rs", "cafe\u{301}", true),
		] {
			assert_eq!(matches_exclude(Path::new(path), pattern), expected, "{path}: {pattern}");
		}
		let extensions = vec!["RS".to_owned(), "Rs.In".to_owned(), "E\u{301}".to_owned()];
		assert!(has_allowed_extension(Path::new("src/main.rS"), &extensions));
		assert!(has_allowed_extension(Path::new("src/generated.RS.IN"), &extensions));
		assert!(has_allowed_extension(Path::new("src/main.E\u{301}"), &extensions));
		assert!(!has_allowed_extension(Path::new("src/main.\u{c9}"), &extensions));
		assert!(!has_allowed_extension(Path::new("src/main.rs.bak"), &extensions));
		assert_eq!(extensions, ["RS", "Rs.In", "E\u{301}"]);
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
	fn cargo_workspace_discovers_non_member_package_manifests() {
		let tmp = tempfile::tempdir().unwrap();
		std::fs::write(
			tmp.path().join("Cargo.toml"),
			"[workspace]\nmembers = [\"stratum-core\"]\nexclude = [\"fuzz\"]\n",
		)
		.unwrap();
		write_crate(tmp.path().join("stratum-core").as_path(), &[("src/lib.rs", "// facade\n")]);
		write_crate(
			tmp.path().join("stratum-core/stratum-translation").as_path(),
			&[("src/lib.rs", "// translation\n")],
		);
		write_crate(tmp.path().join("sv1").as_path(), &[("src/lib.rs", "// sv1\n")]);
		write_crate(tmp.path().join("sv2/binary-sv2").as_path(), &[("src/lib.rs", "// binary\n")]);
		write_crate(tmp.path().join("fuzz").as_path(), &[("src/lib.rs", "// fuzz\n")]);

		let names = rel_names(tmp.path(), walk_source_files(tmp.path(), &ScannerConfig::default()));
		for expected in [
			"stratum-core/src/lib.rs",
			"stratum-core/stratum-translation/src/lib.rs",
			"sv1/src/lib.rs",
			"sv2/binary-sv2/src/lib.rs",
		] {
			assert!(names.iter().any(|n| n == expected), "missing {expected} in {names:?}");
		}
		assert!(names.iter().all(|n| !n.starts_with("fuzz/")), "names: {names:?}");
	}

	#[test]
	fn rust_src_bin_targets_are_discovered() {
		let tmp = tempfile::tempdir().unwrap();
		write_crate(
			tmp.path(),
			&[
				("src/lib.rs", "// library\n"),
				("src/bin/cli.rs", "// binary\n"),
				("src/bin/net8.rs", "// binary with tfm-like name\n"),
				("src/bin/net8/main.rs", "// nested binary with tfm-like name\n"),
				("src/bin/admin/main.rs", "// nested binary\n"),
			],
		);

		let names = rel_names(tmp.path(), walk_source_files(tmp.path(), &ScannerConfig::default()));
		for expected in [
			"src/lib.rs",
			"src/bin/cli.rs",
			"src/bin/net8.rs",
			"src/bin/net8/main.rs",
			"src/bin/admin/main.rs",
		] {
			assert!(names.iter().any(|n| n == expected), "missing {expected} in {names:?}");
		}
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
	fn dotnet_solution_and_project_sources_are_discovered_in_mixed_repos() {
		let tmp = tempfile::tempdir().unwrap();
		std::fs::write(tmp.path().join("package.json"), "{}\n").unwrap();
		std::fs::write(tmp.path().join("Widget.sln"), "\n").unwrap();
		std::fs::create_dir_all(tmp.path().join("frontend/src")).unwrap();
		std::fs::write(tmp.path().join("frontend/src/index.ts"), "// ts\n").unwrap();

		for (path, body) in [
			("src/Web/Web.csproj", "<Project />\n"),
			("src/Web/Program.cs", "class Program {}\n"),
			("src/Web/Controllers/HomeController.cs", "class HomeController {}\n"),
			("src/Domain/Domain.fsproj", "<Project />\n"),
			("src/Domain/Model.fs", "module Model\n"),
			("src/Domain/Model.fsi", "module Model\n"),
			("src/Domain/Scripts/Seed.fsx", "printfn \"seed\"\n"),
			("src/Legacy/Legacy.vbproj", "<Project />\n"),
			("src/Legacy/Module.vb", "Module Legacy\nEnd Module\n"),
			("src/Web/bin/Debug/net8.0/Generated.cs", "class Generated {}\n"),
			("src/Web/obj/Debug/net8.0/AssemblyInfo.cs", "class AssemblyInfo {}\n"),
			("src/Web/obj/Debug/GeneratedFile.cs", "class GeneratedFile {}\n"),
		] {
			let p = tmp.path().join(path);
			if let Some(parent) = p.parent() {
				std::fs::create_dir_all(parent).unwrap();
			}
			std::fs::write(p, body).unwrap();
		}

		let names = rel_names(tmp.path(), walk_source_files(tmp.path(), &ScannerConfig::default()));
		for expected in [
			"frontend/src/index.ts",
			"src/Web/Program.cs",
			"src/Web/Controllers/HomeController.cs",
			"src/Domain/Model.fs",
			"src/Domain/Model.fsi",
			"src/Domain/Scripts/Seed.fsx",
			"src/Legacy/Module.vb",
		] {
			assert!(names.iter().any(|n| n == expected), "missing {expected} in {names:?}");
		}
		assert!(names.iter().all(|n| !n.contains("/bin/")), "bin leak: {names:?}");
		assert!(names.iter().all(|n| !n.contains("/obj/")), "obj leak: {names:?}");
	}

	#[test]
	fn deeply_nested_dotnet_projects_are_discovered() {
		let tmp = tempfile::tempdir().unwrap();

		for (path, body) in [
			("src/services/api/v2/foo/app/Foo.csproj", "<Project />\n"),
			("src/services/api/v2/foo/app/Program.cs", "class Program {}\n"),
		] {
			let p = tmp.path().join(path);
			if let Some(parent) = p.parent() {
				std::fs::create_dir_all(parent).unwrap();
			}
			std::fs::write(p, body).unwrap();
		}

		let names = rel_names(tmp.path(), walk_source_files(tmp.path(), &ScannerConfig::default()));
		assert!(
			names.iter().any(|n| n == "src/services/api/v2/foo/app/Program.cs"),
			"names: {names:?}"
		);
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
