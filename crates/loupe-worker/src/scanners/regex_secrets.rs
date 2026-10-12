//! Trivial regex-based secrets scanner. Walks the worktree, scans text
//! files for AWS-style `AKIA…` access key prefixes, and emits a finding
//! per match.
//!
//! Stays intentionally small and deterministic so the end-to-end
//! pipeline can be tested without invoking an LLM backend.

use std::fs;
use std::path::Path;

use anyhow::Result;
use async_trait::async_trait;
use loupe_core::Finding;
use loupe_provenance::{Ingress, Repo, Untrusted};
use regex::Regex;
use walkdir::WalkDir;

use crate::scanner::{ScanContext, Scanner};

const SCANNER_ID: &str = "regex-secrets";
const CAPABILITIES: &[&str] = &["scan:secrets"];
const MAX_FILE_BYTES: u64 = 1_048_576; // 1 MB; bigger files are skipped.
mod ingress;
#[cfg(fuzzing)]
pub use ingress::observe::RepoFindingObservation;

pub struct RegexSecretsScanner {
	re: Regex,
}

impl RegexSecretsScanner {
	pub fn new() -> Self {
		// AWS access key id: 16-char base32-ish suffix after AKIA prefix.
		// We only check the prefix shape; the dispatcher / verifier later
		// confirms whether it's a live credential.
		let re = Regex::new(r"AKIA[0-9A-Z]{16}").expect("compile-time AKIA regex must be valid");
		Self { re }
	}

	/// Fuzz the synchronous walk used by `scan` without a runtime per input.
	#[cfg(fuzzing)]
	pub fn fuzz_walk(
		&self, workdir: &Path, cancelled: bool,
	) -> Result<Vec<Finding<loupe_provenance::Repo>>> {
		let cancel = tokio_util::sync::CancellationToken::new();
		if cancelled {
			cancel.cancel();
		}
		walk(workdir, &self.re, "fuzz-head", &cancel)
	}
	#[cfg(fuzzing)]
	pub fn fuzz_walk_observed(
		&self, workdir: &Path, cancelled: bool,
	) -> Result<(Vec<Finding<loupe_provenance::Repo>>, Vec<RepoFindingObservation>)> {
		let observation = ingress::observe::Scope::begin();
		let findings = self.fuzz_walk(workdir, cancelled)?;
		Ok((findings, observation.finish()))
	}
}

impl Default for RegexSecretsScanner {
	fn default() -> Self {
		Self::new()
	}
}

#[async_trait]
impl Scanner for RegexSecretsScanner {
	fn id(&self) -> &'static str {
		SCANNER_ID
	}

	fn capabilities(&self) -> &[&'static str] {
		CAPABILITIES
	}

	async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding<loupe_provenance::Repo>>> {
		let mut findings = Vec::new();
		let workdir = ctx.workdir.clone();
		let re = self.re.clone();

		// Run the synchronous walk on a blocking task so we don't stall
		// the runtime on a large worktree.
		let head_sha = ctx.head_sha.clone();
		let cancel = ctx.cancel.clone();
		let result =
			tokio::task::spawn_blocking(move || walk(&workdir, &re, head_sha.expose(), &cancel))
				.await
				.map_err(|e| anyhow::anyhow!("scanner task panicked: {e}"))??;
		findings.extend(result);
		Ok(findings)
	}
}

fn walk(
	workdir: &Path, re: &Regex, head_sha: &str, cancel: &tokio_util::sync::CancellationToken,
) -> Result<Vec<Finding<loupe_provenance::Repo>>> {
	let mut out = Vec::new();
	for entry in WalkDir::new(workdir).into_iter().filter_entry(|e| !is_git_metadata(e.path())) {
		if cancel.is_cancelled() {
			return Ok(out);
		}
		let entry = match entry {
			Ok(e) => e,
			Err(_) => continue,
		};
		if !entry.file_type().is_file() {
			continue;
		}
		let metadata = match entry.metadata() {
			Ok(m) => m,
			Err(_) => continue,
		};
		if metadata.len() == 0 || metadata.len() > MAX_FILE_BYTES {
			continue;
		}
		let bytes = match fs::read(entry.path()) {
			Ok(b) => b,
			Err(_) => continue,
		};
		let input = ingress::RepoFileInput {
			bytes,
			relative_path: entry.path().strip_prefix(workdir).unwrap_or(entry.path()).to_owned(),
		};
		// SAFETY: actual file bytes and native repository-relative path from
		// this walk entry, before text decoding or matching.
		#[allow(unsafe_code)]
		let input = Untrusted::new(input, unsafe { Ingress::<Repo>::new() });
		let _ = head_sha;
		match input.validate(ingress::RegexSecretFindings { regex: re })? {
			ingress::FileFindings::UnrepresentablePath => continue,
			ingress::FileFindings::Findings(findings) => {
				out.extend(findings.into_iter().map(ingress::RepoFinding::into_finding))
			},
		}
	}
	Ok(out)
}

fn is_git_metadata(path: &Path) -> bool {
	path.components().any(|c| c.as_os_str() == ".git")
}

#[cfg(test)]
mod tests {
	use std::fs;

	use loupe_core::Severity;

	use super::*;

	#[cfg(unix)]
	#[tokio::test]
	async fn regex_repo_paths_never_alias_non_utf8_names() {
		use std::os::unix::ffi::OsStringExt;
		let dir = tempfile::tempdir().unwrap();
		let invalid = std::ffi::OsString::from_vec(b"invalid-\xff.rs".to_vec());
		fs::write(dir.path().join(invalid), "AKIAIOSFODNN7EXAMPLE").unwrap();
		fs::write(dir.path().join("visible.rs"), "AKIAIOSFODNN7EXAMPLE").unwrap();
		let findings = RegexSecretsScanner::new().scan(&make_ctx(dir.path())).await.unwrap();
		assert_eq!(
			findings.len(),
			1,
			"unrepresentable native Repo path produced a lossy finding alias"
		);
		assert_eq!(findings[0].file_path.as_ref().map(|v| v.expose()), Some("visible.rs"));
	}

	fn make_ctx(workdir: &Path) -> ScanContext {
		crate::test_support::scan_context(workdir, "abc")
	}

	#[tokio::test]
	async fn finding_debug_does_not_expose_repository_secret() {
		let dir = tempfile::tempdir().unwrap();
		let secret = "AKIAIOSFODNN7EXAMPLE";
		std::fs::write(dir.path().join(format!("{secret}.rs")), secret).unwrap();
		let findings = RegexSecretsScanner::new().scan(&make_ctx(dir.path())).await.unwrap();
		assert_eq!(findings.len(), 1, "fixture must produce a finding");
		assert!(
			!format!("{:?}", findings[0]).contains(secret),
			"Finding Debug exposed the repository secret through a source path"
		);
	}

	#[tokio::test]
	async fn finds_planted_aws_access_key() {
		let tmp = tempfile::tempdir().unwrap();
		let f = tmp.path().join("config.rs");
		fs::write(&f, "const KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";\nconst PORT: u16 = 8080;\n")
			.unwrap();

		let scanner = RegexSecretsScanner::new();
		let findings = scanner.scan(&make_ctx(tmp.path())).await.unwrap();
		assert_eq!(findings.len(), 1);
		assert_eq!(findings[0].scanner_id.expose(), SCANNER_ID);
		assert_eq!(findings[0].severity, Severity::High);
		assert_eq!(findings[0].file_path.as_ref().map(|v| v.expose()), Some("config.rs"));
		assert_eq!(findings[0].line_start, Some(1));
	}

	#[tokio::test]
	async fn ignores_clean_repos() {
		let tmp = tempfile::tempdir().unwrap();
		fs::write(tmp.path().join("README.md"), "# nothing here\n").unwrap();
		let scanner = RegexSecretsScanner::new();
		let findings = scanner.scan(&make_ctx(tmp.path())).await.unwrap();
		assert!(findings.is_empty());
	}

	#[tokio::test]
	async fn skips_dot_git_directory() {
		let tmp = tempfile::tempdir().unwrap();
		let git = tmp.path().join(".git");
		fs::create_dir(&git).unwrap();
		fs::write(git.join("HEAD"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();
		let scanner = RegexSecretsScanner::new();
		let findings = scanner.scan(&make_ctx(tmp.path())).await.unwrap();
		assert!(findings.is_empty(), ".git contents must not yield findings");
	}
}
