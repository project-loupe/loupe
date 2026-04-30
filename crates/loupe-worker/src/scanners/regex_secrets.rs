//! Trivial regex-based secrets scanner. Walks the worktree, scans text
//! files for AWS-style `AKIA…` access key prefixes, and emits a finding
//! per match.
//!
//! Exists primarily so M1 has at least one real scanner producing real
//! findings on a real worktree — the pipeline test would otherwise be
//! a no-op.

use std::fs;
use std::path::Path;

use anyhow::Result;
use async_trait::async_trait;
use loupe_core::{Finding, Severity};
use regex::Regex;
use walkdir::WalkDir;

use crate::scanner::{ScanContext, Scanner};

const SCANNER_ID: &str = "regex-secrets";
const CAPABILITIES: &[&str] = &["scan:secrets"];
const MAX_FILE_BYTES: u64 = 1_048_576; // 1 MB; bigger files are skipped.

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

	async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
		let mut findings = Vec::new();
		let workdir = ctx.workdir.clone();
		let re = self.re.clone();

		// Run the synchronous walk on a blocking task so we don't stall
		// the runtime on a large worktree.
		let head_sha = ctx.head_sha.clone();
		let cancel = ctx.cancel.clone();
		let result = tokio::task::spawn_blocking(move || walk(&workdir, &re, &head_sha, &cancel))
			.await
			.map_err(|e| anyhow::anyhow!("scanner task panicked: {e}"))??;
		findings.extend(result);
		Ok(findings)
	}
}

fn walk(
	workdir: &Path, re: &Regex, head_sha: &str, cancel: &tokio_util::sync::CancellationToken,
) -> Result<Vec<Finding>> {
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
		// Skip binary-looking files.
		if bytes.iter().take(8192).any(|b| *b == 0) {
			continue;
		}
		let Ok(text) = std::str::from_utf8(&bytes) else { continue };
		for m in re.find_iter(text) {
			let line_start = 1 + text[..m.start()].matches('\n').count() as u32;
			let rel = entry.path().strip_prefix(workdir).unwrap_or(entry.path()).to_string_lossy();
			// Fingerprint shape: `(scanner_id, file, matched_secret)`.
			// Deliberately excludes line_start (line shifts when an
			// unrelated line is added above the match) and head_sha
			// (every scan would otherwise produce a fresh fingerprint
			// for the same secret, defeating the dedup index). The
			// matched bytes themselves are stable across cosmetic
			// edits and uniquely identify the secret.
			let _ = head_sha;
			let fingerprint = crate::fingerprint::compute(SCANNER_ID, &rel, m.as_str());
			out.push(Finding {
				scanner_id: SCANNER_ID.into(),
				severity: Severity::High,
				title: "Possible AWS access key id".into(),
				description: format!(
					"Found a string matching the AWS access key id pattern (`AKIA…`) at {rel}:{line_start}. \
					 Treat as a potential secret leak — confirm against the AWS account before reporting."
				),
				file_path: Some(rel.into_owned()),
				line_start: Some(line_start),
				line_end: Some(line_start),
				cwe: Some("CWE-798".into()),
				patch_unified: None,
				poc_unified: None,
				fingerprint,
			});
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

	use loupe_core::RepoSpec;
	use tokio_util::sync::CancellationToken;

	use super::*;

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
			head_sha: "abc".into(),
			base_sha: None,
			config: serde_json::Value::Null,
			cancel: CancellationToken::new(),
		}
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
		assert_eq!(findings[0].scanner_id, SCANNER_ID);
		assert_eq!(findings[0].severity, Severity::High);
		assert_eq!(findings[0].file_path.as_deref(), Some("config.rs"));
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
