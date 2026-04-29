//! Reporter trait + the M1 GithubReporter that opens issues on a
//! target tracker repo.
//!
//! The dispatcher hands a freshly-completed scan's findings to whatever
//! `Reporter` matches the repo's `ReportingDestination`. For M1 that's
//! always `GithubReporter` (issue mode); email and PR-mode are M2.

use std::sync::Arc;

use anyhow::Result;
use loupe_core::{Finding, ReportingDestination};
use loupe_storage::repos::RepoRow;

pub mod email;
pub mod github;

pub use email::EmailReporter;
pub use github::GithubReporter;

/// Result of a successful dispatch — opaque receipt the caller can stamp
/// onto `findings.reported_at` (or scan_history) for audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchReceipt {
	pub kind: &'static str,
	pub external_id: Option<String>,
}

#[async_trait::async_trait]
pub trait Reporter: Send + Sync {
	fn kind(&self) -> &'static str;
	async fn dispatch(
		&self, repo: &RepoRow, findings: &[Finding], pat: &str,
	) -> Result<DispatchReceipt>;
}

/// Pick the right reporter for `repo.reporting`. Returns `None` if the
/// destination is one this build doesn't understand (forward
/// compatibility — older builds shouldn't crash on a future variant).
pub fn select(
	repo: &RepoRow, github: Arc<GithubReporter>, email: Arc<EmailReporter>,
) -> Option<Arc<dyn Reporter>> {
	match &repo.reporting {
		ReportingDestination::GithubIssue { .. } => Some(github),
		ReportingDestination::Email { .. } => Some(email),
	}
}
