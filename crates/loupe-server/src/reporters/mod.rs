//! Reporter trait plus the built-in automatic reporting destinations.
//!
//! The dispatcher hands a freshly-completed scan's findings to whatever
//! `Reporter` matches the repo's `ReportingDestination`. Manual mode
//! short-circuits before a reporter is selected.

use std::sync::Arc;

use anyhow::Result;
use loupe_core::{Finding, ReportingDestination};
use loupe_storage::repos::RepoRow;

pub mod email;
pub mod github;
pub mod github_app;
mod ingress;

pub use email::EmailReporter;
pub use github::GithubReporter;

/// Result of a successful dispatch — opaque receipt the caller can stamp
/// onto `findings.reported_at` (or scan_history) for audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchReceipt {
	pub kind: &'static str,
	pub external_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportFinding {
	/// Stored finding ID, used to render the public `LUP-…` reference.
	pub id: i64,
	pub finding: Finding,
	pub reviewed_revision: Option<String>,
}

/// What the dispatcher resolved from the secrets table for one repo.
/// Reporters that need no credential (email) ignore it.
pub enum ReporterCredential {
	None,
	/// A personal access token stored for this repo.
	GithubPat(loupe_provenance::Secret<Vec<u8>>),
	/// The server-wide GitHub App; the reporter mints a short-lived,
	/// repo-scoped installation token from it per dispatch.
	GithubApp(Box<github_app::GithubAppKey>),
}

impl std::fmt::Debug for ReporterCredential {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::None => f.write_str("None"),
			Self::GithubPat(_) => f.write_str("GithubPat(redacted)"),
			Self::GithubApp(key) => f.debug_tuple("GithubApp").field(&key.app_id()).finish(),
		}
	}
}

#[async_trait::async_trait]
pub trait Reporter: Send + Sync {
	fn kind(&self) -> &'static str;
	async fn dispatch(
		&self, repo: &RepoRow, findings: &[ReportFinding], credential: &ReporterCredential,
	) -> Result<DispatchReceipt>;
}

/// Pick the right reporter for `repo.reporting`. Returns `None` for
/// `Manual` (the dispatcher short-circuits before reaching this — the
/// `None` here just keeps the API total) or for a destination this
/// build doesn't understand (forward compatibility — older builds
/// shouldn't crash on a future variant).
pub fn select(
	repo: &RepoRow, github: Arc<GithubReporter>, email: Arc<EmailReporter>,
) -> Option<Arc<dyn Reporter>> {
	match &repo.reporting {
		ReportingDestination::GithubIssue { .. } => Some(github),
		ReportingDestination::Email { .. } => Some(email),
		ReportingDestination::Manual => None,
	}
}
