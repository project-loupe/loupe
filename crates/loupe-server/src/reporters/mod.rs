//! Reporter trait plus the built-in automatic reporting destinations.
//!
//! The dispatcher hands a freshly-completed scan's findings to whatever
//! `Reporter` matches the repo's `ReportingDestination`. Manual mode
//! short-circuits before a reporter is selected.

use std::sync::Arc;

use anyhow::Result;
use loupe_core::ReportingDestination;
use loupe_storage::reports::{PreparedReport, SelectedCredential};

#[cfg(test)]
mod containment_tests;
pub mod email;
#[cfg(test)]
pub(crate) mod fixtures;
pub mod github;
pub mod github_app;
mod ingress;
pub mod render;
pub use email::EmailReporter;
pub use github::GithubReporter;
#[cfg(fuzzing)]
pub(crate) use ingress::fuzz_support as ingress_fuzz;

/// Result of a successful dispatch — opaque receipt the caller can stamp
/// onto `findings.reported_at` (or scan_history) for audit.
#[derive(Clone, PartialEq, Eq)]
pub struct DispatchReceipt {
	pub kind: &'static str,
	pub external_id: Option<String>,
}
impl std::fmt::Debug for DispatchReceipt {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("DispatchReceipt([redacted])")
	}
}

pub use loupe_storage::reports::ReportFinding;

/// What the dispatcher resolved from the secrets table for one repo.
/// Reporters that need no credential (email) ignore it.
enum ReporterCredential<'a> {
	None,
	/// A personal access token stored for this repo.
	GithubPat(&'a loupe_provenance::Secret<Vec<u8>>),
	/// The server-wide GitHub App; the reporter mints a short-lived,
	/// repo-scoped installation token from it per dispatch.
	GithubApp(Box<github_app::GithubAppKey>),
}

impl std::fmt::Debug for ReporterCredential<'_> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::None => f.write_str("None"),
			Self::GithubPat(_) => f.write_str("GithubPat(redacted)"),
			Self::GithubApp(key) => f.debug_tuple("GithubApp").field(&key.app_id()).finish(),
		}
	}
}

/// Observe the production wrapper's redaction without exposing its constructor.
#[cfg(fuzzing)]
pub fn fuzz_github_pat_debug(secret: &loupe_provenance::Secret<Vec<u8>>) -> String {
	format!("{:?}", ReporterCredential::GithubPat(secret))
}

impl<'a> ReporterCredential<'a> {
	fn selected(batch: &'a PreparedReport) -> Result<Self> {
		batch.check_committed()?;
		Ok(match batch.credential() {
			SelectedCredential::None => Self::None,
			SelectedCredential::Pat(pat) => Self::GithubPat(pat),
			SelectedCredential::App(stored) => Self::GithubApp(Box::new(
				github_app::GithubAppKey::from_pem(stored.app_id, stored.private_key_pem.expose())?,
			)),
		})
	}
}

#[async_trait::async_trait]
pub trait Reporter: Send + Sync {
	fn kind(&self) -> &'static str;
	async fn dispatch(&self, batch: &PreparedReport) -> Result<DispatchReceipt>;
}

/// Pick the right reporter for `repo.reporting`. Returns `None` for
/// `Manual` (the dispatcher short-circuits before reaching this — the
/// `None` here just keeps the API total) or for a destination this
/// build doesn't understand (forward compatibility — older builds
/// shouldn't crash on a future variant).
pub fn select(
	batch: &PreparedReport, github: Arc<GithubReporter>, email: Arc<EmailReporter>,
) -> Option<Arc<dyn Reporter>> {
	match &batch.repository().reporting {
		ReportingDestination::GithubIssue { .. } => Some(github),
		ReportingDestination::Email { .. } => Some(email),
		ReportingDestination::Manual => None,
	}
}
