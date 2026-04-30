use std::sync::Arc;

use loupe_storage::Db;
use loupe_tls::Ca;
use tokio::sync::Notify;

use crate::reporters::{EmailReporter, GithubReporter};

/// Shared state passed to every axum handler. Cheap to clone — wraps
/// `Arc`s around storage, the internal CA, and the reporter that the
/// dispatcher hands findings to.
///
/// `job_arrived` is poked whenever a new job lands in `queued`. Long-
/// polling lease handlers wait on it so workers don't have to busy-poll.
///
/// At-rest encryption of the database itself (including secrets,
/// findings, and everything else) is handled by SQLCipher inside
/// [`Db`] — the master key is consumed at `Db::open` time and is no
/// longer in the AppState.
#[derive(Clone)]
pub struct AppState {
	pub db: Arc<Db>,
	pub ca: Arc<Ca>,
	pub github_reporter: Arc<GithubReporter>,
	pub email_reporter: Arc<EmailReporter>,
	pub job_arrived: Arc<Notify>,
	/// Server-wide default for the human-in-the-loop approval gate.
	/// Used when a repo has `require_approval = NULL` (the wire-side
	/// default — i.e. the operator didn't pin a per-repo override).
	/// `false` keeps the existing immediate-dispatch behaviour.
	pub require_approval_default: bool,
}

impl AppState {
	pub fn new(db: Arc<Db>, ca: Arc<Ca>, github_reporter: Arc<GithubReporter>) -> Self {
		Self {
			db,
			ca,
			github_reporter,
			email_reporter: Arc::new(EmailReporter::new()),
			job_arrived: Arc::new(Notify::new()),
			require_approval_default: false,
		}
	}

	pub fn with_email_reporter(mut self, reporter: EmailReporter) -> Self {
		self.email_reporter = Arc::new(reporter);
		self
	}

	pub fn with_require_approval_default(mut self, on: bool) -> Self {
		self.require_approval_default = on;
		self
	}
}
