use std::sync::Arc;

use loupe_storage::secrets::MasterKey;
use loupe_storage::Db;
use loupe_tls::Ca;
use tokio::sync::Notify;

use crate::reporters::{EmailReporter, GithubReporter};

/// Shared state passed to every axum handler. Cheap to clone — wraps
/// `Arc`s around storage, the internal CA, the reporter that the
/// dispatcher hands findings to, and the optional master key for
/// secrets-at-rest encryption.
///
/// `job_arrived` is poked whenever a new job lands in `queued`. Long-
/// polling lease handlers wait on it so workers don't have to busy-poll.
///
/// `master_key` enables `record_version = 2` secret writes/reads. When
/// `None`, the server falls back to plaintext secrets — fine for dev,
/// strongly discouraged in production.
#[derive(Clone)]
pub struct AppState {
	pub db: Arc<Db>,
	pub ca: Arc<Ca>,
	pub github_reporter: Arc<GithubReporter>,
	pub email_reporter: Arc<EmailReporter>,
	pub job_arrived: Arc<Notify>,
	pub master_key: Option<Arc<MasterKey>>,
}

impl AppState {
	pub fn new(db: Arc<Db>, ca: Arc<Ca>, github_reporter: Arc<GithubReporter>) -> Self {
		Self {
			db,
			ca,
			github_reporter,
			email_reporter: Arc::new(EmailReporter::new()),
			job_arrived: Arc::new(Notify::new()),
			master_key: None,
		}
	}

	pub fn with_master_key(mut self, key: MasterKey) -> Self {
		self.master_key = Some(Arc::new(key));
		self
	}

	pub fn with_email_reporter(mut self, reporter: EmailReporter) -> Self {
		self.email_reporter = Arc::new(reporter);
		self
	}
}
