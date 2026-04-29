use std::sync::Arc;

use loupe_storage::Db;
use loupe_tls::Ca;

use crate::reporters::GithubReporter;

/// Shared state passed to every axum handler. Cheap to clone — wraps
/// `Arc`s around storage, the internal CA, and the reporter that the
/// dispatcher hands findings to.
#[derive(Clone)]
pub struct AppState {
	pub db: Arc<Db>,
	pub ca: Arc<Ca>,
	pub github_reporter: Arc<GithubReporter>,
}

impl AppState {
	pub fn new(db: Arc<Db>, ca: Arc<Ca>, github_reporter: Arc<GithubReporter>) -> Self {
		Self { db, ca, github_reporter }
	}
}
