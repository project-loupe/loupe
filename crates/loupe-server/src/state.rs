use std::sync::Arc;

use loupe_storage::Db;
use loupe_tls::Ca;

/// Shared state passed to every axum handler. Cheap to clone — wraps
/// `Arc`s around storage and the internal CA.
#[derive(Clone)]
pub struct AppState {
	pub db: Arc<Db>,
	pub ca: Arc<Ca>,
}

impl AppState {
	pub fn new(db: Arc<Db>, ca: Arc<Ca>) -> Self {
		Self { db, ca }
	}
}
