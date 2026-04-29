//! Auth middleware: peer cert → worker row.
//!
//! `mtls_auth` runs on every authenticated route. It looks up the peer
//! cert (stamped onto request extensions by the connection handler) in
//! the `workers` table; rejects unknown / revoked / wrong-role certs;
//! and stashes the resolved [`AuthedWorker`] back into extensions for
//! the handler to read.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use loupe_storage::workers::{self, WorkerKind, WorkerRow};
use loupe_tls::cert_fingerprint;

use crate::router::PeerCert;
use crate::state::AppState;

/// What handlers see after the middleware resolved the peer cert.
#[derive(Debug, Clone)]
pub struct AuthedWorker {
	pub worker: WorkerRow,
}

impl AuthedWorker {
	pub fn id(&self) -> i64 {
		self.worker.id
	}
	pub fn kind(&self) -> &WorkerKind {
		&self.worker.kind
	}
	pub fn is_admin(&self) -> bool {
		matches!(self.worker.kind, WorkerKind::Admin)
	}
	pub fn is_worker(&self) -> bool {
		matches!(self.worker.kind, WorkerKind::Worker)
	}
}

/// Middleware: resolve the peer cert to a workers row, attach
/// [`AuthedWorker`] to extensions. Returns 401 on missing cert / unknown
/// fingerprint / revoked worker.
pub async fn mtls_auth(
	State(state): State<AppState>, mut req: Request, next: Next,
) -> Result<Response, StatusCode> {
	let cert = req.extensions().get::<PeerCert>().cloned().ok_or(StatusCode::UNAUTHORIZED)?;
	let fp = cert_fingerprint(cert.0.as_ref());

	let row = state
		.db
		.with_conn(|c| Ok(workers::find_active_by_fingerprint(c, &fp)?))
		.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
		.ok_or(StatusCode::UNAUTHORIZED)?;

	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
	let id = row.id;
	let _ = state.db.with_conn(|c| Ok(workers::touch_last_seen(c, id, now)?));

	req.extensions_mut().insert(AuthedWorker { worker: row });
	Ok(next.run(req).await)
}

/// Middleware: require the resolved worker to be an admin.
pub async fn require_admin(req: Request, next: Next) -> Result<Response, StatusCode> {
	let authed = req.extensions().get::<AuthedWorker>().ok_or(StatusCode::UNAUTHORIZED)?;
	if !authed.is_admin() {
		return Err(StatusCode::FORBIDDEN);
	}
	Ok(next.run(req).await)
}

/// Middleware: require the resolved worker to be a scan/verify worker
/// (i.e. not an admin).
pub async fn require_worker(req: Request, next: Next) -> Result<Response, StatusCode> {
	let authed = req.extensions().get::<AuthedWorker>().ok_or(StatusCode::UNAUTHORIZED)?;
	if !authed.is_worker() {
		return Err(StatusCode::FORBIDDEN);
	}
	Ok(next.run(req).await)
}
