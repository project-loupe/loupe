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
use loupe_provenance::{Ingress, Operator, Worker};
use loupe_storage::workers::{self, WorkerKind, WorkerRow};
use loupe_tls::cert_fingerprint;

use crate::router::PeerCert;
use crate::state::AppState;

/// What handlers see after the middleware resolved the peer cert.
#[derive(Clone)]
pub struct AuthedWorker {
	worker: WorkerRow,
	authority: Authority,
}

#[derive(Clone)]
enum Authority {
	Worker(Ingress<Worker>),
	Operator(Ingress<Operator>),
}

impl std::fmt::Debug for AuthedWorker {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("AuthedWorker")
			.field("id", &self.id())
			.field("kind", self.kind())
			.finish_non_exhaustive()
	}
}

impl AuthedWorker {
	pub fn id(&self) -> i64 {
		self.worker.id
	}
	pub fn name(&self) -> &str {
		&self.worker.name
	}
	pub(crate) fn worker_ingress(&self) -> Option<Ingress<Worker>> {
		match self.authority {
			Authority::Worker(token) => Some(token),
			_ => None,
		}
	}
	pub(crate) fn operator_ingress(&self) -> Option<Ingress<Operator>> {
		match self.authority {
			Authority::Operator(token) => Some(token),
			_ => None,
		}
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
	// SAFETY: the current certificate fingerprint resolved to this active row.
	// Only this middleware grants the role-specific capture authority; neither
	// a caller-supplied row nor a request decoder can upgrade its role.
	#[allow(unsafe_code)]
	let authority = match row.kind {
		WorkerKind::Worker => Authority::Worker(unsafe { Ingress::new() }),
		WorkerKind::Admin => Authority::Operator(unsafe { Ingress::new() }),
	};
	let authed = AuthedWorker { worker: row, authority };
	if let Some(token) = authed.worker_ingress() {
		state.worker_budgets.enforce(authed.id(), token, &mut req).await?;
	}

	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
	let id = authed.id();
	let _ = state.db.with_conn(|c| Ok(workers::touch_last_seen(c, id, now)?));

	req.extensions_mut().insert(authed);
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

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use axum::body::Body;
	use axum::routing::get;
	use axum::{middleware, Extension, Router};
	use loupe_storage::secrets::MasterKey;
	use loupe_storage::Db;
	use tower::ServiceExt;

	use super::*;

	#[tokio::test]
	async fn actual_auth_clone_keeps_role_and_hides_stored_name() {
		async fn inspect(Extension(identity): Extension<AuthedWorker>) -> StatusCode {
			let copy = identity.clone();
			assert_eq!(copy.id(), identity.id());
			assert_eq!(copy.name(), identity.name());
			assert_eq!(copy.kind(), identity.kind());
			assert_eq!(copy.worker_ingress().is_some(), copy.is_worker());
			assert_eq!(copy.operator_ingress().is_some(), copy.is_admin());
			assert!(!format!("{copy:#?}").contains("FAKE_AUTH_NAME"));
			StatusCode::OK
		}
		let db = Arc::new(Db::open_in_memory(&MasterKey::for_tests()).unwrap());
		let state = AppState::new(
			db.clone(),
			Arc::new(loupe_tls::Ca::new("auth ownership").unwrap()),
			Arc::new(crate::reporters::GithubReporter::new().unwrap()),
		);
		let app = Router::new()
			.route("/", get(inspect))
			.layer(middleware::from_fn_with_state(state, mtls_auth));
		for (kind, bytes) in
			[(WorkerKind::Admin, vec![1, 2, 3]), (WorkerKind::Worker, vec![4, 5, 6])]
		{
			let cert = PeerCert(bytes.into());
			let id = db
				.with_conn(|conn| {
					Ok(workers::insert(
						conn,
						&format!("FAKE_AUTH_NAME_{}", kind.as_str()),
						kind,
						&cert_fingerprint(cert.0.as_ref()),
						0,
					)?)
				})
				.unwrap();
			let mut request = Request::new(Body::empty());
			request.extensions_mut().insert(cert.clone());
			assert_eq!(app.clone().oneshot(request).await.unwrap().status(), StatusCode::OK);
			db.with_conn(|conn| Ok(workers::revoke(conn, id, 1)?)).unwrap();
			let mut request = Request::new(Body::empty());
			request.extensions_mut().insert(cert);
			assert_eq!(
				app.clone().oneshot(request).await.unwrap().status(),
				StatusCode::UNAUTHORIZED
			);
		}
	}
}
