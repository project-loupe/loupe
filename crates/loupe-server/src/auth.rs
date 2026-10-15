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
use loupe_core::security_event::{
	emit, CapabilityDenial, EventContext, Operation, RequestedTarget, SecurityEvent,
};
use loupe_provenance::{Ingress, Operator, Worker};
use loupe_storage::workers::{WorkerKind, WorkerRow};
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
	pub fn name(
		&self,
	) -> &loupe_core::text::BoundedText<loupe_core::text::policy::WorkerName, loupe_provenance::Db>
	{
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
	pub(crate) fn require_operator(&self) -> Result<Ingress<Operator>, (StatusCode, String)> {
		self.operator_ingress().ok_or_else(|| {
			role_denial(Some(self), Operation::RequireAdmin, CapabilityDenial::RoleMismatch);
			(StatusCode::FORBIDDEN, "operator required".into())
		})
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
	let cert = req.extensions().get::<PeerCert>().cloned().ok_or_else(unauthenticated)?;
	let fp = cert_fingerprint(cert.0.as_ref());

	let row = loupe_storage::registry::authenticate(&state.db, &fp)
		.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
		.ok_or_else(unauthenticated)?;
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
	let _ = loupe_storage::registry::touch_authenticated(&state.db, id, now);

	req.extensions_mut().insert(authed);
	Ok(next.run(req).await)
}

/// Middleware: require the resolved worker to be an admin.
pub async fn require_admin(req: Request, next: Next) -> Result<Response, StatusCode> {
	let authed = req.extensions().get::<AuthedWorker>().ok_or_else(unauthenticated)?;
	if !authed.is_admin() {
		role_denial(Some(authed), Operation::RequireAdmin, CapabilityDenial::RoleMismatch);
		return Err(StatusCode::FORBIDDEN);
	}
	Ok(next.run(req).await)
}

/// Middleware: require the resolved worker to be a scan/verify worker
/// (i.e. not an admin).
pub async fn require_worker(req: Request, next: Next) -> Result<Response, StatusCode> {
	let authed = req.extensions().get::<AuthedWorker>().ok_or_else(unauthenticated)?;
	if !authed.is_worker() {
		role_denial(Some(authed), Operation::RequireWorker, CapabilityDenial::RoleMismatch);
		return Err(StatusCode::FORBIDDEN);
	}
	Ok(next.run(req).await)
}

fn unauthenticated() -> StatusCode {
	role_denial(None, Operation::Authenticate, CapabilityDenial::Unauthenticated);
	StatusCode::UNAUTHORIZED
}
pub(crate) fn role_denial(
	identity: Option<&AuthedWorker>, operation: Operation, reason: CapabilityDenial,
) {
	emit(SecurityEvent::CapabilityDenied {
		context: EventContext { worker_id: identity.map(AuthedWorker::id), ..Default::default() },
		operation,
		requested: RequestedTarget::None,
		reason,
	});
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
	async fn actual_missing_certificate_emits_closed_authentication_denial() {
		let (_guard, events) = crate::test_support::capture_security_events();
		let state = AppState::new(
			Arc::new(Db::open_in_memory(&MasterKey::for_tests()).unwrap()),
			Arc::new(loupe_tls::Ca::new("security-event").unwrap()),
			Arc::new(crate::reporters::GithubReporter::new().unwrap()),
		);
		let app = Router::new()
			.route("/", get(|| async { StatusCode::OK }))
			.layer(middleware::from_fn_with_state(state, mtls_auth));
		let request = Request::builder().uri("/?FAKE_AGENT_SENTINEL").body(Body::empty()).unwrap();
		assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::UNAUTHORIZED);
		let rows = events.lock().unwrap();
		assert_eq!(rows.len(), 1, "actual certificate rejection must emit the closed event");
		assert_eq!(rows[0]["variant"], "CapabilityDenied");
		assert_eq!(rows[0]["reason"], "unauthenticated");
		assert_eq!(rows[0]["operation"], "authenticate");
		assert!(!format!("{rows:?}").contains("FAKE_AGENT_SENTINEL"));
		assert!(!rows[0].contains_key("worker_id"));
	}

	#[tokio::test]
	async fn actual_body_cap_admission_emits_closed_budget_event() {
		let (_guard, events) = crate::test_support::capture_security_events();
		let db = Arc::new(Db::open_in_memory(&MasterKey::for_tests()).unwrap());
		let cert = PeerCert(vec![9, 7, 5].into());
		let id = loupe_storage::registry::register_worker(
			&db,
			&crate::test_support::operator(),
			&crate::test_support::text("FAKE_NAME"),
			&cert_fingerprint(cert.0.as_ref()),
			0,
		)
		.unwrap();
		let state = AppState::new(
			db,
			Arc::new(loupe_tls::Ca::new("event-body").unwrap()),
			Arc::new(crate::reporters::GithubReporter::new().unwrap()),
		);
		let app = Router::new()
			.route("/", get(|| async { StatusCode::OK }))
			.layer(middleware::from_fn_with_state(state, mtls_auth));
		let mut request = Request::new(Body::from(vec![b'x'; crate::ingress::BODY_CAP + 1]));
		request.extensions_mut().insert(cert);
		assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::PAYLOAD_TOO_LARGE);
		let rows = events.lock().unwrap();
		assert_eq!(rows.len(), 1, "actual body cap rejection must emit the closed event");
		assert_eq!(rows[0]["variant"], "BudgetExhausted");
		assert_eq!(rows[0]["resource"], "request_body_bytes");
		assert_eq!(rows[0]["worker_id"], id.to_string());
		assert_eq!(rows[0]["limit"], crate::ingress::BODY_CAP.to_string());
	}

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
		let mut fixture = crate::test_support::offline::OfflineDatabase::new();
		fixture.edit(|conn| {
			for (kind, bytes) in
				[(WorkerKind::Admin, vec![1, 2, 3]), (WorkerKind::Worker, vec![4, 5, 6])]
			{
				conn.execute(
					"INSERT INTO workers(name,kind,cert_fingerprint,created_at) VALUES(?1,?2,?3,0)",
					rusqlite::params![
						format!("FAKE_AUTH_NAME_{}", kind.as_str()),
						kind.as_str(),
						cert_fingerprint(&bytes).as_slice()
					],
				)?;
			}
			Ok(())
		});
		let db = fixture.open();
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
			let fp = cert_fingerprint(cert.0.as_ref());
			let registered = loupe_storage::registry::authenticate(&db, &fp).unwrap().unwrap();
			assert_eq!(registered.kind, kind);
			assert!(registered.name.expose().contains("FAKE_AUTH_NAME"));
			let id = registered.id;
			let mut request = Request::new(Body::empty());
			request.extensions_mut().insert(cert.clone());
			assert_eq!(app.clone().oneshot(request).await.unwrap().status(), StatusCode::OK);
			loupe_storage::registry::revoke_worker(&db, &crate::test_support::operator(), id, 1)
				.unwrap();
			let mut request = Request::new(Body::empty());
			request.extensions_mut().insert(cert);
			assert_eq!(
				app.clone().oneshot(request).await.unwrap().status(),
				StatusCode::UNAUTHORIZED
			);
		}
	}
}
