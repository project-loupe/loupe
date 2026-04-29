use axum::http::StatusCode;
use axum::{Extension, Json};
use loupe_storage::workers::WorkerKind;
use serde::Serialize;

use crate::auth::AuthedWorker;

#[derive(Serialize)]
pub struct WhoamiResponse {
	pub worker_id: i64,
	pub name: String,
	pub kind: &'static str,
}

/// `GET /v1/whoami` — useful for diagnostics and integration tests:
/// confirms which workers row an mTLS client resolved to.
pub async fn get(Extension(authed): Extension<AuthedWorker>) -> (StatusCode, Json<WhoamiResponse>) {
	let kind = match authed.kind() {
		WorkerKind::Admin => "admin",
		WorkerKind::Worker => "worker",
	};
	let resp = WhoamiResponse { worker_id: authed.id(), name: authed.worker.name.clone(), kind };
	(StatusCode::OK, Json(resp))
}
