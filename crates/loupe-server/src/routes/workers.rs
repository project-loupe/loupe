//! Admin-only worker registration / revocation routes.
//!
//! Mints a fresh client cert from the server's internal CA, records the
//! cert fingerprint against the requested name, and returns the PEM
//! bundle exactly once. The private key never touches the database —
//! callers must persist it themselves on the worker host.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use loupe_proto::{RegisterWorkerRequest, RegisterWorkerResponse, PROTOCOL_VERSION};
use loupe_storage::workers::{self, WorkerKind};
use loupe_tls::cert_fingerprint;
use rustls_pemfile::certs;

use crate::state::AppState;

/// `POST /v1/workers` — admin-only. Mints a worker client cert and
/// records its fingerprint as a `kind = 'worker'` row.
pub async fn create(
	State(state): State<AppState>, Json(req): Json<RegisterWorkerRequest>,
) -> Result<(StatusCode, Json<RegisterWorkerResponse>), (StatusCode, String)> {
	if req.protocol_version != PROTOCOL_VERSION {
		return Err((
			StatusCode::BAD_REQUEST,
			format!("unsupported protocol_version {}", req.protocol_version),
		));
	}
	if req.name.trim().is_empty() {
		return Err((StatusCode::BAD_REQUEST, "worker name must be non-empty".into()));
	}

	let bundle = state
		.ca
		.mint_client(&req.name)
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("mint failed: {e}")))?;

	let fingerprint = first_cert_fingerprint(&bundle.cert_pem)
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("fingerprint failed: {e}")))?;
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
	let id = state
		.db
		.with_conn(|c| Ok(workers::insert(c, &req.name, WorkerKind::Worker, &fingerprint, now)?))
		.map_err(|e| (StatusCode::CONFLICT, format!("insert failed: {e}")))?;

	let resp = RegisterWorkerResponse {
		protocol_version: PROTOCOL_VERSION,
		worker_id: id,
		client_cert_pem: bundle.cert_pem,
		client_key_pem: bundle.key_pem,
		ca_cert_pem: state.ca.cert_pem().to_owned(),
	};
	Ok((StatusCode::CREATED, Json(resp)))
}

/// `DELETE /v1/workers/:id` — admin-only. Marks the worker revoked.
/// Subsequent mTLS requests using that cert will 401 at the auth
/// middleware.
pub async fn revoke(
	State(state): State<AppState>, Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
	let revoked = state
		.db
		.with_conn(|c| Ok(workers::revoke(c, id, now)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("revoke failed: {e}")))?;
	if revoked {
		Ok(StatusCode::NO_CONTENT)
	} else {
		Err((StatusCode::NOT_FOUND, format!("no active worker with id {id}")))
	}
}

fn first_cert_fingerprint(pem: &str) -> anyhow::Result<[u8; 32]> {
	let mut reader = pem.as_bytes();
	let der = certs(&mut reader)
		.next()
		.ok_or_else(|| anyhow::anyhow!("no CERTIFICATE block in minted PEM"))??;
	Ok(cert_fingerprint(der.as_ref()))
}
