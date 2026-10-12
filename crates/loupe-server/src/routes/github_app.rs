//! Admin-only management of the server-wide GitHub App credential.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use loupe_proto::{GithubAppResponse, GithubAppSummary, SetGithubAppRequest, PROTOCOL_VERSION};
use loupe_storage::github_app::{self, StoredGithubApp};
use loupe_storage::repos;

use crate::reporters::github_app::GithubAppKey;
use crate::state::AppState;

/// `PUT /v1/github-app` — admin only. Parses the private key, proves it
/// against GitHub's `GET /app`, checks the app id matches, and stores
/// the credential. Replaces any previously stored app.
pub async fn set(
	State(state): State<AppState>, Json(req): Json<SetGithubAppRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
	if req.protocol_version != PROTOCOL_VERSION {
		return Err((
			StatusCode::BAD_REQUEST,
			format!("unsupported protocol_version {}", req.protocol_version),
		));
	}
	if req.app_id == 0 {
		return Err((StatusCode::BAD_REQUEST, "app_id must be positive".into()));
	}
	let key = GithubAppKey::from_pem(req.app_id, req.private_key_pem.expose())
		.map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid GitHub App private key: {e:#}")))?;
	let info = state.github_reporter.verify_app(&key).await.map_err(|e| {
		(StatusCode::BAD_REQUEST, format!("GitHub rejected the app credential: {e:#}"))
	})?;
	if info.id != req.app_id {
		return Err((
			StatusCode::BAD_REQUEST,
			format!(
				"private key belongs to GitHub App {} ({}), not {}",
				info.id, info.slug, req.app_id
			),
		));
	}

	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
	let stored = StoredGithubApp {
		app_id: req.app_id,
		slug: info.slug,
		private_key_pem: req.private_key_pem,
	};
	state
		.db
		.with_conn(|c| Ok(github_app::set(c, &stored, now)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("storing GitHub App: {e}")))?;
	Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/github-app` — admin only. Reports which app is configured
/// without ever returning the key.
pub async fn get(
	State(state): State<AppState>,
) -> Result<Json<GithubAppResponse>, (StatusCode, String)> {
	let stored = state
		.db
		.with_conn(|c| Ok(github_app::summary(c)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("reading GitHub App: {e}")))?;
	Ok(Json(GithubAppResponse {
		protocol_version: PROTOCOL_VERSION,
		app: stored.map(|app| GithubAppSummary { app_id: app.app_id, slug: app.slug }),
	}))
}

/// `DELETE /v1/github-app` — admin only. Removes the stored credential,
/// unless a repo still reports through it: dropping the key under those
/// repos would make every one of their dispatches fail, so the operator
/// has to re-point them (to a PAT or another destination) first.
pub async fn clear(State(state): State<AppState>) -> Result<StatusCode, (StatusCode, String)> {
	enum Outcome {
		Removed,
		Missing,
		InUse(usize),
	}
	let outcome = state
		.db
		.with_conn(|c| {
			let tx = c.transaction()?;
			let referencing = repos::count_github_app_references(&tx)?;
			if referencing > 0 {
				return Ok(Outcome::InUse(referencing));
			}
			let removed = github_app::clear(&tx)?;
			tx.commit()?;
			Ok(if removed { Outcome::Removed } else { Outcome::Missing })
		})
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("clearing GitHub App: {e}")))?;
	match outcome {
		Outcome::Removed => Ok(StatusCode::NO_CONTENT),
		Outcome::Missing => Err((StatusCode::NOT_FOUND, "no GitHub App configured".into())),
		Outcome::InUse(n) => Err((
			StatusCode::CONFLICT,
			format!(
				"{n} repo(s) still report through the GitHub App; switch them to a PAT or \
				 another destination before clearing it"
			),
		)),
	}
}
