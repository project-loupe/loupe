//! Admin-only repo registration / listing / deregistration.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use loupe_core::ReportingDestination;
use loupe_proto::{
	ListReposResponse, RegisterRepoRequest, RegisterRepoResponse, RepoSummary, ReportingSetup,
	UpdateRepoRequest, PROTOCOL_VERSION,
};
use loupe_storage::repos::{self, NewRepo, RepoRow, RepoUpdate};
use loupe_storage::secrets::{self, SecretKind};

use crate::state::AppState;

fn row_to_summary(r: RepoRow) -> RepoSummary {
	RepoSummary {
		id: r.id,
		clone_url: r.clone_url,
		host: r.host,
		owner: r.owner,
		repo: r.repo,
		default_branch: r.default_branch,
		scan_interval_seconds: r.scan_interval_seconds,
		last_scanned_sha: r.last_scanned_sha,
		last_scanned_at: r.last_scanned_at,
		created_at: r.created_at,
	}
}

/// `POST /v1/repos` — admin only. Stores the GitHub PAT inline to the
/// secrets table and persists the resulting `ReportingDestination` with
/// the generated `pat_secret_id`. Returns the new repo id.
pub async fn create(
	State(state): State<AppState>, Json(req): Json<RegisterRepoRequest>,
) -> Result<(StatusCode, Json<RegisterRepoResponse>), (StatusCode, String)> {
	if req.protocol_version != PROTOCOL_VERSION {
		return Err((
			StatusCode::BAD_REQUEST,
			format!("unsupported protocol_version {}", req.protocol_version),
		));
	}
	let parsed = parse_github_clone_url(&req.clone_url)
		.ok_or((StatusCode::BAD_REQUEST, "clone_url must be an https github URL".into()))?;
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;

	let new_repo_id = state
		.db
		.with_conn(|c| {
			// One transaction so a partially-inserted secret can't outlive
			// a failed repo insert.
			let tx = c.transaction()?;
			let reporting = match &req.reporting {
				ReportingSetup::GithubIssue { target_owner, target_repo, github_pat } => {
					let secret_label = format!("pat:{}:{}/{}", parsed.0, target_owner, target_repo);
					let secret_id = secrets::insert(
						&tx,
						SecretKind::GithubPat,
						&secret_label,
						github_pat.as_bytes(),
						now,
					)?;
					ReportingDestination::GithubIssue {
						target_owner: target_owner.clone(),
						target_repo: target_repo.clone(),
						pat_secret_id: secret_id,
					}
				},
				ReportingSetup::Email { to, from, subject_prefix } => ReportingDestination::Email {
					to: to.clone(),
					from: from.clone(),
					subject_prefix: subject_prefix.clone(),
				},
			};
			let id = repos::insert(
				&tx,
				&NewRepo {
					clone_url: req.clone_url.clone(),
					host: parsed.0.clone(),
					owner: parsed.1.clone(),
					repo: parsed.2.clone(),
					default_branch: req.branch.clone(),
					scan_interval_seconds: req.scan_interval_seconds.map(|v| v as i64),
					scanner_config: req.scanner_config.clone(),
					reporting,
					verification_enabled: req.verification_enabled,
					require_approval: req.require_approval,
				},
				now,
			)?;
			tx.commit()?;
			Ok(id)
		})
		.map_err(|e| (StatusCode::CONFLICT, format!("registering repo failed: {e}")))?;

	Ok((
		StatusCode::CREATED,
		Json(RegisterRepoResponse { protocol_version: PROTOCOL_VERSION, repo_id: new_repo_id }),
	))
}

/// `GET /v1/repos` — admin only. Lists all registered repos. Reporting
/// JSON is **not** included: it carries `pat_secret_id` references that
/// are storage-internal.
pub async fn list(
	State(state): State<AppState>,
) -> Result<Json<ListReposResponse>, (StatusCode, String)> {
	let rows = state
		.db
		.with_conn(|c| Ok(repos::list(c)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("listing repos: {e}")))?;
	Ok(Json(ListReposResponse {
		protocol_version: PROTOCOL_VERSION,
		repos: rows.into_iter().map(row_to_summary).collect(),
	}))
}

/// `PATCH /v1/repos/:id` — admin only. Toggles `disabled`, swaps the
/// scan interval, or flips the verification flag. Each field is
/// independently optional; absent fields are left alone. The clone URL
/// and reporting destination are intentionally not patchable — those
/// would silently change where new findings get filed, so re-register
/// the repo instead.
pub async fn update(
	State(state): State<AppState>, Path(id): Path<i64>, Json(req): Json<UpdateRepoRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
	if req.protocol_version != PROTOCOL_VERSION {
		return Err((
			StatusCode::BAD_REQUEST,
			format!("unsupported protocol_version {}", req.protocol_version),
		));
	}
	if req.require_approval.is_some() && req.inherit_require_approval {
		return Err((
			StatusCode::BAD_REQUEST,
			"require_approval and inherit_require_approval are mutually exclusive".into(),
		));
	}
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
	let patch = RepoUpdate {
		disabled: req.disabled,
		scan_interval_seconds: req.scan_interval_seconds.map(|v| v as i64),
		verification_enabled: req.verification_enabled,
		require_approval: if req.inherit_require_approval {
			Some(None)
		} else {
			req.require_approval.map(Some)
		},
	};
	let updated = state
		.db
		.with_conn(|c| Ok(repos::update(c, id, &patch, now)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("update repo: {e}")))?;
	if updated {
		Ok(StatusCode::NO_CONTENT)
	} else {
		Err((StatusCode::NOT_FOUND, format!("no repo with id {id}")))
	}
}

/// `DELETE /v1/repos/:id` — admin only. CASCADEs onto jobs, findings,
/// scan_history, and verifications via the foreign keys. The secret
/// linked from `reporting.pat_secret_id` is intentionally **not**
/// deleted — it might be shared with other repos.
pub async fn delete(
	State(state): State<AppState>, Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
	let removed = state
		.db
		.with_conn(|c| Ok(repos::delete(c, id)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("delete repo: {e}")))?;
	if removed {
		Ok(StatusCode::NO_CONTENT)
	} else {
		Err((StatusCode::NOT_FOUND, format!("no repo with id {id}")))
	}
}

/// Permissive parser for GitHub-style `https://github.com/<owner>/<repo>(.git)?`.
/// Returns (host, owner, repo). Rejects unrecognised URLs with `None`.
fn parse_github_clone_url(url: &str) -> Option<(String, String, String)> {
	let without_scheme = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
	let mut parts = without_scheme.splitn(2, '/');
	let host = parts.next()?.to_owned();
	let path = parts.next()?;
	let mut path_parts = path.split('/').filter(|s| !s.is_empty());
	let owner = path_parts.next()?.to_owned();
	let repo_raw = path_parts.next()?;
	let repo = repo_raw.strip_suffix(".git").unwrap_or(repo_raw).to_owned();
	if owner.is_empty() || repo.is_empty() {
		return None;
	}
	Some((host, owner, repo))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_canonical_https_clone_url() {
		let (host, owner, repo) =
			parse_github_clone_url("https://github.com/acme/widget.git").unwrap();
		assert_eq!(host, "github.com");
		assert_eq!(owner, "acme");
		assert_eq!(repo, "widget");
	}

	#[test]
	fn parses_url_without_dot_git_suffix() {
		let (_, _, repo) = parse_github_clone_url("https://github.com/acme/widget").unwrap();
		assert_eq!(repo, "widget");
	}

	#[test]
	fn rejects_non_https_url() {
		assert!(parse_github_clone_url("git@github.com:acme/widget.git").is_none());
		assert!(parse_github_clone_url("ssh://github.com/acme/widget").is_none());
	}

	#[test]
	fn rejects_path_without_owner_or_repo() {
		assert!(parse_github_clone_url("https://github.com/").is_none());
		assert!(parse_github_clone_url("https://github.com/acme").is_none());
	}
}
