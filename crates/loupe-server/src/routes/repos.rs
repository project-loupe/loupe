//! Admin-only repository registration and configuration.
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use loupe_core::ReportingDestination;
use loupe_proto::{
	ListReposResponse, RegisterRepoResponse, RepoSummary, ReportingSetup, PROTOCOL_VERSION,
};
use loupe_provenance::Db;
use loupe_storage::registry::{self, ReportingWrite};
use loupe_storage::repos::{self, NewRepo, RepoRow, RepoUpdate};
use loupe_storage::scope::{self, OperatorTarget, RepoScope};
use serde::Deserialize;

use crate::auth::AuthedWorker;
use crate::state::AppState;

fn row_to_summary(r: RepoRow) -> RepoSummary<Db> {
	RepoSummary {
		reporting: Some((&r.reporting).into()),
		id: r.id,
		clone_url: r.clone_url,
		host: r.host,
		owner: r.owner,
		repo: r.repo,
		default_branch: r.default_branch,
		scan_interval_seconds: r.scan_interval_seconds,
		disabled_at: r.disabled_at,
		verification_enabled: r.verification_enabled,
		require_approval: r.require_approval,
		last_scanned_sha: r.last_scanned_sha,
		last_scanned_at: r.last_scanned_at,
		created_at: r.created_at,
	}
}
// debug-ok: this repository list query contains only an optional numeric limit.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
	#[serde(default)]
	pub limit: Option<i64>,
}
fn positive_limit(limit: Option<i64>) -> Result<Option<i64>, (StatusCode, String)> {
	if matches!(limit, Some(n) if n <= 0) {
		return Err((StatusCode::BAD_REQUEST, "limit must be positive".into()));
	}
	Ok(limit)
}
fn check_github_credential<S: loupe_provenance::Source>(
	state: &AppState,
	target_owner: &loupe_core::text::BoundedText<loupe_core::text::policy::RepoOwner, S>,
	github_pat: Option<&str>,
) -> Result<(), (StatusCode, String)> {
	match github_pat {
		Some(pat) if pat.trim().is_empty() => {
			Err((StatusCode::BAD_REQUEST, "github PAT must not be empty".into()))
		},
		Some(_) => Ok(()),
		None => state
			.check_github_app_target_owner(target_owner)
			.map_err(|msg| (StatusCode::BAD_REQUEST, msg)),
	}
}
const NO_APP_CONFIGURED: &str =
	"no GitHub App configured; run loupectl github-app set or pass a PAT";
fn repository<T>(
	state: &AppState, operator: &AuthedWorker, id: i64,
	body: impl for<'tx> FnOnce(&RepoScope<'tx>) -> loupe_storage::Result<T>,
) -> Result<T, (StatusCode, String)> {
	scope::with_operator_repository(
		&state.db,
		&operator.require_operator()?,
		OperatorTarget::Repository(id),
		body,
	)
	.map_err(|error| {
		(StatusCode::INTERNAL_SERVER_ERROR, format!("repository operation failed: {error}"))
	})
}
pub async fn create(
	State(state): State<AppState>, Extension(operator): Extension<AuthedWorker>,
	body: crate::ingress::OperatorJson,
) -> Result<(StatusCode, Json<RegisterRepoResponse>), (StatusCode, String)> {
	let input = crate::ingress::registry::RegisterRepoDecoder::decode(body)?;
	let req = input.request;
	if req.protocol_version != PROTOCOL_VERSION {
		return Err((
			StatusCode::BAD_REQUEST,
			format!("unsupported protocol_version {}", req.protocol_version),
		));
	}
	let parsed = input
		.derived
		.ok_or((StatusCode::BAD_REQUEST, "clone_url must be an https or file URL".into()))?;
	if let ReportingSetup::GithubIssue { target_owner, github_pat, .. } = &req.reporting {
		check_github_credential(
			&state,
			target_owner,
			github_pat.as_ref().map(|pat| pat.expose().as_str()),
		)?;
	}
	let (reporting, pat) = match req.reporting {
		ReportingSetup::GithubIssue { target_owner, target_repo, github_pat } => (
			ReportingDestination::GithubIssue { target_owner, target_repo, pat_secret_id: None },
			github_pat,
		),
		ReportingSetup::Email { to, from, subject_prefix } => {
			(ReportingDestination::Email { to, from, subject_prefix }, None)
		},
		ReportingSetup::Manual => (ReportingDestination::Manual, None),
	};
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
	let new = NewRepo {
		clone_url: req.clone_url,
		host: parsed.host,
		owner: parsed.owner,
		repo: parsed.repo,
		default_branch: req.branch,
		scan_interval_seconds: req.scan_interval_seconds.map(|n| n as i64),
		scanner_config: req.scanner_config.ok_or((
			StatusCode::INTERNAL_SERVER_ERROR,
			"missing admitted scanner document".into(),
		))?,
		reporting,
		verification_enabled: req.verification_enabled.unwrap_or(state.verification_default),
		require_approval: req.require_approval,
	};
	let id = registry::register_repository(
		&state.db,
		&operator.require_operator()?,
		&new,
		pat.as_ref(),
		now,
	)
	.map_err(|error| (StatusCode::CONFLICT, format!("registering repo failed: {error}")))?;
	let ReportingWrite::Done(repo_id) = id else {
		return Err((StatusCode::BAD_REQUEST, NO_APP_CONFIGURED.into()));
	};
	Ok((
		StatusCode::CREATED,
		Json(RegisterRepoResponse { protocol_version: PROTOCOL_VERSION, repo_id }),
	))
}
pub async fn list(
	State(state): State<AppState>, Extension(operator): Extension<AuthedWorker>,
	Query(qp): Query<ListQuery>,
) -> Result<Json<ListReposResponse<Db>>, (StatusCode, String)> {
	let rows =
		registry::repositories(&state.db, &operator.require_operator()?, positive_limit(qp.limit)?)
			.map_err(|error| {
				(StatusCode::INTERNAL_SERVER_ERROR, format!("listing repos: {error}"))
			})?;
	Ok(Json(ListReposResponse {
		protocol_version: PROTOCOL_VERSION,
		repos: rows.into_iter().map(row_to_summary).collect(),
	}))
}
pub async fn update(
	State(state): State<AppState>, Path(id): Path<i64>,
	Extension(operator): Extension<AuthedWorker>, body: crate::ingress::OperatorJson,
) -> Result<StatusCode, (StatusCode, String)> {
	let req = crate::ingress::registry::UpdateRepoDecoder::decode(body)?;
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
	let patch = RepoUpdate {
		disabled: req.disabled,
		scan_interval_seconds: req.scan_interval_seconds.map(|n| n as i64),
		verification_enabled: req.verification_enabled,
		require_approval: if req.inherit_require_approval {
			Some(None)
		} else {
			req.require_approval.map(Some)
		},
	};
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
	if repository(&state, &operator, id, |scope| repos::update(scope, &patch, now))? {
		Ok(StatusCode::NO_CONTENT)
	} else {
		Err((StatusCode::NOT_FOUND, format!("no repo with id {id}")))
	}
}
pub async fn rotate_github_pat(
	State(state): State<AppState>, Path(id): Path<i64>,
	Extension(operator): Extension<AuthedWorker>, body: crate::ingress::OperatorJson,
) -> Result<StatusCode, (StatusCode, String)> {
	let req = crate::ingress::registry::RotateRepoPatDecoder::decode(body)?;
	if req.protocol_version != PROTOCOL_VERSION {
		return Err((
			StatusCode::BAD_REQUEST,
			format!("unsupported protocol_version {}", req.protocol_version),
		));
	}
	if req.github_pat.expose().trim().is_empty() {
		return Err((StatusCode::BAD_REQUEST, "github PAT must not be empty".into()));
	}
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
	match repository(&state, &operator, id, |scope| repos::rotate_github_pat(scope, &req.github_pat, now))? {
		repos::PatRotation::Rotated => Ok(StatusCode::NO_CONTENT),
		repos::PatRotation::Missing => Err((StatusCode::NOT_FOUND, format!("no repo with id {id}"))),
		repos::PatRotation::AppMode => Err((StatusCode::BAD_REQUEST, format!("repo {id} reports through the GitHub App; use set-github-reporting with a PAT to switch"))),
		repos::PatRotation::OtherDestination => Err((StatusCode::BAD_REQUEST, format!("repo {id} does not use GitHub issue reporting"))),
	}
}
pub async fn set_github_reporting(
	State(state): State<AppState>, Path(id): Path<i64>,
	Extension(operator): Extension<AuthedWorker>, body: crate::ingress::OperatorJson,
) -> Result<StatusCode, (StatusCode, String)> {
	let req = crate::ingress::registry::SetRepoGithubReportingDecoder::decode(body)?;
	if req.protocol_version != PROTOCOL_VERSION {
		return Err((
			StatusCode::BAD_REQUEST,
			format!("unsupported protocol_version {}", req.protocol_version),
		));
	}
	if req.target_owner.expose().is_empty() {
		return Err((StatusCode::BAD_REQUEST, "target_owner must not be empty".into()));
	}
	if req.target_repo.expose().is_empty() {
		return Err((StatusCode::BAD_REQUEST, "target_repo must not be empty".into()));
	}
	check_github_credential(
		&state,
		&req.target_owner,
		req.github_pat.as_ref().map(|pat| pat.expose().as_str()),
	)?;
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
	match repository(&state, &operator, id, |scope| {
		repos::set_github_reporting(
			scope,
			&req.target_owner,
			&req.target_repo,
			req.github_pat.as_ref(),
			now,
		)
	})? {
		ReportingWrite::Done(true) => Ok(StatusCode::NO_CONTENT),
		ReportingWrite::Done(false) => {
			Err((StatusCode::NOT_FOUND, format!("no repo with id {id}")))
		},
		ReportingWrite::NoApp => Err((StatusCode::BAD_REQUEST, NO_APP_CONFIGURED.into())),
	}
}
pub async fn delete(
	State(state): State<AppState>, Path(id): Path<i64>,
	Extension(operator): Extension<AuthedWorker>,
) -> Result<StatusCode, (StatusCode, String)> {
	if repository(&state, &operator, id, repos::delete)? {
		Ok(StatusCode::NO_CONTENT)
	} else {
		Err((StatusCode::NOT_FOUND, format!("no repo with id {id}")))
	}
}
/// Permissive parser for clone URLs.
///
/// Accepts `https://<host>/<owner>/<repo>(.git)?` (the GitHub /
/// GitLab / GHE shape) and `file:///path/to/repo(.git)?` (for local-
/// only testing — `loupectl repo add --clone-url file:///tmp/fixture`
/// just works without spinning up a real git server). For `file://`
/// URLs the host/owner triple is synthesized as
/// `("local", "local", <last-path-component>)` so the rest of the
/// schema (which requires non-empty values) stays happy.
pub(crate) fn parse_github_clone_url(url: &str) -> Option<(String, String, String)> {
	if let Some(path) = url.strip_prefix("file://") {
		let trimmed = path.trim_end_matches('/');
		let last = trimmed.rsplit('/').find(|s| !s.is_empty())?;
		let repo = last.strip_suffix(".git").unwrap_or(last).to_owned();
		if repo.is_empty() {
			return None;
		}
		return Some(("local".into(), "local".into(), repo));
	}
	let without_scheme = url.strip_prefix("https://")?;
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
	fn rejects_non_https_or_file_url() {
		assert!(parse_github_clone_url("git@github.com:acme/widget.git").is_none());
		assert!(parse_github_clone_url("ssh://github.com/acme/widget").is_none());
		assert!(parse_github_clone_url("http://github.com/acme/widget").is_none());
	}

	#[test]
	fn rejects_path_without_owner_or_repo() {
		assert!(parse_github_clone_url("https://github.com/").is_none());
		assert!(parse_github_clone_url("https://github.com/acme").is_none());
	}

	#[test]
	fn parses_local_file_url() {
		let (host, owner, repo) = parse_github_clone_url("file:///tmp/fixture/widget.git").unwrap();
		assert_eq!(host, "local");
		assert_eq!(owner, "local");
		assert_eq!(repo, "widget");
		// Without `.git` suffix.
		assert_eq!(parse_github_clone_url("file:///home/me/projects/sample").unwrap().2, "sample");
		// Trailing slash tolerated.
		assert_eq!(parse_github_clone_url("file:///home/me/projects/sample/").unwrap().2, "sample");
	}

	#[test]
	fn rejects_file_url_with_empty_path() {
		assert!(parse_github_clone_url("file:///").is_none());
		assert!(parse_github_clone_url("file://").is_none());
	}
}
