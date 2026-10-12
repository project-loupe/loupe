//! Admin-only repo registration / listing / deregistration.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use loupe_core::ReportingDestination;
use loupe_proto::{
	ListReposResponse, RegisterRepoResponse, RepoSummary, ReportingSetup, PROTOCOL_VERSION,
};
use loupe_provenance::Db;
use loupe_storage::github_app;
use loupe_storage::repos::{self, NewRepo, RepoRow, RepoUpdate};
use loupe_storage::secrets::{self, SecretKind};
use serde::Deserialize;

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

/// Validate the credential side of a GitHub issue destination before
/// touching the database: a PAT must not be blank, and an app-mode
/// destination's tracker owner has to pass `allowed_target_owners`. A
/// PAT-backed destination skips the allowlist — the PAT itself scopes
/// what it can reach. Whether a GitHub App is actually configured is
/// checked inside the writing transaction (see [`NO_APP_CONFIGURED`]),
/// so a concurrent `DELETE /v1/github-app` cannot slip in between.
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

/// 400 body for an app-mode destination on a server without an app.
const NO_APP_CONFIGURED: &str =
	"no GitHub App configured; run loupectl github-app set or pass a PAT";

/// Outcome of a reporting write that may depend on the GitHub App
/// existing at commit time.
enum ReportingWrite<T> {
	Done(T),
	NoApp,
}

/// `POST /v1/repos` — admin only. Moves an inline GitHub PAT into the
/// secrets table and persists the resulting `ReportingDestination` with
/// the generated `pat_secret_id`; without a PAT the destination reports
/// through the server-wide GitHub App. Returns the new repo id.
pub async fn create(
	State(state): State<AppState>, body: crate::ingress::OperatorJson,
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
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;

	let new_repo_id = state
		.db
		.with_conn(|c| {
			// One transaction so a partially-inserted secret can't outlive
			// a failed repo insert.
			let tx = c.transaction()?;
			let reporting = match &req.reporting {
				ReportingSetup::GithubIssue { target_owner, target_repo, github_pat } => {
					let pat_secret_id = match github_pat {
						Some(github_pat) => {
							let secret_label = format!(
								"pat:{}:{}/{}",
								parsed.host.expose(),
								target_owner.expose(),
								target_repo.expose()
							);
							Some(secrets::insert(
								&tx,
								SecretKind::GithubPat,
								&secret_label,
								github_pat.expose().as_bytes(),
								now,
							)?)
						},
						// Checked inside the transaction so the app cannot be
						// cleared between the check and the insert.
						None if github_app::get(&tx)?.is_none() => {
							return Ok(ReportingWrite::NoApp);
						},
						None => None,
					};
					ReportingDestination::GithubIssue {
						target_owner: target_owner.clone(),
						target_repo: target_repo.clone(),
						pat_secret_id,
					}
				},
				ReportingSetup::Email { to, from, subject_prefix } => ReportingDestination::Email {
					to: to.clone(),
					from: from.clone(),
					subject_prefix: subject_prefix.clone(),
				},
				ReportingSetup::Manual => ReportingDestination::Manual,
			};
			let id = repos::insert(
				&tx,
				&NewRepo {
					clone_url: req.clone_url.clone(),
					host: parsed.host.clone(),
					owner: parsed.owner.clone(),
					repo: parsed.repo.clone(),
					default_branch: req.branch.clone(),
					scan_interval_seconds: req.scan_interval_seconds.map(|v| v as i64),
					scanner_config: req
						.scanner_config
						.clone()
						.expect("registration decoder always retains the scanner document"),
					reporting,
					verification_enabled: req
						.verification_enabled
						.unwrap_or(state.verification_default),
					require_approval: req.require_approval,
				},
				now,
			)?;
			tx.commit()?;
			Ok(ReportingWrite::Done(id))
		})
		.map_err(|e| (StatusCode::CONFLICT, format!("registering repo failed: {e}")))?;
	let new_repo_id = match new_repo_id {
		ReportingWrite::Done(id) => id,
		ReportingWrite::NoApp => return Err((StatusCode::BAD_REQUEST, NO_APP_CONFIGURED.into())),
	};

	Ok((
		StatusCode::CREATED,
		Json(RegisterRepoResponse { protocol_version: PROTOCOL_VERSION, repo_id: new_repo_id }),
	))
}

/// `GET /v1/repos` — admin only. Lists all registered repos. The stored
/// reporting JSON is mapped to a sanitized `ReportingSummary` first: the
/// reporter kind and its non-secret targets go out, the storage-internal
/// `pat_secret_id` does not.
pub async fn list(
	State(state): State<AppState>, Query(qp): Query<ListQuery>,
) -> Result<Json<ListReposResponse<Db>>, (StatusCode, String)> {
	let limit = positive_limit(qp.limit)?;
	let rows = state
		.db
		.with_conn(|c| Ok(repos::list(c, limit)?))
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
	State(state): State<AppState>, Path(id): Path<i64>, body: crate::ingress::OperatorJson,
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

/// `POST /v1/repos/:id/reporting/github-pat` — admin only. Repoints a
/// GitHub issue reporting repo to a freshly-stored PAT, then drops the
/// old secret if no other repo still references it.
pub async fn rotate_github_pat(
	State(state): State<AppState>, Path(id): Path<i64>, body: crate::ingress::OperatorJson,
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

	let row = state
		.db
		.with_conn(|c| Ok(repos::get(c, id)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("get repo: {e}")))?
		.ok_or_else(|| (StatusCode::NOT_FOUND, format!("no repo with id {id}")))?;
	let host = row.host;
	let (target_owner, target_repo, old_secret_id) = match row.reporting {
		ReportingDestination::GithubIssue {
			target_owner,
			target_repo,
			pat_secret_id: Some(pat_secret_id),
		} => (target_owner, target_repo, pat_secret_id),
		ReportingDestination::GithubIssue { pat_secret_id: None, .. } => {
			return Err((
				StatusCode::BAD_REQUEST,
				format!(
					"repo {id} reports through the GitHub App; use set-github-reporting with a \
					 PAT to switch"
				),
			));
		},
		ReportingDestination::Email { .. } | ReportingDestination::Manual => {
			return Err((
				StatusCode::BAD_REQUEST,
				format!("repo {id} does not use GitHub issue reporting"),
			));
		},
	};

	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
	let secret_label = format!(
		"pat:{}:{}/{}:repo:{id}:replaces:{old_secret_id}",
		host.expose(),
		target_owner.expose(),
		target_repo.expose()
	);
	let rotated = state
		.db
		.with_conn(|c| {
			let tx = c.transaction()?;
			let new_secret_id = secrets::insert(
				&tx,
				SecretKind::GithubPat,
				&secret_label,
				req.github_pat.expose().as_bytes(),
				now,
			)?;
			let new_reporting = ReportingDestination::GithubIssue {
				target_owner,
				target_repo,
				pat_secret_id: Some(new_secret_id),
			};
			if !repos::update_reporting(&tx, id, &new_reporting)? {
				return Ok(false);
			}
			if repos::count_github_pat_references(&tx, old_secret_id)? == 0 {
				secrets::delete(&tx, old_secret_id)?;
			}
			tx.commit()?;
			Ok(true)
		})
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("rotate repo PAT: {e}")))?;
	if !rotated {
		return Err((StatusCode::NOT_FOUND, format!("no repo with id {id}")));
	}

	Ok(StatusCode::NO_CONTENT)
}

/// `PUT /v1/repos/:id/reporting/github` — admin only. Configures or
/// replaces the GitHub issue reporting destination for a repo. With a
/// PAT the repo gets its own secret; without one it reports through the
/// server-wide GitHub App. Either way a PAT the repo no longer uses is
/// dropped unless another repo still references it.
pub async fn set_github_reporting(
	State(state): State<AppState>, Path(id): Path<i64>, body: crate::ingress::OperatorJson,
) -> Result<StatusCode, (StatusCode, String)> {
	let req = crate::ingress::registry::SetRepoGithubReportingDecoder::decode(body)?;
	if req.protocol_version != PROTOCOL_VERSION {
		return Err((
			StatusCode::BAD_REQUEST,
			format!("unsupported protocol_version {}", req.protocol_version),
		));
	}
	let target_owner = req.target_owner;
	let target_repo = req.target_repo;
	if target_owner.expose().is_empty() {
		return Err((StatusCode::BAD_REQUEST, "target_owner must not be empty".into()));
	}
	if target_repo.expose().is_empty() {
		return Err((StatusCode::BAD_REQUEST, "target_repo must not be empty".into()));
	}
	check_github_credential(
		&state,
		&target_owner,
		req.github_pat.as_ref().map(|pat| pat.expose().as_str()),
	)?;

	let row = state
		.db
		.with_conn(|c| Ok(repos::get(c, id)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("get repo: {e}")))?
		.ok_or_else(|| (StatusCode::NOT_FOUND, format!("no repo with id {id}")))?;
	let host = row.host;
	let old_secret_id = match row.reporting {
		ReportingDestination::GithubIssue { pat_secret_id, .. } => pat_secret_id,
		ReportingDestination::Email { .. } | ReportingDestination::Manual => None,
	};

	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
	let now_secs = now.as_secs() as i64;
	let old_label_id = old_secret_id.unwrap_or(0);
	let updated = state
		.db
		.with_conn(|c| {
			let tx = c.transaction()?;
			let new_secret_id = match &req.github_pat {
				Some(github_pat) => {
					let secret_label = format!(
						"pat:{}:{}/{}:repo:{id}:replaces:\
						 {old_label_id}:at:{}",
						host.expose(),
						target_owner.expose(),
						target_repo.expose(),
						now.as_nanos(),
					);
					Some(secrets::insert(
						&tx,
						SecretKind::GithubPat,
						&secret_label,
						github_pat.expose().as_bytes(),
						now_secs,
					)?)
				},
				// Checked inside the transaction so the app cannot be
				// cleared between the check and the update.
				None if github_app::get(&tx)?.is_none() => return Ok(ReportingWrite::NoApp),
				None => None,
			};
			let new_reporting = ReportingDestination::GithubIssue {
				target_owner,
				target_repo,
				pat_secret_id: new_secret_id,
			};
			if !repos::update_reporting(&tx, id, &new_reporting)? {
				return Ok(ReportingWrite::Done(false));
			}
			if let Some(old_secret_id) = old_secret_id
				&& repos::count_github_pat_references(&tx, old_secret_id)? == 0
			{
				secrets::delete(&tx, old_secret_id)?;
			}
			tx.commit()?;
			Ok(ReportingWrite::Done(true))
		})
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("set GitHub reporting: {e}")))?;
	match updated {
		ReportingWrite::Done(true) => Ok(StatusCode::NO_CONTENT),
		ReportingWrite::Done(false) => {
			Err((StatusCode::NOT_FOUND, format!("no repo with id {id}")))
		},
		ReportingWrite::NoApp => Err((StatusCode::BAD_REQUEST, NO_APP_CONFIGURED.into())),
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
