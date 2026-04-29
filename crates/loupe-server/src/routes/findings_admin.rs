//! Admin-only findings inspection routes:
//!
//! - `GET /v1/repos/:id/findings` → recent findings for a repo
//! - `GET /v1/findings/:id` → full detail for one finding

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use loupe_proto::{FindingDetail, FindingSummary, ListFindingsResponse, PROTOCOL_VERSION};
use loupe_storage::findings::{self, FindingRow};

use crate::state::AppState;

/// How many findings the listing endpoint returns by default. Operators
/// who need to page further should narrow by repo and follow up via
/// `loupectl finding get <id>` for individual rows.
const LIST_LIMIT: i64 = 100;

pub async fn list_for_repo(
	State(state): State<AppState>, Path(repo_id): Path<i64>,
) -> Result<Json<ListFindingsResponse>, (StatusCode, String)> {
	let rows = state
		.db
		.with_conn(|c| Ok(findings::list_for_repo(c, repo_id, LIST_LIMIT)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("listing findings: {e}")))?;
	Ok(Json(ListFindingsResponse {
		protocol_version: PROTOCOL_VERSION,
		findings: rows.into_iter().map(row_to_summary).collect(),
	}))
}

pub async fn get(
	State(state): State<AppState>, Path(id): Path<i64>,
) -> Result<Json<FindingDetail>, (StatusCode, String)> {
	let row = state
		.db
		.with_conn(|c| Ok(findings::get(c, id)?))
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("get finding: {e}")))?
		.ok_or((StatusCode::NOT_FOUND, format!("no finding with id {id}")))?;
	Ok(Json(row_to_detail(row)))
}

fn row_to_summary(r: FindingRow) -> FindingSummary {
	FindingSummary {
		id: r.id,
		repo_id: r.repo_id,
		job_id: r.job_id,
		scanner_id: r.scanner_id,
		severity: r.severity,
		title: r.title,
		file_path: r.file_path,
		line_start: r.line_start,
		fingerprint: r.fingerprint,
		state: r.state,
		verification_required: r.verification_required,
		created_at: r.created_at,
	}
}

fn row_to_detail(r: FindingRow) -> FindingDetail {
	FindingDetail {
		protocol_version: PROTOCOL_VERSION,
		id: r.id,
		repo_id: r.repo_id,
		job_id: r.job_id,
		scanner_id: r.scanner_id,
		severity: r.severity,
		title: r.title,
		description: r.description,
		file_path: r.file_path,
		line_start: r.line_start,
		line_end: r.line_end,
		cwe: r.cwe,
		patch_unified: r.patch_unified,
		poc_unified: r.poc_unified,
		fingerprint: r.fingerprint,
		state: r.state,
		verification_required: r.verification_required,
		created_at: r.created_at,
	}
}
