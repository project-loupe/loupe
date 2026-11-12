//! Thin survey transport; storage owns every authority check and mutation.
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Extension;
use loupe_proto::review_api::ReviewProtocol;
use loupe_proto::review_terminal::{
	FinalizeSurveyRequestDecoder, SurveyCoverage, SurveyReceipt, SurveySummary,
	SurveyTerminalResponse,
};
use loupe_provenance::Db;
use loupe_storage::review_authority::{self as stored, SurveyFinalization};

use crate::auth::AuthedWorker;
use crate::ingress::WorkerBody;
use crate::review::authority::{self, Access, Phase};
use crate::review::http::{self, ApiError, Result};
use crate::AppState;

pub const REQUEST_CAP: usize = 128 * 1024;
pub const RESPONSE_CAP: usize = 16 * 1024;

fn reply(value: SurveyFinalization) -> Result<SurveyTerminalResponse<Db>> {
	Ok(SurveyTerminalResponse {
		protocol_version: ReviewProtocol,
		receipt: SurveyReceipt {
			receipt_id: value.receipt_id.try_into().map_err(ApiError::invalid)?,
			job_id: value.job_id.try_into().map_err(ApiError::invalid)?,
			commit_sha: value.commit,
			result_digest: value.result_digest,
			terminal_reason: value.terminal_reason,
			summary: SurveySummary {
				version: value.summary.version,
				coverage: match value.summary.coverage {
					stored::SurveyCoverage::Complete => SurveyCoverage::Complete,
					stored::SurveyCoverage::Partial => SurveyCoverage::Partial,
				},
				corroboration_satisfied: value.summary.corroboration_satisfied,
				missing_results: value.summary.missing_results,
				needs_follow_up: value.summary.needs_follow_up,
				unresolved_inventory: value.summary.unresolved_inventory,
				follow_up_batches: value.summary.follow_up_batches,
				follow_up_units: value.summary.follow_up_units,
			},
		},
	})
}
fn error(error: loupe_storage::Error) -> ApiError {
	match error {
		loupe_storage::Error::Conflict(loupe_storage::Conflict::TerminalReceipt) => {
			ApiError::conflict("terminal_conflict")
		},
		loupe_storage::Error::Conflict(loupe_storage::Conflict::CheckpointEvidence) => {
			ApiError::conflict("incompatible_review_state")
		},
		other => other.into(),
	}
}
pub async fn finalize(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, headers: HeaderMap, body: WorkerBody,
) -> Result<Response> {
	let body = http::body(&headers, body, REQUEST_CAP)?;
	let request = body
		.0
		.as_bytes()
		.validate_carrying(FinalizeSurveyRequestDecoder)
		.map_err(ApiError::invalid)?;
	let response = http::transaction(&state.db, &worker, &headers, job, RESPONSE_CAP, |tx| {
		let snapshot = tx
			.finalize_survey(&request.payload, |context| {
				authority::policy(Phase::Survey, Access::Domain, context)
			})
			.map_err(error)?;
		reply(snapshot)
	})?;
	state.job_arrived.notify_waiters();
	Ok(response)
}
