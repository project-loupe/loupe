//! Independent verification admission and postcommit delivery of an owned report.
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Extension;
use loupe_core::review_payload::VerificationTerminalV1;
use loupe_proto::review_api::ReviewProtocol;
use loupe_proto::review_verification::{self as wire, FinalizeVerificationRequestDecoder};
use loupe_provenance::{Agent, Db};
use loupe_storage::reports;
use loupe_storage::review_authority::{self as stored, VerificationReceipt};

use crate::auth::AuthedWorker;
use crate::ingress::WorkerBody;
use crate::review::authority::{self, Access, Phase};
use crate::review::http::{self, ApiError, Result};
use crate::AppState;

pub const REQUEST_CAP: usize = 512 * 1024;
pub const RESPONSE_CAP: usize = 16 * 1024;

fn reply(value: VerificationReceipt) -> Result<wire::VerificationTerminalResponse<Db>> {
	let summary = value.summary;
	Ok(wire::VerificationTerminalResponse {
		protocol_version: ReviewProtocol,
		receipt: wire::VerificationReceipt {
			receipt_id: value.receipt_id.try_into().map_err(ApiError::invalid)?,
			job_id: value.job_id.try_into().map_err(ApiError::invalid)?,
			commit_sha: value.commit,
			result_digest: value.result_digest,
			summary: wire::VerificationSummary {
				version: summary.version,
				finding_id: summary.finding_id.try_into().map_err(ApiError::invalid)?,
				verification_id: summary.verification_id.try_into().map_err(ApiError::invalid)?,
				verdict: match summary.verdict {
					stored::VerificationVerdict::Verified => wire::VerificationVerdict::Verified,
					stored::VerificationVerdict::Rejected => wire::VerificationVerdict::Rejected,
					stored::VerificationVerdict::Inconclusive => {
						wire::VerificationVerdict::Inconclusive
					},
				},
				finding_state: summary.finding_state,
				continuation: summary.continuation.map(crate::review::terminal::continuation),
			},
		},
	})
}
fn error(error: loupe_storage::Error) -> ApiError {
	use loupe_storage::{Conflict, Error};
	match error {
		Error::Conflict(Conflict::TerminalReceipt) => ApiError::conflict("terminal_conflict"),
		Error::Conflict(Conflict::CheckpointEvidence | Conflict::IncompatibleReviewState) => {
			ApiError::conflict("incompatible_review_state")
		},
		Error::Conflict(Conflict::RevalidationRequired) => {
			ApiError::conflict("revalidation_required")
		},
		other => other.into(),
	}
}
struct Dispatch {
	preparation: reports::Preparation,
	finding_id: i64,
	now: i64,
}
/// The production transaction half is kept private for the crash-gap test.
fn finish(
	state: &AppState, worker: &AuthedWorker, headers: &HeaderMap, job: i64,
	evidence: &VerificationTerminalV1<Agent>,
) -> Result<(Response, Option<Dispatch>)> {
	let mut dispatch = None;
	let response = http::transaction(&state.db, worker, headers, job, RESPONSE_CAP, |tx| {
		let value = tx
			.finalize_verification(evidence, state.require_approval_default, |context| {
				authority::policy(Phase::Verify, Access::Domain, context)
			})
			.map_err(error)?;
		if !matches!(value.reporting, reports::Preparation::NoReport) {
			dispatch = Some(Dispatch {
				preparation: value.reporting,
				finding_id: value.receipt.summary.finding_id,
				now: value.finalized_at,
			});
		}
		reply(value.receipt)
	})?;
	Ok((response, dispatch))
}
pub async fn finalize(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, headers: HeaderMap, body: WorkerBody,
) -> Result<Response> {
	let body = http::body(&headers, body, REQUEST_CAP)?;
	let request = body
		.0
		.as_bytes()
		.validate_carrying(FinalizeVerificationRequestDecoder)
		.map_err(ApiError::invalid)?;
	let (response, dispatch) = finish(&state, &worker, &headers, job, &request.payload)?;
	state.job_arrived.notify_waiters();
	if let Some(dispatch) = dispatch
		&& super::jobs::dispatch_prepared(
			&state,
			dispatch.preparation,
			super::jobs::DispatchScope::Finding(dispatch.finding_id),
			dispatch.now,
		)
		.await
		.is_err()
	{
		// Retain the accepted verdict; only the authenticated admin recovery
		// route may retry delivery. Arbitrary reporter diagnostics stay out.
		tracing::warn!(job_id = job, "dispatch after verification finalization failed");
	}
	Ok(response)
}

#[cfg(test)]
#[path = "../../tests/review_verification/gap.rs"]
mod tests;
