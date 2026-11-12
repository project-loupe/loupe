//! HTTP evidence ingress and bounded wire responses; storage owns all workflow.
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Extension;
use loupe_proto::review_api::ReviewProtocol;
use loupe_proto::review_evidence::{
	self as wire, LeadCheckpointRequestDecoder, UnitResultCheckpointRequestDecoder,
};
use loupe_storage::review_authority::{
	LeadCheckpoint, LeadCheckpointOutcome, UnitResultCheckpoint,
};
use loupe_storage::scheduler::Band;

use crate::auth::AuthedWorker;
use crate::ingress::WorkerBody;
use crate::review::authority::{self, Access, Phase};
use crate::review::http::{self, ApiError};
use crate::AppState;

/// Shared by `leads` and `sibling-leads`.
pub const LEAD_REQUEST_CAP: usize = 256 * 1024;
pub const LEAD_RESPONSE_CAP: usize = 8192;
pub const RESULT_REQUEST_CAP: usize = 256 * 1024;
pub const RESULT_RESPONSE_CAP: usize = 8192;

pub async fn submit_lead(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, headers: HeaderMap, body: WorkerBody,
) -> http::Result<Response> {
	submit(state, job, worker, headers, body, Phase::Survey).await
}
pub async fn submit_sibling_lead(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, headers: HeaderMap, body: WorkerBody,
) -> http::Result<Response> {
	submit(state, job, worker, headers, body, Phase::Drilldown).await
}
async fn submit(
	state: AppState, job: i64, worker: AuthedWorker, headers: HeaderMap, body: WorkerBody,
	phase: Phase,
) -> http::Result<Response> {
	let body = http::body(&headers, body, LEAD_REQUEST_CAP)?;
	let request = body
		.0
		.as_bytes()
		.validate_carrying(LeadCheckpointRequestDecoder)
		.map_err(ApiError::invalid)?;
	let digest = request.digest().map_err(ApiError::invalid)?;
	let response = http::transaction(&state.db, &worker, &headers, job, LEAD_RESPONSE_CAP, |tx| {
		let scope =
			authority::authorize(tx, phase, Access::Domain)?.ok_or_else(ApiError::denied)?;
		let submission = LeadCheckpoint {
			key: &request.client_lead_key,
			digest: &digest,
			evidence: &request.evidence,
		};
		let receipt = match phase {
			Phase::Survey => scope.submit_lead_checkpoint(&submission)?,
			Phase::Drilldown => scope.submit_sibling_lead_checkpoint(&submission)?,
			Phase::Verify => return Err(ApiError::denied()),
		};
		Ok(wire::LeadCheckpointResponse {
			protocol_version: ReviewProtocol,
			lead_id: receipt.lead_id.try_into().map_err(ApiError::invalid)?,
			outcome: match receipt.outcome {
				LeadCheckpointOutcome::Created => wire::LeadOutcome::Created,
				LeadCheckpointOutcome::Attached => wire::LeadOutcome::Attached,
				LeadCheckpointOutcome::ClosedExists => wire::LeadOutcome::ClosedExists,
			},
			observation_id: receipt
				.observation_id
				.map(TryInto::try_into)
				.transpose()
				.map_err(ApiError::invalid)?,
			accepted_priority: wire::AcceptedPriority {
				band: match receipt.accepted_priority.band {
					Band::Urgent => wire::PriorityBand::Urgent,
					Band::High => wire::PriorityBand::High,
					Band::Normal => wire::PriorityBand::Normal,
					Band::Background => wire::PriorityBand::Background,
				},
				score: receipt.accepted_priority.score,
			},
		})
	})?;
	state.job_arrived.notify_one();
	Ok(response)
}
pub async fn submit_unit_result(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, headers: HeaderMap, body: WorkerBody,
) -> http::Result<Response> {
	let body = http::body(&headers, body, RESULT_REQUEST_CAP)?;
	let request = body
		.0
		.as_bytes()
		.validate_carrying(UnitResultCheckpointRequestDecoder)
		.map_err(ApiError::invalid)?;
	let digest = request.digest().map_err(ApiError::invalid)?;
	let response =
		http::transaction(&state.db, &worker, &headers, job, RESULT_RESPONSE_CAP, |tx| {
			let scope = authority::authorize(tx, Phase::Survey, Access::Domain)?
				.ok_or_else(ApiError::denied)?;
			let receipt = scope.submit_unit_result_checkpoint(&UnitResultCheckpoint {
				key: &request.client_result_key,
				digest: &digest,
				result: &request.result,
			})?;
			Ok(wire::UnitResultCheckpointResponse {
				protocol_version: ReviewProtocol,
				result_id: receipt.result_id.try_into().map_err(ApiError::invalid)?,
				review_unit_id: receipt.review_unit_id.try_into().map_err(ApiError::invalid)?,
				assignment_epoch: receipt.assignment_epoch,
				disposition: receipt.disposition,
			})
		})?;
	state.job_arrived.notify_one();
	Ok(response)
}
