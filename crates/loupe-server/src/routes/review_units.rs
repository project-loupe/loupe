//! Source-retaining survey proposals under storage-owned phase authority.
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Extension;
use loupe_proto::review_api::ReviewProtocol;
use loupe_proto::review_units::{PriorityBand, ReviewUnitRequestDecoder, ReviewUnitResponse};
use loupe_storage::review_authority::UnitProposal;
use loupe_storage::review_units::Priority;

use crate::auth::AuthedWorker;
use crate::ingress::WorkerBody;
use crate::review::authority::{self, Access, Phase};
use crate::review::http::{self, ApiError};
use crate::AppState;

pub const REQUEST_CAP: usize = 256 * 1024;
pub const RESPONSE_CAP: usize = 8192;

pub async fn submit(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, headers: HeaderMap, body: WorkerBody,
) -> http::Result<Response> {
	let body = http::body(&headers, body, REQUEST_CAP)?;
	let request =
		body.0.as_bytes().validate_carrying(ReviewUnitRequestDecoder).map_err(ApiError::invalid)?;
	let digest = request.digest().map_err(ApiError::invalid)?;
	let dependencies = request
		.depends_on_review_unit_ids
		.as_slice()
		.iter()
		.map(|id| i64::from(*id))
		.collect::<Vec<_>>();
	let priority_band = match request.priority_band {
		PriorityBand::Urgent => Priority::Urgent,
		PriorityBand::High => Priority::High,
		PriorityBand::Normal => Priority::Normal,
		PriorityBand::Background => Priority::Background,
	};
	http::transaction(&state.db, &worker, &headers, job, RESPONSE_CAP, |tx| {
		let scope = authority::authorize(tx, Phase::Survey, Access::Domain)?
			.ok_or_else(ApiError::denied)?;
		let receipt = scope.submit_review_unit(&UnitProposal {
			key: &request.client_review_unit_key,
			digest: &digest,
			title: &request.title,
			objective: &request.objective,
			priority_band,
			priority_rationale: request.priority_rationale.as_ref(),
			source_refs: request.source_refs.as_slice(),
			dependencies: &dependencies,
			closure_criteria: request.closure_criteria.as_ref(),
			semantic_context: request.semantic_context.as_ref(),
		})?;
		Ok(ReviewUnitResponse {
			protocol_version: ReviewProtocol,
			review_unit_id: receipt.review_unit_id.try_into().map_err(ApiError::invalid)?,
			assignment_epoch: receipt.assignment_epoch,
			accepted_priority_band: PriorityBand::Normal,
		})
	})
}
