//! Independent inventory updates under storage-owned phase authority.
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Extension;
use loupe_proto::review_api::ReviewProtocol;
use loupe_proto::review_inventory::{
	Disposition, InventoryDispositionRequestDecoder, InventoryDispositionResponse,
	MAX_REQUEST_BYTES,
};
use loupe_storage::{inventory, inventory_disposition as stored};

use crate::auth::AuthedWorker;
use crate::ingress::WorkerBody;
use crate::review::authority::{self, Access, Phase};
use crate::review::http::{self, ApiError};
use crate::AppState;

pub const REQUEST_CAP: usize = MAX_REQUEST_BYTES;
pub const RESPONSE_CAP: usize = 8192;

pub async fn submit(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, headers: HeaderMap, body: WorkerBody,
) -> http::Result<Response> {
	let body = http::body(&headers, body, REQUEST_CAP)?;
	let request = body
		.0
		.as_bytes()
		.validate(InventoryDispositionRequestDecoder)
		.map_err(ApiError::invalid)?;
	let digest = request.digest().map_err(ApiError::invalid)?;
	let mappings = request
		.mappings
		.as_slice()
		.iter()
		.map(|mapping| {
			Ok(stored::Mapping {
				unit_id: i64::from(mapping.review_unit_id),
				assignment_epoch: i64::try_from(mapping.assignment_epoch)
					.map_err(ApiError::invalid)?,
			})
		})
		.collect::<http::Result<Vec<_>>>()?;
	let disposition = match request.disposition {
		Disposition::Mapped => inventory::Disposition::Mapped,
		Disposition::Context => inventory::Disposition::Context,
		Disposition::Excluded => inventory::Disposition::Excluded,
		Disposition::Unresolved => inventory::Disposition::Unresolved,
	};
	http::transaction(&state.db, &worker, &headers, job, RESPONSE_CAP, |tx| {
		let scope = authority::authorize(tx, Phase::Survey, Access::Domain)?
			.ok_or_else(ApiError::denied)?;
		let receipt = scope.submit_inventory_disposition(&stored::Submission {
			key: &request.client_inventory_disposition_key,
			path: &request.source_path,
			digest: &digest,
			expected_revision: request.expected_revision,
			disposition,
			reason: request.reason.as_ref(),
			mappings: &mappings,
		})?;
		Ok(InventoryDispositionResponse {
			protocol_version: ReviewProtocol,
			inventory_entry_id: receipt.inventory_entry_id.try_into().map_err(ApiError::invalid)?,
			revision: receipt.revision,
		})
	})
}
