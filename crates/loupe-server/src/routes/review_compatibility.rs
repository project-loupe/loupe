//! Destructive derived-state reset, with storage-owned authority and rollback.
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Request, State};
use axum::response::Response;
use axum::Extension;
use loupe_proto::review_api::ReviewProtocol;
use loupe_proto::review_compatibility::ResetGenerationResponse;

use crate::auth::AuthedWorker;
use crate::review::http::{self, ApiError};
use crate::AppState;

pub const RESET_REQUEST_CAP: usize = crate::ingress::review_compatibility::LIMIT;
pub const RESET_RESPONSE_CAP: usize = 4096;

pub async fn reset(
	State(state): State<AppState>, Path(generation): Path<i64>,
	Extension(admin): Extension<AuthedWorker>, request: Request,
) -> http::Result<Response> {
	let _ = crate::ingress::review_compatibility::reset(request).await?;
	let operator = admin.operator_ingress().ok_or_else(ApiError::denied)?;
	loupe_storage::review_compatibility::reset(
		&state.db,
		&operator,
		admin.id(),
		generation,
		|| SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64,
		|summary| {
			http::response(
				&ResetGenerationResponse {
					protocol_version: ReviewProtocol,
					inventory_entries_removed: summary.inventory_entries_removed,
					review_units_removed: summary.review_units_removed,
					leads_removed: summary.leads_removed,
					verification_intents_blocked: summary.verification_intents_blocked,
				},
				RESET_RESPONSE_CAP,
			)
		},
	)
}
