//! Drilldown HTTP admission and bounded responses; storage owns finalization.
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Extension;
use loupe_proto::review_api::ReviewProtocol;
use loupe_proto::review_drilldown::{self as wire, FinalizeDrilldownRequestDecoder};
use loupe_provenance::Db;
use loupe_storage::review_authority::{self as stored, DrilldownFinalization};

use crate::auth::AuthedWorker;
use crate::ingress::WorkerBody;
use crate::review::authority::{self, Access, Phase};
use crate::review::http::{self, ApiError, Result};
use crate::AppState;

pub const REQUEST_CAP: usize = 512 * 1024;
pub const RESPONSE_CAP: usize = 16 * 1024;

fn reply(value: DrilldownFinalization) -> Result<wire::DrilldownTerminalResponse<Db>> {
	let summary = value.summary;
	let continuation = summary.continuation.map(crate::review::terminal::continuation);
	Ok(wire::DrilldownTerminalResponse {
		protocol_version: ReviewProtocol,
		receipt: wire::DrilldownReceipt {
			receipt_id: value.receipt_id.try_into().map_err(ApiError::invalid)?,
			job_id: value.job_id.try_into().map_err(ApiError::invalid)?,
			commit_sha: value.commit,
			result_digest: value.result_digest,
			summary: wire::DrilldownSummary {
				version: summary.version,
				lead_id: summary.lead_id.try_into().map_err(ApiError::invalid)?,
				disposition: match summary.disposition {
					stored::DrilldownDisposition::Promoted => wire::DrilldownDisposition::Promoted,
					stored::DrilldownDisposition::Rejected => wire::DrilldownDisposition::Rejected,
					stored::DrilldownDisposition::Duplicate => {
						wire::DrilldownDisposition::Duplicate
					},
					stored::DrilldownDisposition::Hardening => {
						wire::DrilldownDisposition::Hardening
					},
					stored::DrilldownDisposition::Deferred => wire::DrilldownDisposition::Deferred,
				},
				promoted_finding_id: summary
					.promoted_finding_id
					.map(TryInto::try_into)
					.transpose()
					.map_err(ApiError::invalid)?,
				continuation,
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
		Error::Conflict(Conflict::FindingIdentity(_)) => {
			ApiError::conflict("finding_identity_conflict")
		},
		Error::Conflict(Conflict::CompatibilityKey(_)) => {
			ApiError::conflict("compatibility_key_conflict")
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
		.validate_carrying(FinalizeDrilldownRequestDecoder)
		.map_err(ApiError::invalid)?;
	let response = http::transaction(&state.db, &worker, &headers, job, RESPONSE_CAP, |tx| {
		let value = tx
			.finalize_drilldown(&request.payload, |context| {
				authority::policy(Phase::Drilldown, Access::Domain, context)
			})
			.map_err(error)?;
		reply(value)
	})?;
	state.job_arrived.notify_waiters();
	Ok(response)
}
