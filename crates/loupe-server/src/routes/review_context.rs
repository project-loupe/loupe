//! Bounded worker context. Candidate reads durably issue narrowly scoped IDs.
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Uri};
use axum::response::Response;
use axum::Extension;
use loupe_proto::review_api::{
	CandidatesResponse, Capacity, PhaseLimitsResponse, ReviewProtocol, TokenCapacity, Unavailable,
	UnknownSpend,
};
use loupe_proto::review_lease::LeaseList;
use loupe_storage::review_authority::{CapacitySnapshot, LimitsSnapshot};

use crate::auth::AuthedWorker;
use crate::ingress::WorkerBody;
use crate::review::authority::{self, Access, Phase};
use crate::review::http::{self, ApiError};
use crate::AppState;

/// Context GETs accept no body at all; see `http::no_body`.
pub const LIMITS_RESPONSE_CAP: usize = 8192;
pub const CANDIDATES_RESPONSE_CAP: usize = 64 * 1024;

pub async fn limits(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, headers: HeaderMap, uri: Uri, body: WorkerBody,
) -> http::Result<Response> {
	http::no_body(&headers, body)?;
	if uri.query().is_some_and(|query| !query.is_empty()) {
		return Err(ApiError::invalid("limits has no query parameters"));
	}
	http::transaction(&state.db, &worker, &headers, job, LIMITS_RESPONSE_CAP, |tx| {
		for phase in [Phase::Survey, Phase::Drilldown, Phase::Verify] {
			if let Some(scope) = authority::authorize(tx, phase, Access::Checkout)? {
				return Ok(limits_response(scope.limits_snapshot()?));
			}
		}
		Err(ApiError::denied())
	})
}

fn limits_response(snapshot: LimitsSnapshot) -> PhaseLimitsResponse {
	let capacity =
		|value: CapacitySnapshot| Capacity { limit: value.limit, remaining: value.remaining };
	PhaseLimitsResponse {
		protocol_version: ReviewProtocol,
		soft_deadline_at: snapshot.soft_deadline_at,
		submit_by: snapshot.submit_by,
		hard_deadline_at: snapshot.hard_deadline_at,
		remaining_seconds: snapshot.remaining_seconds,
		new_units: capacity(snapshot.new_units),
		leads: capacity(snapshot.leads),
		siblings: capacity(snapshot.siblings),
		candidate_queries: capacity(snapshot.candidate_queries),
		campaign_jobs_limit: snapshot.campaign_jobs_limit,
		campaign_jobs_admitted: snapshot.campaign_jobs_admitted,
		campaign_general_remaining: snapshot.campaign_general_remaining,
		campaign_urgent_remaining: snapshot.campaign_urgent_remaining,
		campaign_verification_remaining: snapshot.campaign_verification_remaining,
		proof_capacity: Unavailable::Unavailable,
		artifact_capacity: Unavailable::Unavailable,
		output_capacity: Unavailable::Unavailable,
		tokens: snapshot.token_budget.map_or(TokenCapacity::None, |limit| {
			TokenCapacity::HostEnforced { limit, spent: UnknownSpend::Unknown }
		}),
	}
}

pub async fn candidates(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, headers: HeaderMap, uri: Uri, body: WorkerBody,
) -> http::Result<Response> {
	http::no_body(&headers, body)?;
	let query = crate::ingress::review_context::candidates(&worker, &uri)?;
	http::transaction(&state.db, &worker, &headers, job, CANDIDATES_RESPONSE_CAP, |tx| {
		for phase in [Phase::Survey, Phase::Drilldown] {
			if let Some(scope) = authority::authorize(tx, phase, Access::Domain)? {
				return Ok(CandidatesResponse {
					protocol_version: ReviewProtocol,
					candidates: LeaseList::new(scope.issue_candidates(&query)?)
						.map_err(ApiError::invalid)?,
				});
			}
		}
		Err(ApiError::denied())
	})
}
