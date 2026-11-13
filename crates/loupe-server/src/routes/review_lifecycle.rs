//! Identity-only shared-route dispatch. The precheck selects transport only;
//! mutation reauthorizes under a fresh IMMEDIATE transaction and clock.
use axum::extract::{FromRequest, Path, Request, State};
use axum::handler::Handler;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use loupe_proto::review_api::ReviewProtocol;
use loupe_proto::review_lifecycle::{
	PhaseControlResponse, PhaseControlState, PhaseFailureRequestDecoder,
	PhaseHeartbeatRequestDecoder,
};
use loupe_proto::{HeartbeatResponse, PROTOCOL_VERSION};
use loupe_storage::{phase_lifecycle, scheduler, scope};

use crate::auth::AuthedWorker;
use crate::ingress::WorkerBody;
use crate::review::authority::{self, Access, Phase};
use crate::review::http::{self, ApiError};
use crate::AppState;

/// Caps of the phase transport; legacy jobs keep the shared-route limits.
pub const COMPLETE_REQUEST_CAP: usize = 8192;
pub const COMPLETE_RESPONSE_CAP: usize = 8192;
pub const HEARTBEAT_REQUEST_CAP: usize = 8192;
pub const HEARTBEAT_RESPONSE_CAP: usize = 8192;
/// Cancellation never reads the body on the phase path.
pub const CANCEL_RESPONSE_CAP: usize = 8192;

fn now() -> i64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
		as i64
}
fn phase_lease(
	state: &AppState, worker: &AuthedWorker, headers: &HeaderMap, job: i64,
) -> http::Result<Option<Phase>> {
	Ok(authority::with_transaction(&state.db, worker, headers, job, now, |tx| {
		for phase in [Phase::Survey, Phase::Drilldown, Phase::Verify] {
			if authority::authorize(tx, phase, Access::LeaseControl)?.is_some() {
				return Ok::<_, loupe_storage::Error>(Some(phase));
			}
		}
		Ok(None)
	})?
	.flatten())
}
pub async fn complete(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, request: Request,
) -> Response {
	match phase_lease(&state, &worker, request.headers(), job) {
		Ok(Some(phase)) => failure(state, worker, job, phase, request).await.into_response(),
		Ok(None) => super::jobs::complete.call(request, state).await,
		Err(error) => error.into_response(),
	}
}
async fn failure(
	state: AppState, worker: AuthedWorker, job: i64, phase: Phase, request: Request,
) -> http::Result<Response> {
	let headers = request.headers().clone();
	let body = WorkerBody::from_request(request, &state)
		.await
		.map_err(|(status, _)| ApiError::new(status, "invalid_request"))?;
	let body = http::body(&headers, body, COMPLETE_REQUEST_CAP)?;
	let request =
		body.0.as_bytes().validate(PhaseFailureRequestDecoder).map_err(ApiError::invalid)?;
	let response =
		http::transaction(&state.db, &worker, &headers, job, COMPLETE_RESPONSE_CAP, |tx| {
			let scope = authority::authorize(tx, phase, Access::LeaseControl)?
				.ok_or_else(ApiError::denied)?;
			let outcome = scope.retry_failure(request.error.as_ref())?;
			let (state, eligible_at) = match outcome {
				scheduler::RetryOutcome::Failed => (PhaseControlState::Failed, None),
				scheduler::RetryOutcome::Requeued { eligible_at } => {
					(PhaseControlState::Queued, Some(eligible_at))
				},
			};
			Ok(PhaseControlResponse {
				protocol_version: ReviewProtocol,
				job_id: job.try_into().map_err(ApiError::invalid)?,
				state,
				eligible_at,
			})
		})?;
	state.job_arrived.notify_waiters();
	Ok(response)
}
pub async fn heartbeat(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, request: Request,
) -> Response {
	match phase_lease(&state, &worker, request.headers(), job) {
		Ok(Some(phase)) => {
			phase_heartbeat(state, worker, job, phase, request).await.into_response()
		},
		Ok(None) => super::jobs::heartbeat.call(request, state).await,
		Err(error) => error.into_response(),
	}
}
async fn phase_heartbeat(
	state: AppState, worker: AuthedWorker, job: i64, phase: Phase, request: Request,
) -> http::Result<Response> {
	let headers = request.headers().clone();
	let body = WorkerBody::from_request(request, &state)
		.await
		.map_err(|(status, _)| ApiError::new(status, "invalid_request"))?;
	let body = http::body(&headers, body, HEARTBEAT_REQUEST_CAP)?;
	body.0.as_bytes().validate(PhaseHeartbeatRequestDecoder).map_err(ApiError::invalid)?;
	http::transaction(&state.db, &worker, &headers, job, HEARTBEAT_RESPONSE_CAP, |tx| {
		let scope =
			authority::authorize(tx, phase, Access::LeaseControl)?.ok_or_else(ApiError::denied)?;
		let lease_expires_at = scope.heartbeat(
			state.review_policy.lease_seconds,
			state.review_policy.lease_report_grace_seconds,
		)?;
		Ok(HeartbeatResponse { protocol_version: PROTOCOL_VERSION, lease_expires_at })
	})
}
/// This is exclusively the operator route. All fallible response encoding is
/// complete before cancellation; no worker scope or domain payload is decoded.
pub async fn cancel(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(operator): Extension<AuthedWorker>, request: Request,
) -> Response {
	let result = (|| {
		let operator = operator.require_operator().map_err(|_| ApiError::denied())?;
		// Historical legacy rows can have nonpositive SQLite IDs. Delay the
		// phase-only identity requirement until scoped dispatch knows the kind.
		let response = job
			.try_into()
			.ok()
			.map(|job_id| {
				http::response(
					&PhaseControlResponse {
						protocol_version: ReviewProtocol,
						job_id,
						state: PhaseControlState::Cancelled,
						eligible_at: None,
					},
					CANCEL_RESPONSE_CAP,
				)
			})
			.transpose()?;
		let phase = scope::with_operator_repository(
			&state.db,
			&operator,
			scope::OperatorTarget::Job(job),
			|scope| {
				let phase = phase_lifecycle::cancel(scope, job, now())?;
				if phase && response.is_none() {
					// An unrepresentable phase response must roll back both the
					// cancellation and assigned-work changes before commit.
					return Err(loupe_storage::Error::Conflict(loupe_storage::Conflict::JobState));
				}
				Ok(phase)
			},
		)
		.map_err(|error| match error {
			loupe_storage::Error::NotFound(loupe_storage::Entity::Job, missing)
				if missing == job =>
			{
				ApiError::new(StatusCode::NOT_FOUND, "not_found")
			},
			error => ApiError::from(error),
		})?;
		Ok::<_, ApiError>(if phase { response } else { None })
	})();
	match result {
		Ok(Some(response)) => response,
		Ok(None) => super::jobs::cancel.call(request, state).await,
		Err(error) => error.into_response(),
	}
}
