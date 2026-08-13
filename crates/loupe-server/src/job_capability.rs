use axum::http::{HeaderMap, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use loupe_proto::{JobCapability, JOB_CAPABILITY_HEADER, JOB_CAPABILITY_TOKEN_CHARS};
use loupe_storage::jobs::{self, JobRow};
use rand_core::{OsRng, RngCore};

use crate::auth::AuthedWorker;
use crate::state::AppState;

pub(crate) struct AuthorizedJob {
	pub row: JobRow,
	pub capability_hash: [u8; 32],
}

impl AuthorizedJob {
	pub(crate) fn lease_identity(&self, worker_id: i64) -> jobs::LeaseIdentity<'_> {
		jobs::LeaseIdentity {
			job_id: self.row.id,
			worker_id,
			capability_hash: &self.capability_hash,
		}
	}

	pub(crate) fn active_lease(&self, worker_id: i64, now: i64) -> jobs::ActiveLease<'_> {
		jobs::ActiveLease { identity: self.lease_identity(worker_id), now }
	}
}

pub(crate) fn issue() -> (JobCapability, [u8; 32]) {
	let mut random = [0u8; 32];
	OsRng.fill_bytes(&mut random);
	let token = URL_SAFE_NO_PAD.encode(random);
	let hash = *blake3::hash(token.as_bytes()).as_bytes();
	(JobCapability::from_secret(token), hash)
}

pub(crate) fn authorize(
	state: &AppState, worker: &AuthedWorker, headers: &HeaderMap, now: i64,
) -> Result<AuthorizedJob, (StatusCode, String)> {
	let token = headers
		.get(JOB_CAPABILITY_HEADER)
		.and_then(|value| value.to_str().ok())
		.filter(|value| value.len() == JOB_CAPABILITY_TOKEN_CHARS)
		.ok_or_else(forbidden)?;
	let capability_hash = *blake3::hash(token.as_bytes()).as_bytes();
	let row = state
		.db
		.with_conn(|conn| {
			Ok(jobs::get_active_by_capability_hash(conn, worker.id(), &capability_hash, now)?)
		})
		.map_err(|error| {
			(StatusCode::INTERNAL_SERVER_ERROR, format!("authorize job capability: {error}"))
		})?
		.ok_or_else(forbidden)?;
	Ok(AuthorizedJob { row, capability_hash })
}

pub(crate) fn authorize_for_job(
	state: &AppState, worker: &AuthedWorker, headers: &HeaderMap, job_id: i64, now: i64,
) -> Result<AuthorizedJob, (StatusCode, String)> {
	let authorized = authorize(state, worker, headers, now)?;
	if authorized.row.id != job_id {
		return Err(forbidden());
	}
	Ok(authorized)
}

pub(crate) fn forbidden() -> (StatusCode, String) {
	(StatusCode::FORBIDDEN, "invalid or expired job capability".into())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn issued_tokens_match_the_length_authorize_filters_on() {
		// `authorize` rejects anything of a different length before it
		// hashes, so widening the random token without widening the
		// filter would reject every capability the server just issued.
		let (token, _) = issue();
		assert_eq!(token.expose_secret().len(), JOB_CAPABILITY_TOKEN_CHARS);
	}
}
