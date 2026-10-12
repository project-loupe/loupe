use axum::http::{HeaderMap, HeaderValue, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use loupe_core::{JobKind, JobState};
use loupe_proto::{JobCapability, JOB_CAPABILITY_HEADER, JOB_CAPABILITY_TOKEN_CHARS};
use loupe_provenance::Zeroise;
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
	let token = JobCapability::from_secret(URL_SAFE_NO_PAD.encode(random.as_slice()));
	random.zeroise();
	let hash = *blake3::hash(token.expose_secret().as_bytes()).as_bytes();
	(token, hash)
}

/// Parse the capability header without requiring a live lease.
pub fn parse_hash(headers: &HeaderMap) -> Result<[u8; 32], (StatusCode, String)> {
	parse_capability(headers).ok_or_else(forbidden)
}

pub(crate) fn parse_capability(headers: &HeaderMap) -> Option<[u8; 32]> {
	parse_capability_value(headers.get(JOB_CAPABILITY_HEADER))
}

pub(crate) fn parse_capability_value(value: Option<&HeaderValue>) -> Option<[u8; 32]> {
	let token = value
		.and_then(|value| value.to_str().ok())
		.filter(|value| value.len() == JOB_CAPABILITY_TOKEN_CHARS)?;
	Some(hash_capability(token.as_bytes()))
}

fn hash_capability(token: &[u8]) -> [u8; 32] {
	*blake3::hash(token).as_bytes()
}

pub(crate) struct LeaseFacts {
	pub worker_id: Option<i64>,
	pub capability_hash: [u8; 32],
	pub lease_expires_at: Option<i64>,
	pub state: JobState,
}

pub(crate) fn capability_admits(
	row: &LeaseFacts, caller_worker: i64, hash: &[u8; 32], now: i64,
) -> bool {
	row.worker_id == Some(caller_worker)
		&& row.capability_hash == *hash
		&& row.state == JobState::Leased
		&& row.lease_expires_at.is_some_and(|expiry| now <= expiry)
}

pub(crate) fn legacy_kind(kind: &JobKind) -> bool {
	matches!(kind, JobKind::Scan | JobKind::Verify)
}

pub(crate) fn authorize(
	state: &AppState, worker: &AuthedWorker, headers: &HeaderMap, now: i64,
) -> Result<AuthorizedJob, (StatusCode, String)> {
	let capability_hash = parse_hash(headers)?;
	let row = state
		.db
		.with_conn(|conn| {
			Ok(jobs::get_active_by_capability_hash(conn, worker.id(), &capability_hash, now)?)
		})
		.map_err(|error| {
			(StatusCode::INTERNAL_SERVER_ERROR, format!("authorize job capability: {error}"))
		})?
		.ok_or_else(forbidden)?;
	// SQL established hash equality in the same lookup. JobRow does not
	// retain the secret hash; the remaining facts come from the returned row.
	let facts = LeaseFacts {
		worker_id: row.worker_id,
		capability_hash,
		lease_expires_at: row.lease_expires_at,
		state: row.state,
	};
	if !capability_admits(&facts, worker.id(), &capability_hash, now) {
		return Err(forbidden());
	}
	Ok(AuthorizedJob { row, capability_hash })
}

pub(crate) fn authorize_for_job(
	state: &AppState, worker: &AuthedWorker, headers: &HeaderMap, job_id: i64, now: i64,
) -> Result<AuthorizedJob, (StatusCode, String)> {
	let authorized = authorize(state, worker, headers, now)?;
	if authorized.row.id != job_id || !legacy_kind(&authorized.row.kind) {
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

#[cfg(test)]
mod decision_tests {
	use axum::http::HeaderValue;

	use super::*;

	#[test]
	fn capability_facts_require_every_lease_condition() {
		let mut facts = LeaseFacts {
			worker_id: Some(7),
			capability_hash: [9; 32],
			lease_expires_at: Some(10),
			state: JobState::Leased,
		};
		assert!(capability_admits(&facts, 7, &[9; 32], 10));
		assert!(capability_admits(&facts, 7, &[9; 32], 9));
		assert!(!capability_admits(&facts, 7, &[9; 32], 11));
		assert!(!capability_admits(&facts, 8, &[9; 32], 10));
		for index in 0..32 {
			let mut wrong = [9; 32];
			wrong[index] ^= 1;
			assert!(!capability_admits(&facts, 7, &wrong, 10));
		}
		facts.worker_id = None;
		assert!(!capability_admits(&facts, 7, &[9; 32], 10));
		facts.worker_id = Some(7);
		facts.lease_expires_at = None;
		assert!(!capability_admits(&facts, 7, &[9; 32], 10));
		facts.lease_expires_at = Some(10);
		for state in [JobState::Queued, JobState::Succeeded, JobState::Failed, JobState::Cancelled]
		{
			facts.state = state;
			assert!(!capability_admits(&facts, 7, &[9; 32], 10));
		}
	}

	#[test]
	fn capability_header_requires_text_of_exact_length_and_hashes_all_bytes() {
		assert!(parse_capability(&HeaderMap::new()).is_none());
		for len in [0, 42, 43, 44] {
			for byte in [b'a', b' ', b'\t', 0x80] {
				let bytes = vec![byte; len];
				let mut headers = HeaderMap::new();
				headers.insert(JOB_CAPABILITY_HEADER, HeaderValue::from_bytes(&bytes).unwrap());
				let expected = if len == 43 && byte != 0x80 {
					Some(*blake3::hash(&bytes).as_bytes())
				} else {
					None
				};
				assert_eq!(parse_capability(&headers), expected, "length {len}, byte {byte}");
			}
		}
	}

	#[test]
	fn legacy_authority_rejects_every_phase_or_unknown_kind() {
		for (kind, expected) in [
			(JobKind::Scan, true),
			(JobKind::Verify, true),
			(JobKind::Survey, false),
			(JobKind::Drilldown, false),
			(JobKind::Unknown("scan".into()), false),
		] {
			assert_eq!(legacy_kind(&kind), expected);
		}
	}
}
