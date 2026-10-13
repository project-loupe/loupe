//! Server entry point for worker claims; all fairness state lives in storage.
use loupe_core::JobKind;
use loupe_storage::scheduler::{self, ClaimRequest, ClaimedLease};
use loupe_storage::Result;

use crate::state::AppState;

pub fn claim_for_worker<S: loupe_provenance::Source>(
	state: &AppState, worker_id: i64, kinds: &[JobKind<S>], now: i64, hash: &[u8],
) -> Result<Option<ClaimedLease>> {
	scheduler::claim(
		&state.db,
		&ClaimRequest {
			worker_id,
			kinds,
			now,
			capability_hash: hash,
			legacy_lease_seconds: loupe_storage::jobs::DEFAULT_LEASE_SECONDS,
			policy: &state.review_policy.claim_policy(),
		},
	)
}
