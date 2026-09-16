//! Server entry point for worker claims; all fairness state lives in storage.
use loupe_core::JobKind;
use loupe_storage::scheduler::{self, ClaimRequest, Claimed};
use loupe_storage::{transaction, Result};

use crate::state::AppState;

pub fn claim_for_worker(
	state: &AppState, worker_id: i64, kinds: &[JobKind], now: i64, hash: &[u8],
) -> Result<Option<Claimed>> {
	state.db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			scheduler::claim(
				tx,
				&ClaimRequest {
					worker_id,
					kinds,
					now,
					capability_hash: hash,
					legacy_lease_seconds: loupe_storage::jobs::DEFAULT_LEASE_SECONDS,
					policy: &state.review_policy.claim_policy(),
				},
			)
		})
	})
}
