//! Storage-owned global selectors. Callers supply time, never selected row IDs.
use crate::{findings, jobs, repos, Db, Result};

pub fn schedule_due(db: &Db, now: i64) -> Result<usize> {
	db.with_conn(|conn| {
		crate::transaction::immediate(conn, |tx| {
			let mut enqueued = 0;
			for repo in repos::list_due_for_scan(tx, now)? {
				if jobs::count_active_scans_for_repo(tx, repo.id)? != 0 {
					continue;
				}
				jobs::enqueue_raw(
					tx,
					&jobs::NewJob {
						repo_id: repo.id,
						kind: loupe_core::JobKind::<loupe_provenance::Db>::Scan,
						incremental: repo.last_scanned_sha.is_some(),
						since_sha: repo.last_scanned_sha,
						parent_job_id: None,
						target_finding_id: None,
					},
					now,
				)?;
				enqueued += 1;
			}
			Ok(enqueued)
		})
	})
}

/// Preserve the lease reaper's independent legacy and per-campaign transactions.
pub fn reap_leases(db: &Db, now: i64) -> Result<usize> {
	db.with_conn(|conn| jobs::reap_stale_leases(conn, now))
}

pub fn reap_validating(db: &Db, now: i64) -> Result<usize> {
	db.with_conn(|conn| Ok(findings::reap_stale_validating(conn, now)?))
}
