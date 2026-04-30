//! Background tasks owned by the server: the scheduler that enqueues
//! due scans, and the reaper that reclaims expired job leases.
//!
//! Both run on the same tokio runtime as the axum handlers and shut
//! down via the same `CancellationToken` the serve loop uses, so the
//! server's `shutdown()` cleans them up too.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use loupe_core::JobKind;
use loupe_storage::jobs::{self, NewJob};
use loupe_storage::{findings, repos, Db};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// How often the scheduler checks for due repos. Operators with very
/// short scan intervals can shorten this; the default is fine for the
/// common case (intervals measured in minutes or hours).
pub const SCHEDULER_TICK: Duration = Duration::from_secs(30);

/// How often the reaper runs. Should be a small fraction of the lease
/// TTL so a stuck worker is reclaimed promptly.
pub const REAPER_TICK: Duration = Duration::from_secs(15);

fn now_secs() -> i64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

/// Scheduler tick: enqueue a scan job for each repo whose interval has
/// elapsed since `last_scanned_at`. Returns the number of jobs
/// enqueued. Exposed so tests can drive a tick directly without waiting
/// for a real timer.
pub fn schedule_due(db: &Db, now: i64) -> anyhow::Result<usize> {
	let due = db.with_conn(|c| Ok(repos::list_due_for_scan(c, now)?))?;
	let mut enqueued = 0;
	for repo in due {
		let since_sha = repo.last_scanned_sha.clone();
		// If a queued or leased scan already exists for this repo, skip
		// — we don't want to pile up duplicates.
		let pending: i64 = db.with_conn(|c| Ok(jobs::count_active_scans_for_repo(c, repo.id)?))?;
		if pending > 0 {
			tracing::debug!(repo = %repo.clone_url, "skipping due repo: prior scan still in flight");
			continue;
		}
		db.with_conn(|c| {
			Ok(jobs::enqueue(
				c,
				&NewJob {
					repo_id: repo.id,
					kind: JobKind::Scan,
					incremental: since_sha.is_some(),
					since_sha,
					parent_job_id: None,
					target_finding_id: None,
				},
				now,
			)?)
		})?;
		enqueued += 1;
		tracing::info!(repo = %repo.clone_url, "scheduler enqueued periodic scan");
	}
	Ok(enqueued)
}

/// Reaper tick: reclaim leases past their TTL. Re-queue if attempts <
/// MAX, fail otherwise. Wraps `loupe-storage::jobs::reap_stale_leases`.
pub fn reap_once(db: &Db, now: i64) -> anyhow::Result<usize> {
	let n = db.with_conn(|c| Ok(jobs::reap_stale_leases(c, now)?))?;
	if n > 0 {
		tracing::info!(reclaimed = n, "reaper transitioned stale leases");
	}
	// Same tick: dismiss findings whose validating_deadline has elapsed.
	// Stale validating findings sit invisible to the dispatcher (state
	// is 'validating', not 'confirmed') so without a reaper they'd
	// never escape their own state.
	let dismissed = db.with_conn(|c| Ok(findings::reap_stale_validating(c, now)?))?;
	if dismissed > 0 {
		tracing::info!(dismissed, "reaper dismissed stale validating findings");
	}
	Ok(n + dismissed)
}

/// Spawn the scheduler. Returns a JoinHandle so the caller can wait on
/// it during shutdown. Cancels cleanly when `cancel` fires. Pokes
/// `job_arrived` whenever it enqueues something so long-polling
/// workers wake immediately.
pub fn spawn_scheduler(
	db: std::sync::Arc<Db>, job_arrived: std::sync::Arc<Notify>, cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
	tokio::spawn(async move {
		let mut interval = tokio::time::interval(SCHEDULER_TICK);
		interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
		loop {
			tokio::select! {
				_ = cancel.cancelled() => return,
				_ = interval.tick() => {
					match schedule_due(&db, now_secs()) {
						Ok(0) => {},
						Ok(_) => job_arrived.notify_waiters(),
						Err(e) => tracing::warn!(error = %e, "scheduler tick failed"),
					}
				}
			}
		}
	})
}

/// Spawn the reaper. Same shape as [`spawn_scheduler`].
pub fn spawn_reaper(
	db: std::sync::Arc<Db>, cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
	tokio::spawn(async move {
		let mut interval = tokio::time::interval(REAPER_TICK);
		interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
		loop {
			tokio::select! {
				_ = cancel.cancelled() => return,
				_ = interval.tick() => {
					if let Err(e) = reap_once(&db, now_secs()) {
						tracing::warn!(error = %e, "reaper tick failed");
					}
				}
			}
		}
	})
}

#[cfg(test)]
mod tests {
	use loupe_core::ReportingDestination;
	use loupe_storage::repos::NewRepo;
	use loupe_storage::secrets::{self, SecretKind};
	use loupe_storage::workers::{self, WorkerKind};

	use super::*;

	fn fixture() -> (std::sync::Arc<Db>, i64, i64) {
		let db = std::sync::Arc::new(
			Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests()).unwrap(),
		);
		let secret_id =
			db.with_conn(|c| Ok(secrets::insert(c, SecretKind::GithubPat, "p", b"x", 0)?)).unwrap();
		let repo_id = db
			.with_conn(|c| {
				Ok(repos::insert(
					c,
					&NewRepo {
						clone_url: "https://github.com/a/b.git".into(),
						host: "github.com".into(),
						owner: "a".into(),
						repo: "b".into(),
						default_branch: None,
						scan_interval_seconds: Some(60),
						scanner_config: serde_json::Value::Null,
						reporting: ReportingDestination::GithubIssue {
							target_owner: "x".into(),
							target_repo: "y".into(),
							pat_secret_id: secret_id,
						},
						verification_enabled: false,
						require_approval: None,
					},
					0,
				)?)
			})
			.unwrap();
		let worker_id = db
			.with_conn(|c| Ok(workers::insert(c, "w1", WorkerKind::Worker, &[1u8; 32], 0)?))
			.unwrap();
		(db, repo_id, worker_id)
	}

	#[test]
	fn scheduler_enqueues_due_repos() {
		let (db, _repo_id, _) = fixture();
		// Repo just inserted, never scanned ⇒ due immediately.
		let n = schedule_due(&db, 1_000).unwrap();
		assert_eq!(n, 1);
		// A second tick must not double-enqueue (in-flight job).
		let n = schedule_due(&db, 1_000).unwrap();
		assert_eq!(n, 0);
	}

	#[test]
	fn reaper_reclaims_stale_leases() {
		let (db, repo_id, worker_id) = fixture();
		db.with_conn(|c| {
			Ok(jobs::enqueue(
				c,
				&NewJob {
					repo_id,
					kind: JobKind::Scan,
					incremental: false,
					since_sha: None,
					parent_job_id: None,
					target_finding_id: None,
				},
				0,
			)?)
		})
		.unwrap();
		// Lease at t=100 with TTL=10. Reap at t=200 ⇒ requeue.
		db.with_conn(|c| Ok(jobs::lease_next(c, worker_id, false, 100, 10)?)).unwrap();
		let n = reap_once(&db, 200).unwrap();
		assert_eq!(n, 1);
	}
}
