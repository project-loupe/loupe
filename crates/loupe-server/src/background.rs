//! Background tasks owned by the server: the scheduler that enqueues
//! due scans, and the reaper that reclaims expired job leases.
//!
//! Both run on the same tokio runtime as the axum handlers and shut
//! down via the same `CancellationToken` the serve loop uses, so the
//! server's `shutdown()` cleans them up too.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(test)]
use loupe_core::JobKind;
#[cfg(test)]
use loupe_storage::jobs;
use loupe_storage::Db;
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
	let enqueued = loupe_storage::maintenance::schedule_due(db, now)?;
	if enqueued != 0 {
		tracing::info!(enqueued, "scheduler enqueued periodic scans");
	}
	Ok(enqueued)
}

/// Reaper tick: reclaim leases past their TTL. Re-queue if attempts <
/// MAX, fail otherwise. Wraps `loupe-storage::jobs::reap_stale_leases`.
pub fn reap_once(db: &Db, now: i64) -> anyhow::Result<usize> {
	let n = loupe_storage::maintenance::reap_leases(db, now)?;
	if n > 0 {
		tracing::info!(reclaimed = n, "reaper transitioned stale leases");
	}
	// Same tick: dismiss findings whose validating_deadline has elapsed.
	// Stale validating findings sit invisible to the dispatcher (state
	// is 'validating', not 'confirmed') so without a reaper they'd
	// never escape their own state.
	let dismissed = loupe_storage::maintenance::reap_validating(db, now)?;
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
					let now = now_secs();
					match schedule_due(&db, now) {
						Ok(0) => {},
						Ok(_) => job_arrived.notify_waiters(),
						Err(e) => tracing::warn!(error = %e, "scheduler tick failed"),
					}
					match crate::review::campaign::tick(&db, now) {
						Ok(report) if report.enqueued > 0 => job_arrived.notify_waiters(),
						Ok(_) => {},
						Err(e) => tracing::warn!(error = %e, "campaign scheduler tick failed"),
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

	use super::*;

	fn fixture() -> (std::sync::Arc<Db>, i64, i64) {
		let db = std::sync::Arc::new(
			Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests()).unwrap(),
		);
		let loupe_storage::registry::ReportingWrite::Done(repo_id) =
			loupe_storage::registry::register_repository(
				&db,
				&crate::test_support::operator(),
				&NewRepo {
					clone_url: crate::test_support::text("https://github.com/a/b.git"),
					host: crate::test_support::text("github.com"),
					owner: crate::test_support::text("a"),
					repo: crate::test_support::text("b"),
					default_branch: None,
					scan_interval_seconds: Some(60),
					scanner_config: crate::test_support::scanner(serde_json::Value::Null),
					reporting: ReportingDestination::GithubIssue {
						target_owner: crate::test_support::text("x"),
						target_repo: crate::test_support::text("y"),
						pat_secret_id: None,
					},
					verification_enabled: false,
					require_approval: None,
				},
				Some(&loupe_provenance::Secret::new("x".into())),
				0,
			)
			.unwrap()
		else {
			panic!("PAT registration")
		};
		let worker_id = loupe_storage::registry::register_worker(
			&db,
			&crate::test_support::operator(),
			&crate::test_support::text("w1"),
			&[1u8; 32],
			0,
		)
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
		loupe_storage::scope::with_operator_repository(
			&db,
			&crate::test_support::operator(),
			loupe_storage::scope::OperatorTarget::Repository(repo_id),
			|scope| {
				jobs::enqueue(
					scope,
					&jobs::QueuedJob {
						kind: JobKind::<loupe_provenance::Db>::Scan,
						incremental: false,
						since_sha: None,
						parent_job_id: None,
						target_finding_id: None,
					},
					0,
				)
			},
		)
		.unwrap();
		// Lease at t=100 with TTL=10. Reap at t=200 ⇒ requeue.
		loupe_storage::scheduler::claim(
			&db,
			&loupe_storage::scheduler::ClaimRequest {
				worker_id,
				kinds: &[JobKind::<loupe_provenance::Db>::Scan],
				now: 100,
				legacy_lease_seconds: 10,
				capability_hash: &[1; 32],
				policy: &loupe_storage::scheduler::ClaimPolicy::default(),
			},
		)
		.unwrap();
		let n = reap_once(&db, 200).unwrap();
		assert_eq!(n, 1);
	}
}
