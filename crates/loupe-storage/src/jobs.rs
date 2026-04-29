//! DAO for the `jobs` table — including the atomic
//! `queued → leased` transition that backs `POST /v1/jobs/lease`.
//!
//! State strings match `loupe-core::JobState::as_str` /
//! `JobKind::as_str` exactly so callers can shuttle them through SQL
//! without having to define their own constants.

use loupe_core::{JobKind, JobState};
use rusqlite::{params, Connection, OptionalExtension};

/// Lease lifetime in seconds. Worker must heartbeat or complete before
/// `lease_expires_at` or the reaper will reclaim the job.
pub const DEFAULT_LEASE_SECONDS: i64 = 600;

/// Cap on retry attempts. After this many leases-then-failures, the job
/// is moved to `failed` rather than back to `queued`.
pub const MAX_ATTEMPTS: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRow {
	pub id: i64,
	pub repo_id: i64,
	pub kind: JobKind,
	pub state: JobState,
	pub incremental: bool,
	pub since_sha: Option<String>,
	pub head_sha: Option<String>,
	pub parent_job_id: Option<i64>,
	pub target_finding_id: Option<i64>,
	pub worker_id: Option<i64>,
	pub lease_expires_at: Option<i64>,
	pub attempts: u32,
	pub enqueued_at: i64,
	pub started_at: Option<i64>,
	pub finished_at: Option<i64>,
	pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewJob {
	pub repo_id: i64,
	pub kind: JobKind,
	pub incremental: bool,
	pub since_sha: Option<String>,
	pub parent_job_id: Option<i64>,
	pub target_finding_id: Option<i64>,
}

/// Insert a `queued` job, returning the new id.
pub fn enqueue(conn: &Connection, new: &NewJob, now: i64) -> rusqlite::Result<i64> {
	conn.execute(
		"INSERT INTO jobs
		   (repo_id, kind, state, incremental, since_sha,
		    parent_job_id, target_finding_id, enqueued_at)
		 VALUES (?1, ?2, 'queued', ?3, ?4, ?5, ?6, ?7)",
		params![
			new.repo_id,
			new.kind.as_str(),
			new.incremental as i64,
			new.since_sha,
			new.parent_job_id,
			new.target_finding_id,
			now,
		],
	)?;
	Ok(conn.last_insert_rowid())
}

/// Lease the next queued job. Atomic: a single `UPDATE … WHERE state =
/// 'queued' … RETURNING` flips one row to `leased` and hands it back, so
/// two concurrent workers can't race the same job.
///
/// Returns `Ok(None)` if the queue is empty. Increments `attempts` and
/// stamps `worker_id`, `lease_expires_at`, `started_at`.
pub fn lease_next(
	conn: &Connection, worker_id: i64, now: i64, lease_seconds: i64,
) -> rusqlite::Result<Option<JobRow>> {
	let lease_until = now + lease_seconds;
	let mut stmt = conn.prepare(
		"UPDATE jobs
		   SET state = 'leased',
		       worker_id = ?1,
		       lease_expires_at = ?2,
		       attempts = attempts + 1,
		       started_at = COALESCE(started_at, ?3)
		 WHERE id = (
		     SELECT id FROM jobs
		     WHERE state = 'queued'
		     ORDER BY enqueued_at ASC
		     LIMIT 1
		 )
		 RETURNING id, repo_id, kind, state, incremental, since_sha, head_sha,
		           parent_job_id, target_finding_id, worker_id, lease_expires_at,
		           attempts, enqueued_at, started_at, finished_at, error",
	)?;
	let mut iter = stmt.query_map(params![worker_id, lease_until, now], row_to_job)?;
	match iter.next() {
		Some(row) => Ok(Some(row?)),
		None => Ok(None),
	}
}

/// Extend a lease. Returns `Ok(false)` if the job isn't currently
/// leased to `worker_id` (which means the caller's token is stale and
/// they should drop the work).
pub fn heartbeat(
	conn: &Connection, job_id: i64, worker_id: i64, now: i64, lease_seconds: i64,
) -> rusqlite::Result<Option<i64>> {
	let lease_until = now + lease_seconds;
	let n = conn.execute(
		"UPDATE jobs
		   SET lease_expires_at = ?1
		 WHERE id = ?2 AND state = 'leased' AND worker_id = ?3",
		params![lease_until, job_id, worker_id],
	)?;
	Ok(if n > 0 { Some(lease_until) } else { None })
}

/// Mark a leased job as complete. Caller picks the new state
/// (`succeeded` or `failed`).
pub fn complete(
	conn: &Connection, job_id: i64, worker_id: i64, new_state: JobState, head_sha: Option<&str>,
	error: Option<&str>, now: i64,
) -> rusqlite::Result<bool> {
	let n = conn.execute(
		"UPDATE jobs
		   SET state = ?1,
		       head_sha = COALESCE(?2, head_sha),
		       error = ?3,
		       finished_at = ?4,
		       lease_expires_at = NULL
		 WHERE id = ?5 AND state = 'leased' AND worker_id = ?6",
		params![new_state.as_str(), head_sha, error, now, job_id, worker_id],
	)?;
	Ok(n > 0)
}

pub fn get(conn: &Connection, id: i64) -> rusqlite::Result<Option<JobRow>> {
	conn.query_row(
		"SELECT id, repo_id, kind, state, incremental, since_sha, head_sha,
		        parent_job_id, target_finding_id, worker_id, lease_expires_at,
		        attempts, enqueued_at, started_at, finished_at, error
		 FROM jobs WHERE id = ?1",
		params![id],
		row_to_job,
	)
	.optional()
}

pub fn list(conn: &Connection) -> rusqlite::Result<Vec<JobRow>> {
	let mut stmt = conn.prepare(
		"SELECT id, repo_id, kind, state, incremental, since_sha, head_sha,
		        parent_job_id, target_finding_id, worker_id, lease_expires_at,
		        attempts, enqueued_at, started_at, finished_at, error
		 FROM jobs
		 ORDER BY enqueued_at DESC, id DESC",
	)?;
	let rows = stmt.query_map([], row_to_job)?.collect::<rusqlite::Result<Vec<_>>>()?;
	Ok(rows)
}

/// Count scan jobs for `repo_id` that are still queued or leased.
/// Used by the scheduler to avoid piling up duplicate scans for the
/// same repo.
pub fn count_active_scans_for_repo(conn: &Connection, repo_id: i64) -> rusqlite::Result<i64> {
	conn.query_row(
		"SELECT COUNT(*) FROM jobs
		 WHERE repo_id = ?1 AND kind = 'scan' AND state IN ('queued','leased')",
		params![repo_id],
		|r| r.get(0),
	)
}

/// Reap leases that have expired. For each, transitions back to
/// `queued` if `attempts < MAX_ATTEMPTS`, else `failed` with an error
/// message. Returns the number of rows affected.
pub fn reap_stale_leases(conn: &Connection, now: i64) -> rusqlite::Result<usize> {
	let requeued = conn.execute(
		"UPDATE jobs
		   SET state = 'queued',
		       worker_id = NULL,
		       lease_expires_at = NULL
		 WHERE state = 'leased'
		   AND lease_expires_at < ?1
		   AND attempts < ?2",
		params![now, MAX_ATTEMPTS],
	)?;
	let failed = conn.execute(
		"UPDATE jobs
		   SET state = 'failed',
		       worker_id = NULL,
		       lease_expires_at = NULL,
		       finished_at = ?1,
		       error = COALESCE(error, 'lease expired after max attempts')
		 WHERE state = 'leased'
		   AND lease_expires_at < ?1
		   AND attempts >= ?2",
		params![now, MAX_ATTEMPTS],
	)?;
	Ok(requeued + failed)
}

fn row_to_job(row: &rusqlite::Row) -> rusqlite::Result<JobRow> {
	let kind_str: String = row.get(2)?;
	let state_str: String = row.get(3)?;
	let kind = kind_str.parse::<JobKind>().map_err(|e| {
		rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, e.into())
	})?;
	let state = state_str.parse::<JobState>().map_err(|e| {
		rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, e.into())
	})?;
	Ok(JobRow {
		id: row.get(0)?,
		repo_id: row.get(1)?,
		kind,
		state,
		incremental: row.get::<_, i64>(4)? != 0,
		since_sha: row.get(5)?,
		head_sha: row.get(6)?,
		parent_job_id: row.get(7)?,
		target_finding_id: row.get(8)?,
		worker_id: row.get(9)?,
		lease_expires_at: row.get(10)?,
		attempts: row.get::<_, i64>(11)? as u32,
		enqueued_at: row.get(12)?,
		started_at: row.get(13)?,
		finished_at: row.get(14)?,
		error: row.get(15)?,
	})
}

#[cfg(test)]
mod tests {
	use loupe_core::ReportingDestination;

	use super::*;
	use crate::repos::{self, NewRepo};
	use crate::secrets::{self, SecretKind};
	use crate::workers::{self, WorkerKind};
	use crate::Db;

	fn db_with_repo_and_worker() -> (Db, i64, i64) {
		let db = Db::open_in_memory().unwrap();
		let secret_id = db
			.with_conn(|c| Ok(secrets::insert_plaintext(c, SecretKind::GithubPat, "p", b"x", 0)?))
			.unwrap();
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
						scan_interval_seconds: None,
						scanner_config: serde_json::Value::Null,
						reporting: ReportingDestination::GithubIssue {
							target_owner: "a".into(),
							target_repo: "t".into(),
							pat_secret_id: secret_id,
						},
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
	fn enqueue_then_lease_transitions_to_leased() {
		let (db, repo_id, worker_id) = db_with_repo_and_worker();
		let job_id = db
			.with_conn(|c| {
				Ok(enqueue(
					c,
					&NewJob {
						repo_id,
						kind: JobKind::Scan,
						incremental: false,
						since_sha: None,
						parent_job_id: None,
						target_finding_id: None,
					},
					100,
				)?)
			})
			.unwrap();

		let leased = db
			.with_conn(|c| Ok(lease_next(c, worker_id, 200, DEFAULT_LEASE_SECONDS)?))
			.unwrap()
			.expect("lease should produce a job");
		assert_eq!(leased.id, job_id);
		assert_eq!(leased.state, JobState::Leased);
		assert_eq!(leased.attempts, 1);
		assert_eq!(leased.worker_id, Some(worker_id));
		assert!(leased.lease_expires_at.unwrap() > 200);
	}

	#[test]
	fn lease_is_atomic_across_concurrent_callers() {
		let (db, repo_id, worker_id) = db_with_repo_and_worker();
		db.with_conn(|c| {
			Ok(enqueue(
				c,
				&NewJob {
					repo_id,
					kind: JobKind::Scan,
					incremental: false,
					since_sha: None,
					parent_job_id: None,
					target_finding_id: None,
				},
				100,
			)?)
		})
		.unwrap();

		let first =
			db.with_conn(|c| Ok(lease_next(c, worker_id, 200, DEFAULT_LEASE_SECONDS)?)).unwrap();
		let second =
			db.with_conn(|c| Ok(lease_next(c, worker_id, 201, DEFAULT_LEASE_SECONDS)?)).unwrap();
		assert!(first.is_some(), "first lease must succeed");
		assert!(second.is_none(), "second lease must see an empty queue");
	}

	#[test]
	fn empty_queue_returns_none() {
		let (db, _, worker_id) = db_with_repo_and_worker();
		let r =
			db.with_conn(|c| Ok(lease_next(c, worker_id, 100, DEFAULT_LEASE_SECONDS)?)).unwrap();
		assert!(r.is_none());
	}

	#[test]
	fn heartbeat_extends_lease() {
		let (db, repo_id, worker_id) = db_with_repo_and_worker();
		db.with_conn(|c| {
			Ok(enqueue(
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
		let leased = db.with_conn(|c| Ok(lease_next(c, worker_id, 100, 60)?)).unwrap().unwrap();
		let new_until = db.with_conn(|c| Ok(heartbeat(c, leased.id, worker_id, 200, 60)?)).unwrap();
		assert_eq!(new_until, Some(260));
	}

	#[test]
	fn heartbeat_from_wrong_worker_is_rejected() {
		let (db, repo_id, worker_id) = db_with_repo_and_worker();
		db.with_conn(|c| {
			Ok(enqueue(
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
		let leased = db.with_conn(|c| Ok(lease_next(c, worker_id, 100, 60)?)).unwrap().unwrap();
		let other_worker_id = db
			.with_conn(|c| Ok(workers::insert(c, "w2", WorkerKind::Worker, &[2u8; 32], 0)?))
			.unwrap();
		let res = db.with_conn(|c| Ok(heartbeat(c, leased.id, other_worker_id, 200, 60)?)).unwrap();
		assert_eq!(res, None, "stranger heartbeat must not extend the lease");
	}

	#[test]
	fn complete_succeeded_terminates_job() {
		let (db, repo_id, worker_id) = db_with_repo_and_worker();
		db.with_conn(|c| {
			Ok(enqueue(
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
		let leased = db.with_conn(|c| Ok(lease_next(c, worker_id, 100, 60)?)).unwrap().unwrap();
		let ok = db
			.with_conn(|c| {
				Ok(complete(c, leased.id, worker_id, JobState::Succeeded, Some("abc"), None, 200)?)
			})
			.unwrap();
		assert!(ok);
		let row = db.with_conn(|c| Ok(get(c, leased.id)?)).unwrap().unwrap();
		assert_eq!(row.state, JobState::Succeeded);
		assert_eq!(row.head_sha.as_deref(), Some("abc"));
		assert_eq!(row.finished_at, Some(200));
	}

	#[test]
	fn reap_requeues_under_max_attempts() {
		let (db, repo_id, worker_id) = db_with_repo_and_worker();
		db.with_conn(|c| {
			Ok(enqueue(
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
		// Lease at t=100 with TTL=10. Reap at t=200 ⇒ should requeue.
		db.with_conn(|c| Ok(lease_next(c, worker_id, 100, 10)?)).unwrap();
		let n = db.with_conn(|c| Ok(reap_stale_leases(c, 200)?)).unwrap();
		assert_eq!(n, 1);
		let row = db.with_conn(|c| Ok(list(c)?)).unwrap().pop().unwrap();
		assert_eq!(row.state, JobState::Queued);
		assert_eq!(row.attempts, 1, "reap doesn't reset attempts");
	}

	#[test]
	fn reap_fails_after_max_attempts() {
		let (db, repo_id, worker_id) = db_with_repo_and_worker();
		db.with_conn(|c| {
			Ok(enqueue(
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
		// Drive the attempts column to MAX_ATTEMPTS by leasing+reaping
		// in a loop, then one more lease should be the last one and the
		// next reap should send it to `failed`.
		for t in 0..MAX_ATTEMPTS as i64 {
			db.with_conn(|c| Ok(lease_next(c, worker_id, t * 100, 10)?)).unwrap();
			db.with_conn(|c| Ok(reap_stale_leases(c, t * 100 + 50)?)).unwrap();
		}
		// Now attempts == MAX_ATTEMPTS. One more lease and reap drops it
		// to failed.
		db.with_conn(|c| Ok(lease_next(c, worker_id, 999, 10)?)).unwrap();
		db.with_conn(|c| Ok(reap_stale_leases(c, 9_999)?)).unwrap();
		let row = db.with_conn(|c| Ok(list(c)?)).unwrap().pop().unwrap();
		assert_eq!(row.state, JobState::Failed);
	}
}
