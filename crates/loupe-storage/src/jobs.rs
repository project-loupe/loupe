//! DAO for the `jobs` table — including the atomic
//! `queued → leased` transition that backs `POST /v1/jobs/lease`.
//!
//! State strings match `loupe-core::JobState::as_str` /
//! `JobKind::as_str` exactly so callers can shuttle them through SQL
//! without having to define their own constants.

use loupe_core::{
	initial_job_state, FindingState, JobKind, JobState, JobTransition, StateTransitionError,
};
use rusqlite::{params, Connection, OptionalExtension};

/// Lease lifetime in seconds. Worker must heartbeat or complete before
/// `lease_expires_at` or the reaper will reclaim the job.
pub const DEFAULT_LEASE_SECONDS: i64 = 600;

/// Cap on retry attempts. After this many leases-then-failures, the job
/// is moved to `failed` rather than back to `queued`.
pub const MAX_ATTEMPTS: u32 = 3;

pub const JOB_CANCELLED_BY_ADMIN_ERROR: &str = "cancelled by admin";
pub const LEASE_EXPIRED_AFTER_MAX_ATTEMPTS_ERROR: &str = "lease expired after max attempts";

const JOB_COLUMNS: &str = "id, repo_id, kind, state, incremental, since_sha, head_sha,
        parent_job_id, target_finding_id, worker_id, lease_expires_at,
        attempts, enqueued_at, started_at, finished_at, error";

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelOutcome {
	Cancelled(JobRow),
	NotFound,
	NotCancellable(JobState),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryOutcome {
	Retried(JobRow),
	NotFound,
	Conflict(String),
}

/// Insert a `queued` job, returning the new id.
pub fn enqueue(conn: &Connection, new: &NewJob, now: i64) -> rusqlite::Result<i64> {
	let initial_state =
		initial_job_state(JobTransition::Enqueue).map_err(sql_state_transition_error)?;
	conn.execute(
		"INSERT INTO jobs
		   (repo_id, kind, state, incremental, since_sha,
		    parent_job_id, target_finding_id, enqueued_at)
		 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
		params![
			new.repo_id,
			new.kind.as_str(),
			initial_state.as_str(),
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
/// `accepts_verify` controls capability matching for `kind=verify`
/// jobs: when `false`, the worker is excluded from picking up verify
/// jobs. Scan jobs are unconstrained today — adding scan-side
/// capability matching is its own follow-up.
///
/// Returns `Ok(None)` if no eligible job is queued. Increments
/// `attempts` and stamps `worker_id`, `lease_expires_at`, `started_at`.
pub fn lease_next(
	conn: &Connection, worker_id: i64, accepts_verify: bool, now: i64, lease_seconds: i64,
) -> rusqlite::Result<Option<JobRow>> {
	let lease_until = now + lease_seconds;
	let target_state =
		JobState::Queued.apply(JobTransition::Lease).map_err(sql_state_transition_error)?;
	let mut stmt = conn.prepare(&format!(
		"UPDATE jobs
		   SET state = ?1,
		       worker_id = ?2,
		       lease_expires_at = ?3,
		       attempts = attempts + 1,
		       started_at = COALESCE(started_at, ?4)
		 WHERE id = (
		     SELECT id FROM jobs
		     WHERE state = 'queued'
		       AND (kind = 'scan' OR (kind = 'verify' AND ?5 = 1))
		     ORDER BY
		       CASE WHEN kind = 'verify' AND ?5 = 1 THEN 0 ELSE 1 END,
		       enqueued_at ASC
		     LIMIT 1
		 )
		 RETURNING {JOB_COLUMNS}",
	))?;
	let mut iter = stmt.query_map(
		params![target_state.as_str(), worker_id, lease_until, now, accepts_verify as i64],
		row_to_job,
	)?;
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
	let leased_state =
		JobState::Leased.apply(JobTransition::Heartbeat).map_err(sql_state_transition_error)?;
	let n = conn.execute(
		"UPDATE jobs
		   SET lease_expires_at = ?1
		 WHERE id = ?2 AND state = ?3 AND worker_id = ?4",
		params![lease_until, job_id, leased_state.as_str(), worker_id],
	)?;
	Ok(if n > 0 { Some(lease_until) } else { None })
}

/// Mark a leased job as complete. Caller picks the new state
/// (`succeeded` or `failed`).
pub fn complete(
	conn: &Connection, job_id: i64, worker_id: i64, new_state: JobState, head_sha: Option<&str>,
	error: Option<&str>, now: i64,
) -> rusqlite::Result<bool> {
	let transition = match new_state {
		JobState::Succeeded => JobTransition::CompleteSucceeded,
		JobState::Failed => JobTransition::CompleteFailed,
		other => {
			return Err(rusqlite::Error::InvalidParameterName(format!(
				"job completion target must be succeeded or failed, got {}",
				other.as_str()
			)));
		},
	};
	let target_state = JobState::Leased.apply(transition).map_err(sql_state_transition_error)?;
	let n = conn.execute(
		"UPDATE jobs
		   SET state = ?1,
		       head_sha = COALESCE(?2, head_sha),
		       error = ?3,
		       finished_at = ?4,
		       lease_expires_at = NULL
		 WHERE id = ?5 AND state = ?6 AND worker_id = ?7",
		params![
			target_state.as_str(),
			head_sha,
			error,
			now,
			job_id,
			JobState::Leased.as_str(),
			worker_id,
		],
	)?;
	Ok(n > 0)
}

/// Cancel queued or leased work. Scan jobs may have inserted pending
/// findings while leased; remove those so a later scan retry is not
/// blocked by fingerprint deduplication.
pub fn cancel(conn: &mut Connection, job_id: i64, now: i64) -> rusqlite::Result<CancelOutcome> {
	let tx = conn.transaction()?;
	let Some(row) = get(&tx, job_id)? else { return Ok(CancelOutcome::NotFound) };
	let target_state = match row.state.apply(JobTransition::Cancel) {
		Ok(state) => state,
		Err(_) => return Ok(CancelOutcome::NotCancellable(row.state)),
	};

	let updated = tx.execute(
		"UPDATE jobs
		   SET state = ?2,
		       worker_id = NULL,
		       lease_expires_at = NULL,
		       finished_at = ?3,
		       error = ?4
		 WHERE id = ?1 AND state IN ('queued','leased')",
		(job_id, target_state.as_str(), now, JOB_CANCELLED_BY_ADMIN_ERROR),
	)?;
	if updated == 0 {
		let state = get(&tx, job_id)?.map(|row| row.state).unwrap_or(JobState::Cancelled);
		return Ok(CancelOutcome::NotCancellable(state));
	}
	if row.kind == JobKind::Scan {
		crate::findings::delete_pending_for_job(&tx, job_id)?;
	}
	let row = get(&tx, job_id)?.expect("cancelled job row still exists");
	tx.commit()?;
	Ok(CancelOutcome::Cancelled(row))
}

pub fn enqueue_verify_jobs_for_scan(
	conn: &Connection, repo_id: i64, scan_job_id: i64, now: i64,
) -> rusqlite::Result<usize> {
	let initial_state =
		initial_job_state(JobTransition::Enqueue).map_err(sql_state_transition_error)?;
	conn.execute(
		"INSERT INTO jobs
		   (repo_id, kind, state, incremental, parent_job_id,
		    target_finding_id, enqueued_at)
		 SELECT ?1, ?2, ?3, 0, ?4, id, ?5
		 FROM findings
		 WHERE job_id = ?4 AND state = ?6",
		params![
			repo_id,
			JobKind::Verify.as_str(),
			initial_state.as_str(),
			scan_job_id,
			now,
			FindingState::Validating.as_str(),
		],
	)
}

pub fn retry_failed(
	conn: &mut Connection, job_id: i64, now: i64, validating_deadline: i64,
) -> rusqlite::Result<RetryOutcome> {
	let tx = conn.transaction()?;
	let Some(row) = get(&tx, job_id)? else { return Ok(RetryOutcome::NotFound) };
	if row.state != JobState::Failed {
		return Ok(RetryOutcome::Conflict(format!("job {job_id} is {:?}, not failed", row.state)));
	}
	if row.kind == JobKind::Verify {
		let Some(finding_id) = row.target_finding_id else {
			return Ok(RetryOutcome::Conflict(format!(
				"verify job {job_id} has no target finding"
			)));
		};
		let Some(finding) = crate::findings::get(&tx, finding_id)? else {
			return Ok(RetryOutcome::Conflict(format!(
				"verify job {job_id} target finding {finding_id} no longer exists"
			)));
		};
		match finding.state {
			FindingState::Validating => {},
			FindingState::Dismissed => {
				if !crate::findings::is_deadline_dismissed_without_terminal_verdict(
					&tx, finding_id,
				)? {
					return Ok(RetryOutcome::Conflict(format!(
						"verify job {job_id} target finding {finding_id} is dismissed by a terminal verdict"
					)));
				}
			},
			other => {
				return Ok(RetryOutcome::Conflict(format!(
					"verify job {job_id} target finding {finding_id} is {other}, not validating"
				)));
			},
		}
		if !crate::findings::retry_verification(&tx, finding_id, validating_deadline)? {
			return Ok(RetryOutcome::Conflict(format!(
				"verify job {job_id} target finding {finding_id} changed before retry"
			)));
		}
	}

	let Some(row) = requeue_failed(&tx, job_id, now)? else {
		return Ok(RetryOutcome::Conflict(format!("job {job_id} changed before retry")));
	};
	tx.commit()?;
	Ok(RetryOutcome::Retried(row))
}

pub fn requeue_failed(
	conn: &Connection, job_id: i64, now: i64,
) -> rusqlite::Result<Option<JobRow>> {
	let target_state =
		JobState::Failed.apply(JobTransition::Retry).map_err(sql_state_transition_error)?;
	let updated = conn.execute(
		"UPDATE jobs
		   SET state = ?1,
		       worker_id = NULL,
		       lease_expires_at = NULL,
		       attempts = 0,
		       started_at = NULL,
		       finished_at = NULL,
		       error = NULL,
		       head_sha = NULL,
		       enqueued_at = ?2
		 WHERE id = ?3 AND state = ?4",
		(target_state.as_str(), now, job_id, JobState::Failed.as_str()),
	)?;
	if updated == 0 {
		return Ok(None);
	}
	get(conn, job_id)
}

pub fn get(conn: &Connection, id: i64) -> rusqlite::Result<Option<JobRow>> {
	conn.query_row(
		&format!("SELECT {JOB_COLUMNS} FROM jobs WHERE id = ?1"),
		params![id],
		row_to_job,
	)
	.optional()
}

pub fn list(conn: &Connection, limit: Option<i64>) -> rusqlite::Result<Vec<JobRow>> {
	let sql = format!(
		"SELECT {JOB_COLUMNS}
		 FROM jobs
		 ORDER BY enqueued_at DESC, id DESC",
	);
	let Some(limit) = limit else {
		let mut stmt = conn.prepare(&sql)?;
		let rows = stmt.query_map([], row_to_job)?.collect::<rusqlite::Result<Vec<_>>>()?;
		return Ok(rows);
	};
	let mut stmt = conn.prepare(&format!("{sql} LIMIT ?1"))?;
	let rows = stmt.query_map(params![limit], row_to_job)?.collect::<rusqlite::Result<Vec<_>>>()?;
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

/// Whether `worker_id` currently holds a non-expired lease for any job
/// on `repo_id`. Used by server-side prior-finding routes so a worker
/// can only search/read finding history for the repo it is actively
/// scanning or verifying.
pub fn worker_has_active_lease_for_repo(
	conn: &Connection, worker_id: i64, repo_id: i64, now: i64,
) -> rusqlite::Result<bool> {
	let found: i64 = conn.query_row(
		"SELECT EXISTS(
		     SELECT 1 FROM jobs
		     WHERE repo_id = ?1
		       AND worker_id = ?2
		       AND state = 'leased'
		       AND lease_expires_at IS NOT NULL
		       AND lease_expires_at >= ?3
		 )",
		params![repo_id, worker_id, now],
		|r| r.get(0),
	)?;
	Ok(found != 0)
}

/// Reap leases that have expired. For each, transitions back to
/// `queued` if `attempts < MAX_ATTEMPTS`, else `failed` with an error
/// message. Returns the number of rows affected.
pub fn reap_stale_leases(conn: &Connection, now: i64) -> rusqlite::Result<usize> {
	let requeued_state =
		JobState::Leased.apply(JobTransition::ReapToQueued).map_err(sql_state_transition_error)?;
	let failed_state =
		JobState::Leased.apply(JobTransition::ReapToFailed).map_err(sql_state_transition_error)?;
	let failing_scan_jobs = {
		let mut stmt = conn.prepare(
			"SELECT id FROM jobs
			 WHERE kind = 'scan'
			   AND state = 'leased'
			   AND lease_expires_at < ?1
			   AND attempts >= ?2",
		)?;
		let rows = stmt.query_map(params![now, MAX_ATTEMPTS], |r| r.get::<_, i64>(0))?;
		rows.collect::<rusqlite::Result<Vec<_>>>()?
	};
	let requeued = conn.execute(
		"UPDATE jobs
		   SET state = ?2,
		       worker_id = NULL,
		       lease_expires_at = NULL
		 WHERE state = 'leased'
		   AND lease_expires_at < ?1
		   AND attempts < ?3",
		params![now, requeued_state.as_str(), MAX_ATTEMPTS],
	)?;
	let failed = conn.execute(
		"UPDATE jobs
		   SET state = ?3,
		       worker_id = NULL,
		       lease_expires_at = NULL,
		       finished_at = ?1,
		       error = COALESCE(error, ?4)
		 WHERE state = 'leased'
		   AND lease_expires_at < ?1
		   AND attempts >= ?2",
		params![now, MAX_ATTEMPTS, failed_state.as_str(), LEASE_EXPIRED_AFTER_MAX_ATTEMPTS_ERROR],
	)?;
	for job_id in failing_scan_jobs {
		crate::findings::delete_pending_for_job(conn, job_id)?;
	}
	Ok(requeued + failed)
}

fn sql_state_transition_error(error: StateTransitionError) -> rusqlite::Error {
	rusqlite::Error::InvalidParameterName(error.to_string())
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
	use loupe_core::{Finding, ReportingDestination, Severity};

	use super::*;
	use crate::repos::{self, NewRepo};
	use crate::secrets::{self, SecretKind};
	use crate::workers::{self, WorkerKind};
	use crate::Db;

	fn db_with_repo_and_worker() -> (Db, i64, i64) {
		let db = Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
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
						scan_interval_seconds: None,
						scanner_config: serde_json::Value::Null,
						reporting: ReportingDestination::GithubIssue {
							target_owner: "a".into(),
							target_repo: "t".into(),
							pat_secret_id: secret_id,
						},
						verification_enabled: false,
						require_approval: None,
						clone_token_secret_id: None,
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
			.with_conn(|c| Ok(lease_next(c, worker_id, false, 200, DEFAULT_LEASE_SECONDS)?))
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

		let first = db
			.with_conn(|c| Ok(lease_next(c, worker_id, false, 200, DEFAULT_LEASE_SECONDS)?))
			.unwrap();
		let second = db
			.with_conn(|c| Ok(lease_next(c, worker_id, false, 201, DEFAULT_LEASE_SECONDS)?))
			.unwrap();
		assert!(first.is_some(), "first lease must succeed");
		assert!(second.is_none(), "second lease must see an empty queue");
	}

	#[test]
	fn verify_jobs_skip_workers_that_do_not_accept_verify() {
		let (db, repo_id, worker_id) = db_with_repo_and_worker();
		// One scan job and one verify job, scan first.
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
		db.with_conn(|c| {
			Ok(enqueue(
				c,
				&NewJob {
					repo_id,
					kind: JobKind::Verify,
					incremental: false,
					since_sha: None,
					parent_job_id: None,
					target_finding_id: Some(42),
				},
				101,
			)?)
		})
		.unwrap();

		// Worker that does NOT accept verify: leases scan, then sees
		// the queue as empty (verify is gated).
		let first = db.with_conn(|c| Ok(lease_next(c, worker_id, false, 200, 60)?)).unwrap();
		assert!(matches!(first.as_ref().map(|r| r.kind), Some(JobKind::Scan)));
		let second = db.with_conn(|c| Ok(lease_next(c, worker_id, false, 201, 60)?)).unwrap();
		assert!(second.is_none(), "verify job must be invisible to non-verify workers");

		// A verify-capable worker DOES pick it up.
		let third = db.with_conn(|c| Ok(lease_next(c, worker_id, true, 202, 60)?)).unwrap();
		assert!(matches!(third.as_ref().map(|r| r.kind), Some(JobKind::Verify)));
	}

	#[test]
	fn verify_capable_workers_prioritize_verify_jobs() {
		let (db, repo_id, worker_id) = db_with_repo_and_worker();
		let scan_id = db
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
		let verify_id = db
			.with_conn(|c| {
				Ok(enqueue(
					c,
					&NewJob {
						repo_id,
						kind: JobKind::Verify,
						incremental: false,
						since_sha: None,
						parent_job_id: Some(scan_id),
						target_finding_id: Some(42),
					},
					200,
				)?)
			})
			.unwrap();

		let first = db.with_conn(|c| Ok(lease_next(c, worker_id, true, 300, 60)?)).unwrap();
		assert_eq!(first.as_ref().map(|r| r.id), Some(verify_id));
		assert!(matches!(first.as_ref().map(|r| r.kind), Some(JobKind::Verify)));

		let second = db.with_conn(|c| Ok(lease_next(c, worker_id, true, 301, 60)?)).unwrap();
		assert_eq!(second.as_ref().map(|r| r.id), Some(scan_id));
		assert!(matches!(second.as_ref().map(|r| r.kind), Some(JobKind::Scan)));
	}

	#[test]
	fn empty_queue_returns_none() {
		let (db, _, worker_id) = db_with_repo_and_worker();
		let r = db
			.with_conn(|c| Ok(lease_next(c, worker_id, false, 100, DEFAULT_LEASE_SECONDS)?))
			.unwrap();
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
		let leased =
			db.with_conn(|c| Ok(lease_next(c, worker_id, false, 100, 60)?)).unwrap().unwrap();
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
		let leased =
			db.with_conn(|c| Ok(lease_next(c, worker_id, false, 100, 60)?)).unwrap().unwrap();
		let other_worker_id = db
			.with_conn(|c| Ok(workers::insert(c, "w2", WorkerKind::Worker, &[2u8; 32], 0)?))
			.unwrap();
		let res = db.with_conn(|c| Ok(heartbeat(c, leased.id, other_worker_id, 200, 60)?)).unwrap();
		assert_eq!(res, None, "stranger heartbeat must not extend the lease");
	}

	#[test]
	fn active_lease_lookup_is_worker_repo_and_expiry_scoped() {
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
		let leased = db.with_conn(|c| Ok(lease_next(c, worker_id, false, 200, 60)?)).unwrap();
		assert_eq!(leased.as_ref().map(|j| j.id), Some(job_id));

		let other_worker_id = db
			.with_conn(|c| Ok(workers::insert(c, "w3", WorkerKind::Worker, &[9u8; 32], 100)?))
			.unwrap();
		assert!(db
			.with_conn(|c| Ok(worker_has_active_lease_for_repo(c, worker_id, repo_id, 250)?))
			.unwrap());
		assert!(!db
			.with_conn(|c| Ok(worker_has_active_lease_for_repo(c, other_worker_id, repo_id, 250)?))
			.unwrap());
		assert!(!db
			.with_conn(|c| Ok(worker_has_active_lease_for_repo(c, worker_id, repo_id + 1, 250)?))
			.unwrap());
		assert!(!db
			.with_conn(|c| Ok(worker_has_active_lease_for_repo(c, worker_id, repo_id, 261)?))
			.unwrap());
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
		let leased =
			db.with_conn(|c| Ok(lease_next(c, worker_id, false, 100, 60)?)).unwrap().unwrap();
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
	fn cancel_queued_job_marks_cancelled_and_unleasable() {
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

		let outcome = db.with_conn(|c| Ok(cancel(c, job_id, 200)?)).unwrap();
		let CancelOutcome::Cancelled(row) = outcome else { panic!("expected cancelled outcome") };
		assert_eq!(row.state, JobState::Cancelled);
		assert_eq!(row.finished_at, Some(200));
		assert_eq!(row.error.as_deref(), Some(JOB_CANCELLED_BY_ADMIN_ERROR));
		assert!(row.worker_id.is_none());
		assert!(row.lease_expires_at.is_none());

		let leased = db.with_conn(|c| Ok(lease_next(c, worker_id, false, 300, 60)?)).unwrap();
		assert!(leased.is_none(), "cancelled job must not be leased");
		let second = db.with_conn(|c| Ok(cancel(c, job_id, 400)?)).unwrap();
		assert_eq!(second, CancelOutcome::NotCancellable(JobState::Cancelled));
	}

	#[test]
	fn cancel_leased_scan_discards_pending_findings() {
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
		let leased =
			db.with_conn(|c| Ok(lease_next(c, worker_id, false, 200, 60)?)).unwrap().unwrap();
		db.with_conn(|c| {
			Ok(crate::findings::insert_or_ignore(
				c,
				repo_id,
				leased.id,
				&Finding {
					scanner_id: "regex".into(),
					severity: Severity::High,
					title: "Cancelled finding".into(),
					description: "submitted before cancellation".into(),
					file_path: Some("src/x.rs".into()),
					line_start: Some(1),
					line_end: Some(1),
					cwe: None,
					patch_unified: None,
					poc_unified: None,
					fingerprint: "fp-cancelled".into(),
				},
				true,
				210,
			)?)
		})
		.unwrap();

		let outcome = db.with_conn(|c| Ok(cancel(c, leased.id, 300)?)).unwrap();
		let CancelOutcome::Cancelled(row) = outcome else { panic!("expected cancelled outcome") };
		assert_eq!(row.state, JobState::Cancelled);
		assert!(row.worker_id.is_none());
		assert!(row.lease_expires_at.is_none());
		let pending_findings: i64 = db
			.with_conn(|c| {
				Ok(c.query_row(
					"SELECT COUNT(*) FROM findings WHERE job_id = ?1",
					[leased.id],
					|r| r.get(0),
				)?)
			})
			.unwrap();
		assert_eq!(pending_findings, 0);
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
		db.with_conn(|c| Ok(lease_next(c, worker_id, false, 100, 10)?)).unwrap();
		let n = db.with_conn(|c| Ok(reap_stale_leases(c, 200)?)).unwrap();
		assert_eq!(n, 1);
		let row = db.with_conn(|c| Ok(list(c, None)?)).unwrap().pop().unwrap();
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
			db.with_conn(|c| Ok(lease_next(c, worker_id, false, t * 100, 10)?)).unwrap();
			db.with_conn(|c| Ok(reap_stale_leases(c, t * 100 + 50)?)).unwrap();
		}
		// Now attempts == MAX_ATTEMPTS. One more lease and reap drops it
		// to failed.
		db.with_conn(|c| Ok(lease_next(c, worker_id, false, 999, 10)?)).unwrap();
		db.with_conn(|c| Ok(reap_stale_leases(c, 9_999)?)).unwrap();
		let row = db.with_conn(|c| Ok(list(c, None)?)).unwrap().pop().unwrap();
		assert_eq!(row.state, JobState::Failed);
	}

	#[test]
	fn reap_failed_scan_discards_pending_findings() {
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
		let leased =
			db.with_conn(|c| Ok(lease_next(c, worker_id, false, 999, 10)?)).unwrap().unwrap();
		db.with_conn(|c| {
			Ok(crate::findings::insert_or_ignore(
				c,
				repo_id,
				leased.id,
				&Finding {
					scanner_id: "regex".into(),
					severity: Severity::High,
					title: "Partial scan finding".into(),
					description: "submitted before lease expiry".into(),
					file_path: Some("src/x.rs".into()),
					line_start: Some(1),
					line_end: Some(1),
					cwe: None,
					patch_unified: None,
					poc_unified: None,
					fingerprint: "fp-reaped".into(),
				},
				true,
				1_000,
			)?)
		})
		.unwrap();
		db.with_conn(|c| {
			Ok(c.execute(
				"UPDATE jobs
				    SET attempts = ?1,
				        lease_expires_at = 1000
				  WHERE id = ?2",
				(MAX_ATTEMPTS as i64, leased.id),
			)?)
		})
		.unwrap();

		db.with_conn(|c| Ok(reap_stale_leases(c, 9_999)?)).unwrap();
		let row = db.with_conn(|c| Ok(list(c, None)?)).unwrap().pop().unwrap();
		assert_eq!(row.state, JobState::Failed);
		let pending_findings: i64 = db
			.with_conn(|c| {
				Ok(c.query_row(
					"SELECT COUNT(*) FROM findings WHERE job_id = ?1",
					[leased.id],
					|r| r.get(0),
				)?)
			})
			.unwrap();
		assert_eq!(pending_findings, 0);
	}
}
