//! Owned report selection and the narrow completion right that survives commit.
//!
//! Selected settings, content and completion rights have no public constructors.
//! ```compile_fail,E0451
//! use loupe_storage::reports::ReportFinding;
//! let _ = ReportFinding { id: 1, finding: todo!(), reviewed_revision: None };
//! ```
//! ```compile_fail,E0599
//! use loupe_storage::reports::StoredMailSettings;
//! let _ = StoredMailSettings::default();
//! ```
//! ```compile_fail,E0277
//! use loupe_storage::reports::PreparedReport;
//! let _: PreparedReport = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_storage::reports::ReportReceipt;
//! let _: ReportReceipt = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_storage::reports::ReportReceipt;
//! fn duplicate(receipt: &ReportReceipt) -> ReportReceipt { <ReportReceipt as Clone>::clone(receipt) }
//! ```
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use loupe_core::text::policy::{
	JobDiagnostic, MailAddress, MailSubjectPrefix, RepoName, RepoOwner, RevisionText, WorkerName,
};
use loupe_core::text::BoundedText;
use loupe_core::{Finding, FindingState, JobKind, JobState, ReportingDestination, Verdict};
use loupe_provenance::{Agent, Db as DbSource, Secret, Source};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::findings::{FindingIdentity, FindingRow};
use crate::scope::{AssignmentScope, RepoScope};
use crate::{Db, Error, Result};

// debug-ok: unavailable reasons are closed categories without stored input or credential bytes.
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum Unavailable {
	#[error("stored report input is unavailable")]
	StoredInput,
	#[error("stored reporting credential is unavailable")]
	Credential,
	#[error("stored reviewed revision is unavailable")]
	Revision,
}

pub enum Preparation {
	NoReport,
	Unavailable(Unavailable),
	Ready(Box<PreparedReport>),
}

/// These credential bytes were selected with the report's destination.
pub enum SelectedCredential {
	None,
	Pat(Secret<Vec<u8>>),
	App(crate::github_app::StoredGithubApp<DbSource>),
}

struct BatchIdentity;

/// An immutable projection of the selected repository's stored mail settings.
pub struct StoredMailSettings {
	batch: Arc<BatchIdentity>,
	database: Arc<crate::db::DbIdentity>,
	repo_id: i64,
	owner: BoundedText<RepoOwner, DbSource>,
	repository: BoundedText<RepoName, DbSource>,
	to: Vec<BoundedText<MailAddress, DbSource>>,
	from: Option<BoundedText<MailAddress, DbSource>>,
	prefix: Option<BoundedText<MailSubjectPrefix, DbSource>>,
}
impl std::fmt::Debug for StoredMailSettings {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("StoredMailSettings([redacted])")
	}
}
impl StoredMailSettings {
	pub fn owner(&self) -> &BoundedText<RepoOwner, DbSource> {
		&self.owner
	}
	pub fn repository(&self) -> &BoundedText<RepoName, DbSource> {
		&self.repository
	}
	pub fn recipients(&self) -> &[BoundedText<MailAddress, DbSource>] {
		&self.to
	}
	pub fn from(&self) -> Option<&BoundedText<MailAddress, DbSource>> {
		self.from.as_ref()
	}
	pub fn prefix(&self) -> Option<&BoundedText<MailSubjectPrefix, DbSource>> {
		self.prefix.as_ref()
	}
}

/// Finding content is Agent; the independently selected reviewed revision is Db.
pub struct ReportFinding {
	id: i64,
	finding: Finding<Agent>,
	reviewed_revision: Option<BoundedText<RevisionText, DbSource>>,
}
impl ReportFinding {
	pub fn id(&self) -> i64 {
		self.id
	}
	pub fn finding(&self) -> &Finding<Agent> {
		&self.finding
	}
	pub fn reviewed_revision(&self) -> Option<&BoundedText<RevisionText, DbSource>> {
		self.reviewed_revision.as_ref()
	}
}
impl std::fmt::Debug for ReportFinding {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ReportFinding").field("id", &self.id).finish_non_exhaustive()
	}
}

pub struct ReportEntry {
	id: i64,
	content: std::result::Result<ReportFinding, Unavailable>,
}
impl ReportEntry {
	pub fn id(&self) -> i64 {
		self.id
	}
	pub fn content(&self) -> std::result::Result<&ReportFinding, Unavailable> {
		self.content.as_ref().map_err(|error| *error)
	}
}

/// No caller can replace the selected repository, settings, entries or receipt.
pub struct PreparedReport {
	repo: crate::repos::RepoRow,
	batch: Arc<BatchIdentity>,
	mail: Option<StoredMailSettings>,
	entries: Vec<ReportEntry>,
	credential: SelectedCredential,
	receipt: ReportReceipt,
}
impl PreparedReport {
	/// An owned result captured from a callback that rolls back stays inactive.
	pub fn check_committed(&self) -> Result<()> {
		if self.receipt.committed.load(Ordering::Acquire) {
			Ok(())
		} else {
			Err(Error::ReportReceipt)
		}
	}
	pub fn repository(&self) -> &crate::repos::RepoRow {
		&self.repo
	}
	pub fn entries(&self) -> &[ReportEntry] {
		&self.entries
	}
	pub fn credential(&self) -> &SelectedCredential {
		&self.credential
	}
	pub fn mail_settings(&self) -> Result<&StoredMailSettings> {
		self.check_committed()?;
		let settings = self.mail.as_ref().ok_or(Error::ScopeDenied)?;
		if settings.repo_id != self.repo.id
			|| !Arc::ptr_eq(&settings.batch, &self.batch)
			|| !Arc::ptr_eq(&settings.database, &self.receipt.database)
		{
			return Err(Error::ScopeDenied);
		}
		Ok(settings)
	}
	pub fn mark_one(&mut self, db: &Db, finding_id: i64, now: i64) -> Result<usize> {
		self.receipt.mark_one(db, finding_id, now)
	}
	pub fn mark_all(&mut self, db: &Db, now: i64) -> Result<usize> {
		self.receipt.mark_all(db, now)
	}
}

struct Member {
	id: i64,
	identity: FindingIdentity,
	completed: bool,
}

/// Private membership and exact-row identity cannot be extended after selection.
pub struct ReportReceipt {
	database: Arc<crate::db::DbIdentity>,
	committed: Arc<AtomicBool>,
	repo_id: i64,
	members: Vec<Member>,
}
impl ReportReceipt {
	pub fn mark_one(&mut self, db: &Db, id: i64, now: i64) -> Result<usize> {
		if !self.committed.load(Ordering::Acquire) || !Arc::ptr_eq(&self.database, &db.identity) {
			return Err(Error::ReportReceipt);
		}
		let member =
			self.members.iter().position(|entry| entry.id == id).ok_or(Error::ReportReceipt)?;
		self.complete(db, Some(member), now)
	}
	pub fn mark_all(&mut self, db: &Db, now: i64) -> Result<usize> {
		if !self.committed.load(Ordering::Acquire) || !Arc::ptr_eq(&self.database, &db.identity) {
			return Err(Error::ReportReceipt);
		}
		self.complete(db, None, now)
	}
	fn complete(&mut self, db: &Db, selected: Option<usize>, now: i64) -> Result<usize> {
		let changed = db.with_conn(|conn| {
			let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
			let mut changed = 0;
			for (index, member) in self.members.iter().enumerate().filter(|(index, member)| !member.completed && selected.is_none_or(|selected| selected == *index)) {
				let _ = index;
				let valid: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM findings WHERE id=?1 AND repo_id=?2 AND report_identity=?3)", params![member.id,self.repo_id,member.identity.scope_bytes().as_slice()], |row| row.get(0))?;
				if !valid { return Err(Error::ReportReceipt); }
				changed += tx.execute("UPDATE findings SET state='reported',reported_at=?1 WHERE id=?2 AND repo_id=?3 AND report_identity=?4 AND state='confirmed'", params![now,member.id,self.repo_id,member.identity.scope_bytes().as_slice()])?;
			}
			tx.commit()?;
			Ok(changed)
		})?;
		for (index, member) in self.members.iter_mut().enumerate() {
			if selected.is_none_or(|selected| selected == index) {
				member.completed = true;
			}
		}
		Ok(changed)
	}
}

enum Selection {
	Job(i64),
	Finding(i64),
}

/// Complete the selected lease and prepare delivery before revoking it.
pub fn complete_assignment<RevisionS: Source, DiagnosticS: Source>(
	scope: &AssignmentScope<'_>, state: JobState,
	head_sha: Option<&BoundedText<RevisionText, RevisionS>>,
	error: Option<&BoundedText<JobDiagnostic, DiagnosticS>>, require_approval_default: bool,
	validating_deadline: i64,
) -> Result<Preparation> {
	let job = &scope.job;
	let conn = scope.repo.conn;
	let now = scope.lease.now;
	let mut preparation = Preparation::NoReport;
	if state == JobState::Succeeded {
		match job.kind {
			JobKind::Scan => {
				let revision = head_sha
					.filter(|sha| !sha.expose().trim().is_empty())
					.ok_or(Error::Conflict(crate::Conflict::JobState))?;
				let repo =
					crate::repos::get_raw(conn, scope.repo.repo_id)?.ok_or(Error::ScopeDenied)?;
				// Make the finding's own job revision visible to preparation while
				// retaining the live capability until the final guarded update.
				conn.execute(
					"UPDATE jobs SET head_sha=?1 WHERE id=?2 AND repo_id=?3 AND state='leased'",
					params![revision.expose(), job.id, scope.repo.repo_id],
				)?;
				conn.execute("UPDATE registered_repos SET last_scanned_sha=?1,last_scanned_at=?2 WHERE id=?3", params![revision.expose(),now,scope.repo.repo_id])?;
				conn.execute("INSERT INTO scan_history(repo_id,job_id,head_sha,base_sha,finding_count,duration_ms,finished_at) SELECT ?1,?2,?3,?4,(SELECT count(*) FROM findings WHERE job_id=?2 AND repo_id=?1),?5,?6", params![scope.repo.repo_id,job.id,revision.expose(),job.since_sha.as_ref().map(BoundedText::expose),job.started_at.map(|start| (now-start)*1000).unwrap_or(0),now])?;
				crate::findings::transition_scan_findings_after_success(
					conn,
					scope.repo.repo_id,
					job.id,
					repo.effective_require_approval(require_approval_default),
					validating_deadline,
					now,
				)?;
				crate::jobs::enqueue_verify_jobs_for_scan(conn, scope.repo.repo_id, job.id, now)?;
				preparation = prepare_assignment(scope)?;
			},
			JobKind::Verify => {
				let exists: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM finding_verifications v JOIN findings f ON f.id=v.finding_id WHERE v.job_id=?1 AND f.repo_id=?2 AND f.id=?3)", params![job.id,scope.repo.repo_id,job.target_finding_id], |row| row.get(0))?;
				if !exists {
					return Err(Error::Conflict(crate::Conflict::JobState));
				}
			},
			_ => return Err(Error::ScopeDenied),
		}
	} else if state == JobState::Failed && job.kind == JobKind::Scan {
		crate::findings::delete_pending_for_job(conn, scope.repo.repo_id, job.id)?;
	}
	if !crate::jobs::complete(conn, scope.lease.identity, state, head_sha, error, now)? {
		return Err(Error::ScopeDenied);
	}
	Ok(preparation)
}

/// A verifier may mutate only its assigned finding, inside its lease check.
pub fn submit_verdict(
	scope: &AssignmentScope<'_>, verdict: &Verdict<Agent>,
	by_cn: &BoundedText<WorkerName, DbSource>, terminal_inconclusive: bool,
	require_approval_default: bool,
) -> Result<(Option<FindingState>, Preparation)> {
	if scope.job.kind != JobKind::Verify {
		return Err(Error::ScopeDenied);
	}
	let target = scope.job.target_finding_id.ok_or(Error::ScopeDenied)?;
	let conn = scope.repo.conn;
	let exists: bool = conn.query_row(
		"SELECT EXISTS(SELECT 1 FROM findings WHERE id=?1 AND repo_id=?2)",
		params![target, scope.repo.repo_id],
		|row| row.get(0),
	)?;
	if !exists {
		return Err(Error::ScopeDenied);
	}
	let repo = crate::repos::get_raw(conn, scope.repo.repo_id)?.ok_or(Error::ScopeDenied)?;
	crate::findings::insert_verification(
		conn,
		scope.repo.repo_id,
		target,
		crate::findings::VerificationInput::Submitted { job_id: scope.job.id, verdict },
		scope.lease.now,
	)?;
	if let Verdict::Confirmed { patch: Some(patch), .. } = verdict {
		crate::findings::attach_proposed_patch(
			conn,
			scope.repo.repo_id,
			target,
			&patch.patch_unified,
			&patch.notes,
			by_cn,
			scope.lease.now,
		)?;
	}
	let state = crate::findings::roll_up_verdicts_for_finding(
		conn,
		scope.repo.repo_id,
		target,
		terminal_inconclusive,
		repo.effective_require_approval(require_approval_default),
		scope.lease.now,
	)?;
	let preparation = if state == Some(FindingState::Confirmed) {
		prepare_assignment(scope)?
	} else {
		Preparation::NoReport
	};
	Ok((state, preparation))
}

pub fn approve(
	scope: &RepoScope<'_>, id: i64, by_cn: &BoundedText<WorkerName, DbSource>, now: i64,
) -> Result<(crate::findings::ApprovalOutcome, Preparation)> {
	scope.require_operator()?;
	let exists: bool = scope.conn.query_row(
		"SELECT EXISTS(SELECT 1 FROM findings WHERE id=?1 AND repo_id=?2)",
		params![id, scope.repo_id],
		|row| row.get(0),
	)?;
	if !exists {
		return Ok((crate::findings::ApprovalOutcome::NotFound, Preparation::NoReport));
	}
	let outcome = crate::findings::approve(scope.conn, scope.repo_id, id, by_cn, now)?;
	let preparation = if outcome == crate::findings::ApprovalOutcome::Applied {
		prepare_operator(scope, id)?
	} else {
		Preparation::NoReport
	};
	Ok((outcome, preparation))
}

pub fn prepare_assignment(scope: &AssignmentScope<'_>) -> Result<Preparation> {
	let selection = match scope.job.kind {
		JobKind::Scan => Selection::Job(scope.job.id),
		JobKind::Verify => {
			Selection::Finding(scope.job.target_finding_id.ok_or(Error::ScopeDenied)?)
		},
		_ => return Err(Error::ScopeDenied),
	};
	prepare(&scope.repo, selection)
}

pub fn prepare_operator(scope: &RepoScope<'_>, finding_id: i64) -> Result<Preparation> {
	scope.require_operator()?;
	prepare(scope, Selection::Finding(finding_id))
}

fn prepare(scope: &RepoScope<'_>, selection: Selection) -> Result<Preparation> {
	// Read failures in this report-only projection must not undo an otherwise
	// completed domain mutation. Its caller still propagates domain SQL errors.
	match select(scope, selection) {
		Ok(preparation) => Ok(preparation),
		Err(Error::Sqlite(
			rusqlite::Error::FromSqlConversionFailure(..)
			| rusqlite::Error::InvalidColumnType(..)
			| rusqlite::Error::IntegralValueOutOfRange(..),
		))
		| Err(Error::Validation(_)) => Ok(Preparation::Unavailable(Unavailable::StoredInput)),
		Err(error) => Err(error),
	}
}

fn select(scope: &RepoScope<'_>, selection: Selection) -> Result<Preparation> {
	let repo = crate::repos::get_raw(scope.conn, scope.repo_id)?.ok_or(Error::ScopeDenied)?;
	if matches!(repo.reporting, ReportingDestination::Manual) {
		return Ok(Preparation::NoReport);
	}
	let (filter, id) = match selection {
		Selection::Job(id) => ("job_id", id),
		Selection::Finding(id) => ("id", id),
	};
	let rows: Vec<FindingRow> = {
		let mut statement = scope.conn.prepare(&format!(
			"SELECT {} FROM findings WHERE repo_id=?1 AND {filter}=?2 ORDER BY id ASC",
			crate::findings::FINDING_COLUMNS
		))?;
		statement
			.query_map(params![scope.repo_id, id], crate::findings::row_to_finding)?
			.collect::<rusqlite::Result<_>>()?
	};
	let rows: Vec<_> =
		rows.into_iter().filter(|row| row.state == FindingState::Confirmed).collect();
	if rows.is_empty() {
		return Ok(Preparation::NoReport);
	}
	let credential = match &repo.reporting {
		ReportingDestination::GithubIssue { pat_secret_id: Some(id), .. } => {
			let Some(secret) = crate::secrets::read(scope.conn, *id)? else {
				return Ok(Preparation::Unavailable(Unavailable::Credential));
			};
			SelectedCredential::Pat(secret)
		},
		ReportingDestination::GithubIssue { pat_secret_id: None, .. } => {
			let Some(app) = crate::github_app::get(scope.conn)? else {
				return Ok(Preparation::Unavailable(Unavailable::Credential));
			};
			SelectedCredential::App(app)
		},
		_ => SelectedCredential::None,
	};
	let batch = Arc::new(BatchIdentity);
	let mail = match &repo.reporting {
		ReportingDestination::Email { to, from, subject_prefix } => Some(StoredMailSettings {
			batch: batch.clone(),
			database: scope.identity.clone(),
			repo_id: scope.repo_id,
			owner: repo.owner.clone(),
			repository: repo.repo.clone(),
			to: to.clone(),
			from: from.clone(),
			prefix: subject_prefix.clone(),
		}),
		_ => None,
	};
	let mut members = Vec::with_capacity(rows.len());
	let mut entries = Vec::with_capacity(rows.len());
	for row in rows {
		let id = row.id;
		members.push(Member { id, identity: row.report_identity(), completed: false });
		let revision = scope
			.conn
			.query_row(
				"SELECT head_sha FROM jobs WHERE id=?1 AND repo_id=?2",
				params![row.job_id, scope.repo_id],
				|row| crate::ingress::optional_revision(row, 0),
			)
			.optional();
		let content = match revision {
			Ok(revision) => Ok(ReportFinding {
				id,
				finding: row.into_finding(),
				reviewed_revision: revision.flatten(),
			}),
			Err(_) => Err(Unavailable::Revision),
		};
		entries.push(ReportEntry { id, content });
	}
	Ok(Preparation::Ready(Box::new(PreparedReport {
		repo,
		batch,
		mail,
		entries,
		credential,
		receipt: ReportReceipt {
			database: scope.identity.clone(),
			committed: scope.committed.clone(),
			repo_id: scope.repo_id,
			members,
		},
	})))
}

#[cfg(test)]
mod tests {
	#[test]
	fn assignment_completion_confines_legacy_mixed_repository_rows() {
		let (db, repo, job) = fixture();
		let (local, foreign) = db.with_conn(|conn| {
			conn.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(2,'other','h','o','r','{\"kind\":\"manual\"}',0)",[])?;
			conn.execute("INSERT INTO workers(id,name,kind,cert_fingerprint,created_at) VALUES(1,'fixture','worker',X'07',0)",[])?;
			conn.execute("UPDATE jobs SET state='leased',worker_id=1,job_capability_hash=?1,lease_expires_at=100 WHERE id=?2",params![vec![7u8;32],job])?;
			let local = crate::findings::insert_or_ignore(conn,repo,job,&sample("local"),true,0)?.unwrap();
			let foreign = crate::findings::insert_or_ignore(conn,2,job,&sample("foreign"),true,0)?.unwrap();
			Ok((local, foreign))
		}).unwrap();
		crate::scope::with_active_lease(
			&db,
			crate::jobs::ActiveLease {
				identity: crate::jobs::LeaseIdentity {
					job_id: job,
					worker_id: 1,
					capability_hash: &[7; 32],
				},
				now: 2,
			},
			|scope| {
				complete_assignment(
					scope,
					JobState::Succeeded,
					Some(&crate::test_support::text::<RevisionText>("head").unwrap()),
					None::<&BoundedText<JobDiagnostic, Agent>>,
					false,
					100,
				)
			},
		)
		.unwrap()
		.unwrap();
		assert_eq!(state(&db, local), FindingState::Validating);
		assert_eq!(
			state(&db, foreign),
			FindingState::Pending,
			"a selected assignment must not transition a foreign row sharing its legacy job ID"
		);
		db.with_conn(|conn| {
			let targets: Vec<i64> = conn
				.prepare("SELECT target_finding_id FROM jobs WHERE kind='verify' ORDER BY id")?
				.query_map([], |row| row.get(0))?
				.collect::<rusqlite::Result<_>>()?;
			assert_eq!(
				targets,
				vec![local],
				"verification fan-out must remain in the selected repository"
			);
			Ok(())
		})
		.unwrap();
	}
	use super::*;
	use crate::findings::tests::{fixture, sample};
	use crate::scope::{with_operator_repository, OperatorTarget};

	fn confirmed(db: &Db, repo: i64, job: i64, name: &str) -> i64 {
		db.with_conn(|conn| {
			let id = crate::findings::insert_or_ignore(conn, repo, job, &sample(name), false, 0)?
				.unwrap();
			conn.execute("UPDATE findings SET state='confirmed' WHERE id=?1", [id])?;
			Ok(id)
		})
		.unwrap()
	}
	fn prepare_one(db: &Db, id: i64) -> Box<PreparedReport> {
		match with_operator_repository(
			db,
			&crate::test_support::operator_ingress(),
			OperatorTarget::Finding(id),
			|scope| prepare_operator(scope, id),
		)
		.unwrap()
		{
			Preparation::Ready(prepared) => prepared,
			_ => panic!("confirmed fixture must prepare"),
		}
	}
	fn state(db: &Db, id: i64) -> FindingState {
		db.with_conn(|conn| Ok(crate::findings::get_raw(conn, id)?.unwrap().state)).unwrap()
	}
	#[test]
	fn receipt_rejects_foreign_database_and_nonmember_without_consumption() {
		let (db, repo, job) = fixture();
		let (other, other_repo, other_job) = fixture();
		let selected = confirmed(&db, repo, job, "selected");
		let nonmember = confirmed(&db, repo, job, "nonmember");
		let foreign = confirmed(&other, other_repo, other_job, "selected");
		assert_eq!(selected, foreign, "same integer IDs in distinct databases");
		let mut report = prepare_one(&db, selected);
		assert!(matches!(report.mark_one(&other, foreign, 1), Err(Error::ReportReceipt)));
		assert!(matches!(report.mark_one(&db, nonmember, 1), Err(Error::ReportReceipt)));
		assert_eq!(state(&other, foreign), FindingState::Confirmed);
		assert_eq!(state(&db, nonmember), FindingState::Confirmed);
		assert_eq!(report.mark_one(&db, selected, 1).unwrap(), 1);
		assert_eq!(report.mark_one(&db, selected, 2).unwrap(), 0);
		assert_eq!(state(&db, selected), FindingState::Reported);
	}
	#[test]
	fn operator_callback_failure_rolls_back_composed_mutation() {
		let (db, repo, job) = fixture();
		let id = confirmed(&db, repo, job, "rollback");
		let result: Result<()> = with_operator_repository(
			&db,
			&crate::test_support::operator_ingress(),
			OperatorTarget::Finding(id),
			|scope| {
				scope.conn.execute(
					"UPDATE findings SET state='dismissed' WHERE id=?1 AND repo_id=?2",
					params![id, scope.repo_id],
				)?;
				let _ = prepare_operator(scope, id)?;
				Err(Error::ScopeDenied)
			},
		);
		assert!(matches!(result, Err(Error::ScopeDenied)));
		assert_eq!(state(&db, id), FindingState::Confirmed);
	}
	#[test]
	fn receipt_whole_batch_rolls_back_and_can_retry_after_sql_failure() {
		let (db, repo, job) = fixture();
		let first = confirmed(&db, repo, job, "first");
		let second = confirmed(&db, repo, job, "second");
		let mut batch = with_operator_repository(
			&db,
			&crate::test_support::operator_ingress(),
			OperatorTarget::Repository(repo),
			|scope| prepare(scope, Selection::Job(job)),
		)
		.unwrap();
		let Preparation::Ready(ref mut batch) = batch else { panic!("batch") };
		db.with_conn(|conn| { conn.execute_batch(&format!("CREATE TRIGGER fail_second BEFORE UPDATE OF state ON findings WHEN OLD.id={second} AND NEW.state='reported' BEGIN SELECT RAISE(ABORT,'fixture failure'); END;"))?; Ok(()) }).unwrap();
		assert!(batch.mark_all(&db, 1).is_err());
		assert_eq!(state(&db, first), FindingState::Confirmed);
		assert_eq!(state(&db, second), FindingState::Confirmed);
		db.with_conn(|conn| {
			conn.execute_batch("DROP TRIGGER fail_second")?;
			Ok(())
		})
		.unwrap();
		assert_eq!(batch.mark_all(&db, 2).unwrap(), 2);
		assert_eq!(batch.mark_all(&db, 3).unwrap(), 0);
	}
	#[test]
	fn receipt_changed_state_is_noop_and_foreign_repository_is_denied() {
		let (db, repo, job) = fixture();
		let selected = confirmed(&db, repo, job, "selected");
		let foreign = db.with_conn(|conn| {
			conn.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(2,'other','h','o','r','{\"kind\":\"manual\"}',0)",[])?;
			conn.execute("INSERT INTO jobs(id,repo_id,kind,state,incremental,enqueued_at) VALUES(2,2,'scan','queued',0,0)",[])?;
			let foreign = crate::findings::insert_or_ignore(conn,2,2,&sample("foreign"),false,0)?.unwrap();
			conn.execute("UPDATE findings SET state='confirmed' WHERE id=?1",[foreign])?;
			Ok(foreign)
		}).unwrap();
		let mut batch = prepare_one(&db, selected);
		assert!(matches!(batch.mark_one(&db, foreign, 1), Err(Error::ReportReceipt)));
		db.with_conn(|conn| {
			conn.execute("UPDATE findings SET state='dismissed' WHERE id=?1", [selected])?;
			Ok(())
		})
		.unwrap();
		assert_eq!(batch.mark_all(&db, 1).unwrap(), 0);
		assert_eq!(state(&db, selected), FindingState::Dismissed);
		assert_eq!(state(&db, foreign), FindingState::Confirmed);
	}
	#[test]
	fn mail_projection_rejects_another_selection_even_in_same_repository() {
		let (db, repo, job) = fixture();
		db.with_conn(|conn| {conn.execute("UPDATE registered_repos SET reporting='{\"kind\":\"email\",\"to\":[\"to\"]}' WHERE id=?1",[repo])?;Ok(())}).unwrap();
		let first = confirmed(&db, repo, job, "first");
		let second = confirmed(&db, repo, job, "second");
		let mut left = prepare_one(&db, first);
		let mut right = prepare_one(&db, second);
		assert!(left.mail_settings().is_ok());
		assert!(right.mail_settings().is_ok());
		std::mem::swap(&mut left.mail, &mut right.mail);
		assert!(matches!(left.mail_settings(), Err(Error::ScopeDenied)));
		assert!(matches!(right.mail_settings(), Err(Error::ScopeDenied)));
	}
	#[test]
	fn receipt_captured_from_a_rolled_back_issuer_cannot_complete() {
		let (db, repo, job) = fixture();
		let id = confirmed(&db, repo, job, "rollback-capture");
		let mut escaped = None;
		let result: Result<()> = with_operator_repository(
			&db,
			&crate::test_support::operator_ingress(),
			OperatorTarget::Finding(id),
			|scope| {
				if let Preparation::Ready(batch) = prepare_operator(scope, id)? {
					escaped = Some(batch);
				}
				Err(Error::ScopeDenied)
			},
		);
		assert!(result.is_err());
		let mut escaped = escaped.unwrap();
		assert!(matches!(escaped.check_committed(), Err(Error::ReportReceipt)));
		assert!(
			matches!(escaped.mark_one(&db, id, 1), Err(Error::ReportReceipt)),
			"a receipt from a rolled-back selection must stay inactive"
		);
		assert_eq!(state(&db, id), FindingState::Confirmed);
	}

	#[test]
	fn completion_commits_when_report_projection_is_unavailable() {
		for failure in ["missing-pat", "missing-app", "malformed-content"] {
			let (db, repo, job) = fixture();
			let id = confirmed(&db, repo, job, "selected");
			db.with_conn(|conn| {
				conn.execute("INSERT INTO workers(id,name,kind,cert_fingerprint,created_at) VALUES(1,'fixture','worker',X'07',0)",[])?;
				conn.execute("UPDATE jobs SET state='leased',worker_id=1,job_capability_hash=?1,lease_expires_at=100,started_at=1 WHERE id=?2",params![vec![7u8;32],job])?;
				match failure {
					"missing-pat" => {conn.execute("DELETE FROM secrets",[])?;},
					"missing-app" => {conn.execute("UPDATE registered_repos SET reporting='{\"kind\":\"github_issue\",\"target_owner\":\"a\",\"target_repo\":\"b\"}' WHERE id=?1",[repo])?;},
					_ => {conn.execute("UPDATE findings SET description=?1 WHERE id=?2",params!["invalid\0description",id])?;},
				}
				Ok(())
			}).unwrap();
			let head = crate::test_support::text::<RevisionText>("head").unwrap();
			let preparation = crate::scope::with_active_lease(
				&db,
				crate::jobs::ActiveLease {
					identity: crate::jobs::LeaseIdentity {
						job_id: job,
						worker_id: 1,
						capability_hash: &[7; 32],
					},
					now: 2,
				},
				|scope| {
					complete_assignment(
						scope,
						JobState::Succeeded,
						Some(&head),
						None::<&BoundedText<JobDiagnostic, Agent>>,
						false,
						100,
					)
				},
			)
			.unwrap()
			.unwrap();
			assert!(matches!(preparation, Preparation::Unavailable(_)), "{failure}");
			db.with_conn(|conn| {
				assert_eq!(crate::jobs::get_raw(conn, job)?.unwrap().state, JobState::Succeeded);
				assert_eq!(
					conn.query_row("SELECT state FROM findings WHERE id=?1", [id], |row| row
						.get::<_, String>(
						0
					))?,
					"confirmed"
				);
				assert_eq!(
					conn.query_row(
						"SELECT count(*) FROM scan_history WHERE job_id=?1",
						[job],
						|row| row.get::<_, i64>(0)
					)?,
					1
				);
				assert!(conn
					.query_row("SELECT job_capability_hash FROM jobs WHERE id=?1", [job], |row| {
						row.get::<_, Option<Vec<u8>>>(0)
					})?
					.is_none());
				Ok(())
			})
			.unwrap();
		}
	}
	#[test]
	fn completion_keeps_zero_duration_when_a_lease_has_no_start_time() {
		let (db, repo, job) = fixture();
		confirmed(&db, repo, job, "duration");
		db.with_conn(|conn| {
			conn.execute("INSERT INTO workers(id,name,kind,cert_fingerprint,created_at) VALUES(1,'fixture','worker',X'07',0)",[])?;
			conn.execute("UPDATE jobs SET state='leased',worker_id=1,job_capability_hash=?1,lease_expires_at=100,started_at=NULL WHERE id=?2",params![vec![7u8;32],job])?;
			Ok(())
		}).unwrap();
		let head = crate::test_support::text::<RevisionText>("head").unwrap();
		crate::scope::with_active_lease(
			&db,
			crate::jobs::ActiveLease {
				identity: crate::jobs::LeaseIdentity {
					job_id: job,
					worker_id: 1,
					capability_hash: &[7; 32],
				},
				now: 2,
			},
			|scope| {
				complete_assignment(
					scope,
					JobState::Succeeded,
					Some(&head),
					None::<&BoundedText<JobDiagnostic, Agent>>,
					false,
					100,
				)
			},
		)
		.unwrap()
		.unwrap();
		let duration = db
			.with_conn(|conn| {
				Ok(conn.query_row(
					"SELECT duration_ms FROM scan_history WHERE job_id=?1",
					[job],
					|row| row.get::<_, Option<i64>>(0),
				)?)
			})
			.unwrap();
		assert_eq!(duration, Some(0), "preserve the historical zero-duration fallback");
	}
}
