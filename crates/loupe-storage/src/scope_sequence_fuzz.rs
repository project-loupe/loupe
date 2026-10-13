//! Bounded stateful checks of the real SQL authority and report boundaries.
//!
//! Four bytes per operation: opcode, database/repository selector, finding ID
//! selector, flags/receipt slot. At most 64 operations, two independent databases,
//! two repositories per database, six finding IDs and four retained batches.
//! Trailing incomplete operations are ignored. IDs 7 and 8 deliberately miss.
//! Opcodes: 0 read, 1 lease/prepare, 2 revoke, 3 complete, 4 operator prepare,
//! 5 mark one, 6 mark all, 7 delete, 8 recreate, 9 dismiss, 10 rolled-back
//! preparation, 11 toggle delivery SQL failure, 12 recreate malformed identity.
//! Flags 0..2 corrupt worker/hash/job authority; bits 3..4 choose clock
//! 10/100/101/99 (expiry is 100); bits 5..6 select the retained batch slot.
//!
//! The model uses monotonically increasing row incarnations, never production
//! scope predicates or receipt identities. Private fixture SQL seeds deliberate
//! legacy/malformed states; all authority and completion calls use public APIs.
#![cfg(any(test, fuzzing))]

use loupe_core::text::policy::JobDiagnostic;
use loupe_core::text::BoundedText;
use loupe_core::{FindingState, JobState};
use loupe_provenance::{Db as DbSource, Ingress, Operator};
use rusqlite::params;
use rusqlite::types::Value;

use crate::reports::{Preparation, PreparedReport};
use crate::scope::{with_active_lease, with_operator_repository, OperatorTarget};
use crate::{findings, jobs, reports, Db, Error, Result};

const ROWS: usize = 6;
const OPS: usize = 64;

#[derive(Clone, Copy)]
struct Row {
	incarnation: u8,
	present: bool,
	malformed: bool,
	state: FindingState,
	reported: Option<i64>,
}

struct Model {
	rows: [Row; ROWS],
	jobs: [JobState; 2],
	fail_delivery: bool,
}
impl Model {
	fn new() -> Self {
		Self {
			rows: std::array::from_fn(|index| Row {
				incarnation: 0,
				present: true,
				malformed: false,
				state: if index % 3 == 1 { FindingState::Pending } else { FindingState::Confirmed },
				reported: None,
			}),
			jobs: [JobState::Leased; 2],
			fail_delivery: false,
		}
	}
}
struct Member {
	index: usize,
	incarnation: u8,
	consumed: bool,
}
struct Batch {
	report: Box<PreparedReport>,
	database: usize,
	committed: bool,
	members: Vec<Member>,
}

fn must<T>(result: Result<T>) -> T {
	result.unwrap_or_else(|error| panic!("scope sequence fixture: {error}"))
}

#[allow(unsafe_code)]
fn operator() -> Ingress<Operator> {
	// SAFETY: synthetic operator for this private cfg(test/fuzzing) driver only.
	// No token, callback, connection or scope is exported to the fuzz caller.
	unsafe { Ingress::new() }
}

fn repository(index: usize) -> i64 {
	(index / 3 + 1) as i64
}
fn producing_job(index: usize) -> i64 {
	repository(index) + if index % 3 == 2 { 2 } else { 0 }
}

fn insert_row(db: &Db, index: usize, row: Row) {
	must(db.with_conn(|conn| {
		let mut identity = [0u8; 16];
		identity[0] = index as u8 + 1;
		identity[1] = row.incarnation;
		conn.execute(
			"INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,verification_required,created_at,report_identity,source) VALUES(?1,?2,?3,'test','high','title','description',?1,?4,0,0,?5,'agent')",
			params![index as i64 + 1, repository(index), producing_job(index), row.state.as_str(), (!row.malformed).then_some(identity.as_slice())],
		)?;
		Ok(())
	}));
}

fn database(model: &Model) -> Db {
	let db = must(Db::open_in_memory(&crate::secrets::MasterKey::for_tests()));
	must(db.with_conn(|conn| {
		conn.execute_batch("INSERT INTO workers(id,name,kind,cert_fingerprint,created_at) VALUES(1,'worker','worker',X'07',0);")?;
		for repo in [1i64, 2] {
			conn.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,verification_enabled,require_approval,created_at) VALUES(?1,?2,'host','owner','repo','{\"kind\":\"email\",\"to\":[\"to@example.test\"]}',0,0,0)", params![repo,format!("https://example.test/{repo}")])?;
			conn.execute("INSERT INTO jobs(id,repo_id,kind,state,worker_id,job_capability_hash,lease_expires_at,head_sha,incremental,enqueued_at) VALUES(?1,?1,'scan','leased',1,?2,100,'head',0,0)", params![repo, vec![repo as u8;32]])?;
			conn.execute("INSERT INTO jobs(id,repo_id,kind,state,head_sha,incremental,enqueued_at) VALUES(?1,?2,'scan','succeeded','head',0,0)", params![repo+2,repo])?;
		}
		Ok(())
	}));
	for (index, row) in model.rows.iter().enumerate() {
		insert_row(&db, index, *row);
	}
	db
}

// Entire rows catch writes outside the modelled state columns as well. IDs in
// these four tables lead each row, including scan_history's repository binding.
// debug-ok: cfg-only deterministic SQL fixtures; no external text or credentials.
#[derive(PartialEq, Debug)]
struct Snapshot(Vec<Vec<Vec<Value>>>);
fn snapshot(db: &Db) -> Snapshot {
	must(db.with_conn(|conn| {
		let mut tables = Vec::new();
		for table in ["findings", "jobs", "registered_repos", "scan_history"] {
			let mut statement = conn.prepare(&format!("SELECT * FROM {table} ORDER BY id"))?;
			let columns = statement.column_count();
			let rows = statement
				.query_map([], |row| {
					(0..columns)
						.map(|index| row.get(index))
						.collect::<rusqlite::Result<Vec<Value>>>()
				})?
				.collect::<rusqlite::Result<Vec<_>>>()?;
			tables.push(rows);
		}
		Ok(Snapshot(tables))
	}))
}

fn unchanged_except(
	before: Snapshot, after: Snapshot, findings: &[usize], job: Option<i64>, completed: Option<i64>,
) {
	for (table, (before, after)) in before.0.into_iter().zip(after.0).enumerate() {
		let keep = |row: &Vec<Value>| {
			let Some(Value::Integer(id)) = row.first() else { panic!("integer row identity") };
			match table {
				0 => !findings.iter().any(|index| *id == *index as i64 + 1),
				1 => Some(*id) != job,
				2 => Some(*id) != completed,
				3 => !completed.is_some_and(|repo| row.get(1) == Some(&Value::Integer(repo))),
				_ => unreachable!(),
			}
		};
		assert_eq!(
			before.into_iter().filter(keep).collect::<Vec<_>>(),
			after.into_iter().filter(keep).collect::<Vec<_>>(),
			"unrelated SQL rows changed in table {table}"
		);
	}
}

fn check_model(db: &Db, model: &Model) {
	must(db.with_conn(|conn| {
		let actual: Vec<(i64, i64, i64, String, Option<i64>)> = conn
			.prepare("SELECT id,repo_id,job_id,state,reported_at FROM findings ORDER BY id")?
			.query_map([], |row| {
				Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
			})?
			.collect::<rusqlite::Result<_>>()?;
		let expected: Vec<_> = model
			.rows
			.iter()
			.enumerate()
			.filter(|(_, row)| row.present)
			.map(|(index, row)| {
				(
					index as i64 + 1,
					repository(index),
					producing_job(index),
					row.state.as_str().to_owned(),
					row.reported,
				)
			})
			.collect();
		assert_eq!(actual, expected, "finding state disagrees with independent sequence model");
		for (index, expected) in model.jobs.iter().enumerate() {
			let (state, hash, expires): (String, Option<Vec<u8>>, Option<i64>) = conn.query_row(
				"SELECT state,job_capability_hash,lease_expires_at FROM jobs WHERE id=?1",
				[index as i64 + 1],
				|row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
			)?;
			assert_eq!(state, expected.as_str(), "job state disagrees with model");
			assert_eq!(
				hash,
				(*expected == JobState::Leased).then(|| vec![index as u8 + 1; 32]),
				"lease capability changed unexpectedly"
			);
			assert_eq!(expires, (*expected == JobState::Leased).then_some(100));
		}
		Ok(())
	}));
}

fn capture(
	preparation: Preparation, database: usize, committed: bool, selected: &[usize], model: &Model,
) -> Option<Batch> {
	if selected.iter().any(|index| model.rows[*index].present && model.rows[*index].malformed) {
		assert!(
			matches!(preparation, Preparation::Unavailable(_)),
			"malformed stored identity must disable preparation"
		);
		return None;
	}
	let expected: Vec<_> = selected
		.iter()
		.copied()
		.filter(|index| {
			let row = model.rows[*index];
			row.present && row.state == FindingState::Confirmed
		})
		.collect();
	if expected.is_empty() {
		assert!(
			matches!(preparation, Preparation::NoReport),
			"empty selection must not issue a batch"
		);
		return None;
	}
	let Preparation::Ready(report) = preparation else {
		panic!("confirmed selection must prepare a batch")
	};
	assert_eq!(
		report.entries().iter().map(|entry| entry.id()).collect::<Vec<_>>(),
		expected.iter().map(|index| *index as i64 + 1).collect::<Vec<_>>(),
		"prepared batch contains unexpected findings"
	);
	assert_eq!(
		report.check_committed().is_ok(),
		committed,
		"preparation escaped rollback authority"
	);
	assert_eq!(report.mail_settings().is_ok(), committed);
	for entry in report.entries() {
		assert!(entry.content().is_ok(), "valid fixture report content");
	}
	Some(Batch {
		report,
		database,
		committed,
		members: expected
			.into_iter()
			.map(|index| Member {
				index,
				incarnation: model.rows[index].incarnation,
				consumed: false,
			})
			.collect(),
	})
}

fn read_selection(db: &Db, model: &Model, repo: i64, id: i64) {
	must(with_operator_repository(db, &operator(), OperatorTarget::Repository(repo), |scope| {
		// Malformed rows are tested by prepare; ordinary DAO reads keep their
		// validation errors instead of treating them as authorization failures.
		if model
			.rows
			.iter()
			.enumerate()
			.any(|(index, row)| repository(index) == repo && row.present && row.malformed)
		{
			return Ok(());
		}
		let result = findings::get(scope, id)?;
		let expected = model.rows.iter().enumerate().find(|(index, row)| {
			*index as i64 + 1 == id && repository(*index) == repo && row.present
		});
		assert_eq!(
			result.as_ref().map(|row| row.id),
			expected.map(|(index, _)| index as i64 + 1),
			"scoped finding read crossed repositories"
		);
		let mut actual: Vec<_> =
			findings::list_for_repo(scope, 20)?.iter().map(|row| row.id).collect();
		actual.sort_unstable();
		let expected: Vec<_> = model
			.rows
			.iter()
			.enumerate()
			.filter(|(index, row)| repository(*index) == repo && row.present)
			.map(|(index, _)| index as i64 + 1)
			.collect();
		assert_eq!(actual, expected, "scoped list crossed repositories");
		assert!(jobs::get(scope, 3 - repo)?.is_none(), "scoped job read crossed repositories");
		assert!(
			findings::list_for_job(scope, 3 - repo)?.is_empty(),
			"scoped job findings crossed repositories"
		);
		Ok(())
	}));
}

fn mark(
	batch: &mut Batch, db: &Db, model: &mut Model, database: usize, id: Option<i64>, now: i64,
) -> Vec<usize> {
	let selected: Vec<_> = batch
		.members
		.iter()
		.enumerate()
		.filter(|(_, member)| id.is_none_or(|id| member.index as i64 + 1 == id))
		.map(|(index, _)| index)
		.collect();
	let authorized = batch.committed && batch.database == database && !selected.is_empty();
	let pending: Vec<_> =
		selected.iter().copied().filter(|index| !batch.members[*index].consumed).collect();
	let bound = pending.iter().all(|index| {
		let member = &batch.members[*index];
		let row = model.rows[member.index];
		row.present && !row.malformed && row.incarnation == member.incarnation
	});
	let fail = model.fail_delivery
		&& pending.iter().any(|index| {
			let member = &batch.members[*index];
			member.index % 3 == 1 && model.rows[member.index].state == FindingState::Confirmed
		});
	let result = match id {
		Some(id) => batch.report.mark_one(db, id, now),
		None => batch.report.mark_all(db, now),
	};
	if !authorized || !bound {
		assert!(
			matches!(result, Err(Error::ReportReceipt)),
			"receipt accepted the wrong database, member, incarnation or rollback"
		);
		return vec![];
	}
	if fail {
		assert!(
			matches!(result, Err(Error::Sqlite(_))),
			"injected delivery failure must roll back the batch"
		);
		return vec![];
	}
	let changed: Vec<_> = pending
		.iter()
		.map(|index| batch.members[*index].index)
		.filter(|index| model.rows[*index].state == FindingState::Confirmed)
		.collect();
	assert_eq!(must(result), changed.len(), "receipt changed an unexpected number of findings");
	for index in &changed {
		model.rows[*index].state = FindingState::Reported;
		model.rows[*index].reported = Some(now);
	}
	for index in selected {
		batch.members[index].consumed = true;
	}
	changed
}

/// Exercise real storage operations without exporting synthetic authority.
pub fn exercise(data: &[u8]) {
	drive(data);
}

fn drive(data: &[u8]) {
	let mut models = [Model::new(), Model::new()];
	let dbs = [database(&models[0]), database(&models[1])];
	let mut batches: [Option<Batch>; 4] = std::array::from_fn(|_| None);
	for (step, bytes) in data.as_chunks::<4>().0.iter().take(OPS).enumerate() {
		let code = bytes[0] % 13;
		let database = usize::from(bytes[1] & 1);
		let repo = i64::from((bytes[1] >> 1) & 1) + 1;
		let index = usize::from(bytes[2] % 8);
		let id = index as i64 + 1;
		let slot = usize::from((bytes[3] >> 5) & 3);
		let now = [10, 100, 101, 99][usize::from((bytes[3] >> 3) & 3)];
		let db = &dbs[database];
		let before = [snapshot(&dbs[0]), snapshot(&dbs[1])];
		let model = &mut models[database];
		let mut changed = Vec::new();
		let mut changed_job = None;
		let mut completed_repo = None;
		match code {
			0 => read_selection(db, model, repo, id),
			1 | 3 => {
				let hash = vec![if bytes[3] & 2 == 0 { repo as u8 } else { 99 }; 32];
				let lease = jobs::ActiveLease {
					identity: jobs::LeaseIdentity {
						job_id: if bytes[3] & 4 == 0 { repo } else { 3 - repo },
						worker_id: if bytes[3] & 1 == 0 { 1 } else { 2 },
						capability_hash: &hash,
					},
					now,
				};
				let admitted = model.jobs[repo as usize - 1] == JobState::Leased
					&& bytes[3] & 7 == 0
					&& now <= 100;
				let mut called = false;
				let result = must(with_active_lease(db, lease, |scope| {
					called = true;
					assert_eq!(scope.repo().repository_id(), repo);
					assert!(
						jobs::get(scope.repo(), 3 - repo)?.is_none(),
						"lease scope crossed repositories"
					);
					if code == 3 {
						reports::complete_assignment(
							scope,
							JobState::Succeeded,
							scope.job().head_sha.as_ref(),
							None::<&BoundedText<JobDiagnostic, DbSource>>,
							false,
							200,
						)
					} else {
						reports::prepare_assignment(scope)
					}
				}));
				assert_eq!(
					called, admitted,
					"inactive or mismatched lease entered protected callback"
				);
				assert_eq!(result.is_some(), admitted);
				if let Some(preparation) = result {
					if code == 3 {
						model.jobs[repo as usize - 1] = JobState::Succeeded;
						changed_job = Some(repo);
						completed_repo = Some(repo);
						for (index, row) in model.rows.iter_mut().enumerate() {
							if producing_job(index) == repo
								&& row.present
								&& row.state == FindingState::Pending
							{
								row.state = FindingState::Confirmed;
								changed.push(index);
							}
						}
					}
					let selected: Vec<_> =
						(0..ROWS).filter(|index| producing_job(*index) == repo).collect();
					batches[slot] = capture(preparation, database, true, &selected, model);
				}
			},
			2 => {
				let result = must(crate::recovery::cancel_job(db, &operator(), repo, now));
				if model.jobs[repo as usize - 1] == JobState::Leased {
					assert!(matches!(result, jobs::CancelOutcome::Cancelled(_)));
					model.jobs[repo as usize - 1] = JobState::Cancelled;
					changed_job = Some(repo);
					for (index, row) in model.rows.iter_mut().enumerate() {
						if producing_job(index) == repo
							&& row.present
							&& row.state == FindingState::Pending
						{
							row.present = false;
							changed.push(index);
						}
					}
				} else {
					assert!(matches!(result, jobs::CancelOutcome::NotCancellable(_)));
				}
			},
			4 | 10 => {
				let mut escaped = None;
				let result = with_operator_repository(
					db,
					&operator(),
					OperatorTarget::Repository(repo),
					|scope| {
						let prepared = reports::prepare_operator(scope, id)?;
						if code == 10 {
							escaped = Some(prepared);
							Err(Error::ScopeDenied)
						} else {
							Ok(prepared)
						}
					},
				);
				let preparation = if code == 10 {
					assert!(matches!(result, Err(Error::ScopeDenied)));
					escaped.unwrap_or_else(|| panic!("rollback callback must execute"))
				} else {
					must(result)
				};
				let selected: Vec<_> = (0..ROWS)
					.filter(|selected| *selected == index && repository(*selected) == repo)
					.collect();
				batches[slot] = capture(preparation, database, code != 10, &selected, model);
			},
			5 | 6 => {
				if let Some(batch) = &mut batches[slot] {
					changed = mark(
						batch,
						db,
						model,
						database,
						(code == 5).then_some(id),
						1000 + step as i64,
					);
				}
			},
			7..=9 | 12 => {
				if index < ROWS {
					let row = &mut model.rows[index];
					if code == 9 {
						must(db.with_conn(|conn| {
							conn.execute(
								"UPDATE findings SET state='dismissed' WHERE id=?1",
								[id],
							)?;
							Ok(())
						}));
						if row.present {
							row.state = FindingState::Dismissed;
							changed.push(index);
						}
					} else {
						must(db.with_conn(|conn| {
							conn.execute("DELETE FROM findings WHERE id=?1", [id])?;
							Ok(())
						}));
						row.present = code != 7;
						if row.present {
							row.incarnation += 1;
							row.state = FindingState::Confirmed;
							row.reported = None;
							row.malformed = code == 12;
							insert_row(db, index, *row);
						}
						changed.push(index);
					}
				}
			},
			11 => {
				model.fail_delivery = !model.fail_delivery;
				must(db.with_conn(|conn| { conn.execute_batch(if model.fail_delivery { "CREATE TRIGGER sequence_fail BEFORE UPDATE OF state ON findings WHEN OLD.id IN (2,5) AND NEW.state='reported' BEGIN SELECT RAISE(ABORT,'sequence delivery failure'); END;" } else { "DROP TRIGGER sequence_fail;" })?; Ok(()) }));
			},
			_ => unreachable!(),
		}
		for (other, before) in before.into_iter().enumerate() {
			if other == database {
				unchanged_except(
					before,
					snapshot(&dbs[other]),
					&changed,
					changed_job,
					completed_repo,
				);
			} else {
				assert_eq!(before, snapshot(&dbs[other]), "operation wrote to the other database");
			}
			check_model(&dbs[other], &models[other]);
		}
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn bounded_scope_sequence_combinations() {
		// Deterministic broad smoke exploration; the fuzz campaign mutates the
		// retained corpus independently rather than relying on this generator.
		let mut state = 0x1234_5678_9abc_def0u64;
		for _ in 0..32 {
			let mut data = [0u8; super::OPS * 4];
			for byte in &mut data {
				state ^= state << 13;
				state ^= state >> 7;
				state ^= state << 17;
				*byte = state as u8;
			}
			super::exercise(&data);
		}
	}

	#[test]
	fn retained_scope_sequences() {
		for seed in [
			include_bytes!("../../../fuzz/test_cases/storage_scope_sequence/cross-database")
				.as_slice(),
			include_bytes!("../../../fuzz/test_cases/storage_scope_sequence/nonmember"),
			include_bytes!("../../../fuzz/test_cases/storage_scope_sequence/reused-id"),
			include_bytes!("../../../fuzz/test_cases/storage_scope_sequence/partial-success"),
			include_bytes!("../../../fuzz/test_cases/storage_scope_sequence/lease-boundaries"),
			include_bytes!("../../../fuzz/test_cases/storage_scope_sequence/rollback-malformed"),
			include_bytes!("../../../fuzz/test_cases/storage_scope_sequence/malformed-trailing"),
		] {
			super::exercise(seed);
		}
	}
}
