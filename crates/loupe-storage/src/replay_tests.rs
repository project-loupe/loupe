use loupe_core::text::policy::Payload;
use loupe_core::text::{Anchor, BoundedJson, Identifier};

use crate::review_tests::{fixture, payload, reason};
use crate::{checkpoints as c, terminal_receipt as t, transaction, Conflict, Error};
#[test]
fn checkpoint_run_owns_the_replay_sequence() {
	// `run` is the API handlers are meant to use: the body never executes on a
	// replay hit, and a reused key with different content is a conflict.
	let db = fixture();
	let key = Identifier::new("owned-sequence").unwrap();
	let calls = std::cell::Cell::new(0);
	let body = |_: &rusqlite::Transaction<'_>| -> crate::Result<BoundedJson<Payload>> {
		calls.set(calls.get() + 1);
		Ok(BoundedJson::new("{\"lead_id\":7}")?)
	};
	db.with_conn(|conn| {
		let first = transaction::immediate(conn, |tx| {
			c::run(tx, 101, c::Operation::SubmitLead, &key, &[1; 32], 0, body)
		})?;
		assert!(matches!(first, c::Outcome::Fresh(ref r) if r.expose() == "{\"lead_id\":7}"));
		let second = transaction::immediate(conn, |tx| {
			c::run(tx, 101, c::Operation::SubmitLead, &key, &[1; 32], 1, body)
		})?;
		assert!(matches!(second, c::Outcome::Replayed(ref r) if r.expose() == "{\"lead_id\":7}"));
		assert_eq!(calls.get(), 1, "a replay must not re-run the domain body");
		let conflict = transaction::immediate(conn, |tx| {
			c::run(tx, 101, c::Operation::SubmitLead, &key, &[2; 32], 2, body)
		});
		assert!(matches!(conflict, Err(Error::Conflict(Conflict::Checkpoint))));
		assert_eq!(calls.get(), 1, "a conflicting reuse must not run the body either");
		Ok(())
	})
	.unwrap();
}
#[test]
fn replay_lookup_prevents_repeating_domain_side_effects() {
	use crate::identity::Identity;
	use crate::leads as l;
	use crate::review_units::Priority;
	let db = fixture();
	let key = Identifier::new("lead-command").unwrap();
	let data = payload();
	let identity = Identity {
		family: Identifier::new("auth-bypass").unwrap(),
		anchor: Anchor::new("token refresh").unwrap(),
		instance: None,
	};
	let submit = |tx: &rusqlite::Transaction<'_>| -> crate::Result<_> {
		if let Some(response) = c::lookup(tx, 101, c::Operation::SubmitLead, &key, &[1; 32])? {
			return Ok(response);
		}
		let outcome = l::submit(
			tx,
			&l::NewLead {
				generation_id: 11,
				unit_id: None,
				identity: &identity,
				payload: &data,
				commit_sha: "base",
				priority: Priority::Normal,
				priority_proposal: None,
				supersedes: None,
				created_by_job: Some(101),
			},
			0,
		)?;
		let id = match outcome {
			l::Submitted::Created(id) | l::Submitted::Attached { lead_id: id, .. } => id,
			_ => panic!("open lead"),
		};
		let response = BoundedJson::new(&format!("{{\"lead_id\":{id}}}"))?;
		c::record_or_replay(tx, 101, c::Operation::SubmitLead, &key, &[1; 32], &response, 0)?;
		Ok(response)
	};
	db.with_conn(|conn| {
		let first = transaction::immediate(conn, submit)?;
		let replayed = transaction::immediate(conn, submit)?;
		assert_eq!(replayed, first);
		let id = l::list(conn, 11)?[0].lead_id;
		assert!(
			crate::lead_observations::list(conn, id)?.is_empty(),
			"checkpoint replay must not repeat domain side effects"
		);
		transaction::immediate(conn, |tx| {
			assert!(matches!(
				c::lookup(tx, 101, c::Operation::SubmitLead, &key, &[2; 32]),
				Err(Error::Conflict(Conflict::Checkpoint))
			));
			assert!(c::lookup(tx, 102, c::Operation::SubmitLead, &key, &[1; 32])?.is_none());
			Ok(())
		})
	})
	.unwrap();
}
#[test]
fn lease_transaction_composes_checkpoints_and_typed_failures() {
	use crate::jobs::{self, ActiveLease, LeaseIdentity};
	let db = fixture();
	db.with_conn(|conn|{
  conn.execute_batch("INSERT INTO workers VALUES(1,'worker','worker',x'01',0,0,NULL); UPDATE jobs SET kind='scan',state='leased',worker_id=1,lease_expires_at=10,job_capability_hash=zeroblob(32) WHERE id=101;")?;
  let lease=ActiveLease{identity:LeaseIdentity{job_id:101,worker_id:1,capability_hash:&[0;32]},now:5};
  let key=Identifier::new("typed-transaction").unwrap();
  let result:crate::Result<Option<()>>=jobs::with_active_lease_transaction(conn,lease,|tx,_|{
   c::record_or_replay(tx,101,c::Operation::SubmitLead,&key,&[1;32],&payload(),0)?;
   Err(Error::Conflict(Conflict::LeadState))
  });
  assert!(matches!(result,Err(Error::Conflict(Conflict::LeadState))));
  assert_eq!(conn.query_row("SELECT COUNT(*) FROM job_checkpoints",[],|r|r.get::<_,i64>(0))?,0);
  let recorded=jobs::with_active_lease_transaction(conn,lease,|tx,_|c::record_or_replay(tx,101,c::Operation::SubmitLead,&key,&[1;32],&payload(),0))?;
  assert_eq!(recorded,Some(c::Recorded::Recorded));
  assert!(jobs::with_active_lease_transaction(conn,ActiveLease{now:11,..lease},|_,_|->crate::Result<()>{panic!("an expired capability cannot enter the mutation")})?.is_none());
  Ok(())
 }).unwrap();
}
#[test]
fn checkpoint_replay_is_scoped_by_operation_job_and_digest() {
	let db = fixture();
	db.with_conn(|conn|transaction::immediate(conn,|tx|{
  let key=Identifier::new("client-key").unwrap();let original=BoundedJson::new("{\"id\":42}").unwrap();
  assert_eq!(c::record_or_replay(tx,101,c::Operation::SubmitLead,&key,&[1;32],&original,0).expect("record first submission"),c::Recorded::Recorded);
  assert_eq!(c::record_or_replay(tx,101,c::Operation::SubmitLead,&key,&[1;32],&payload(),1)?,c::Recorded::Replayed(original));
  assert!(matches!(c::record_or_replay(tx,101,c::Operation::SubmitLead,&key,&[2;32],&payload(),1),Err(Error::Conflict(Conflict::Checkpoint))));
  assert_eq!(c::record_or_replay(tx,101,c::Operation::SubmitReviewUnit,&key,&[2;32],&payload(),1)?,c::Recorded::Recorded);
  assert_eq!(c::record_or_replay(tx,102,c::Operation::SubmitLead,&key,&[2;32],&payload(),1)?,c::Recorded::Recorded);
  tx.execute("UPDATE job_checkpoints SET operation='submit_observation' WHERE job_id=101 AND operation='submit_lead'",[])?;
  assert!(matches!(c::record_or_replay(tx,101,c::Operation::SubmitLead,&key,&[1;32],&payload(),1),Err(Error::Conflict(Conflict::Checkpoint))));
  Ok(())
 })).unwrap();
}
#[test]
fn checkpoint_and_domain_rows_roll_back_together() {
	use crate::identity::Identity;
	use crate::leads as l;
	use crate::review_units::Priority;
	let db = fixture();
	db.with_conn(|conn| {
		let key = Identifier::new("retry").unwrap();
		let data = payload();
		let result: crate::Result<()> = transaction::immediate(conn, |tx| {
			assert_eq!(
				c::record_or_replay(tx, 101, c::Operation::SubmitLead, &key, &[1; 32], &data, 0)?,
				c::Recorded::Recorded
			);
			let identity = Identity {
				family: Identifier::new("auth-bypass").unwrap(),
				anchor: Anchor::new("token refresh").unwrap(),
				instance: None,
			};
			assert!(matches!(
				l::submit(
					tx,
					&l::NewLead {
						generation_id: 11,
						unit_id: None,
						identity: &identity,
						payload: &data,
						commit_sha: "base",
						priority: Priority::Normal,
						priority_proposal: None,
						supersedes: None,
						created_by_job: Some(101)
					},
					0
				)?,
				l::Submitted::Created(_)
			));
			Err(Error::Conflict(Conflict::CampaignState))
		});
		assert!(
			matches!(result, Err(Error::Conflict(Conflict::CampaignState))),
			"failure must occur after both writes"
		);
		assert!(l::list(conn, 11)?.is_empty());
		assert_eq!(
			conn.query_row("SELECT COUNT(*) FROM job_checkpoints", [], |r| r.get::<_, i64>(0))?,
			0
		);
		assert_eq!(
			c::standalone::record_or_replay(
				conn,
				101,
				c::Operation::SubmitLead,
				&key,
				&[1; 32],
				&data,
				1
			)?,
			c::Recorded::Recorded
		);
		Ok(())
	})
	.unwrap();
}
#[test]
fn terminal_replay_rejects_each_incomplete_or_wrong_binding() {
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			fn rejected(value: t::Replayed, expected: t::Reject) {
				assert!(
					matches!(value,t::Replayed::Reject(actual) if actual==expected),
					"expected {expected:?}"
				);
			}
			rejected(t::replay_terminal(tx, 999, &[1; 32], &[2; 32])?, t::Reject::MissingJob);
			rejected(t::replay_terminal(tx, 101, &[1; 32], &[2; 32])?, t::Reject::NonterminalJob);
			tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101", [])?;
			rejected(t::replay_terminal(tx, 101, &[1; 32], &[2; 32])?, t::Reject::MissingReceipt);
			let data = payload();
			let why = reason();
			let new = t::NewReceipt {
				job_id: 101,
				phase: loupe_core::JobKind::Survey,
				terminal_reason: &why,
				subject_title: None,
				subject_digest: None,
				pinned_commit_sha: "base",
				effective_recipe: &data,
				result_digest: &[2; 32],
				evidence_rung: Some(t::EvidenceRung::L1),
				result_counts: Some(&data),
				finishing_capability_hash: Some(&[1; 32]),
			};
			t::insert(tx, &new, 1)?;
			assert!(
				matches!(t::replay_terminal(tx,101,&[1;32],&[2;32])?,t::Replayed::Receipt(r) if r.job_id==101)
			);
			rejected(t::replay_terminal(tx, 101, &[9; 32], &[2; 32])?, t::Reject::WrongCapability);
			rejected(t::replay_terminal(tx, 101, &[1; 32], &[9; 32])?, t::Reject::WrongDigest);
			tx.execute(
				"UPDATE job_terminal_receipts SET finishing_capability_hash=NULL WHERE job_id=101",
				[],
			)?;
			rejected(
				t::replay_terminal(tx, 101, &[1; 32], &[2; 32])?,
				t::Reject::MissingCapability,
			);
			assert!(matches!(
				t::insert(tx, &new, 2),
				Err(Error::Conflict(Conflict::TerminalReceipt))
			));
			assert_eq!(t::get(tx, 101)?.unwrap().terminal_reason, why);
			Ok(())
		})
	})
	.unwrap();
}
