use std::cell::RefCell;
use std::sync::{mpsc, Arc};
use std::time::Duration;

use rusqlite::{params, Connection};

use super::*;
use crate::secrets::MasterKey;

const HASH: [u8; 32] = [7; 32];
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn ordinary_assignment_snapshot_requires_domain_readiness() {
	let db = fixture();
	mutate(&db,"UPDATE review_generations SET generated_profile=NULL,generated_profile_digest=NULL WHERE generation_id=11");
	with_phase_transaction(
		&db,
		identity(),
		|| 100,
		|tx| {
			let scope = tx
				.authorize(Phase::Survey, Access::PreparedHost, |_| {
					Ok(Some(PolicyDecision::Ordinary))
				})?
				.unwrap();
			assert!(
				scope.preparation_snapshot().is_err(),
				"ordinary assignments require Domain readiness, not checkout preparation alone"
			);
			Ok::<_, Error>(())
		},
	)
	.unwrap();
}

#[test]
fn preparation_snapshot_requires_prepared_purpose_and_keeps_content_sources() {
	let db = fixture();
	mutate(&db, "INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,closure_criteria,assignment_epoch,created_by_job_id,created_at) VALUES(31,11,'owned','title','objective','[]','closure',3,101,0); INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch) VALUES(101,31,0,3);");
	for access in [Access::LeaseControl, Access::Checkout, Access::PreparedHost, Access::Domain] {
		with_phase_transaction(
			&db,
			identity(),
			|| 100,
			|tx| {
				let scope = tx
					.authorize(Phase::Survey, access, |_| Ok(Some(PolicyDecision::Ordinary)))?
					.unwrap();
				let snapshot = scope.preparation_snapshot();
				if access != Access::Domain {
					assert!(snapshot.is_err());
				} else {
					let snapshot = snapshot?;
					assert_eq!(snapshot.commit.expose(), SHA);
					let _: loupe_core::review_payload::GeneratedProfile<loupe_provenance::Agent> =
						snapshot.profile.unwrap().profile;
					let units = snapshot.assignments.unwrap();
					assert_eq!(units.len(), 1);
					assert_eq!(units[0].id, 31);
					assert_eq!(units[0].epoch, 3);
					assert_eq!(units[0].closure_criteria.as_ref().unwrap().expose(), "closure");
				}
				Ok::<_, Error>(())
			},
		)
		.unwrap();
	}
	with_phase_transaction(
		&db,
		identity(),
		|| 100,
		|tx| {
			let scope = tx
				.authorize(Phase::Survey, Access::PreparedHost, |_| {
					Ok(Some(PolicyDecision::Bootstrap))
				})?
				.unwrap();
			let snapshot = scope.preparation_snapshot()?;
			assert_eq!(snapshot.commit.expose(), SHA);
			assert!(
				snapshot.assignments.is_none(),
				"bootstrap preparation carries no ordinary assignments"
			);
			Ok::<_, Error>(())
		},
	)
	.unwrap();
}

#[test]
fn preparation_snapshot_refuses_foreign_stale_or_incompatible_assignments() {
	for sql in [
		"UPDATE job_assigned_review_units SET assignment_epoch=2",
		"UPDATE review_units SET generation_id=21",
		"UPDATE review_units SET source='db'",
		"UPDATE review_units SET depends_on='[999]'",
		"UPDATE review_units SET source_refs='[{\"path\":\"missing.rs\"}]'",
		"UPDATE review_units SET closure_criteria=printf('%010000d',0)",
	] {
		let db = fixture();
		mutate(&db,"INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,assignment_epoch,created_by_job_id,created_at) VALUES(31,11,'owned','title','objective','[]',3,101,0); INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch) VALUES(101,31,0,3);");
		mutate(&db, sql);
		with_phase_transaction(
			&db,
			identity(),
			|| 100,
			|tx| {
				let scope = tx
					.authorize(Phase::Survey, Access::Domain, |_| {
						Ok(Some(PolicyDecision::Ordinary))
					})?
					.unwrap();
				assert!(scope.preparation_snapshot().is_err(), "{sql}");
				Ok::<_, Error>(())
			},
		)
		.unwrap();
	}
}

#[test]
fn domain_authority_requires_agent_profile_classification() {
	for source in ["operator", "db", "worker", "unknown"] {
		let db = fixture();
		assert!(allowed(&db, identity(), Phase::Survey, Access::Domain, 100));
		db.with_conn(|conn| {
			conn.execute(
				"UPDATE review_generations SET generated_profile_source=?1 WHERE generation_id=11",
				[source],
			)?;
			Ok(())
		})
		.unwrap();
		assert!(allowed(&db, identity(), Phase::Survey, Access::LeaseControl, 100));
		assert!(allowed(&db, identity(), Phase::Survey, Access::PreparedHost, 100));
		assert!(
			!allowed(&db, identity(), Phase::Survey, Access::Domain, 100),
			"non-Agent profile must not authorize domain work: {source}"
		);
	}
}

fn terminal_payload(notes: Option<&str>) -> crate::terminal_payloads::TerminalPayload {
	let raw =
		serde_json::json!({"version":1,"terminal_reason":"completed","security_model_notes":notes})
			.to_string();
	crate::terminal_payloads::TerminalPayload::Survey(
		crate::test_support::agent(&raw, |raw, mark| {
			loupe_core::review_payload::SurveyTerminalV1::from_json(mark, raw)
		})
		.unwrap(),
	)
}
fn finish(db: &crate::Db) {
	db.with_conn(|conn| crate::transaction::immediate(conn, |tx| {
		crate::terminal_receipt::insert(
			&crate::test_support::scope(tx, 1),
			&crate::terminal_receipt::NewReceipt::<loupe_provenance::Db, loupe_provenance::Agent, loupe_provenance::Agent, loupe_provenance::Agent, loupe_provenance::Agent> {
				job_id:101, phase:JobKind::Survey,
				terminal_reason:&crate::test_support::text("completed").unwrap(),
				subject_title:None, subject_digest:None,
				pinned_commit_sha:&crate::test_support::db_text(SHA).unwrap(),
				effective_recipe:&crate::test_support::json("{}").unwrap(),
				result_digest:&terminal_payload(None).digest()?, evidence_rung:None,
				result_counts:None, finishing_capability_hash:Some(&HASH),
			},100,
		)?;
		tx.execute("UPDATE jobs SET state='succeeded',job_capability_hash=NULL,lease_expires_at=NULL WHERE id=101",[])?;
		Ok(())
	})).unwrap();
}
fn replay(
	db: &crate::Db, identity: jobs::LeaseIdentity<'_>, phase: Phase, notes: Option<&str>,
) -> Result<crate::terminal_receipt::Replayed> {
	with_phase_transaction(
		db,
		identity,
		|| i64::MAX,
		|tx| tx.replay_terminal(phase, &terminal_payload(notes)),
	)
}

#[test]
fn terminal_facade_replays_without_live_or_derived_state() {
	use crate::terminal_receipt::{Reject, Replayed};
	let db = fixture();
	finish(&db);
	mutate(&db,"DELETE FROM review_generations WHERE generation_id=11; UPDATE review_campaigns SET state='cancelled'; UPDATE jobs SET recipe=x'ff',head_sha=x'ff',hard_deadline_at=x'ff',workflow_contract_version=x'ff',prepared_attempt=NULL,prepared_capability_hash=NULL,prepared_at=NULL WHERE id=101;");
	assert!(
		matches!(replay(&db,identity(),Phase::Survey,None).unwrap(),Replayed::Receipt(receipt) if receipt.job_id==101)
	);
	assert!(matches!(
		replay(&db, identity(), Phase::Survey, Some("different")).unwrap(),
		Replayed::Reject(Reject::WrongDigest)
	));
	for sql in [
		"UPDATE workers SET revoked_at=1 WHERE id=1",
		"UPDATE workers SET kind='admin' WHERE id=1",
		"UPDATE jobs SET worker_id=2 WHERE id=101",
		"UPDATE jobs SET worker_id=NULL WHERE id=101",
		"UPDATE jobs SET campaign_id=NULL WHERE id=101",
		"UPDATE jobs SET state='queued' WHERE id=101",
		"UPDATE jobs SET kind='verify' WHERE id=101",
		"UPDATE job_terminal_receipts SET finishing_capability_hash=NULL WHERE job_id=101",
	] {
		let db = fixture();
		finish(&db);
		assert!(matches!(
			replay(&db, identity(), Phase::Survey, None).unwrap(),
			Replayed::Receipt(_)
		));
		mutate(&db, sql);
		assert!(
			matches!(
				replay(&db, identity(), Phase::Survey, None).unwrap(),
				Replayed::Reject(Reject::Denied)
			),
			"{sql}"
		);
	}
}

#[test]
fn terminal_facade_checks_binding_before_receipt_decode_or_digest_oracle() {
	use crate::terminal_receipt::{Reject, Replayed};
	let db = fixture();
	finish(&db);
	for malformed in [false, true] {
		if malformed {
			mutate(
				&db,
				"UPDATE job_terminal_receipts SET effective_recipe='broken JSON' WHERE job_id=101",
			);
		}
		for (identity, phase) in [
			(jobs::LeaseIdentity { job_id: 999, ..identity() }, Phase::Survey),
			(jobs::LeaseIdentity { worker_id: 2, ..identity() }, Phase::Survey),
			(jobs::LeaseIdentity { capability_hash: &[9; 32], ..identity() }, Phase::Survey),
			(jobs::LeaseIdentity { capability_hash: &[7; 31], ..identity() }, Phase::Survey),
			(identity(), Phase::Drilldown),
		] {
			assert!(matches!(
				replay(&db, identity, phase, Some("different")).unwrap(),
				Replayed::Reject(Reject::Denied)
			));
		}
	}
	assert!(
		replay(&db, identity(), Phase::Survey, None).is_err(),
		"the authorized binding reaches the actually corrupt receipt"
	);
}

#[test]
fn phase_checkpoint_replay_precedes_fresh_subject_checks_and_rolls_back() {
	use crate::checkpoints::{self, Operation, Outcome};
	let db = fixture();
	mutate(&db,"INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,assignment_epoch,created_by_job_id,created_at) VALUES(31,11,'owned','title','objective','[]',3,101,0); INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch) VALUES(101,31,0,3);");
	let key = crate::test_support::identifier("result").unwrap();
	for expect_replay in [false, true] {
		with_phase_transaction(
			&db,
			identity(),
			|| 100,
			|tx| {
				let auth = tx
					.authorize(Phase::Survey, Access::Domain, |_| {
						Ok(Some(PolicyDecision::Ordinary))
					})?
					.unwrap();
				let outcome = checkpoints::run(
					&crate::test_support::scope(auth.transaction.conn, 1),
					101,
					Operation::SubmitUnitResult,
					&key,
					&[7; 32],
					100,
					|scope| {
						assert!(!expect_replay, "fresh callback must not run on exact replay");
						assert!(auth.survey_unit(31, 3)?);
						scope.conn.execute(
							"UPDATE review_units SET status='retired' WHERE review_unit_id=31",
							[],
						)?;
						Ok(crate::test_support::json("{\"unit_id\":31}")?)
					},
				)?;
				assert_eq!(matches!(outcome, Outcome::Replayed(_)), expect_replay);
				Ok::<_, Error>(())
			},
		)
		.unwrap();
	}
	mutate(&db, "UPDATE review_units SET status='open' WHERE review_unit_id=31");
	let failed: Result<()> = with_phase_transaction(
		&db,
		identity(),
		|| 100,
		|tx| {
			let auth = tx
				.authorize(Phase::Survey, Access::Domain, |_| Ok(Some(PolicyDecision::Ordinary)))?
				.unwrap();
			checkpoints::run::<_, loupe_provenance::Agent>(
				&crate::test_support::scope(auth.transaction.conn, 1),
				101,
				Operation::SubmitUnitResult,
				&crate::test_support::identifier("rollback").unwrap(),
				&[8; 32],
				100,
				|scope| {
					assert!(auth.survey_unit(31, 3)?);
					scope.conn.execute(
						"UPDATE review_units SET status='retired' WHERE review_unit_id=31",
						[],
					)?;
					Err(Error::Conflict(crate::Conflict::UnitState))
				},
			)?;
			Ok(())
		},
	);
	assert!(matches!(failed, Err(Error::Conflict(crate::Conflict::UnitState))));
	db.with_conn(|conn| {
		assert_eq!(
			conn.query_row("SELECT COUNT(*) FROM job_checkpoints", [], |row| row.get::<_, i64>(0))?,
			1
		);
		assert_eq!(
			conn.query_row("SELECT status FROM review_units WHERE review_unit_id=31", [], |row| {
				row.get::<_, String>(0)
			})?,
			"open"
		);
		Ok(())
	})
	.unwrap();
}

pub(super) fn identity() -> jobs::LeaseIdentity<'static> {
	jobs::LeaseIdentity { job_id: 101, worker_id: 1, capability_hash: &HASH }
}
fn seed(db: &crate::Db) {
	db.with_conn(|conn| {
		conn.execute_batch("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at)
		 VALUES(1,'u1','github.com','o','r1','{\"kind\":\"manual\"}',0),(2,'u2','github.com','o','r2','{\"kind\":\"manual\"}',0);
		 INSERT INTO workers VALUES(1,'worker','worker',x'01',0,0,NULL),(2,'other','worker',x'02',0,0,NULL);
		 INSERT INTO review_generations(generation_id,repo_id,generation_commit_sha,state,workflow_contract_version,created_at)
		 VALUES(11,1,'placeholder','active',1,0),(21,2,'foreign','active',1,0);
		 INSERT INTO review_campaigns(campaign_id,repo_id,recipe,trigger,target_commit_sha,generation_id,state,effective_policy,effective_policy_digest,deadline_at,created_at)
		 VALUES(1,1,'bootstrap','manual','placeholder',11,'active','{}',zeroblob(32),1000,0);
		 INSERT INTO jobs(id,repo_id,kind,state,campaign_id,generation_id,worker_id,lease_expires_at,attempts,workflow_contract_version,recipe,hard_deadline_at,enqueued_at)
		 VALUES(101,1,'survey','leased',1,11,1,500,2,1,'{\"version\":1,\"phase\":\"survey\",\"recipe\":\"coverage\",\"assignment_key\":\"ordinary\"}',1000,0);
		 INSERT INTO generation_manifests(generation_id,format_version,owner_job_id,expected_entry_count,expected_digest,created_at,sealed_at)
		 VALUES(11,1,101,0,zeroblob(32),0,1);")?;
		conn.execute("UPDATE jobs SET head_sha=?1,job_capability_hash=?2,prepared_attempt=2,prepared_capability_hash=?2,prepared_at=1 WHERE id=101", params![SHA,HASH.as_slice()])?;
		conn.execute("UPDATE jobs SET workflow_contract_version=?1", [WORKFLOW_CONTRACT_VERSION])?;
		conn.execute("UPDATE review_generations SET workflow_contract_version=?1", [WORKFLOW_CONTRACT_VERSION])?;
		conn.execute("UPDATE review_campaigns SET target_commit_sha=?1", [SHA])?;
		let digest = loupe_core::canonical::digest(b"{}");
		conn.execute("UPDATE review_generations SET generation_commit_sha=?1,profile_version=1,generated_profile='{}',generated_profile_digest=?2 WHERE generation_id=11", params![SHA,digest.as_slice()])?;
		Ok(())
	}).unwrap();
}
pub(super) fn fixture() -> crate::Db {
	let db = crate::Db::open_in_memory(&MasterKey::for_tests()).unwrap();
	seed(&db);
	db
}
pub(super) fn mutate(db: &crate::Db, sql: &str) {
	db.with_conn(|conn| {
		conn.execute_batch(sql)?;
		Ok(())
	})
	.unwrap_or_else(|error| panic!("fixture mutation failed: {sql}: {error}"));
}
fn allowed(
	db: &crate::Db, identity: jobs::LeaseIdentity<'_>, phase: Phase, access: Access, now: i64,
) -> bool {
	with_phase_transaction(
		db,
		identity,
		|| now,
		|tx| {
			Ok::<_, crate::Error>(
				tx.authorize(phase, access, |_| Ok(Some(PolicyDecision::Ordinary)))?.is_some(),
			)
		},
	)
	.unwrap()
}

#[test]
fn exact_lease_expiry_is_authorized_but_next_tick_is_not() {
	let db = fixture();
	for access in [Access::LeaseControl, Access::Checkout, Access::PreparedHost, Access::Domain] {
		assert!(
			allowed(&db, identity(), Phase::Survey, access, 500),
			"the exact expiry instant remains authorized: {access:?}"
		);
		assert!(!allowed(&db, identity(), Phase::Survey, access, 501));
	}
}

#[test]
fn identity_revocation_is_rechecked_for_every_purpose() {
	for sql in [
		"UPDATE workers SET revoked_at=1 WHERE id=1",
		"UPDATE workers SET kind='admin' WHERE id=1",
		"UPDATE jobs SET worker_id=2 WHERE id=101",
		"UPDATE jobs SET state='queued' WHERE id=101",
		"UPDATE jobs SET lease_expires_at=99 WHERE id=101",
		"UPDATE jobs SET lease_expires_at=x'ff' WHERE id=101",
		"UPDATE jobs SET attempts=x'ff' WHERE id=101",
		"UPDATE jobs SET attempts=0 WHERE id=101",
		"UPDATE jobs SET campaign_id=NULL WHERE id=101",
		"UPDATE jobs SET job_capability_hash=zeroblob(32) WHERE id=101",
	] {
		let db = fixture();
		assert!(allowed(&db, identity(), Phase::Survey, Access::Domain, 100));
		mutate(&db, sql);
		for access in [Access::LeaseControl, Access::Checkout, Access::PreparedHost, Access::Domain]
		{
			assert!(!allowed(&db, identity(), Phase::Survey, access, 100), "{sql}: {access:?}");
		}
	}
	let db = fixture();
	for bad in [
		jobs::LeaseIdentity { worker_id: 2, ..identity() },
		jobs::LeaseIdentity { job_id: 999, ..identity() },
		jobs::LeaseIdentity { capability_hash: &[0; 32], ..identity() },
		jobs::LeaseIdentity { capability_hash: &[7; 31], ..identity() },
	] {
		assert!(!allowed(&db, bad, Phase::Survey, Access::LeaseControl, 100));
	}
	assert!(!allowed(&db, identity(), Phase::Verify, Access::LeaseControl, 100));
}

#[test]
fn lease_control_does_not_decode_context_or_invoke_policy() {
	for sql in [
		"UPDATE jobs SET recipe=x'ff',head_sha=x'ff',hard_deadline_at=x'ff',workflow_contract_version=x'ff' WHERE id=101",
		"UPDATE review_campaigns SET state='cancelled',deadline_at=100",
		"UPDATE review_generations SET generated_profile=x'ff',generated_profile_digest=x'ff',profile_version=1.5 WHERE generation_id=11",
		"DELETE FROM review_generations WHERE generation_id=11",
	] {
		let db = fixture();
		mutate(&db, sql);
		with_phase_transaction(&db, identity(), || 100, |tx| {
			let scope = tx.authorize(Phase::Survey, Access::LeaseControl, |_| panic!("control must not consult recipe policy"))?.unwrap();
			assert_eq!(scope.job().id, 101);
			assert!(!scope.survey_unit(1, 1)?);
			assert!(!scope.assigned_lead(1)?);
			assert!(!scope.assigned_finding(1)?);
			Ok::<_, crate::Error>(())
		}).unwrap();
	}
}

#[test]
fn campaign_and_hard_deadlines_remain_exclusive() {
	for sql in [
		"UPDATE review_campaigns SET deadline_at=100",
		"UPDATE review_campaigns SET deadline_at=x'ff'",
		"UPDATE jobs SET hard_deadline_at=100 WHERE id=101",
		"UPDATE jobs SET hard_deadline_at=NULL WHERE id=101",
	] {
		let db = fixture();
		mutate(&db, sql);
		assert!(allowed(&db, identity(), Phase::Survey, Access::LeaseControl, 100));
		for access in [Access::Checkout, Access::PreparedHost, Access::Domain] {
			assert!(!allowed(&db, identity(), Phase::Survey, access, 100));
		}
	}
}

#[test]
fn context_bindings_preparation_and_readiness_are_storage_owned() {
	for (sql, checkout, prepared) in [
		("UPDATE jobs SET prepared_attempt=1 WHERE id=101", true, false),
		("UPDATE jobs SET prepared_capability_hash=zeroblob(32) WHERE id=101", true, false),
		("UPDATE jobs SET prepared_at=101 WHERE id=101", true, false),
		("UPDATE jobs SET head_sha='old' WHERE id=101", true, false),
		("PRAGMA foreign_keys=OFF; UPDATE review_campaigns SET repo_id=2; PRAGMA foreign_keys=ON", false, false),
		("UPDATE generation_manifests SET owner_job_id=NULL; UPDATE jobs SET generation_id=21 WHERE id=101", false, false),
		("UPDATE jobs SET workflow_contract_version=0 WHERE id=101", false, false),
		("UPDATE review_generations SET workflow_contract_version=0 WHERE generation_id=11", false, false),
		("UPDATE generation_manifests SET sealed_at=NULL", true, true),
		("UPDATE review_generations SET generated_profile='[]' WHERE generation_id=11", true, true),
		("UPDATE review_generations SET generated_profile_digest=zeroblob(32) WHERE generation_id=11", true, true),
		("UPDATE review_generations SET profile_version=4294967296 WHERE generation_id=11", true, true),
	] {
		let db = fixture();
		assert!(allowed(&db, identity(), Phase::Survey, Access::Domain, 100));
		mutate(&db, sql);
		assert_eq!(allowed(&db, identity(), Phase::Survey, Access::Checkout, 100), checkout, "{sql}");
		assert_eq!(allowed(&db, identity(), Phase::Survey, Access::PreparedHost, 100), prepared, "{sql}");
		assert!(!allowed(&db, identity(), Phase::Survey, Access::Domain, 100), "{sql}");
	}
}

#[test]
fn policy_sees_exact_original_recipe_and_db_owned_revisions() {
	let db = fixture();
	let recipe = "{ \"phase\":\"survey\",\"phase\":\"verify\" }";
	let called = std::cell::Cell::new(false);
	db.with_conn(|conn| {
		conn.execute("UPDATE jobs SET recipe=?1 WHERE id=101", [recipe])?;
		Ok(())
	})
	.unwrap();
	with_phase_transaction(
		&db,
		identity(),
		|| 100,
		|tx| {
			assert!(
				tx.authorize(Phase::Survey, Access::Checkout, |context| {
					called.set(true);
					let _: &BoundedText<RevisionText, DbSource> = &context.target_commit;
					assert_eq!(context.recipe.as_ref().unwrap().expose(), recipe);
					Ok(None)
				})?
				.is_none(),
				"server policy refusal cannot grant authority"
			);
			Ok::<_, crate::Error>(())
		},
	)
	.unwrap();
	assert!(called.get(), "the valid fixture must reach server recipe policy");
}

fn units(db: &crate::Db) {
	mutate(db, "INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,assignment_epoch,created_by_job_id,created_at)
	 VALUES(31,11,'owned','title','objective','[]',3,101,0),(32,11,'other','title','objective','[]',3,NULL,0),(41,21,'foreign','title','objective','[]',3,NULL,0);
	 INSERT INTO job_assigned_review_units(job_id,review_unit_id,position,assignment_epoch) VALUES(101,31,0,3);");
}
fn unit_allowed(db: &crate::Db, id: i64, epoch: i64, decision: PolicyDecision) -> bool {
	with_phase_transaction(
		db,
		identity(),
		|| 100,
		|tx| {
			tx.authorize(Phase::Survey, Access::Domain, |_| Ok(Some(decision)))?
				.unwrap()
				.survey_unit(id, epoch)
		},
	)
	.unwrap()
}
#[test]
fn survey_subjects_require_exact_membership_epoch_and_freshness() {
	let db = fixture();
	units(&db);
	assert!(unit_allowed(&db, 31, 3, PolicyDecision::Ordinary));
	for id in [32, 41, 999] {
		assert!(!unit_allowed(&db, id, 3, PolicyDecision::Ordinary));
	}
	assert!(!unit_allowed(&db, 31, 2, PolicyDecision::Ordinary));
	for sql in [
		"UPDATE job_assigned_review_units SET assignment_epoch=NULL",
		"UPDATE job_assigned_review_units SET assignment_epoch=2",
		"UPDATE review_units SET assignment_epoch=4 WHERE review_unit_id=31",
		"UPDATE review_units SET stale=1 WHERE review_unit_id=31",
		"UPDATE review_units SET status='retired' WHERE review_unit_id=31",
	] {
		let db = fixture();
		units(&db);
		mutate(&db, sql);
		assert!(!unit_allowed(&db, 31, 3, PolicyDecision::Ordinary), "{sql}");
	}
	// A conclusive control needs current Recorded evidence. Historical '{}'
	// is retained, but deliberately cannot certify modern coverage.
	let covered_db = fixture();
	units(&covered_db);
	assert!(unit_allowed(&covered_db, 31, 3, PolicyDecision::Ordinary));
	covered_db.with_conn(|conn| {
		conn.execute("UPDATE generation_manifests SET expected_entry_count=1,received_entry_count=1 WHERE generation_id=11",[])?;
		conn.execute("INSERT INTO generation_inventory(generation_id,path,source_path,raw_path,blob_sha,entry_kind,git_mode,manifest_position,disposition,created_at) VALUES(11,'src.rs','src.rs',?1,?2,'tracked',33188,0,'context',0)",params![b"src.rs".as_slice(),SHA])?;
		let payload=crate::test_support::agent(&serde_json::json!({"format":"loupe.unit_result","version":1,"review_unit_id":31,"assignment_epoch":3,"disposition":"no_lead_found","inspected_refs":[{"path":"src.rs"}],"created_lead_ids":[],"counterevidence":"Guard traced","proof_gaps":"None"}).to_string(),|raw,mark|loupe_core::review_payload::UnitResultPayloadV1::from_json(mark,raw))?;
		crate::review_unit_results::insert_evidence(&crate::test_support::scope(conn,1),&crate::review_unit_results::NewResultEvidence{generation_id:11,produced_by_job:101,commit_sha:&crate::test_support::db_text(SHA)?,profile_version:1,payload:&payload},100)?;
		Ok(())
	}).unwrap();
	assert!(
		!unit_allowed(&covered_db, 31, 3, PolicyDecision::Ordinary),
		"current conclusive evidence excludes another fresh result"
	);
	mutate(&db, "DELETE FROM job_assigned_review_units");
	assert!(!unit_allowed(&db, 31, 3, PolicyDecision::Ordinary));
	assert!(unit_allowed(&db, 31, 3, PolicyDecision::Bootstrap));
	assert!(!unit_allowed(&db, 32, 3, PolicyDecision::Bootstrap));
}

#[test]
fn child_subjects_are_exact_phase_and_repository_bound() {
	for phase in [Phase::Drilldown, Phase::Verify] {
		let db = fixture();
		mutate(&db,"INSERT INTO leads(lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at)
		 VALUES(31,11,'family','anchor',zeroblob(32),'{}',zeroblob(32),'base',0),(41,21,'family','anchor',zeroblob(32),'{}',zeroblob(32),'foreign',0);
		 INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,created_at,report_identity)
		 VALUES(51,1,101,'test','high','title','description','a',0,x'11111111111111111111111111111111'),(61,2,101,'test','high','title','description','b',0,x'22222222222222222222222222222222');");
		db.with_conn(|conn| {
			conn.execute(
				"UPDATE jobs SET kind=?1,assigned_lead_id=?2,target_finding_id=?3 WHERE id=101",
				params![
					phase.job_kind().as_str(),
					(phase == Phase::Drilldown).then_some(31),
					(phase == Phase::Verify).then_some(51)
				],
			)?;
			Ok(())
		})
		.unwrap();
		with_phase_transaction(
			&db,
			identity(),
			|| 100,
			|tx| {
				let scope = tx
					.authorize(phase, Access::Domain, |_| Ok(Some(PolicyDecision::Ordinary)))?
					.unwrap();
				assert_eq!(scope.assigned_lead(31)?, phase == Phase::Drilldown);
				assert_eq!(scope.assigned_finding(51)?, phase == Phase::Verify);
				for id in [41, 61, 999] {
					assert!(!scope.assigned_lead(id)?);
					assert!(!scope.assigned_finding(id)?);
				}
				assert!(!scope.survey_unit(31, 3)?);
				Ok::<_, crate::Error>(())
			},
		)
		.unwrap();
	}
}

#[test]
fn child_jobs_require_their_own_owned_subject() {
	for (phase, lead, finding, expected) in [
		(Phase::Drilldown, Some(31), None, true),
		(Phase::Drilldown, Some(41), None, false),
		(Phase::Drilldown, None, Some(51), false),
		(Phase::Verify, None, Some(51), true),
		(Phase::Verify, None, Some(61), false),
		(Phase::Verify, Some(31), None, false),
	] {
		let db = fixture();
		mutate(&db,"INSERT INTO leads(lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at)
		 VALUES(31,11,'family','anchor',zeroblob(32),'{}',zeroblob(32),'base',0),(41,21,'family','anchor',zeroblob(32),'{}',zeroblob(32),'foreign',0);
		 INSERT INTO findings(id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,created_at,report_identity)
		 VALUES(51,1,101,'test','high','title','description','a',0,x'11111111111111111111111111111111'),(61,2,101,'test','high','title','description','b',0,x'22222222222222222222222222222222');");
		db.with_conn(|conn| {
			conn.execute(
				"UPDATE jobs SET kind=?1,assigned_lead_id=?2,target_finding_id=?3 WHERE id=101",
				params![phase.job_kind().as_str(), lead, finding],
			)?;
			Ok(())
		})
		.unwrap();
		for access in [Access::Checkout, Access::PreparedHost, Access::Domain] {
			assert_eq!(
				allowed(&db, identity(), phase, access, 100),
				expected,
				"{phase:?} lead={lead:?} finding={finding:?} {access:?}"
			);
		}
	}
}

#[test]
fn prepared_head_must_be_an_oid_matching_target_and_generation() {
	const OTHER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	const UPPER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	for (head, target, generation) in [(SHA, OTHER, SHA), (SHA, SHA, OTHER), (UPPER, UPPER, UPPER)]
	{
		let db = fixture();
		assert!(allowed(&db, identity(), Phase::Survey, Access::PreparedHost, 100));
		db.with_conn(|conn| {
			conn.execute("UPDATE jobs SET head_sha=?1 WHERE id=101", [head])?;
			conn.execute("UPDATE review_campaigns SET target_commit_sha=?1", [target])?;
			conn.execute(
				"UPDATE review_generations SET generation_commit_sha=?1 WHERE generation_id=11",
				[generation],
			)?;
			Ok(())
		})
		.unwrap();
		assert!(allowed(&db, identity(), Phase::Survey, Access::Checkout, 100));
		for access in [Access::PreparedHost, Access::Domain] {
			assert!(
				!allowed(&db, identity(), Phase::Survey, access, 100),
				"head={head} target={target} generation={generation} {access:?}"
			);
		}
	}
}

// debug-ok: test callback errors contain only two closed categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallbackError {
	Storage,
	HttpRender,
}
impl From<crate::Error> for CallbackError {
	fn from(_: crate::Error) -> Self {
		Self::Storage
	}
}
#[test]
fn all_callback_errors_roll_back_before_commit() {
	let db = fixture();
	for error in [CallbackError::HttpRender, CallbackError::Storage] {
		let result = with_phase_transaction(
			&db,
			identity(),
			|| 100,
			|tx| {
				assert!(tx
					.authorize(Phase::Survey, Access::Domain, |_| Ok(Some(
						PolicyDecision::Ordinary
					)))?
					.is_some());
				// White-box stand-in for a future named storage workflow: no SQL
				// accessor is exposed to the production callback.
				tx.conn
					.execute("UPDATE jobs SET enqueued_at=77 WHERE id=101", [])
					.map_err(crate::Error::from)?;
				Err::<(), _>(error)
			},
		);
		assert_eq!(result, Err(error), "the original callback error must survive rollback");
		assert_eq!(
			db.with_conn(|conn| Ok(conn.query_row(
				"SELECT enqueued_at FROM jobs WHERE id=101",
				[],
				|row| row.get::<_, i64>(0)
			)?))
			.unwrap(),
			0
		);
	}
	with_phase_transaction(
		&db,
		identity(),
		|| 100,
		|tx| {
			tx.conn
				.execute("UPDATE jobs SET enqueued_at=88 WHERE id=101", [])
				.map_err(crate::Error::from)?;
			Ok::<_, CallbackError>(())
		},
	)
	.unwrap();
	assert_eq!(
		db.with_conn(|conn| Ok(conn.query_row(
			"SELECT enqueued_at FROM jobs WHERE id=101",
			[],
			|row| row.get::<_, i64>(0)
		)?))
		.unwrap(),
		88
	);
}

thread_local! { static BUSY: RefCell<Option<mpsc::Sender<()>>> = const { RefCell::new(None) }; }
#[test]
fn clock_is_sampled_only_after_immediate_lock_acquisition() {
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("phase.sqlite");
	let key = MasterKey::for_tests();
	let db = Arc::new(crate::Db::open(&path, &key).unwrap());
	seed(&db);
	let mut other = Connection::open(&path).unwrap();
	other.pragma_update(None, "key", key.sqlcipher_key().expose()).unwrap();
	let locked = other.transaction_with_behavior(TransactionBehavior::Immediate).unwrap();
	let (busy_tx, busy_rx) = mpsc::channel();
	let (clock_tx, clock_rx) = mpsc::channel();
	let child = std::thread::spawn(move || {
		BUSY.with(|slot| *slot.borrow_mut() = Some(busy_tx));
		db.with_conn(|conn| {
			conn.busy_handler(Some(|count| {
				BUSY.with(|slot| {
					if let Some(sender) = slot.borrow_mut().take() {
						sender.send(()).unwrap();
					}
				});
				std::thread::sleep(Duration::from_millis(1));
				count < 5000
			}))?;
			Ok(())
		})
		.unwrap();
		with_phase_transaction(
			&db,
			identity(),
			|| {
				clock_tx.send(()).unwrap();
				500
			},
			|tx| {
				Ok::<_, crate::Error>(
					tx.authorize(Phase::Survey, Access::LeaseControl, |_| unreachable!())?
						.is_some(),
				)
			},
		)
		.unwrap()
	});
	busy_rx.recv_timeout(Duration::from_secs(5)).unwrap();
	assert!(
		matches!(clock_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
		"clock ran before IMMEDIATE acquired the database lock"
	);
	locked.commit().unwrap();
	clock_rx.recv_timeout(Duration::from_secs(5)).unwrap();
	assert!(child.join().unwrap(), "time sampled under the lock includes exact expiry");
}
