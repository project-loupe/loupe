//! Domain contract tests use real encrypted databases and enabled foreign keys.
use loupe_core::text::{Anchor, BoundedText, Identifier, RepoPath, SourceRef};
use rusqlite::{params, Transaction};

use crate::identity::Identity;
use crate::review_tests::{fixture, payload, reason};
use crate::{transaction, Conflict, Error, Ownership};

fn identity() -> Identity {
	Identity {
		family: Identifier::new("auth-bypass").unwrap(),
		anchor: Anchor::new("token refresh handler").unwrap(),
		instance: None,
	}
}
#[test]
fn concurrent_lead_submission_creates_once_and_attaches_once() {
	use crate::review_units::Priority;
	use crate::secrets::MasterKey;
	use crate::{leads as l, Db};
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("leads.sqlite");
	let a = Db::open(&path, &MasterKey::for_tests()).unwrap();
	crate::review_tests::seed(&a);
	let b = Db::open(&path, &MasterKey::for_tests()).unwrap();
	let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
	let submit = |db: Db, barrier: std::sync::Arc<std::sync::Barrier>| {
		db.with_conn(|c| {
			c.busy_timeout(std::time::Duration::from_secs(5))?;
			barrier.wait();
			let identity = identity();
			let data = payload();
			l::standalone::submit(
				c,
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
			)
		})
		.expect("concurrent submissions serialize successfully")
	};
	let other_barrier = barrier.clone();
	let thread = std::thread::spawn(move || submit(b, other_barrier));
	let first = submit(a, barrier);
	let second = thread.join().unwrap();
	assert_eq!(
		[&first, &second].iter().filter(|v| matches!(v, l::Submitted::Created(_))).count(),
		1
	);
	assert_eq!(
		[&first, &second].iter().filter(|v| matches!(v, l::Submitted::Attached { .. })).count(),
		1
	);
	let reopened = Db::open(&path, &MasterKey::for_tests()).unwrap();
	reopened
		.with_conn(|c| {
			let leads = l::list(c, 11)?;
			assert_eq!(leads.len(), 1);
			assert_eq!(crate::lead_observations::list(c, leads[0].lead_id)?.len(), 1);
			Ok(())
		})
		.unwrap();
}
fn units(tx: &Transaction<'_>) -> crate::Result<()> {
	for g in [11, 12, 21] {
		tx.execute("INSERT INTO review_units (review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES (?1,?1,'key','title','objective','[]',0)",[g])?;
	}
	Ok(())
}
pub(crate) fn findings(tx: &Transaction<'_>) -> crate::Result<()> {
	for (id, repo, job) in [(11, 1, 101), (12, 1, 102), (21, 2, 201)] {
		tx.execute("INSERT INTO findings (id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,created_at) VALUES (?1,?2,?3,'test','high','title','description',?1,0)",params![id,repo,job])?;
		tx.execute("INSERT INTO finding_verifications (id,finding_id,verdict,created_at) VALUES (?1,?1,'confirmed',0)",[id])?;
	}
	Ok(())
}
#[test]
fn references_preserve_paths_and_enforce_field_specific_count_caps() {
	use crate::source_refs::{InspectedRefs, UnitRefs};
	let reference = SourceRef {
		path: RepoPath::new("cafe\u{301}.rs").unwrap(),
		symbol: Some(BoundedText::new("cafe\u{301}").unwrap()),
	};
	let refs =
		UnitRefs::new(vec![reference.clone()]).expect("a valid source reference must be accepted");
	assert!(refs.expose().contains("cafe\u{301}.rs"));
	assert!(refs.expose().contains("café"));
	assert_eq!(refs.expose().parse::<UnitRefs>().unwrap(), refs);
	assert!(UnitRefs::new(vec![reference.clone(); 33]).is_err());
	assert!(InspectedRefs::new(vec![reference; 33]).is_ok());
	assert!("[]".repeat(65537).parse::<UnitRefs>().is_err());
	assert!(!format!("{refs:?}").contains("cafe"));
}
#[test]
fn unit_creation_transitions_and_carry_forward() {
	use crate::review_units as u;
	let db = fixture();
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			let key = Identifier::new("scope").unwrap();
			let title = BoundedText::new("Authentication").unwrap();
			let objective = BoundedText::new("Review token refresh").unwrap();
			let refs = crate::source_refs::UnitRefs::new(vec![]).unwrap();
			let new = u::NewUnit {
				generation_id: 11,
				client_key: &key,
				title: &title,
				objective: &objective,
				priority: u::Priority::High,
				priority_proposal: Some(&payload()),
				source_refs: &refs,
				depends_on: None,
				closure_criteria: None,
				semantic_context: None,
				carried_from: None,
				created_by_job: Some(101),
			};
			let id = u::create(tx, &new, 0).expect("create a typed review unit");
			assert!(matches!(u::create(tx, &new, 0), Err(Error::Conflict(Conflict::UnitKey))));
			u::defer(tx, id, &reason())?;
			assert!(u::defer(tx, id, &reason()).is_err());
			u::reopen(tx, id)?;
			u::mark_stale(tx, id, &reason())?;
			let carried = u::carry_forward(tx, id, 12, Some(102), None, 1)?;
			let row = u::get(tx, carried)?.unwrap();
			assert_eq!(row.carry_depth, 1);
			assert_eq!(row.carried_from, Some(id));
			assert!(!row.stale);
			u::retire(tx, id)?;
			assert!(u::reopen(tx, id).is_err());
			assert_eq!(u::list(tx, 11)?.len(), 1);
			assert!(matches!(
				u::carry_forward(tx, carried, 21, Some(201), None, 1),
				Err(Error::Ownership(Ownership::CarriedUnit))
			));
			Ok(())
		})
	})
	.unwrap();
}
#[test]
fn units_reject_foreign_and_other_generation_jobs() {
	use crate::review_units as u;
	let db = fixture();
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			units(tx)?;
			let key = Identifier::new("scope").unwrap();
			let title = BoundedText::new("title").unwrap();
			let objective = BoundedText::new("objective").unwrap();
			let refs = crate::source_refs::UnitRefs::new(vec![]).unwrap();
			let mut new = u::NewUnit {
				generation_id: 11,
				client_key: &key,
				title: &title,
				objective: &objective,
				priority: u::Priority::Normal,
				priority_proposal: None,
				source_refs: &refs,
				depends_on: None,
				closure_criteria: None,
				semantic_context: None,
				carried_from: None,
				created_by_job: None,
			};
			for job in [201, 102] {
				new.created_by_job = Some(job);
				assert!(matches!(
					u::create(tx, &new, 0),
					Err(Error::Ownership(Ownership::UnitJob))
				));
			}
			new.created_by_job = Some(101);
			new.carried_from = Some(21);
			assert!(matches!(
				u::create(tx, &new, 0),
				Err(Error::Ownership(Ownership::CarriedUnit))
			));
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn scheduler_links_and_campaign_only_provenance_are_scoped() {
	let db = fixture();
	db.with_conn(|c|transaction::immediate(c,|tx|{
  assert!(matches!(crate::ownership::job_links(tx,1,Some(21),None),Err(Error::Ownership(Ownership::JobGeneration))));
  tx.execute("INSERT INTO leads (lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at) VALUES (21,21,'test-family','handler',zeroblob(32),'{}',zeroblob(32),'foreign',0)",[])?;
  assert!(matches!(crate::ownership::job_links(tx,1,None,Some(21)),Err(Error::Ownership(Ownership::JobLead))));
  crate::ownership::job_links(tx,2,Some(21),Some(21))?;
  tx.execute("INSERT INTO jobs (id,repo_id,kind,state,campaign_id,enqueued_at) VALUES (103,1,'survey','queued',1,0)",[])?;
  crate::ownership::job_for_generation(tx,103,11,Ownership::UnitJob)?;
  crate::ownership::job_for_generation(tx,103,12,Ownership::UnitJob)?;
  assert!(matches!(crate::ownership::job_for_generation(tx,103,21,Ownership::UnitJob),Err(Error::Ownership(Ownership::UnitJob))));
  Ok(())
 })).unwrap();
}

#[test]
fn assignment_positions_continue_across_batches() {
	// A survey holds an ordered set; a later batch for the same job must extend
	// the order, not restart at zero and alias the first unit's position.
	use crate::review_units as u;
	let db = fixture();
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			units(tx)?;
			tx.execute("INSERT INTO review_units (review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES (13,11,'second','title','objective','[]',0)",[])?;
			u::assign(tx, 101, &[u::Assignment { unit_id: 11, expected_epoch: 0 }])?;
			u::assign(tx, 101, &[u::Assignment { unit_id: 13, expected_epoch: 0 }])?;
			let positions: Vec<(i64, i64)> = tx
				.prepare("SELECT review_unit_id, position FROM job_assigned_review_units WHERE job_id=101 ORDER BY position, review_unit_id")?
				.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
				.collect::<rusqlite::Result<_>>()?;
			assert_eq!(positions, vec![(11, 0), (13, 1)], "positions must stay unique per job");
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn a_failed_assignment_batch_rolls_back_every_epoch() {
	use crate::review_units as u;
	let db = fixture();
	db.with_conn(|c| {
		transaction::immediate(c, units)?;
		let result = u::standalone::assign(
			c,
			101,
			&[
				u::Assignment { unit_id: 11, expected_epoch: 0 },
				u::Assignment { unit_id: 12, expected_epoch: 0 },
			],
		);
		assert!(matches!(result, Err(Error::Ownership(Ownership::Assignment))));
		assert_eq!(u::get(c, 11)?.unwrap().assignment_epoch, 0);
		assert_eq!(
			c.query_row("SELECT COUNT(*) FROM job_assigned_review_units", [], |r| r
				.get::<_, i64>(0))?,
			0
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn carry_forward_does_not_reuse_prior_generation_dependency_ids() {
	let db = fixture();
	db.with_conn(|c|transaction::immediate(c,|tx|{
  tx.execute_batch("INSERT INTO review_units (review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,depends_on,created_at) VALUES (31,11,'source','title','objective','[]','[32]',0),(32,11,'dependency','title','objective','[]',NULL,0);")?;
  let id=crate::review_units::carry_forward(tx,31,12,Some(102),None,1)?;
  assert_eq!(crate::review_units::get(tx,id)?.unwrap().depends_on,None,"dependency IDs must be rebuilt for the successor generation");
  Ok(())
 })).unwrap();
}
#[test]
fn assignments_require_generation_epoch_and_exclusive_active_ownership() {
	use crate::review_units as u;
	let db = fixture();
	db.with_conn(|c|transaction::immediate(c,|tx|{
 units(tx)?;
 assert!(matches!(u::assign(tx,101,&[u::Assignment{unit_id:12,expected_epoch:0}]),Err(Error::Ownership(Ownership::Assignment))));
 u::assign(tx,101,&[u::Assignment{unit_id:11,expected_epoch:0}]).expect("claim with the current epoch");
 assert_eq!(u::get(tx,11)?.unwrap().assignment_epoch,1);
 tx.execute("INSERT INTO jobs (id,repo_id,kind,state,generation_id,enqueued_at) VALUES (103,1,'survey','queued',11,0)",[])?;
 assert!(matches!(u::assign(tx,103,&[u::Assignment{unit_id:11,expected_epoch:1}]),Err(Error::Conflict(Conflict::Assignment))));
 tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101",[])?;
 assert!(matches!(u::assign(tx,103,&[u::Assignment{unit_id:11,expected_epoch:0}]),Err(Error::Conflict(Conflict::Assignment))));
 u::assign(tx,103,&[u::Assignment{unit_id:11,expected_epoch:1}])?;
 assert_eq!(u::get(tx,11)?.unwrap().assignment_epoch,2);
 Ok(())
 })).unwrap();
}
#[test]
fn unit_results_check_all_corroboration_and_job_relations() {
	use crate::review_unit_results as r;
	let db = fixture();
	db.with_conn(|c|transaction::immediate(c,|tx|{
 units(tx)?;let refs=crate::source_refs::InspectedRefs::new(vec![]).unwrap();let data=payload();
 let mut new=r::NewResult{generation_id:11,unit_id:11,produced_by_job:Some(101),commit_sha:"base",profile_version:1,disposition:r::Disposition::NoLeadFound,inspected_refs:&refs,counterevidence:None,proof_gaps:None,payload:&data,corroborates_result:None,corroborates_exclusion:None};
 let id=r::insert(tx,&new,0).expect("append a unit result");
 for job in [102,201] {new.produced_by_job=Some(job);assert!(matches!(r::insert(tx,&new,0),Err(Error::Ownership(Ownership::ResultJob))));}
 new.produced_by_job=Some(101);new.unit_id=12;
 assert!(matches!(r::insert(tx,&new,0),Err(Error::Ownership(Ownership::ResultUnit))));
 new.unit_id=11;new.corroborates_result=Some(id);
 let corroboration=r::insert(tx,&new,1)?;
 new.corroborates_result=Some(corroboration);
 assert!(matches!(r::insert(tx,&new,1),Err(Error::Ownership(Ownership::CorroboratedResult))));
 new.corroborates_result=None;
 tx.execute("INSERT INTO review_unit_results (review_unit_result_id,review_unit_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,created_at) VALUES (99,12,'next',1,'no_lead_found','[]','{}',zeroblob(32),0)",[])?;
 new.corroborates_result=Some(99);
 assert!(matches!(r::insert(tx,&new,1),Err(Error::Ownership(Ownership::CorroboratedResult))));
 tx.execute_batch("INSERT INTO generation_inventory (inventory_entry_id,generation_id,path,entry_kind,disposition,created_at) VALUES (11,11,'a','tracked','excluded',0),(12,11,'b','tracked','mapped',0),(21,21,'a','tracked','excluded',0);")?;
 new.corroborates_exclusion=Some(11);
 assert!(matches!(r::insert(tx,&new,1),Err(Error::Conflict(Conflict::Corroboration))));
 new.corroborates_result=None;
 for exclusion in [12,21] {new.corroborates_exclusion=Some(exclusion);assert!(matches!(r::insert(tx,&new,1),Err(Error::Ownership(Ownership::CorroboratedExclusion))));}
 new.corroborates_exclusion=Some(11);r::insert(tx,&new,1)?;
 r::invalidate(tx,id,&reason())?;assert!(r::list(tx,11)?.iter().any(|r|r.result_id==id && r.invalidated));
 Ok(())
 })).unwrap();
}
#[test]
fn every_identity_collision_preserves_the_observation() {
	use crate::review_units::Priority;
	use crate::{lead_observations as o, leads as l};
	for status in ["open", "deferred", "promoted", "rejected", "duplicate", "hardening", "stale"] {
		let db = fixture();
		db.with_conn(|c| {
			transaction::immediate(c, |tx| {
				findings(tx)?;
				let identity = identity();
				let data = payload();
				let new = l::NewLead {
					generation_id: 11,
					unit_id: None,
					identity: &identity,
					payload: &data,
					commit_sha: "base",
					priority: Priority::Normal,
					priority_proposal: None,
					supersedes: None,
					created_by_job: Some(101),
				};
				let l::Submitted::Created(id) =
					l::submit(tx, &new, 0).expect("create a first lead")
				else {
					panic!("new identity")
				};
				match status {
					"deferred" => l::defer(tx, id, &reason(), Some(&reason()))?,
					"promoted" => l::close(tx, id, &l::Closure::Promoted { finding: 11 }, 1)?,
					"rejected" => l::close(tx, id, &l::Closure::Rejected, 1)?,
					"duplicate" => l::close(
						tx,
						id,
						&l::Closure::Duplicate { lead: None, finding: Some(11) },
						1,
					)?,
					"hardening" => l::close(tx, id, &l::Closure::Hardening, 1)?,
					"stale" => l::close(tx, id, &l::Closure::Stale, 1)?,
					_ => {},
				}
				let outcome = l::submit(tx, &new, 2)?;
				match status {
					"open" | "deferred" => assert_eq!(
						outcome,
						l::Submitted::Attached { lead_id: id, status: status.parse().unwrap() }
					),
					"stale" => {
						let l::Submitted::Created(next) = outcome else {
							panic!("stale identity is reusable")
						};
						assert_ne!(id, next);
						assert_eq!(l::get(tx, next)?.unwrap().supersedes, Some(id));
					},
					_ => assert_eq!(
						outcome,
						l::Submitted::ClosedExists {
							lead_id: id,
							disposition: status.parse().unwrap(),
							finding_id: if status == "promoted" { Some(11) } else { None }
						}
					),
				}
				let observations = o::list(tx, id)?;
				assert_eq!(observations.len(), usize::from(status != "stale"));
				if let Some(observation) = observations.first() {
					assert_eq!(observation.payload, data);
				}
				Ok(())
			})
		})
		.unwrap();
	}
}
#[test]
fn leads_and_observations_reject_every_wrong_scope() {
	use crate::review_units::Priority;
	use crate::{lead_observations as o, leads as l};
	let db = fixture();
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			units(tx)?;
			findings(tx)?;
			let identity = identity();
			let data = payload();
			let mut new = l::NewLead {
				generation_id: 11,
				unit_id: None,
				identity: &identity,
				payload: &data,
				commit_sha: "base",
				priority: Priority::Normal,
				priority_proposal: None,
				supersedes: None,
				created_by_job: Some(101),
			};
			for unit in [12, 21] {
				new.unit_id = Some(unit);
				assert!(matches!(
					l::submit(tx, &new, 0),
					Err(Error::Ownership(Ownership::LeadUnit))
				));
			}
			new.unit_id = None;
			for job in [102, 201] {
				new.created_by_job = Some(job);
				assert!(matches!(
					l::submit(tx, &new, 0),
					Err(Error::Ownership(Ownership::LeadJob))
				));
			}
			new.created_by_job = Some(101);
			let l::Submitted::Created(id) = l::submit(tx, &new, 0)? else { panic!() };
			for job in [102, 201] {
				assert!(matches!(
					o::insert(
						tx,
						&o::NewObservation {
							lead_id: id,
							submitted_by_job: Some(job),
							payload: &data,
							commit_sha: "base"
						},
						1
					),
					Err(Error::Ownership(Ownership::ObservationJob))
				));
			}
			new.generation_id = 21;
			new.created_by_job = Some(201);
			let l::Submitted::Created(foreign) = l::submit(tx, &new, 0)? else { panic!() };
			new.generation_id = 11;
			new.created_by_job = Some(101);
			new.supersedes = Some(foreign);
			assert!(matches!(
				l::submit(tx, &new, 0),
				Err(Error::Ownership(Ownership::SupersededLead))
			));
			assert!(matches!(
				l::close(tx, id, &l::Closure::Duplicate { lead: Some(foreign), finding: None }, 1),
				Err(Error::Ownership(Ownership::DuplicateLead))
			));
			assert!(matches!(
				l::close(tx, id, &l::Closure::Duplicate { lead: None, finding: Some(21) }, 1),
				Err(Error::Ownership(Ownership::DuplicateFinding))
			));
			assert!(matches!(
				l::close(tx, id, &l::Closure::Promoted { finding: 21 }, 1),
				Err(Error::Ownership(Ownership::PromotedFinding))
			));
			Ok(())
		})
	})
	.unwrap();
}
#[test]
fn explicit_supersedes_requires_a_stale_closed_lead() {
	// `supersedes_lead_id` records that a stale-closed identity was resubmitted;
	// pointing it at a live or otherwise-closed lead would fabricate that history.
	use crate::leads as l;
	use crate::review_units::Priority;
	let db = fixture();
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			let first = identity();
			let data = payload();
			let l::Submitted::Created(open) = l::submit(
				tx,
				&l::NewLead {
					generation_id: 11,
					unit_id: None,
					identity: &first,
					payload: &data,
					commit_sha: "base",
					priority: Priority::Normal,
					priority_proposal: None,
					supersedes: None,
					created_by_job: Some(101),
				},
				0,
			)?
			else {
				panic!("fresh identity")
			};
			let other = Identity {
				family: Identifier::new("auth-bypass").unwrap(),
				anchor: Anchor::new("session cookie handler").unwrap(),
				instance: None,
			};
			let mut new = l::NewLead {
				generation_id: 11,
				unit_id: None,
				identity: &other,
				payload: &data,
				commit_sha: "base",
				priority: Priority::Normal,
				priority_proposal: None,
				supersedes: Some(open),
				created_by_job: Some(101),
			};
			assert!(
				matches!(l::submit(tx, &new, 1), Err(Error::Conflict(Conflict::LeadState))),
				"an open lead cannot be superseded"
			);
			l::close(tx, open, &l::Closure::Rejected, 2)?;
			assert!(
				matches!(l::submit(tx, &new, 3), Err(Error::Conflict(Conflict::LeadState))),
				"a rejected lead cannot be superseded either"
			);
			let l::Submitted::Created(second) =
				l::submit(tx, &l::NewLead { supersedes: None, ..new }, 4)?
			else {
				panic!("fresh identity")
			};
			l::close(tx, second, &l::Closure::Stale, 5)?;
			new.supersedes = Some(second);
			let l::Submitted::Created(successor) = l::submit(tx, &new, 6)? else {
				panic!("stale identity is reusable")
			};
			assert_eq!(l::get(tx, successor)?.unwrap().supersedes, Some(second));
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn stale_close_refuses_active_jobs_and_unrelated_failures_stay_sqlite() {
	use crate::leads as l;
	use crate::review_units::Priority;
	let db = fixture();
	db.with_conn(|c|transaction::immediate(c,|tx|{
 let identity=identity();let data=payload();
 let new=l::NewLead{generation_id:11,unit_id:None,identity:&identity,payload:&data,commit_sha:"base",priority:Priority::Normal,priority_proposal:None,supersedes:None,created_by_job:Some(101)};
 let l::Submitted::Created(id)=l::submit(tx,&new,0)? else{panic!()};
 tx.execute("UPDATE jobs SET assigned_lead_id=?1 WHERE id=101",[id])?;
 assert!(matches!(l::close(tx,id,&l::Closure::Stale,1),Err(Error::Conflict(Conflict::LeadState))));
 tx.execute("UPDATE jobs SET state='succeeded' WHERE id=101",[])?;
 l::close(tx,id,&l::Closure::Stale,2)?;
 tx.execute_batch("CREATE TEMP TRIGGER fail_lead BEFORE INSERT ON leads BEGIN SELECT RAISE(ABORT,'unrelated constraint'); END;")?;
 assert!(matches!(l::submit(tx,&new,3),Err(Error::Sqlite(_))));
 Ok(())
 })).unwrap();
}
