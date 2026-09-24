use loupe_core::text::policy::Payload;
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_core::{JobKind, JobState};
use loupe_server::review::campaign::{self, KindHint, OpenCampaign, Opened, RequestedRef};
use loupe_server::review::policy::ReviewPolicy;
use loupe_storage::{campaigns, generations, jobs, transaction, Conflict, Db, Error};

// Pinning only accepts complete object ids, so fixtures use full SHA-1s.
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OLD: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const NEW: &str = "cccccccccccccccccccccccccccccccccccccccc";
const DIFFERENT: &str = "dddddddddddddddddddddddddddddddddddddddd";
const OTHER: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

fn fixture() -> Db {
	let db = Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests()).unwrap();
	db.with_conn(|c| {
		c.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(1,'u','github.com','o','r','{\"kind\":\"manual\"}',0)",[])?;
		Ok(())
	}).unwrap();
	db
}

fn request(reference: RequestedRef<'_>) -> OpenCampaign<'_> {
	OpenCampaign {
		repo_id: 1,
		trigger: campaigns::Trigger::Manual,
		requested_ref: reference,
		base_sha: None,
		kind_hint: KindHint::Incremental,
	}
}

fn created(opened: Opened) -> (i64, i64) {
	match opened {
		Opened::Created { campaign_id, job_id } => (campaign_id, job_id),
		other => panic!("expected a new campaign: {other:?}"),
	}
}

fn ready(tx: &rusqlite::Transaction<'_>, generation: i64) -> loupe_storage::Result<()> {
	generations::set_profile(tx, generation, 1, &BoundedJson::<Payload>::new("{}")?)?;
	tx.execute(
		"UPDATE review_generations SET inventory_digest=zeroblob(32) WHERE generation_id=?1",
		[generation],
	)?;
	Ok(())
}

fn idle_campaign(
	tx: &rusqlite::Transaction<'_>, repo_id: i64, policy: &ReviewPolicy, now: i64, has_work: bool,
) -> loupe_storage::Result<(i64, i64)> {
	let mut new = request(RequestedRef::Pinned(SHA));
	new.repo_id = repo_id;
	let (campaign_id, job_id) = created(campaign::open(tx, &new, policy, now)?);
	let generation = jobs::get(tx, job_id)?.unwrap().generation_id.unwrap();
	ready(tx, generation)?;
	campaign::activate_generation(tx, campaign_id, now)?;
	tx.execute(
		"UPDATE jobs SET state='succeeded',finished_at=?2 WHERE id=?1",
		rusqlite::params![job_id, now],
	)?;
	if has_work {
		tx.execute(
			"INSERT INTO review_units(generation_id,client_review_unit_key,title,objective,
			 source_refs,priority_band,created_at) VALUES(?1,'u','t','o','[]','high',0)",
			[generation],
		)?;
	}
	Ok((campaign_id, generation))
}

#[tokio::test]
async fn background_scheduler_notifies_waiters_for_replenished_campaign_work() {
	let db = std::sync::Arc::new(fixture());
	let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
		as i64;
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			idle_campaign(tx, 1, &ReviewPolicy::default(), now, true)?;
			Ok(())
		})
	})
	.unwrap();
	let arrived = std::sync::Arc::new(tokio::sync::Notify::new());
	let cancelled = tokio_util::sync::CancellationToken::new();
	let notified = arrived.notified();
	tokio::pin!(notified);
	notified.as_mut().enable();
	let handle =
		loupe_server::background::spawn_scheduler(db.clone(), arrived.clone(), cancelled.clone());
	let notification = tokio::time::timeout(std::time::Duration::from_secs(2), notified).await;
	cancelled.cancel();
	handle.await.unwrap();
	assert!(notification.is_ok(), "campaign replenishment must wake leasing workers");
	db.with_conn(|c| {
		let queued: i64 =
			c.query_row("SELECT COUNT(*) FROM jobs WHERE state='queued'", [], |r| r.get(0))?;
		assert_eq!(queued, 1, "the notification must correspond to the new coverage survey");
		Ok(())
	})
	.unwrap();
}

#[test]
fn open_pins_only_known_commits_and_freezes_policy() {
	for pinned in [false, true] {
		let db = fixture();
		db.with_conn(|c| {
			transaction::immediate(c, |tx| {
				let policy = ReviewPolicy {
					campaign_max_jobs: 9,
					survey_token_budget: Some(123),
					..ReviewPolicy::default()
				};
				let reference =
					if pinned { RequestedRef::Pinned(SHA) } else { RequestedRef::Branch("main") };
				let (campaign, job) =
					created(campaign::open(tx, &request(reference), &policy, 100)?);
				let row = campaigns::get(tx, campaign)?.unwrap();
				assert_eq!(row.recipe, campaigns::Recipe::Bootstrap);
				assert_eq!(row.deadline_at, Some(21700));
				assert_eq!(row.effective_policy, policy.snapshot().unwrap());
				assert_eq!(row.generation_id.is_some(), pinned);
				let job = jobs::get(tx, job)?.unwrap();
				assert_eq!(job.kind, JobKind::Survey);
				assert_eq!(job.generation_id, row.generation_id);
				assert_eq!(job.token_budget, Some(123));
				assert_eq!(job.state, JobState::Queued);
				Ok(())
			})
		})
		.unwrap();
	}
}

#[test]
fn pending_triggers_do_not_write_and_pinned_triggers_coalesce_boundedly() {
	let db = fixture();
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			let (campaign, job) = created(campaign::open(
				tx,
				&request(RequestedRef::Branch("main")),
				&ReviewPolicy::default(),
				0,
			)?);
			let before = tx.total_changes();
			assert_eq!(
				campaign::open(
					tx,
					&request(RequestedRef::Pinned(NEW)),
					&ReviewPolicy::default(),
					1
				)?,
				Opened::Pending { campaign_id: campaign }
			);
			assert_eq!(tx.total_changes(), before, "pending must not pretend to persist a trigger");
			let generation = campaign::pin(tx, campaign, job, SHA, 2)?;
			for at in 0..20 {
				assert_eq!(
					campaign::open(
						tx,
						&request(RequestedRef::Pinned(&format!("next-{at}"))),
						&ReviewPolicy::default(),
						at + 3
					)?,
					Opened::Coalesced { campaign_id: campaign }
				);
			}
			let follow = generations::get(tx, generation)?.unwrap().pending_follow_up.unwrap();
			let value: serde_json::Value = serde_json::from_str(follow.expose()).unwrap();
			assert_eq!(value["triggers"].as_array().unwrap().len(), 16);
			assert_eq!(value["triggers"][0]["ref"], "next-4");
			assert_eq!(value["newest_ref"], "next-19");
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn coalescing_retains_the_strongest_kind_hint_after_truncation() {
	for full_review in [true, false] {
		let db = fixture();
		let (campaign_id, generation_id) = db
			.with_conn(|conn| {
				transaction::immediate(conn, |tx| {
					let (campaign_id, _) = created(campaign::open(
						tx,
						&request(RequestedRef::Pinned(SHA)),
						&ReviewPolicy::default(),
						0,
					)?);
					let generation_id =
						campaigns::get(tx, campaign_id)?.unwrap().generation_id.unwrap();
					// Older version-1 payloads have no kind hints. Keep them readable.
					generations::set_pending_follow_up(
						tx,
						generation_id,
						&BoundedJson::new(
							r#"{"version":1,"triggers":[{"trigger":"manual","ref":"old","at":0}],"newest_ref":"old"}"#,
						)?,
					)?;
					Ok((campaign_id, generation_id))
				})
			})
			.unwrap();
		for at in 1..=20 {
			db.with_conn(|conn| {
				transaction::immediate(conn, |tx| {
					let reference = format!("next-{at}");
					let mut new = request(RequestedRef::Branch(&reference));
					if full_review && at == 1 {
						new.kind_hint = KindHint::FullReview;
					}
					assert_eq!(
						campaign::open(tx, &new, &ReviewPolicy::default(), at)?,
						Opened::Coalesced { campaign_id }
					);
					Ok(())
				})
			})
			.unwrap();
		}
		db.with_conn(|conn| {
			let pending =
				generations::get(conn, generation_id)?.unwrap().pending_follow_up.unwrap();
			let value: serde_json::Value = serde_json::from_str(pending.expose()).unwrap();
			assert_eq!(
				value["kind_hint"],
				if full_review { "full_review" } else { "incremental" },
				"coalesced review intent must survive trigger-history truncation"
			);
			let triggers = value["triggers"].as_array().unwrap();
			assert_eq!(triggers.len(), 16);
			assert_eq!(triggers[0]["ref"], "next-5");
			assert!(triggers.iter().all(|t| t["kind_hint"] == "incremental"));
			assert_eq!(value["newest_ref"], "next-20");
			Ok(())
		})
		.unwrap();
	}
}

#[test]
fn pin_is_idempotent_but_never_changes_an_already_pinned_commit() {
	let db = fixture();
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			let (campaign, job) = created(campaign::open(
				tx,
				&request(RequestedRef::Branch("main")),
				&ReviewPolicy::default(),
				0,
			)?);
			let generation = campaign::pin(tx, campaign, job, SHA, 1)?;
			let before = tx.total_changes();
			assert_eq!(campaign::pin(tx, campaign, job, SHA, 2)?, generation);
			assert_eq!(before, tx.total_changes());
			assert!(matches!(
				campaign::pin(tx, campaign, job, DIFFERENT, 2),
				Err(Error::Conflict(Conflict::CampaignPinned))
			));
			assert!(campaign::pin(tx, campaign, job + 100, SHA, 2).is_err());
			tx.execute("UPDATE jobs SET state='failed' WHERE id=?1", [job])?;
			assert!(campaign::pin(tx, campaign, job, SHA, 2).is_err());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn bootstrap_abandons_all_building_leftovers_without_relaxing_retire() {
	let db = fixture();
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			let same = generations::create(
				tx,
				&generations::NewGeneration {
					repo_id: 1,
					predecessor_generation_id: None,
					commit_sha: SHA,
					workflow_contract_version: 1,
				},
				0,
			)?;
			ready(tx, same)?;
			let other = generations::create(
				tx,
				&generations::NewGeneration {
					repo_id: 1,
					predecessor_generation_id: None,
					commit_sha: OTHER,
					workflow_contract_version: 1,
				},
				0,
			)?;
			assert!(generations::retire(tx, same, &BoundedText::new("test")?, 1).is_err());
			let (campaign, _) = created(campaign::open(
				tx,
				&request(RequestedRef::Pinned(SHA)),
				&ReviewPolicy::default(),
				2,
			)?);
			let new = campaigns::get(tx, campaign)?.unwrap().generation_id.unwrap();
			assert_ne!(new, same);
			assert_ne!(new, other);
			for id in [same, other] {
				let row = generations::get(tx, id)?.unwrap();
				assert_eq!(row.state, generations::State::Retired);
				assert_eq!(row.activated_at, None);
				assert_eq!(row.retired_at, Some(2));
				assert_eq!(row.retired_reason.unwrap().expose(), "superseded bootstrap");
				assert!(generations::abandon(tx, id, &BoundedText::new("again")?, 3).is_err());
			}
			ready(tx, new)?;
			campaign::activate_generation(tx, campaign, 3)?;
			assert!(generations::abandon(tx, new, &BoundedText::new("active")?, 4).is_err());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn pin_selects_active_continuation_or_matching_successor() {
	for (active_sha, active_version, reuse_successor, expected_same) in [
		(SHA, 1, false, true),
		(SHA, 2, false, false),
		(OLD, 1, false, false),
		(OLD, 1, true, false),
	] {
		let db = fixture();
		db.with_conn(|c| {
			transaction::immediate(c, |tx| {
				let active = generations::create(
					tx,
					&generations::NewGeneration {
						repo_id: 1,
						predecessor_generation_id: None,
						commit_sha: active_sha,
						workflow_contract_version: active_version,
					},
					0,
				)?;
				ready(tx, active)?;
				generations::activate(tx, active, 1)?;
				let successor = if reuse_successor {
					Some(generations::create(
						tx,
						&generations::NewGeneration {
							repo_id: 1,
							predecessor_generation_id: Some(active),
							commit_sha: SHA,
							workflow_contract_version: 1,
						},
						1,
					)?)
				} else {
					None
				};
				let (campaign, _) = created(campaign::open(
					tx,
					&request(RequestedRef::Pinned(SHA)),
					&ReviewPolicy::default(),
					2,
				)?);
				let row = campaigns::get(tx, campaign)?.unwrap();
				assert_eq!(row.recipe, campaigns::Recipe::Incremental);
				let generation = row.generation_id.unwrap();
				assert_eq!(generation == active, expected_same);
				if let Some(successor) = successor {
					assert_eq!(generation, successor);
				}
				if !expected_same {
					assert_eq!(
						generations::get(tx, generation)?.unwrap().predecessor_generation_id,
						Some(active)
					);
					assert!(matches!(
						campaign::activate_generation(tx, campaign, 3),
						Err(Error::Conflict(Conflict::GenerationPredecessor))
					));
					assert_eq!(campaign::replenish(tx, campaign, 3)?, None);
				}
				Ok(())
			})
		})
		.unwrap();
	}
}

#[test]
fn recipe_selection_uses_only_an_active_baseline() {
	for state in [None, Some("retired"), Some("building"), Some("active")] {
		for hint in [KindHint::Incremental, KindHint::FullReview] {
			let db = fixture();
			db.with_conn(|c|transaction::immediate(c,|tx| {
				if let Some(state)=state {
					tx.execute("INSERT INTO review_generations(repo_id,generation_commit_sha,state,workflow_contract_version,created_at) VALUES(1,?2,?1,1,0)",rusqlite::params![state, SHA])?;
				}
				let mut new=request(RequestedRef::Branch("main"));new.kind_hint=hint;
				let (campaign,_)=created(campaign::open(tx,&new,&ReviewPolicy::default(),0)?);
				let expected=if state!=Some("active") {campaigns::Recipe::Bootstrap} else if hint==KindHint::FullReview {campaigns::Recipe::Reconciliation} else {campaigns::Recipe::Incremental};
				assert_eq!(campaigns::get(tx,campaign)?.unwrap().recipe,expected);
				Ok(())
			})).unwrap();
		}
	}
}

#[test]
fn bootstrap_activation_requires_profile_and_inventory() {
	let db = fixture();
	db.with_conn(|c|transaction::immediate(c,|tx| {
		let (campaign,job)=created(campaign::open(tx,&request(RequestedRef::Pinned(SHA)),&ReviewPolicy::default(),0)?);
		let generation=jobs::get(tx,job)?.unwrap().generation_id.unwrap();
		assert!(campaign::activate_generation(tx,campaign,1).is_err());
		generations::set_profile(tx,generation,1,&BoundedJson::<Payload>::new("{}")?)?;
		assert!(campaign::activate_generation(tx,campaign,1).is_err());
		tx.execute("UPDATE review_generations SET inventory_digest=zeroblob(32) WHERE generation_id=?1",[generation])?;
		campaign::activate_generation(tx,campaign,1)?;
		assert_eq!(generations::get(tx,generation)?.unwrap().state,generations::State::Active);
		Ok(())
	})).unwrap();
}

#[test]
fn replenish_uses_coverage_recipe_and_frozen_budget_after_activation() {
	let db = fixture();
	db.with_conn(|c|transaction::immediate(c,|tx| {
		let policy=ReviewPolicy{campaign_max_jobs:3,campaign_handoff_reserve:1,..ReviewPolicy::default()};
		let (campaign,job)=created(campaign::open(tx,&request(RequestedRef::Pinned(SHA)),&policy,0)?);
		let generation=jobs::get(tx,job)?.unwrap().generation_id.unwrap();
		ready(tx,generation)?;
		tx.execute("INSERT INTO review_units(generation_id,client_review_unit_key,title,objective,source_refs,priority_band,created_at) VALUES(?1,'u','t','o','[]','high',0)",[generation])?;
		assert_eq!(campaign::replenish(tx,campaign,1)?,None,"building generations must not receive ordinary coverage work");
		tx.execute("UPDATE jobs SET state='succeeded',finished_at=1 WHERE id=?1",[job])?;
		campaign::activate_generation(tx,campaign,1)?;
		let next=campaign::replenish(tx,campaign,1)?.unwrap();
		let row=jobs::get(tx,next)?.unwrap();
		let recipe:serde_json::Value=serde_json::from_str(row.recipe.unwrap().expose()).unwrap();
		assert_eq!(recipe["recipe"],"coverage");
		assert_eq!(row.continuation_of_job_id,Some(job));
		assert_eq!(row.scheduling_band,Some(loupe_storage::scheduler::Band::High));
		assert_eq!(campaign::replenish(tx,campaign,2)?,None,"at most one queued survey");
		tx.execute("UPDATE jobs SET state='succeeded',finished_at=2 WHERE id=?1",[next])?;
		assert_eq!(campaign::replenish(tx,campaign,3)?,None,"frozen budget remains three, including the reserve");
		let generation=generations::get(tx,generation)?.unwrap();
		assert_eq!(generation.profile_version,1);
		assert_eq!(generation.activated_at,Some(1));
		Ok(())
	})).unwrap();
}

#[test]
fn cancellation_keeps_leased_children_and_records_a_summary() {
	let db = fixture();
	db.with_conn(|c|transaction::immediate(c,|tx| {
		let (campaign,job)=created(campaign::open(tx,&request(RequestedRef::Pinned(SHA)),&ReviewPolicy::default(),0)?);
		tx.execute("UPDATE jobs SET state='leased' WHERE id=?1",[job])?;
		tx.execute("INSERT INTO jobs(repo_id,kind,state,campaign_id,enqueued_at) VALUES(1,'survey','queued',?1,1)",[campaign])?;
		let queued=tx.last_insert_rowid();
		campaign::cancel(tx,campaign,&BoundedText::new("operator")?,2)?;
		assert_eq!(jobs::get(tx,job)?.unwrap().state,JobState::Leased);
		assert_eq!(jobs::get(tx,queued)?.unwrap().state,JobState::Cancelled);
		let row=campaigns::get(tx,campaign)?.unwrap();
		assert_eq!(row.state,campaigns::State::Cancelled);
		assert!(row.terminal_counts.is_some());
		assert!(row.coverage_at_finish.is_some());
		Ok(())
	})).unwrap();
}

#[test]
fn idle_campaign_replenishes_before_finishing_and_snapshots_terminal_counts() {
	for has_work in [true, false] {
		let db = fixture();
		db.with_conn(|c| {
			transaction::immediate(c, |tx| {
				let (id, _) = idle_campaign(tx, 1, &ReviewPolicy::default(), 0, has_work)?;
				let finish = campaign::try_finish(tx, id, 1)?;
				let row = campaigns::get(tx, id)?.unwrap();
				if has_work {
					assert_eq!(finish, None);
					assert_eq!(row.state, campaigns::State::Active);
					let queued: i64 = tx.query_row(
						"SELECT COUNT(*) FROM jobs WHERE campaign_id=?1 AND state='queued'",
						[id],
						|r| r.get(0),
					)?;
					assert_eq!(queued, 1);
				} else {
					assert_eq!(finish, Some(campaign::Finish::Completed));
					assert_eq!(row.state, campaigns::State::Finished);
					assert_eq!(row.terminal_reason.unwrap().expose(), "completed");
					assert_eq!(row.coverage_at_finish, Some(generations::Coverage::Unknown));
					let summary: serde_json::Value =
						serde_json::from_str(row.terminal_counts.unwrap().expose()).unwrap();
					assert_eq!(
						summary["jobs"],
						serde_json::json!([{"kind":"survey","state":"succeeded","count":1}])
					);
					let before = tx.total_changes();
					assert_eq!(campaign::try_finish(tx, id, 2)?, None);
					assert_eq!(tx.total_changes(), before);
				}
				Ok(())
			})
		})
		.unwrap();
	}
}

#[test]
fn deadline_cancels_only_queued_work_and_waits_for_the_leased_child() {
	let db = fixture();
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			let (id, leased) = created(campaign::open(tx, &request(RequestedRef::Branch("main")), &ReviewPolicy::default(), 0)?);
			tx.execute("UPDATE jobs SET state='leased' WHERE id=?1", [leased])?;
			tx.execute("INSERT INTO jobs(repo_id,kind,state,campaign_id,enqueued_at) VALUES(1,'survey','queued',?1,1)", [id])?;
			let queued = tx.last_insert_rowid();
			assert_eq!(campaign::try_finish(tx, id, 21599)?, None);
			assert_eq!(jobs::get(tx, queued)?.unwrap().state, JobState::Queued);
			assert_eq!(campaign::try_finish(tx, id, 21600)?, None);
			let cancelled = jobs::get(tx, queued)?.unwrap();
			assert_eq!(cancelled.state, JobState::Cancelled);
			assert_eq!(cancelled.error.as_deref(), Some("campaign deadline"));
			assert_eq!(jobs::get(tx, leased)?.unwrap().state, JobState::Leased);
			assert_eq!(campaign::replenish(tx, id, 21600)?, None);
			tx.execute("UPDATE jobs SET state='succeeded',finished_at=21601 WHERE id=?1", [leased])?;
			assert_eq!(campaign::try_finish(tx, id, 21601)?, Some(campaign::Finish::DeadlineReached));
			let row = campaigns::get(tx, id)?.unwrap();
			assert_eq!(row.terminal_reason.unwrap().expose(), "deadline");
			assert!(row.terminal_counts.is_some());
			assert!(row.coverage_at_finish.is_some());
			Ok(())
		})
	}).unwrap();
}

#[test]
fn tick_without_active_campaigns_performs_no_writes() {
	let db = fixture();
	let before = db.with_conn(|c| Ok(c.total_changes())).unwrap();
	assert_eq!(campaign::tick(&db, 1).unwrap(), campaign::TickReport::default());
	assert_eq!(db.with_conn(|c| Ok(c.total_changes())).unwrap(), before);
	db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			let (id, _) = idle_campaign(tx, 1, &ReviewPolicy::default(), 0, false)?;
			campaign::try_finish(tx, id, 1)?;
			Ok(())
		})
	})
	.unwrap();
	let before = db.with_conn(|c| Ok(c.total_changes())).unwrap();
	assert_eq!(campaign::tick(&db, 2).unwrap(), campaign::TickReport::default());
	assert_eq!(db.with_conn(|c| Ok(c.total_changes())).unwrap(), before);
}

#[test]
fn tick_reports_budget_exhaustion_once_without_claiming_complete_coverage() {
	let db = fixture();
	let id = db
		.with_conn(|c| {
			transaction::immediate(c, |tx| {
				let policy = ReviewPolicy {
					campaign_max_jobs: 2,
					campaign_handoff_reserve: 1,
					..ReviewPolicy::default()
				};
				let (id, _) = idle_campaign(tx, 1, &policy, 0, true)?;
				Ok(id)
			})
		})
		.unwrap();
	let report = campaign::tick(&db, 1).unwrap();
	assert_eq!(report.completed, 1);
	assert_eq!(report.enqueued, 0);
	assert_eq!(report.budget_exhausted, 1);
	db.with_conn(|c| {
		let row = campaigns::get(c, id)?.unwrap();
		assert_eq!(row.coverage_at_finish, Some(generations::Coverage::Unknown));
		assert_eq!(row.state, campaigns::State::Finished);
		Ok(())
	})
	.unwrap();
	assert_eq!(campaign::tick(&db, 2).unwrap(), campaign::TickReport::default());
}

#[test]
fn tick_rolls_back_a_failed_campaign_and_still_processes_other_repositories() {
	let db = fixture();
	let first = db.with_conn(|c| {
		transaction::immediate(c, |tx| {
			let (first, _) = idle_campaign(tx, 1, &ReviewPolicy::default(), 0, true)?;
			tx.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(2,'v','github.com','o','r2','{\"kind\":\"manual\"}',0)", [])?;
			idle_campaign(tx, 2, &ReviewPolicy::default(), 0, true)?;
			tx.execute_batch("CREATE TEMP TRIGGER reject_first_campaign BEFORE INSERT ON jobs WHEN NEW.repo_id=1 BEGIN SELECT RAISE(ABORT,'injected campaign failure'); END")?;
			Ok(first)
		})
	}).unwrap();
	let report = campaign::tick(&db, 1).unwrap();
	assert_eq!(report.failed, 1);
	assert_eq!(report.enqueued, 1);
	db.with_conn(|c| {
		assert_eq!(campaigns::get(c, first)?.unwrap().state, campaigns::State::Active);
		let first_jobs: i64 =
			c.query_row("SELECT COUNT(*) FROM jobs WHERE campaign_id=?1", [first], |r| r.get(0))?;
		assert_eq!(first_jobs, 1);
		c.execute_batch("DROP TRIGGER reject_first_campaign")?;
		Ok(())
	})
	.unwrap();
	let report = campaign::tick(&db, 2).unwrap();
	assert_eq!(report.failed, 0);
	assert_eq!(report.enqueued, 1);
}

#[test]
fn pin_accepts_only_full_lowercase_hex_commit_ids() {
	// The pinned commit arrives from the worker's checkout checkpoint (B5),
	// so it is boundary input: only a complete SHA-1 or SHA-256 object id
	// may reach `target_commit_sha` and generation selection.
	let sha1 = "0123456789abcdef0123456789abcdef01234567";
	let sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
	for good in [sha1, sha256] {
		let db = fixture();
		db.with_conn(|c| {
			transaction::immediate(c, |tx| {
				let (campaign, job) = created(campaign::open(
					tx,
					&request(RequestedRef::Branch("main")),
					&ReviewPolicy::default(),
					0,
				)?);
				for bad in [
					"main",
					"sha",
					"ABCDEF0123456789ABCDEF0123456789ABCDEF01",
					&"a".repeat(39),
					&"a".repeat(41),
					&format!("{}\n", "a".repeat(39)),
					&"g".repeat(40),
				] {
					let outcome = campaign::pin(tx, campaign, job, bad, 1);
					assert!(matches!(outcome, Err(Error::Validation(_))), "{bad:?} → {outcome:?}");
				}
				let row = campaigns::get(tx, campaign)?.unwrap();
				assert!(row.generation_id.is_none());
				assert_eq!(row.target_commit_sha, "main");
				campaign::pin(tx, campaign, job, good, 1)?;
				assert_eq!(campaigns::get(tx, campaign)?.unwrap().target_commit_sha, good);
				Ok(())
			})
		})
		.unwrap();
	}
}
