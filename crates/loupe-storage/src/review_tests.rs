//! Encrypted, FK-enabled fixtures with two projects and a successor generation.
use loupe_core::text::policy::{Payload, Reason};
use loupe_core::text::{BoundedJson, BoundedText};

use crate::secrets::MasterKey;
use crate::Db;

pub(crate) fn fixture() -> Db {
	let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
	seed(&db);
	db
}
pub(crate) fn seed(db: &Db) {
	db.with_conn(|c| {
		c.execute_batch("INSERT INTO registered_repos (id, clone_url, host, owner, repo, reporting, created_at)
		VALUES (1,'u1','github.com','o','r1','{\"kind\":\"manual\"}',0), (2,'u2','github.com','o','r2','{\"kind\":\"manual\"}',0);
		INSERT INTO review_generations (generation_id, repo_id, predecessor_generation_id, generation_commit_sha, state, workflow_contract_version, created_at)
		VALUES (11,1,NULL,'base','active',1,0), (12,1,11,'next','building',1,0), (21,2,NULL,'foreign','active',1,0);
		INSERT INTO review_campaigns (campaign_id,repo_id,recipe,trigger,target_commit_sha,generation_id,state,effective_policy,effective_policy_digest,created_at)
		VALUES (1,1,'bootstrap','manual','base',11,'active','{}',zeroblob(32),0), (2,2,'bootstrap','manual','foreign',21,'active','{}',zeroblob(32),0);
		INSERT INTO jobs (id,repo_id,kind,state,campaign_id,generation_id,enqueued_at)
		VALUES (101,1,'survey','queued',1,11,0), (102,1,'survey','queued',1,12,0), (201,2,'survey','queued',2,21,0);")?;
		Ok(())
	}).unwrap();
}
pub(crate) fn payload() -> BoundedJson<Payload> {
	BoundedJson::new("{}").unwrap()
}
pub(crate) fn reason() -> BoundedText<Reason> {
	BoundedText::new("completed").unwrap()
}

#[test]
fn inventory_real_paths_win_across_ingestion_batches() {
	use loupe_core::text::{RepoPath, SourceRef};

	use crate::{inventory as i, transaction};
	let db = fixture();
	db.with_conn(|conn| {
		let invalid = i::InventoryPath::from_git_bytes(b"bad\xff.rs");
		let first = i::NewEntry {
			path: &invalid,
			blob_sha: Some("invalid-blob"),
			kind: i::EntryKind::Tracked,
			disposition: i::Disposition::Unresolved,
			reason: None,
			highlighted: false,
		};
		i::standalone::insert(conn, 1, 11, &[first], 0)?;
		let real = i::InventoryPath::from_git_bytes(b"bad%FF.rs");
		let entry = i::NewEntry {
			path: &real,
			blob_sha: Some("real-blob"),
			kind: i::EntryKind::Tracked,
			disposition: i::Disposition::Mapped,
			reason: None,
			highlighted: true,
		};
		let outcome = i::standalone::insert(conn, 1, 11, &[entry], 1)
			.expect("real Git paths must supersede earlier encoded exclusions");
		assert_eq!(outcome.skipped, 1, "count the displaced unrepresentable entry");
		let rows = i::list(conn, 11)?;
		assert_eq!(rows.len(), 1);
		assert!(rows[0].path.representable());
		assert_eq!(rows[0].blob_sha.as_deref(), Some("real-blob"));
		assert_eq!(rows[0].disposition, i::Disposition::Mapped);
		transaction::immediate(conn, |tx| {
			i::verify_refs(
				tx,
				11,
				&[SourceRef { path: RepoPath::new("bad%FF.rs").unwrap(), symbol: None }],
			)
		})?;
		// Once evidence refers to an exclusion, replacing its display alias
		// would silently change that evidence's target; fail closed instead.
		let first=i::NewEntry{path:&invalid,blob_sha:Some("invalid-blob"),kind:i::EntryKind::Tracked,disposition:i::Disposition::Unresolved,reason:None,highlighted:false};
		i::standalone::insert(conn,1,12,&[first],0)?;
		conn.execute_batch("INSERT INTO review_units (review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES (31,12,'evidence','title','objective','[]',0);
            INSERT INTO review_unit_results (review_unit_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,corroborates_inventory_exclusion_id,created_at)
            SELECT 31,'next',1,'not_applicable','[]','{}',zeroblob(32),inventory_entry_id,0 FROM generation_inventory WHERE generation_id=12;")?;
		let entry=i::NewEntry{path:&real,blob_sha:Some("real-blob"),kind:i::EntryKind::Tracked,disposition:i::Disposition::Mapped,reason:None,highlighted:true};
		assert!(matches!(i::standalone::insert(conn,1,12,&[entry],1),Err(crate::Error::Conflict(crate::Conflict::InventoryPath))));
		assert!(!i::list(conn,12)?[0].path.representable());
		Ok(())
	})
	.unwrap();
}

#[test]
fn inventory_reingestion_of_identical_paths_is_idempotent() {
	// A retried or duplicated ingestion of the very same path and blob is a
	// no-op, so a partial upload can be resumed; only a *different* blob under
	// the same path is a conflict.
	use crate::{inventory as i, Conflict, Error};
	let db = fixture();
	db.with_conn(|conn| {
		let path = i::InventoryPath::from_git_bytes(b"src/lib.rs");
		let entry = |blob: &'static str| i::NewEntry {
			path: &path,
			blob_sha: Some(blob),
			kind: i::EntryKind::Tracked,
			disposition: i::Disposition::Unresolved,
			reason: None,
			highlighted: false,
		};
		assert_eq!(
			i::standalone::insert(conn, 1, 11, &[entry("blob-a"), entry("blob-a")], 0)?,
			i::Inserted { inserted: 1, excluded: 0, skipped: 1 },
			"a duplicate inside one batch is skipped, not fatal"
		);
		assert_eq!(
			i::standalone::insert(conn, 1, 11, &[entry("blob-a")], 1)?,
			i::Inserted { inserted: 0, excluded: 0, skipped: 1 },
			"re-ingesting the identical path is idempotent"
		);
		assert_eq!(i::list(conn, 11)?.len(), 1);
		assert!(
			matches!(
				i::standalone::insert(conn, 1, 11, &[entry("blob-b")], 2),
				Err(Error::Conflict(Conflict::InventoryPath))
			),
			"the same path with different content is a real conflict"
		);
		assert_eq!(i::list(conn, 11)?[0].blob_sha.as_deref(), Some("blob-a"));
		Ok(())
	})
	.unwrap();
}

#[test]
fn inventory_reason_cannot_impersonate_a_synthetic_exclusion() {
	use crate::{inventory as i, Error};
	let db = fixture();
	db.with_conn(|conn| {
		let real = i::InventoryPath::from_git_bytes(b"source.rs");
		let reserved = BoundedText::new("unrepresentable-path").unwrap();
		let entry = i::NewEntry {
			path: &real,
			blob_sha: None,
			kind: i::EntryKind::Tracked,
			disposition: i::Disposition::Excluded,
			reason: Some(&reserved),
			highlighted: false,
		};
		assert!(
			matches!(i::standalone::insert(conn, 1, 11, &[entry], 0), Err(Error::Validation(_))),
			"reserve the synthetic exclusion marker for ingestion"
		);
		assert!(i::list(conn, 11)?.is_empty());
		Ok(())
	})
	.unwrap();
}

#[test]
fn generation_activation_failure_rolls_back_both_states() {
	use crate::{generations as g, Error};
	let db = fixture();
	db.with_conn(|conn| {
		conn.execute_batch("CREATE TEMP TRIGGER fail_activation BEFORE UPDATE OF state ON review_generations WHEN NEW.generation_id=12 AND NEW.state='active' BEGIN SELECT RAISE(ABORT,'injected activation failure'); END;")?;
		assert!(matches!(g::standalone::activate(conn,12,10),Err(Error::Sqlite(_))));
		assert_eq!(g::get(conn,11)?.unwrap().state,g::State::Active);
		assert_eq!(g::get(conn,12)?.unwrap().state,g::State::Building);
		Ok(())
	}).unwrap();
}

#[test]
fn campaign_and_generation_reject_each_foreign_parent() {
	use crate::{campaigns as c, generations as g, inventory as i, transaction, Error, Ownership};
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let policy = payload();
			let mut new = c::NewCampaign {
				repo_id: 1,
				recipe: c::Recipe::Bootstrap,
				trigger: c::Trigger::Manual,
				requested_base_sha: None,
				target_commit_sha: "base",
				generation_id: None,
				effective_policy: &policy,
				deadline_at: None,
				root_campaign_id: None,
				continuation_of_campaign_id: None,
			};
			new.generation_id = Some(21);
			assert!(matches!(
				c::create(tx, &new, 0),
				Err(Error::Ownership(Ownership::CampaignGeneration))
			));
			new.generation_id = None;
			new.root_campaign_id = Some(2);
			assert!(matches!(
				c::create(tx, &new, 0),
				Err(Error::Ownership(Ownership::CampaignRoot))
			));
			new.root_campaign_id = None;
			new.continuation_of_campaign_id = Some(2);
			assert!(matches!(
				c::create(tx, &new, 0),
				Err(Error::Ownership(Ownership::CampaignContinuation))
			));
			assert!(matches!(
				g::create(
					tx,
					&g::NewGeneration {
						repo_id: 1,
						predecessor_generation_id: Some(21),
						commit_sha: "new",
						workflow_contract_version: 1
					},
					0
				),
				Err(Error::Ownership(Ownership::GenerationPredecessor))
			));
			assert!(matches!(
				i::insert(tx, 1, 21, &[], 0),
				Err(Error::Ownership(Ownership::InventoryGeneration))
			));
			let summary = c::summarize(tx, 2)?;
			assert!(matches!(
				c::finish(tx, 1, &summary, &reason(), 1),
				Err(Error::Ownership(Ownership::CampaignSummary))
			));
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn profiles_are_canonical_versioned_and_frozen_on_retirement() {
	use crate::{generations as g, transaction};
	let db = fixture();
	db.with_conn(|conn| transaction::immediate(conn, |tx| {
		let profile=BoundedJson::new("{\"z\":1, \"a\":2}").unwrap();
		g::set_profile(tx,11,1,&profile)?;
		assert!(g::set_profile(tx,11,1,&profile).is_err());
		g::set_profile(tx,11,2,&profile)?;
		let (stored,digest):(String,Vec<u8>)=tx.query_row("SELECT generated_profile,generated_profile_digest FROM review_generations WHERE generation_id=11",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
		assert_eq!(stored,profile.expose()); assert_eq!(digest,profile.digest());
		g::retire(tx,11,&reason(),2)?;
		assert!(g::set_profile(tx,11,3,&profile).is_err());
		assert!(g::set_pending_follow_up(tx,11,&payload()).is_err());
		Ok(())
	})).unwrap();
}

#[test]
fn inventory_exclusions_are_visible_but_not_referenceable() {
	use loupe_core::text::{RepoPath, SourceRef};

	use crate::{inventory as i, transaction, Conflict, Error};
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let paths = [
				i::InventoryPath::from_git_bytes(b"bad\xff.rs"),
				i::InventoryPath::from_git_bytes(b"bad%FF.rs"),
				i::InventoryPath::from_git_bytes(b"other\n.rs"),
			];
			let entries: Vec<_> = paths
				.iter()
				.map(|path| i::NewEntry {
					path,
					blob_sha: None,
					kind: i::EntryKind::Tracked,
					disposition: i::Disposition::Unresolved,
					reason: None,
					highlighted: false,
				})
				.collect();
			assert_eq!(
				i::insert(tx, 1, 11, &entries, 0)?,
				i::Inserted { inserted: 2, excluded: 1, skipped: 1 }
			);
			let rows = i::list(tx, 11)?;
			assert!(rows
				.iter()
				.any(|r| r.path.expose() == "other%0A.rs"
					&& r.disposition == i::Disposition::Excluded));
			i::verify_refs(
				tx,
				11,
				&[SourceRef { path: RepoPath::new("bad%FF.rs").unwrap(), symbol: None }],
			)?;
			assert!(i::verify_refs(
				tx,
				11,
				&[SourceRef { path: RepoPath::new("other%0A.rs").unwrap(), symbol: None }]
			)
			.is_err());
			let too_many: Vec<_> = (0..=i::MAX_ENTRIES)
				.map(|_| i::NewEntry {
					path: &paths[1],
					blob_sha: None,
					kind: i::EntryKind::Tracked,
					disposition: i::Disposition::Unresolved,
					reason: None,
					highlighted: false,
				})
				.collect();
			assert!(matches!(
				i::insert(tx, 1, 11, &too_many, 0),
				Err(Error::Conflict(Conflict::InventoryLimit))
			));
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn campaign_snapshots_stay_scoped_and_survive_generation_purge() {
	use crate::{campaigns as c, transaction};
	let db = fixture();
	db.with_conn(|conn| transaction::immediate(conn, |tx| {
		for (generation,repo,job) in [(11,1,101),(12,1,102),(21,2,201)] {
			tx.execute("INSERT INTO generation_inventory (generation_id,path,entry_kind,created_at) VALUES (?1,'src.rs','tracked',0)",[generation])?;
			tx.execute("INSERT INTO review_units (review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES (?1,?1,'unit','title','objective','[]',0)",[generation])?;
			tx.execute("INSERT INTO leads (lead_id,generation_id,review_unit_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at) VALUES (?1,?1,?1,'test-family','handler',?2,'{}',zeroblob(32),'base',0)",rusqlite::params![generation,[generation as u8;32].as_slice()])?;
			tx.execute("INSERT INTO findings (id,repo_id,job_id,scanner_id,severity,title,description,fingerprint,created_at) VALUES (?1,?2,?3,'test','high','title','description',?1,0)",rusqlite::params![generation,repo,job])?;
			tx.execute("INSERT INTO finding_review_details (finding_id,repo_id,workflow_contract_version,profile_version,reviewed_commit_sha,identity_family,identity_anchor,identity_fingerprint,l2_argument,counterevidence,assumptions_gaps,confidence,submitted_rung,origin_lead_id,created_at) VALUES (?1,?2,1,1,'base','test-family','handler',?3,'{}','counterevidence','gaps','high','L2',?1,0)",rusqlite::params![generation,repo,[generation as u8;32].as_slice()])?;
			tx.execute("INSERT INTO finding_verifications (finding_id,verdict,created_at) VALUES (?1,'confirmed',0)",[generation])?;
		}
		let summary=c::summarize(tx,1)?;
		let counts:serde_json::Value=serde_json::from_str(summary.counts.expose()).unwrap();
		assert_eq!(counts,serde_json::json!({"jobs":[{"kind":"survey","state":"queued","count":2}],"leads":{"status":{"open":1},"disposition":{}},"findings":{"pending":1},"verdicts":{"confirmed":1}}));
		c::finish(tx,1,&summary,&reason(),1)?;
		tx.execute("DELETE FROM review_generations WHERE generation_id=11",[])?;
		let campaign=c::get(tx,1)?.unwrap();
		assert_eq!(campaign.generation_id,None);
		assert_eq!(campaign.terminal_counts,Some(summary.counts));
		for table in ["review_units","leads","generation_inventory"] {
			let count:i64=tx.query_row(&format!("SELECT COUNT(*) FROM {table} WHERE generation_id=11"),[],|r|r.get(0))?;
			assert_eq!(count,0);
		}
		assert_eq!(tx.query_row("SELECT origin_lead_id FROM finding_review_details WHERE finding_id=11",[],|r|r.get::<_,Option<i64>>(0))?,None);
		assert_eq!(tx.query_row("SELECT COUNT(*) FROM findings",[],|r|r.get::<_,i64>(0))?,3);
		Ok(())
	})).unwrap();
}

#[test]
fn campaign_summaries_survive_future_job_kinds() {
	// job_kinds.kind is unconstrained text and future kinds stay readable
	// after a rollback, so a kind like `fix-patch` must not make the
	// campaign that owns it unfinishable by this binary.
	use crate::{campaigns as c, transaction};
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			tx.execute_batch(
				"INSERT INTO job_kinds VALUES ('fix-patch', 0);
				 INSERT INTO jobs (id,repo_id,kind,state,campaign_id,generation_id,enqueued_at)
				 VALUES (104,1,'fix-patch','queued',1,11,0);",
			)?;
			let summary = c::summarize(tx, 1)
				.expect("a future job kind must not make its campaign unfinishable");
			let counts: serde_json::Value = serde_json::from_str(summary.counts.expose()).unwrap();
			assert!(
				counts["jobs"].as_array().unwrap().iter().any(|row| row["kind"] == "fix-patch"
					&& row["state"] == "queued"
					&& row["count"] == 1),
				"the summary must still account for the unknown kind: {counts}"
			);
			c::finish(tx, 1, &summary, &reason(), 1)?;
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn campaign_and_generation_lifecycles_are_guarded_and_atomic() {
	use crate::{campaigns as c, generations as g, transaction, Conflict, Error};
	let db = fixture();
	db.with_conn(|conn| {
		assert_eq!(c::get(conn, 1)?.unwrap().state, c::State::Active);
		let policy = payload();
		let new = c::NewCampaign {
			repo_id: 1,
			recipe: c::Recipe::Bootstrap,
			trigger: c::Trigger::Manual,
			requested_base_sha: None,
			target_commit_sha: "base",
			generation_id: Some(11),
			effective_policy: &policy,
			deadline_at: None,
			root_campaign_id: None,
			continuation_of_campaign_id: None,
		};
		assert!(matches!(
			c::standalone::create(conn, &new, 1),
			Err(Error::Conflict(Conflict::ActiveCampaign))
		));
		transaction::immediate(conn, |tx| {
			g::activate(tx, 12, 10)?;
			assert_eq!(g::get(tx, 11)?.unwrap().state, g::State::Retired);
			assert_eq!(g::get(tx, 12)?.unwrap().state, g::State::Active);
			Ok(())
		})?;
		assert!(matches!(
			g::standalone::activate(conn, 12, 11),
			Err(Error::Conflict(Conflict::GenerationState))
		));
		let summary = transaction::immediate(conn, |tx| c::summarize(tx, 1))?;
		assert!(summary
			.counts
			.expose()
			.contains("\"count\":2,\"kind\":\"survey\",\"state\":\"queued\""));
		c::standalone::finish(conn, 1, &summary, &reason(), 12)?;
		assert_eq!(c::get(conn, 1)?.unwrap().state, c::State::Finished);
		assert!(matches!(
			c::standalone::cancel(conn, 1, &reason(), 13),
			Err(Error::Conflict(Conflict::CampaignState))
		));
		let id = c::standalone::create(conn, &new, 14)?;
		c::standalone::cancel(conn, id, &reason(), 15)?;
		assert_eq!(c::get(conn, id)?.unwrap().state, c::State::Cancelled);
		Ok(())
	})
	.unwrap();
}

#[test]
fn inventory_preserves_unicode_paths_and_scope() {
	use loupe_core::text::{RepoPath, SourceRef};

	use crate::{inventory as i, transaction};
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			let paths = [
				i::InventoryPath::from_git_bytes("café.rs".as_bytes()),
				i::InventoryPath::from_git_bytes("cafe\u{301}.rs".as_bytes()),
			];
			let entries: Vec<_> = paths
				.iter()
				.map(|path| i::NewEntry {
					path,
					blob_sha: None,
					kind: i::EntryKind::Tracked,
					disposition: i::Disposition::Unresolved,
					reason: None,
					highlighted: false,
				})
				.collect();
			assert_eq!(i::insert(tx, 1, 11, &entries, 0)?.inserted, 2);
			let rows = i::list(tx, 11)?;
			assert_eq!(rows.len(), 2);
			assert!(rows.iter().any(|e| e.path.expose() == "café.rs"));
			assert!(rows.iter().any(|e| e.path.expose() == "cafe\u{301}.rs"));
			let refs = [SourceRef { path: RepoPath::new("cafe\u{301}.rs").unwrap(), symbol: None }];
			i::verify_refs(tx, 11, &refs)?;
			assert!(i::verify_refs(
				tx,
				11,
				&[SourceRef { path: RepoPath::new("missing.rs").unwrap(), symbol: None }]
			)
			.is_err());
			assert!(i::insert(tx, 2, 11, &[], 0).is_err());
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn coverage_requires_all_three_rollup_conditions_and_corroboration() {
	use crate::{generations as g, transaction};
	let db = fixture();
	db.with_conn(|conn| transaction::immediate(conn, |tx| {
		assert!(g::set_coverage(tx, 11, g::Coverage::Complete).is_err());
		g::set_corroboration(tx, 11, g::Corroboration::Satisfied)?;
		g::set_coverage(tx, 11, g::Coverage::Complete)?;
		assert_eq!(g::get(tx, 11)?.unwrap().coverage, g::Coverage::Complete);
		tx.execute("INSERT INTO review_units (generation_id, client_review_unit_key, title, objective, source_refs, created_at) VALUES (11,'key','title','objective','[]',0)", [])?;
		assert!(!g::coverage_rollup(tx, 11)?.complete());
		assert!(g::set_coverage(tx, 11, g::Coverage::Complete).is_err());
		let unit=tx.last_insert_rowid();
		tx.execute("INSERT INTO review_unit_results (review_unit_id,produced_by_job_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,created_at) VALUES (?1,101,'older',1,'no_lead_found','[]','{}',zeroblob(32),0)",[unit])?;
		assert_eq!(g::coverage_rollup(tx,11)?.missing_results,1,"old-commit result does not establish coverage");
		tx.execute("UPDATE review_unit_results SET commit_sha='base'",[])?;
		g::set_coverage(tx,11,g::Coverage::Complete)?;
		tx.execute("UPDATE review_unit_results SET disposition='needs_follow_up'",[])?;
		assert_eq!(g::coverage_rollup(tx,11)?.needs_follow_up,1);
		assert!(g::set_coverage(tx,11,g::Coverage::Complete).is_err());
		tx.execute("UPDATE review_unit_results SET invalidated=1",[])?;
		assert_eq!(g::coverage_rollup(tx,11)?.missing_results,1);
		assert_eq!(g::coverage_rollup(tx,11)?.needs_follow_up,0);
		tx.execute("UPDATE review_unit_results SET invalidated=0,disposition='no_lead_found'",[])?;
		tx.execute("INSERT INTO generation_inventory (generation_id,path,entry_kind,created_at) VALUES (11,'src.rs','tracked',0)",[])?;
		assert_eq!(g::coverage_rollup(tx,11)?.unresolved_inventory,1);
		assert!(g::set_coverage(tx,11,g::Coverage::Complete).is_err());
		tx.execute("UPDATE generation_inventory SET disposition='mapped'",[])?;
		g::set_coverage(tx,11,g::Coverage::Complete)?;
		g::set_corroboration(tx,11,g::Corroboration::Contradicted)?;
		assert_eq!(g::get(tx,11)?.unwrap().coverage,g::Coverage::Partial);
		Ok(())
	})).unwrap();
}
