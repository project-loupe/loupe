use rusqlite::types::Value;
use rusqlite::Connection;

use super::{apply_migrations, fixtures, MIGRATIONS};
use crate::secrets::MasterKey;
use crate::{Db, Error};

const PRIVATE: &str = "private-upgrade-payload\u{1b}";

pub(super) fn snapshot(conn: &Connection) -> Vec<(String, Vec<Vec<Value>>)> {
	let names: Vec<String> = conn
		.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
		.unwrap()
		.query_map([], |r| r.get(0))
		.unwrap()
		.collect::<rusqlite::Result<_>>()
		.unwrap();
	names
		.into_iter()
		.map(|name| {
			let sql = format!("SELECT * FROM \"{}\"", name.replace('"', "\"\""));
			let rows = fixtures::rows(conn, &sql);
			(name, rows)
		})
		.collect()
}

fn rich_v5(conn: &mut Connection) {
	fixtures::v1(conn);
	apply_migrations(conn, &MIGRATIONS[..5]).unwrap();
	conn.execute_batch(r#"
INSERT INTO review_generations(generation_id,repo_id,generation_commit_sha,state,workflow_contract_version,created_at) VALUES(11,1,'base','retired',1,0);
INSERT INTO review_campaigns(campaign_id,repo_id,recipe,trigger,target_commit_sha,generation_id,state,effective_policy,effective_policy_digest,created_at) VALUES(11,1,'bootstrap','manual','base',11,'finished','{}',zeroblob(32),0);
INSERT INTO generation_inventory(inventory_entry_id,generation_id,path,entry_kind,created_at) VALUES(11,11,'src/lib.rs','tracked',0);
INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,status,source_refs,created_at) VALUES(11,11,'unit','title','objective','retired','[]',0);
INSERT INTO review_unit_results(review_unit_result_id,review_unit_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,invalidated,created_at) VALUES(11,11,'base',1,'not_applicable','[]','{}',zeroblob(32),1,0);
INSERT INTO leads(lead_id,generation_id,status,disposition,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at) VALUES(11,11,'closed','stale','family','anchor',zeroblob(32),'{}',zeroblob(32),'base',0);
INSERT INTO lead_observations(lead_observation_id,lead_id,observation_payload,observation_digest,commit_sha,created_at) VALUES(11,11,'{}',zeroblob(32),'base',0);
INSERT INTO job_checkpoints(job_checkpoint_id,job_id,client_key,operation,payload_digest,response,created_at) VALUES(11,1,'submit_lead:key','submit_lead',zeroblob(32),'{}',0);
INSERT INTO job_terminal_receipts(job_terminal_receipt_id,job_id,phase,terminal_reason,pinned_commit_sha,effective_recipe,result_digest,created_at) VALUES(11,1,'scan','complete','base','{}',zeroblob(32),0);
INSERT INTO finding_review_details(finding_id,repo_id,workflow_contract_version,profile_version,reviewed_commit_sha,identity_family,identity_anchor,identity_fingerprint,l2_argument,counterevidence,assumptions_gaps,confidence,submitted_rung,created_at) VALUES(1,1,1,1,'base','family','anchor',zeroblob(32),'{}','counterevidence','assumptions','high','L2',0);
INSERT INTO verification_attempt_details(verification_id,workflow_contract_version,checkout_commit_sha,e2e_applicability,e2e_rationale,terminal_digest,created_at) VALUES(1,1,'base','not_applicable','rationale',zeroblob(32),0);
INSERT INTO proof_artifact_blobs(proof_artifact_blob_id,repo_id,sha256,byte_len,content,created_at) VALUES(11,1,zeroblob(32),1,x'61',0);
INSERT INTO proof_artifacts(proof_artifact_id,repo_id,proof_artifact_blob_id,artifact_role,media_type,original_name,sha256,byte_len,created_at) VALUES(11,1,11,'crafted_input','text/plain','sample.txt',zeroblob(32),1,0);
INSERT INTO staged_proof_artifacts(staged_proof_artifact_id,repo_id,job_id,proof_artifact_blob_id,artifact_role,media_type,original_name,created_at) VALUES(11,1,1,11,'crafted_input','text/plain','sample.txt',0);
INSERT INTO proof_executions(proof_execution_id,repo_id,produced_by_job_id,target_commit_sha,clean_tree,argv,working_dir,env_names,fixture_artifact_ids,network_policy,limits,timeout_seconds,started_at,duration_ms,created_at) VALUES(11,1,1,'base',1,'[]','.','[]','[11]','isolated','{}',1,0,1,0);
INSERT INTO verification_proofs(verification_proof_id,finding_id,verification_id,repo_id,rung,pinned_commit_sha,manifest,manifest_digest,created_at) VALUES(11,4,1,1,'L3','base','{}',zeroblob(32),0);
INSERT INTO secrets(id,kind,label,value,created_at) VALUES(11,'github_app','server',x'7b7d',0);
"#).unwrap();
	let policy = serde_json::to_string(&crate::scheduler::CampaignPolicy::default()).unwrap();
	conn.execute("UPDATE review_campaigns SET effective_policy=?1", [policy]).unwrap();
	conn.execute(
		"UPDATE secrets SET value=?1 WHERE id=11",
		[br#"{"app_id":1,"slug":"application","private_key_pem":"opaque PEM"}"#.as_slice()],
	)
	.unwrap();
}

fn refuse(table: &'static str, column: &'static str, rowid: i64, bad: Value) {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("upgrade.sqlite");
	let mut conn = fixtures::open(&path);
	rich_v5(&mut conn);
	let sql = format!("UPDATE {table} SET {column}=?1 WHERE rowid=?2");
	let original: Value = conn
		.query_row(&format!("SELECT {column} FROM {table} WHERE rowid=?1"), [rowid], |r| r.get(0))
		.unwrap();
	conn.execute(&sql, (&bad, rowid)).unwrap();
	let schema = fixtures::schema(&conn);
	let before = snapshot(&conn);
	drop(conn);
	let error = match Db::open(&path, &MasterKey::for_tests()) {
		Err(error) => error,
		Ok(_) => panic!("upgrade admission must reject invalid {table}.{column} row {rowid}"),
	};
	let Error::Migration(failure) = &error else {
		panic!("expected safe migration failure: {error}")
	};
	assert_eq!(failure.table, Some(table));
	assert_eq!(failure.column, Some(column));
	assert_eq!(failure.rowid, Some(rowid));
	assert_eq!(failure.source_version, Some(5));
	assert_eq!(failure.target_version, 6);
	assert!(!format!("{error} {error:?} {error:#}").contains("private-upgrade-payload"));
	assert!(std::error::Error::source(&error).is_none());
	let conn = fixtures::open(&path);
	assert_eq!(fixtures::markers(&conn), (5, 5));
	assert_eq!(fixtures::schema(&conn), schema);
	assert_eq!(snapshot(&conn), before);
	conn.execute(&sql, (&original, rowid)).unwrap();
	drop(conn);
	let db = Db::open(&path, &MasterKey::for_tests()).unwrap();
	assert_eq!(db.schema_version().unwrap(), 6);
}

macro_rules! rejects {
	($name:ident, $table:literal, $column:literal, $id:expr, $bad:expr) => {
		#[test]
		fn $name() {
			refuse($table, $column, $id, $bad);
		}
	};
}
rejects!(
	upgrade_admission_disabled_repo,
	"registered_repos",
	"owner",
	3,
	PRIVATE.to_owned().into()
);
rejects!(upgrade_admission_revoked_worker, "workers", "name", 2, PRIVATE.to_owned().into());
rejects!(upgrade_admission_cancelled_job, "jobs", "error", 4, PRIVATE.to_owned().into());
rejects!(upgrade_admission_later_finding, "findings", "title", 6, PRIVATE.to_owned().into());
rejects!(upgrade_admission_verdict, "finding_verifications", "notes", 1, PRIVATE.to_owned().into());
rejects!(upgrade_admission_history, "scan_history", "head_sha", 1, PRIVATE.to_owned().into());
rejects!(
	upgrade_admission_campaign,
	"review_campaigns",
	"effective_policy",
	11,
	"{}".to_owned().into()
);
rejects!(
	upgrade_admission_retired_generation,
	"review_generations",
	"generated_profile",
	11,
	"[}".to_owned().into()
);
rejects!(
	upgrade_admission_inventory,
	"generation_inventory",
	"path",
	11,
	"../private-upgrade-payload".to_owned().into()
);
rejects!(upgrade_admission_retired_unit, "review_units", "title", 11, PRIVATE.to_owned().into());
rejects!(
	upgrade_admission_unit_refs,
	"review_units",
	"source_refs",
	11,
	r#"[{"path":"../private-upgrade-payload"}]"#.to_owned().into()
);
rejects!(
	upgrade_admission_invalidated_result,
	"review_unit_results",
	"result_payload",
	11,
	"[}".to_owned().into()
);
rejects!(upgrade_admission_closed_lead, "leads", "identity_family", 11, PRIVATE.to_owned().into());
rejects!(
	upgrade_admission_observation,
	"lead_observations",
	"observation_payload",
	11,
	"[}".to_owned().into()
);
rejects!(upgrade_admission_checkpoint, "job_checkpoints", "response", 11, "[}".to_owned().into());
rejects!(
	upgrade_admission_receipt,
	"job_terminal_receipts",
	"terminal_reason",
	11,
	PRIVATE.to_owned().into()
);
rejects!(
	upgrade_admission_review_details,
	"finding_review_details",
	"counterevidence",
	1,
	PRIVATE.to_owned().into()
);
rejects!(
	upgrade_admission_attempt_details,
	"verification_attempt_details",
	"blocker",
	1,
	PRIVATE.to_owned().into()
);
rejects!(
	upgrade_admission_artifact,
	"proof_artifacts",
	"original_name",
	11,
	PRIVATE.to_owned().into()
);
rejects!(
	upgrade_admission_staged_artifact,
	"staged_proof_artifacts",
	"media_type",
	11,
	PRIVATE.to_owned().into()
);
rejects!(
	upgrade_admission_execution,
	"proof_executions",
	"working_dir",
	11,
	"../private-upgrade-payload".to_owned().into()
);
rejects!(
	upgrade_admission_execution_fixtures,
	"proof_executions",
	"fixture_artifact_ids",
	11,
	"{}".to_owned().into()
);
rejects!(upgrade_admission_proof, "verification_proofs", "manifest", 11, "[}".to_owned().into());
rejects!(
	upgrade_admission_full_app,
	"secrets",
	"value",
	11,
	br#"{"app_id":1,"slug":"application","private_key_pem":12}"#.to_vec().into()
);
rejects!(
	upgrade_admission_blob_type,
	"jobs",
	"job_capability_hash",
	4,
	"private-upgrade-payload".to_owned().into()
);

#[test]
fn upgrade_admission_every_historical_version_is_atomic() {
	for version in 1..=5 {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("upgrade.sqlite");
		let mut conn = fixtures::open(&path);
		fixtures::v1(&mut conn);
		apply_migrations(&mut conn, &MIGRATIONS[..version]).unwrap();
		conn.execute("UPDATE registered_repos SET owner=?1 WHERE id=3", [PRIVATE]).unwrap();
		if version == 1 {
			conn.execute("UPDATE jobs SET state='leased' WHERE id=3", []).unwrap();
		}
		let schema = fixtures::schema(&conn);
		let before = snapshot(&conn);
		drop(conn);
		assert!(
			Db::open(&path, &MasterKey::for_tests()).is_err(),
			"upgrade admission must reject invalid v{version} data"
		);
		let conn = fixtures::open(&path);
		assert_eq!(fixtures::markers(&conn), (version as u32, version as u32));
		assert_eq!(fixtures::schema(&conn), schema);
		assert_eq!(snapshot(&conn), before);
		conn.execute("UPDATE registered_repos SET owner='c' WHERE id=3", []).unwrap();
		drop(conn);
		assert_eq!(Db::open(&path, &MasterKey::for_tests()).unwrap().schema_version().unwrap(), 6);
	}
}

#[test]
fn upgrade_preserves_compatible_bytes_and_all_table_contents() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("compatible.sqlite");
	let mut conn = fixtures::open(&path);
	rich_v5(&mut conn);
	conn.execute(
		"UPDATE registered_repos SET owner=?1,scanner_config='{malformed' WHERE id=3",
		[" cafe\u{301}  "],
	)
	.unwrap();
	conn.execute(
		"UPDATE registered_repos SET reporting=?1 WHERE id=2",
		[r#"["email",["same","same"],null,""]"#],
	)
	.unwrap();
	conn.execute("UPDATE findings SET description=?1 WHERE id=6", ["one\r\ntwo cafe\u{301}  "])
		.unwrap();
	conn.execute_batch("UPDATE generation_inventory SET path='../display-alias',disposition='excluded',disposition_reason='unrepresentable-path';
INSERT INTO job_checkpoints(job_id,client_key,operation,payload_digest,response,created_at) VALUES(1,'initialize_survey_batch:ordinary','initialize_survey_batch',zeroblob(32),'{}',0);
INSERT INTO job_kinds VALUES('future.phase',0);
INSERT INTO jobs(repo_id,kind,state,enqueued_at) VALUES(1,'future.phase','succeeded',0);").unwrap();
	let before = snapshot(&conn);
	// Save historical projections so the new source metadata does not hide
	// any changes to old fields. Include derived FTS table contents as well.
	let projections: Vec<_> = before
		.iter()
		.map(|(table, _)| {
			let names: Vec<String> = conn
				.prepare(&format!("PRAGMA table_info({table})"))
				.unwrap()
				.query_map([], |r| r.get(1))
				.unwrap()
				.collect::<rusqlite::Result<_>>()
				.unwrap();
			(table.clone(), names.join(","))
		})
		.collect();
	drop(conn);
	let db = Db::open(&path, &MasterKey::for_tests()).unwrap();
	assert_eq!(db.schema_version().unwrap(), 6);
	db.with_conn(|conn| {
		for ((table, expected), (_, columns)) in before.iter().zip(&projections) {
			if table != "schema_meta" {
				assert_eq!(
					&fixtures::rows(conn, &format!("SELECT {columns} FROM {table}")),
					expected,
					"old content changed in {table}"
				);
			}
		}
		// Generic write-only sources are valid classifications, and content
		// admission must not reinterpret them as Agent fields.
		for table in [
			"verification_attempt_details",
			"proof_artifacts",
			"staged_proof_artifacts",
			"proof_executions",
			"verification_proofs",
		] {
			conn.execute(&format!("UPDATE {table} SET source='config'"), [])?;
		}
		super::admission::validate(conn)?;
		Ok(())
	})
	.unwrap();
	drop(db);
	assert_eq!(Db::open(&path, &MasterKey::for_tests()).unwrap().schema_version().unwrap(), 6);
}
