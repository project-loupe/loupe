//! Acceptance fixtures for the currently write-only proof/detail APIs. These
//! closed read projections exercise actual SQLite columns and source metadata;
//! they do not claim a new production read endpoint or restore source types
//! from a runtime string. Non-Agent content remains Db on read.
use super::*;
use crate::{finding_details as details, proofs, test_support as input, transaction};

#[derive(Debug, Clone, Copy, PartialEq, Eq)] // debug-ok: closed source names only.
enum RecordedSource {
	Repo,
	Sandbox,
	Worker,
	Server,
	Operator,
	Provider,
	Reporter,
	Db,
	Config,
	Browser,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)] // debug-ok: closed classification only.
enum Classification {
	Agent,
	Recorded(RecordedSource),
}
fn classification(row: &Row<'_>, index: usize) -> rusqlite::Result<Classification> {
	use RecordedSource::*;
	let ValueRef::Text(bytes) = row.get_ref(index)? else {
		return Err(sql_error(index, ReadError::Syntax));
	};
	Ok(match bytes {
		b"agent" => Classification::Agent,
		b"repo" => Classification::Recorded(Repo),
		b"sandbox" => Classification::Recorded(Sandbox),
		b"worker" => Classification::Recorded(Worker),
		b"server" => Classification::Recorded(Server),
		b"operator" => Classification::Recorded(Operator),
		b"provider" => Classification::Recorded(Provider),
		b"reporter" => Classification::Recorded(Reporter),
		b"db" => Classification::Recorded(Db),
		b"config" => Classification::Recorded(Config),
		b"browser" => Classification::Recorded(Browser),
		_ => return Err(sql_error(index, ReadError::Syntax)),
	})
}
enum PayloadRead {
	AgentContent(BoundedJson<policy::Payload, Agent>),
	RecordedContent { source: RecordedSource, value: BoundedJson<policy::Payload, Db> },
}
fn payload_read(row: &Row<'_>, value: usize, source: usize) -> rusqlite::Result<PayloadRead> {
	Ok(match classification(row, source)? {
		Classification::Agent => PayloadRead::AgentContent(agent_payload(row, value)?),
		Classification::Recorded(source) => {
			PayloadRead::RecordedContent { source, value: db_payload(row, value)? }
		},
	})
}
// Only these two write-only display/narrative fields have fixture projections.
agent_field!(
	FixtureStoredName,
	FixtureAgentName,
	agent_name,
	BoundedText,
	policy::OriginalName,
	existing
);
db_field!(FixtureDbName, db_name, BoundedText, policy::OriginalName, existing);
agent_field!(
	FixtureStoredReason,
	FixtureAgentReason,
	agent_reason,
	BoundedText,
	policy::Reason,
	existing
);
enum NameRead {
	AgentContent(BoundedText<policy::OriginalName, Agent>),
	RecordedContent { source: RecordedSource, value: BoundedText<policy::OriginalName, Db> },
}
fn name_read(row: &Row<'_>) -> rusqlite::Result<NameRead> {
	Ok(match classification(row, 1)? {
		Classification::Agent => NameRead::AgentContent(agent_name(row, 0)?),
		Classification::Recorded(source) => {
			NameRead::RecordedContent { source, value: db_name(row, 0)? }
		},
	})
}
enum ReasonRead {
	AgentContent(BoundedText<policy::Reason, Agent>),
	RecordedContent { source: RecordedSource, value: BoundedText<policy::Reason, Db> },
}
fn reason_read(row: &Row<'_>) -> rusqlite::Result<Option<ReasonRead>> {
	let source = classification(row, 1)?;
	if is_null(row, 0)? {
		return Ok(None);
	}
	Ok(Some(match source {
		Classification::Agent => ReasonRead::AgentContent(agent_reason(row, 0)?),
		Classification::Recorded(source) => {
			ReasonRead::RecordedContent { source, value: reason(row, 0)? }
		},
	}))
}

#[test]
fn mixed_proof_inputs_record_only_the_designated_group_and_read_exclusions_as_db() {
	let db = crate::review_tests::fixture();
	db.with_conn(|conn| transaction::immediate(conn, |tx| {
        crate::scope_tests::findings(tx)?;
        let revision = input::repository("repo cafe\u{301}  ", |raw, mark| BoundedText::<policy::RevisionText, loupe_provenance::Repo>::new(mark, raw)).unwrap();
        let request = input::json::<policy::Payload>(r#"["agent-request"]"#).unwrap();
        let limits = input::config_json::<policy::Payload>(r#"{"unknown":"configured-limit"}"#).unwrap();
        let run = proofs::insert_execution(tx, &proofs::NewExecution {
            repo_id:1, produced_by_job:101, target_commit_sha:&revision, clean_tree:true,
            argv:&request, working_dir:&proofs::WorkingDirectory::Root, env_names:&request,
            fixture_artifact_ids:None, network_policy:proofs::NetworkPolicy::Isolated, limits:&limits,
            timeout_seconds:10, started_at:1, duration_ms:2, exit_status:Some(0), term_signal:None,
            stdout_artifact:None, stderr_artifact:None, output_truncated:false,
        }, 3)?;
        tx.query_row("SELECT argv,source,target_commit_sha,limits,working_dir,fixture_artifact_ids FROM proof_executions WHERE proof_execution_id=?1", [run], |row| {
            let PayloadRead::AgentContent(value) = payload_read(row,0,1)? else { panic!("Agent request lost its designated classification"); };
            let revision: BoundedText<policy::RevisionText,Db> = super::revision(row,2)?;
            let policy: BoundedJson<policy::Payload,Db> = db_payload(row,3)?;
            assert_eq!(value.expose(),request.expose()); assert_eq!(revision.expose(),"repo cafe\u{301}  "); assert_eq!(policy.expose(),limits.expose());
            assert_eq!(row.get::<_,String>(4)?,"."); assert!(is_null(row,5)?); Ok(())
        })?;
        let blob = proofs::insert_blob(tx,1,&input::artifact_bytes(b"opaque repository artifact"),0)?;
        let media = input::config_text("text/plain").unwrap();
        let name = input::config_text("configured-name.txt").unwrap();
        let artifact = proofs::insert_artifact(tx,&proofs::NewArtifact { repo_id:1,blob_id:blob,role:proofs::Role::CraftedInput,media_type:&media,label:None,original_name:&name,produced_by_job:Some(101) },0)?;
        let staged = proofs::insert_staged_artifact(tx,&proofs::NewStagedArtifact { repo_id:1,job_id:101,blob_id:blob,role:proofs::Role::CraftedInput,media_type:&media,label:None,original_name:&name },0)?;
        for (table,key,id) in [("proof_artifacts","proof_artifact_id",artifact),("staged_proof_artifacts","staged_proof_artifact_id",staged)] {
            let sql=format!("SELECT original_name,source,label FROM {table} WHERE {key}=?1");
            tx.query_row(&sql,[id],|row| {
                let NameRead::RecordedContent {source,value}=name_read(row)? else {panic!("Config metadata is not Agent content");};
                assert_eq!(source,RecordedSource::Config); assert_eq!(value.expose(),name.expose()); assert!(is_null(row,2)?); Ok(())
            })?;
        }
        let raw:Vec<u8>=tx.query_row("SELECT content FROM proof_artifact_blobs WHERE proof_artifact_blob_id=?1",[blob],|r|r.get(0))?;
        assert_eq!(raw,b"opaque repository artifact");
        let proof=proofs::insert_proof(tx,&proofs::NewProof{repo_id:1,finding_id:11,verification_id:11,rung:proofs::Rung::L3,pinned_commit_sha:&revision,manifest:&limits},0)?;
        tx.query_row("SELECT manifest,source,pinned_commit_sha FROM verification_proofs WHERE verification_proof_id=?1",[proof],|row|{
            let PayloadRead::RecordedContent{source,value}=payload_read(row,0,1)? else {panic!("Config manifest remains Db on read");};
            assert_eq!(source,RecordedSource::Config); assert_eq!(value.expose(),limits.expose()); assert_eq!(super::revision(row,2)?.expose(),revision.expose()); Ok(())
        })?;
        let narrative=input::config_text("configured rationale").unwrap();
        details::insert_attempt_details(tx,&details::NewAttempt{verification_id:11,repo_id:1,workflow_contract_version:1,checkout_commit_sha:&revision,established_rung:None,e2e_applicability:details::Applicability::NotApplicable,e2e_rationale:Some(&narrative),blocker:None,retry_condition:None,verification_proof:None,terminal_digest:&[7;32]},0)?;
        tx.query_row("SELECT e2e_rationale,source,checkout_commit_sha,blocker,retry_condition FROM verification_attempt_details WHERE verification_id=11",[],|row|{
            let Some(ReasonRead::RecordedContent{source,value})=reason_read(row)? else {panic!("Config narrative remains Db on read");};
            assert_eq!(source,RecordedSource::Config); assert_eq!(value.expose(),narrative.expose()); assert_eq!(super::revision(row,2)?.expose(),revision.expose()); assert!(is_null(row,3)?); assert!(is_null(row,4)?); Ok(())
        })?;
        Ok(())
    })).unwrap();
}

#[test]
fn closed_generic_read_fixture_accepts_known_metadata_and_refuses_noncanonical_names() {
	let conn = rusqlite::Connection::open_in_memory().unwrap();
	for source in [
		"agent", "repo", "sandbox", "worker", "server", "operator", "provider", "reporter", "db",
		"config", "browser",
	] {
		conn.query_row("SELECT ?1,?2", [r#"{"value":"cafe\u0301"}"#, source], |row| {
			match payload_read(row, 0, 1)? {
				PayloadRead::AgentContent(value) => {
					assert_eq!(source, "agent");
					assert_eq!(value.expose(), r#"{"value":"café"}"#);
				},
				PayloadRead::RecordedContent { source: kind, value } => {
					assert_ne!(source, "agent");
					assert_eq!(Classification::Recorded(kind), classification(row, 1)?);
					assert_eq!(value.expose(), r#"{"value":"café"}"#);
				},
			}
			Ok(())
		})
		.unwrap();
	}
	for source in ["Agent", "agent ", "unknown-private-source", ""] {
		let error = conn
			.query_row("SELECT '{}',?1", [source], |row| payload_read(row, 0, 1).map(|_| ()))
			.unwrap_err();
		assert!(!format!("{error:?} {error}").contains("unknown-private-source"));
		assert_eq!(
			conn.query_row("SELECT ?1", [source], |r| r.get::<_, String>(0)).unwrap(),
			source
		);
	}
	conn.query_row("SELECT 'agent-name.txt','agent'", [], |row| {
		let NameRead::AgentContent(value) = name_read(row)? else {
			panic!("Agent branch");
		};
		assert_eq!(value.expose(), "agent-name.txt");
		Ok(())
	})
	.unwrap();
	conn.query_row("SELECT 'agent-reason','agent'", [], |row| {
		let Some(ReasonRead::AgentContent(value)) = reason_read(row)? else {
			panic!("Agent branch");
		};
		assert_eq!(value.expose(), "agent-reason");
		Ok(())
	})
	.unwrap();
	conn.query_row("SELECT NULL,'config'", [], |row| {
		assert!(reason_read(row)?.is_none());
		Ok(())
	})
	.unwrap();
	assert!(conn
		.query_row("SELECT NULL,'Config'", [], |row| reason_read(row).map(|_| ()))
		.is_err());
}

#[test]
fn fixed_agent_review_readers_refuse_other_source_metadata_without_rewriting_rows() {
	let db = crate::review_tests::fixture();
	db.with_conn(|conn|{
        conn.execute_batch("INSERT INTO review_units(review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,created_at) VALUES(31,11,'unit','title','objective','[]',0);
        INSERT INTO review_unit_results(review_unit_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,created_at) VALUES(31,'repo-revision',1,'not_applicable','[]','{}',zeroblob(32),0);
        INSERT INTO leads(lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at) VALUES(41,11,'family','anchor',zeroblob(32),'{}',zeroblob(32),'repo-revision',0);
        INSERT INTO lead_observations(lead_id,observation_payload,observation_digest,commit_sha,created_at) VALUES(41,'{}',zeroblob(32),'repo-revision',0);")?;
        for source in ["agent","repo","config","Agent","agent ","unknown-private-source"] {
            for table in ["review_units","review_unit_results","leads","lead_observations"] {conn.execute(&format!("UPDATE {table} SET source=?1"),[source])?;}
            assert_eq!(crate::review_units::get(conn,31).is_ok(),source=="agent");
            assert_eq!(crate::review_unit_results::list(conn,31).is_ok(),source=="agent");
            assert_eq!(crate::leads::get(conn,41).is_ok(),source=="agent");
            assert_eq!(crate::lead_observations::list(conn,41).is_ok(),source=="agent");
            for table in ["review_units","review_unit_results","leads","lead_observations"] {assert_eq!(conn.query_row(&format!("SELECT source FROM {table}"),[],|r|r.get::<_,String>(0))?,source);}
        }
        Ok(())
    }).unwrap();
}
