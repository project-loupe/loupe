use crate::identity::Identity;
use crate::review_tests::{fixture, payload, reason};
use crate::scope_tests::findings;
use crate::{finding_details as f, proofs as p, transaction, Conflict, Error, Ownership};

#[test]
fn finding_identity_conflicts_report_the_canonical_finding() {
	let db = fixture();
	db.with_conn(|conn|transaction::immediate(conn,|tx|{
  findings(tx)?;let identity=Identity{family:crate::test_support::identifier("auth-bypass").unwrap(),anchor:crate::test_support::anchor("token refresh").unwrap(),instance:None};let argument=crate::test_support::text("Source-backed reasoning").unwrap();let data=payload();
  let mut new_repo = 1; let mut new=f::NewReview{finding_id:11,workflow_contract_version:1,profile_version:1,profile_digest:None,reviewed_commit_sha: &crate::test_support::db_text("base").unwrap(),identity:&identity,l2_argument:&data,counterevidence:&argument,assumptions_gaps:&argument,confidence:f::Confidence::High,submitted_rung:f::SubmittedRung::L2,origin_lead:None};
  f::insert_review_details(&crate::test_support::scope(tx, new_repo),&new,0).expect("store canonical review details");
  new.finding_id=12;
  assert!(matches!(f::insert_review_details(&crate::test_support::scope(tx, new_repo),&new,1),Err(Error::Conflict(Conflict::FindingIdentity(11)))));
  new.finding_id=21;
  assert!(matches!(f::insert_review_details(&crate::test_support::scope(tx, new_repo),&new,1),Err(Error::Ownership(Ownership::Finding))));
  new_repo=2;f::insert_review_details(&crate::test_support::scope(tx, new_repo),&new,1)?;
  tx.execute("INSERT INTO leads (lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at) VALUES (21,21,'test-family','handler',zeroblob(32),'{}',zeroblob(32),'foreign',0)",[])?;
  new.finding_id=12;new_repo=1;new.origin_lead=Some(21);
  assert!(matches!(f::insert_review_details(&crate::test_support::scope(tx, new_repo),&new,1),Err(Error::Ownership(Ownership::FindingLead))));
  Ok(())
 })).unwrap();
}
#[test]
fn proof_rows_derive_blob_metadata_and_check_every_project_link() {
	let db = fixture();
	db.with_conn(|conn|transaction::immediate(conn,|tx|{
  findings(tx)?;
  let a=p::insert_blob(&crate::test_support::scope(tx, 1),&crate::test_support::artifact_bytes(b"proof"),0).expect("persist a project blob");
  assert_eq!(p::insert_blob(&crate::test_support::scope(tx, 1),&crate::test_support::artifact_bytes(b"proof"),1)?,a);
  let b=p::insert_blob(&crate::test_support::scope(tx, 2),&crate::test_support::artifact_bytes(b"proof"),0)?;assert_ne!(a,b);
  let media=crate::test_support::text("text/plain").unwrap();let name=crate::test_support::text("proof.txt").unwrap();let label=crate::test_support::identifier("Reproducer").unwrap();
  let mut artifact_repo = 1; let mut artifact=p::NewArtifact{blob_id:b,role:p::Role::ReproducerSource,media_type:&media,label:Some(&label),original_name:&name,produced_by_job:Some(101)};
  assert!(matches!(p::insert_artifact(&crate::test_support::scope(tx, artifact_repo),&artifact,0),Err(Error::Ownership(Ownership::ArtifactBlob))));
  artifact.blob_id=a;artifact.produced_by_job=Some(201);
  assert!(matches!(p::insert_artifact(&crate::test_support::scope(tx, artifact_repo),&artifact,0),Err(Error::Ownership(Ownership::ArtifactJob))));
  artifact.produced_by_job=Some(101);let canonical=p::insert_artifact(&crate::test_support::scope(tx, artifact_repo),&artifact,0)?;
  artifact_repo=2;artifact.blob_id=b;artifact.produced_by_job=Some(201);let foreign=p::insert_artifact(&crate::test_support::scope(tx, artifact_repo),&artifact,0)?;
  let (len,digest):(i64,Vec<u8>)=tx.query_row("SELECT byte_len,sha256 FROM proof_artifacts WHERE proof_artifact_id=?1",[canonical],|r|Ok((r.get(0)?,r.get(1)?)))?;
  assert_eq!(len,5);assert_eq!(digest.len(),32);
  let mut staged_repo = 1; let mut staged=p::NewStagedArtifact{job_id:101,blob_id:b,role:p::Role::CraftedInput,media_type:&media,label:None,original_name:&name};
  assert!(matches!(p::insert_staged_artifact(&crate::test_support::scope(tx, staged_repo),&staged,0),Err(Error::Ownership(Ownership::ArtifactBlob))));
  staged.blob_id=a;staged.job_id=201;
  assert!(matches!(p::insert_staged_artifact(&crate::test_support::scope(tx, staged_repo),&staged,0),Err(Error::Ownership(Ownership::ArtifactJob))));
  staged.job_id=101;let staged_id=p::insert_staged_artifact(&crate::test_support::scope(tx, staged_repo),&staged,0)?;
  staged_repo=2;staged.job_id=201;staged.blob_id=b;
  let foreign_staged=p::insert_staged_artifact(&crate::test_support::scope(tx, staged_repo),&staged,0)?;
  staged_repo=1;staged.job_id=102;staged.blob_id=a;
  let other_job_staged=p::insert_staged_artifact(&crate::test_support::scope(tx, staged_repo),&staged,0)?;
  let data=payload();let argv=crate::test_support::json("[\"test\"]").unwrap();let root=p::WorkingDirectory::Root;
  let mut execution_repo = 1; let mut execution=p::NewExecution{produced_by_job:201,target_commit_sha: &crate::test_support::db_text("base").unwrap(),clean_tree:true,argv:&argv,working_dir:&root,env_names:&data,fixture_artifact_ids:None,network_policy:p::NetworkPolicy::Isolated,limits:&data,timeout_seconds:10,started_at:0,duration_ms:1,exit_status:Some(0),term_signal:None,stdout_artifact:None,stderr_artifact:None,output_truncated:false};
  assert!(matches!(p::insert_execution(&crate::test_support::scope(tx, execution_repo),&execution,0),Err(Error::Ownership(Ownership::ExecutionJob))));
  execution.produced_by_job=101;execution.stdout_artifact=Some(foreign);
  assert!(matches!(p::insert_execution(&crate::test_support::scope(tx, execution_repo),&execution,0),Err(Error::Ownership(Ownership::ExecutionArtifact))));
  execution.stdout_artifact=None;execution.stderr_artifact=Some(foreign);
  assert!(matches!(p::insert_execution(&crate::test_support::scope(tx, execution_repo),&execution,0),Err(Error::Ownership(Ownership::ExecutionArtifact))));
  execution.stderr_artifact=Some(canonical);
  let foreign_refs=crate::test_support::json(&format!("[{foreign_staged}]")).unwrap();
  let other_job_refs=crate::test_support::json(&format!("[{other_job_staged}]")).unwrap();
  for refs in [&foreign_refs,&other_job_refs]{
   execution.fixture_artifact_ids=Some(refs);
   assert!(matches!(p::insert_execution(&crate::test_support::scope(tx, execution_repo),&execution,0),Err(Error::Ownership(Ownership::ExecutionArtifact))));
  }
  let own_refs=crate::test_support::json(&format!("[{staged_id}]")).unwrap();
  execution.fixture_artifact_ids=Some(&own_refs);
  let run=p::insert_execution(&crate::test_support::scope(tx, execution_repo),&execution,0)?;
  let stored_dir:String=tx.query_row("SELECT working_dir FROM proof_executions WHERE proof_execution_id=?1",[run],|r|r.get(0))?;assert_eq!(stored_dir,".");
  execution_repo=2;execution.produced_by_job=201;execution.stderr_artifact=Some(foreign);execution.fixture_artifact_ids=None;let foreign_run=p::insert_execution(&crate::test_support::scope(tx, execution_repo),&execution,0)?;
  let mut proof_repo = 1; let mut proof=p::NewProof{finding_id:21,verification_id:21,rung:p::Rung::L3,pinned_commit_sha: &crate::test_support::db_text("base").unwrap(),manifest:&data};
  assert!(matches!(p::insert_proof(&crate::test_support::scope(tx, proof_repo),&proof,0),Err(Error::Ownership(Ownership::ProofFinding))));
  proof.finding_id=11;proof.verification_id=12;
  assert!(matches!(p::insert_proof(&crate::test_support::scope(tx, proof_repo),&proof,0),Err(Error::Ownership(Ownership::ProofVerification))));
  proof.verification_id=11;let proof_id=p::insert_proof(&crate::test_support::scope(tx, proof_repo),&proof,0)?;
  proof_repo=2;proof.finding_id=21;proof.verification_id=21;let foreign_proof=p::insert_proof(&crate::test_support::scope(tx, proof_repo),&proof,0)?;
  assert!(matches!(p::link_artifact(&crate::test_support::scope(tx, 1),proof_id,foreign),Err(Error::Ownership(Ownership::ProofArtifact))));
  assert!(matches!(p::link_artifact(&crate::test_support::scope(tx, 1),foreign_proof,canonical),Err(Error::Ownership(Ownership::ProofArtifact))));
  assert!(matches!(p::link_execution(&crate::test_support::scope(tx, 1),proof_id,foreign_run),Err(Error::Ownership(Ownership::ProofExecution))));
  assert!(matches!(p::link_execution(&crate::test_support::scope(tx, 1),foreign_proof,run),Err(Error::Ownership(Ownership::ProofExecution))));
  p::link_artifact(&crate::test_support::scope(tx, 1),proof_id,canonical)?;p::link_execution(&crate::test_support::scope(tx, 1),proof_id,run)?;
  let why=reason();
  let mut attempt_repo = 2; let mut attempt=f::NewAttempt{verification_id:11,workflow_contract_version:1,checkout_commit_sha: &crate::test_support::db_text("base").unwrap(),established_rung:Some(f::EstablishedRung::L3),e2e_applicability:f::Applicability::NotApplicable,e2e_rationale:Some(&why),blocker:None,retry_condition:None,verification_proof:Some(proof_id),terminal_digest:&[1;32]};
  assert!(matches!(f::insert_attempt_details(&crate::test_support::scope(tx, attempt_repo),&attempt,0),Err(Error::Ownership(Ownership::Verification))));
  attempt_repo=1;attempt.verification_proof=Some(foreign_proof);
  assert!(matches!(f::insert_attempt_details(&crate::test_support::scope(tx, attempt_repo),&attempt,0),Err(Error::Ownership(Ownership::VerificationProof))));
  proof_repo=1;proof.finding_id=12;proof.verification_id=12;
  let sibling_proof=p::insert_proof(&crate::test_support::scope(tx, proof_repo),&proof,0)?;
  attempt.verification_proof=Some(sibling_proof);
  assert!(matches!(f::insert_attempt_details(&crate::test_support::scope(tx, attempt_repo),&attempt,0),Err(Error::Ownership(Ownership::VerificationProof))));
  attempt.verification_proof=Some(proof_id);f::insert_attempt_details(&crate::test_support::scope(tx, attempt_repo),&attempt,0)?;
  assert!(tx.query_row("SELECT EXISTS(SELECT 1 FROM staged_proof_artifacts WHERE staged_proof_artifact_id=?1)",[staged_id],|r|r.get::<_,bool>(0))?);
  Ok(())
 })).unwrap();
}
#[test]
fn repeated_detail_rows_are_conflicts_not_internal_errors() {
	// Both detail tables are keyed by their parent's id; a client retrying after
	// a committed first attempt must see a conflict, not a 500-shaped error.
	let db = fixture();
	db.with_conn(|conn| {
		transaction::immediate(conn, |tx| {
			findings(tx)?;
			let argument = crate::test_support::text("Source-backed reasoning").unwrap();
			let data = payload();
			let first = Identity {
				family: crate::test_support::identifier("auth-bypass").unwrap(),
				anchor: crate::test_support::anchor("token refresh").unwrap(),
				instance: None,
			};
			let second = Identity {
				family: crate::test_support::identifier("auth-bypass").unwrap(),
				anchor: crate::test_support::anchor("session cookie").unwrap(),
				instance: None,
			};
			let mut review = f::NewReview {
				finding_id: 11,

				workflow_contract_version: 1,
				profile_version: 1,
				profile_digest: None,
				reviewed_commit_sha: &crate::test_support::db_text("base").unwrap(),
				identity: &first,
				l2_argument: &data,
				counterevidence: &argument,
				assumptions_gaps: &argument,
				confidence: f::Confidence::High,
				submitted_rung: f::SubmittedRung::L2,
				origin_lead: None,
			};
			f::insert_review_details(&crate::test_support::scope(tx, 1), &review, 0)?;
			review.identity = &second;
			assert!(
				matches!(
					f::insert_review_details(&crate::test_support::scope(tx, 1), &review, 1),
					Err(Error::Conflict(Conflict::FindingDetails))
				),
				"a second details row for one finding is a conflict"
			);
			let why = reason();
			let attempt_repo = 1;
			let attempt = f::NewAttempt {
				verification_id: 11,

				workflow_contract_version: 1,
				checkout_commit_sha: &crate::test_support::db_text("base").unwrap(),
				established_rung: None,
				e2e_applicability: f::Applicability::NotApplicable,
				e2e_rationale: Some(&why),
				blocker: None,
				retry_condition: None,
				verification_proof: None,
				terminal_digest: &[1; 32],
			};
			f::insert_attempt_details(&crate::test_support::scope(tx, attempt_repo), &attempt, 0)?;
			assert!(
				matches!(
					f::insert_attempt_details(
						&crate::test_support::scope(tx, attempt_repo),
						&attempt,
						1
					),
					Err(Error::Conflict(Conflict::AttemptDetails))
				),
				"a second attempt-details row for one verification is a conflict"
			);
			Ok(())
		})
	})
	.unwrap();
}

#[test]
fn proof_display_fields_are_bound_to_their_own_policies() {
	assert!(crate::test_support::text::<p::MediaType>(&"a".repeat(101)).is_err());
	assert!(crate::test_support::text::<p::OriginalName>(&"x".repeat(513)).is_err());
	assert!(crate::test_support::text::<p::OriginalName>("bad\nname").is_err());
	assert_eq!(
		p::WorkingDirectory::Directory(crate::test_support::path("tests").unwrap()).expose(),
		"tests"
	);
}
