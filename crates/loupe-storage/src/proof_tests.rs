use loupe_core::text::{Anchor, BoundedText, Identifier};

use crate::identity::Identity;
use crate::review_tests::{fixture, payload, reason};
use crate::scope_tests::findings;
use crate::{finding_details as f, proofs as p, transaction, Conflict, Error, Ownership};

#[test]
fn finding_identity_conflicts_report_the_canonical_finding() {
	let db = fixture();
	db.with_conn(|conn|transaction::immediate(conn,|tx|{
  findings(tx)?;let identity=Identity{family:Identifier::new("auth-bypass").unwrap(),anchor:Anchor::new("token refresh").unwrap(),instance:None};let argument=BoundedText::new("Source-backed reasoning").unwrap();let data=payload();
  let mut new=f::NewReview{finding_id:11,repo_id:1,workflow_contract_version:1,profile_version:1,profile_digest:None,reviewed_commit_sha:"base",identity:&identity,l2_argument:&data,counterevidence:&argument,assumptions_gaps:&argument,confidence:f::Confidence::High,submitted_rung:f::SubmittedRung::L2,origin_lead:None};
  f::insert_review_details(tx,&new,0).expect("store canonical review details");
  new.finding_id=12;
  assert!(matches!(f::insert_review_details(tx,&new,1),Err(Error::Conflict(Conflict::FindingIdentity(11)))));
  new.finding_id=21;
  assert!(matches!(f::insert_review_details(tx,&new,1),Err(Error::Ownership(Ownership::Finding))));
  new.repo_id=2;f::insert_review_details(tx,&new,1)?;
  tx.execute("INSERT INTO leads (lead_id,generation_id,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at) VALUES (21,21,'test-family','handler',zeroblob(32),'{}',zeroblob(32),'foreign',0)",[])?;
  new.finding_id=12;new.repo_id=1;new.origin_lead=Some(21);
  assert!(matches!(f::insert_review_details(tx,&new,1),Err(Error::Ownership(Ownership::FindingLead))));
  Ok(())
 })).unwrap();
}
#[test]
fn proof_rows_derive_blob_metadata_and_check_every_project_link() {
	let db = fixture();
	db.with_conn(|conn|transaction::immediate(conn,|tx|{
  findings(tx)?;
  let a=p::insert_blob(tx,1,b"proof",0).expect("persist a project blob");
  assert_eq!(p::insert_blob(tx,1,b"proof",1)?,a);
  let b=p::insert_blob(tx,2,b"proof",0)?;assert_ne!(a,b);
  let media=BoundedText::new("text/plain").unwrap();let name=BoundedText::new("proof.txt").unwrap();let label=Identifier::new("Reproducer").unwrap();
  let mut artifact=p::NewArtifact{repo_id:1,blob_id:b,role:p::Role::ReproducerSource,media_type:&media,label:Some(&label),original_name:&name,produced_by_job:Some(101)};
  assert!(matches!(p::insert_artifact(tx,&artifact,0),Err(Error::Ownership(Ownership::ArtifactBlob))));
  artifact.blob_id=a;artifact.produced_by_job=Some(201);
  assert!(matches!(p::insert_artifact(tx,&artifact,0),Err(Error::Ownership(Ownership::ArtifactJob))));
  artifact.produced_by_job=Some(101);let canonical=p::insert_artifact(tx,&artifact,0)?;
  artifact.repo_id=2;artifact.blob_id=b;artifact.produced_by_job=Some(201);let foreign=p::insert_artifact(tx,&artifact,0)?;
  let (len,digest):(i64,Vec<u8>)=tx.query_row("SELECT byte_len,sha256 FROM proof_artifacts WHERE proof_artifact_id=?1",[canonical],|r|Ok((r.get(0)?,r.get(1)?)))?;
  assert_eq!(len,5);assert_eq!(digest.len(),32);
  let mut staged=p::NewStagedArtifact{repo_id:1,job_id:101,blob_id:b,role:p::Role::CraftedInput,media_type:&media,label:None,original_name:&name};
  assert!(matches!(p::insert_staged_artifact(tx,&staged,0),Err(Error::Ownership(Ownership::ArtifactBlob))));
  staged.blob_id=a;staged.job_id=201;
  assert!(matches!(p::insert_staged_artifact(tx,&staged,0),Err(Error::Ownership(Ownership::ArtifactJob))));
  staged.job_id=101;let staged_id=p::insert_staged_artifact(tx,&staged,0)?;
  staged.repo_id=2;staged.job_id=201;staged.blob_id=b;
  let foreign_staged=p::insert_staged_artifact(tx,&staged,0)?;
  staged.repo_id=1;staged.job_id=102;staged.blob_id=a;
  let other_job_staged=p::insert_staged_artifact(tx,&staged,0)?;
  let data=payload();let argv="[\"test\"]".parse().unwrap();let root=p::WorkingDirectory::Root;
  let mut execution=p::NewExecution{repo_id:1,produced_by_job:201,target_commit_sha:"base",clean_tree:true,argv:&argv,working_dir:&root,env_names:&data,fixture_artifact_ids:None,network_policy:p::NetworkPolicy::Isolated,limits:&data,timeout_seconds:10,started_at:0,duration_ms:1,exit_status:Some(0),term_signal:None,stdout_artifact:None,stderr_artifact:None,output_truncated:false};
  assert!(matches!(p::insert_execution(tx,&execution,0),Err(Error::Ownership(Ownership::ExecutionJob))));
  execution.produced_by_job=101;execution.stdout_artifact=Some(foreign);
  assert!(matches!(p::insert_execution(tx,&execution,0),Err(Error::Ownership(Ownership::ExecutionArtifact))));
  execution.stdout_artifact=None;execution.stderr_artifact=Some(foreign);
  assert!(matches!(p::insert_execution(tx,&execution,0),Err(Error::Ownership(Ownership::ExecutionArtifact))));
  execution.stderr_artifact=Some(canonical);
  let foreign_refs=format!("[{foreign_staged}]").parse().unwrap();
  let other_job_refs=format!("[{other_job_staged}]").parse().unwrap();
  for refs in [&foreign_refs,&other_job_refs]{
   execution.fixture_artifact_ids=Some(refs);
   assert!(matches!(p::insert_execution(tx,&execution,0),Err(Error::Ownership(Ownership::ExecutionArtifact))));
  }
  let own_refs=format!("[{staged_id}]").parse().unwrap();
  execution.fixture_artifact_ids=Some(&own_refs);
  let run=p::insert_execution(tx,&execution,0)?;
  let stored_dir:String=tx.query_row("SELECT working_dir FROM proof_executions WHERE proof_execution_id=?1",[run],|r|r.get(0))?;assert_eq!(stored_dir,".");
  execution.repo_id=2;execution.produced_by_job=201;execution.stderr_artifact=Some(foreign);execution.fixture_artifact_ids=None;let foreign_run=p::insert_execution(tx,&execution,0)?;
  let mut proof=p::NewProof{repo_id:1,finding_id:21,verification_id:21,rung:p::Rung::L3,pinned_commit_sha:"base",manifest:&data};
  assert!(matches!(p::insert_proof(tx,&proof,0),Err(Error::Ownership(Ownership::ProofFinding))));
  proof.finding_id=11;proof.verification_id=12;
  assert!(matches!(p::insert_proof(tx,&proof,0),Err(Error::Ownership(Ownership::ProofVerification))));
  proof.verification_id=11;let proof_id=p::insert_proof(tx,&proof,0)?;
  proof.repo_id=2;proof.finding_id=21;proof.verification_id=21;let foreign_proof=p::insert_proof(tx,&proof,0)?;
  assert!(matches!(p::link_artifact(tx,1,proof_id,foreign),Err(Error::Ownership(Ownership::ProofArtifact))));
  assert!(matches!(p::link_artifact(tx,1,foreign_proof,canonical),Err(Error::Ownership(Ownership::ProofArtifact))));
  assert!(matches!(p::link_execution(tx,1,proof_id,foreign_run),Err(Error::Ownership(Ownership::ProofExecution))));
  assert!(matches!(p::link_execution(tx,1,foreign_proof,run),Err(Error::Ownership(Ownership::ProofExecution))));
  p::link_artifact(tx,1,proof_id,canonical)?;p::link_execution(tx,1,proof_id,run)?;
  let why=reason();
  let mut attempt=f::NewAttempt{verification_id:11,repo_id:2,workflow_contract_version:1,checkout_commit_sha:"base",established_rung:Some(f::EstablishedRung::L3),e2e_applicability:f::Applicability::NotApplicable,e2e_rationale:Some(&why),blocker:None,retry_condition:None,verification_proof:Some(proof_id),terminal_digest:&[1;32]};
  assert!(matches!(f::insert_attempt_details(tx,&attempt,0),Err(Error::Ownership(Ownership::Verification))));
  attempt.repo_id=1;attempt.verification_proof=Some(foreign_proof);
  assert!(matches!(f::insert_attempt_details(tx,&attempt,0),Err(Error::Ownership(Ownership::VerificationProof))));
  proof.repo_id=1;proof.finding_id=12;proof.verification_id=12;
  let sibling_proof=p::insert_proof(tx,&proof,0)?;
  attempt.verification_proof=Some(sibling_proof);
  assert!(matches!(f::insert_attempt_details(tx,&attempt,0),Err(Error::Ownership(Ownership::VerificationProof))));
  attempt.verification_proof=Some(proof_id);f::insert_attempt_details(tx,&attempt,0)?;
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
			let argument = BoundedText::new("Source-backed reasoning").unwrap();
			let data = payload();
			let first = Identity {
				family: Identifier::new("auth-bypass").unwrap(),
				anchor: Anchor::new("token refresh").unwrap(),
				instance: None,
			};
			let second = Identity {
				family: Identifier::new("auth-bypass").unwrap(),
				anchor: Anchor::new("session cookie").unwrap(),
				instance: None,
			};
			let mut review = f::NewReview {
				finding_id: 11,
				repo_id: 1,
				workflow_contract_version: 1,
				profile_version: 1,
				profile_digest: None,
				reviewed_commit_sha: "base",
				identity: &first,
				l2_argument: &data,
				counterevidence: &argument,
				assumptions_gaps: &argument,
				confidence: f::Confidence::High,
				submitted_rung: f::SubmittedRung::L2,
				origin_lead: None,
			};
			f::insert_review_details(tx, &review, 0)?;
			review.identity = &second;
			assert!(
				matches!(
					f::insert_review_details(tx, &review, 1),
					Err(Error::Conflict(Conflict::FindingDetails))
				),
				"a second details row for one finding is a conflict"
			);
			let why = reason();
			let attempt = f::NewAttempt {
				verification_id: 11,
				repo_id: 1,
				workflow_contract_version: 1,
				checkout_commit_sha: "base",
				established_rung: None,
				e2e_applicability: f::Applicability::NotApplicable,
				e2e_rationale: Some(&why),
				blocker: None,
				retry_condition: None,
				verification_proof: None,
				terminal_digest: &[1; 32],
			};
			f::insert_attempt_details(tx, &attempt, 0)?;
			assert!(
				matches!(
					f::insert_attempt_details(tx, &attempt, 1),
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
	assert!(BoundedText::<p::MediaType>::new(&"a".repeat(101)).is_err());
	assert!(BoundedText::<p::OriginalName>::new(&"x".repeat(513)).is_err());
	assert!(BoundedText::<p::OriginalName>::new("bad\nname").is_err());
	assert_eq!(p::WorkingDirectory::Directory("tests".parse().unwrap()).expose(), "tests");
}
