//! Typed proof-row persistence, without staging/finalization or garbage collection.
use loupe_core::text::policy::{Label, Payload, RevisionText};
pub use loupe_core::text::policy::{MediaType, OriginalName};
use loupe_core::text::{BoundedJson, BoundedText, Identifier, RepoPath};
use loupe_provenance::{Mark, Source};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};

use crate::review::{is_unique, standalone, string_enum};
use crate::scope::{Assignment, Scope, Subject, SubjectKind};
use crate::{ownership, Ownership, Result};
string_enum!(Role { ReproducerSource=>"reproducer_source", CraftedInput=>"crafted_input", TestPatch=>"test_patch", CommandStdout=>"command_stdout", CommandStderr=>"command_stderr", ExecutionTrace=>"execution_trace" });
string_enum!(Rung { L3=>"L3", L4=>"L4" });
string_enum!(NetworkPolicy { Isolated=>"isolated" });
#[derive(Debug)]
pub enum WorkingDirectory<S: Source> {
	Root,
	Directory(RepoPath<S>),
}
impl<S: Source> Clone for WorkingDirectory<S> {
	fn clone(&self) -> Self {
		match self {
			Self::Root => Self::Root,
			Self::Directory(path) => Self::Directory(path.clone()),
		}
	}
}
impl<S: Source> PartialEq for WorkingDirectory<S> {
	fn eq(&self, other: &Self) -> bool {
		match (self, other) {
			(Self::Root, Self::Root) => true,
			(Self::Directory(a), Self::Directory(b)) => a == b,
			_ => false,
		}
	}
}
impl<S: Source> Eq for WorkingDirectory<S> {}
impl<S: Source> WorkingDirectory<S> {
	pub fn expose(&self) -> &str {
		match self {
			Self::Root => ".",
			Self::Directory(path) => path.expose(),
		}
	}
}
pub struct NewArtifact<'a, MetadataS: Source> {
	pub repo_id: i64,
	pub blob_id: i64,
	pub role: Role,
	pub media_type: &'a BoundedText<MediaType, MetadataS>,
	pub label: Option<&'a Identifier<Label, MetadataS>>,
	pub original_name: &'a BoundedText<OriginalName, MetadataS>,
	pub produced_by_job: Option<i64>,
}
pub struct NewStagedArtifact<'a, MetadataS: Source> {
	pub repo_id: i64,
	pub job_id: i64,
	pub blob_id: i64,
	pub role: Role,
	pub media_type: &'a BoundedText<MediaType, MetadataS>,
	pub label: Option<&'a Identifier<Label, MetadataS>>,
	pub original_name: &'a BoundedText<OriginalName, MetadataS>,
}
pub struct NewExecution<'a, RevisionS: Source, RequestS: Source, PolicyS: Source> {
	pub repo_id: i64,
	pub produced_by_job: i64,
	pub target_commit_sha: &'a BoundedText<RevisionText, RevisionS>,
	pub clean_tree: bool,
	pub argv: &'a BoundedJson<Payload, RequestS>,
	pub working_dir: &'a WorkingDirectory<RequestS>,
	pub env_names: &'a BoundedJson<Payload, RequestS>,
	pub fixture_artifact_ids: Option<&'a BoundedJson<Payload, RequestS>>,
	pub network_policy: NetworkPolicy,
	pub limits: &'a BoundedJson<Payload, PolicyS>,
	pub timeout_seconds: i64,
	pub started_at: i64,
	pub duration_ms: i64,
	pub exit_status: Option<i64>,
	pub term_signal: Option<i64>,
	pub stdout_artifact: Option<i64>,
	pub stderr_artifact: Option<i64>,
	pub output_truncated: bool,
}
pub struct NewProof<'a, RevisionS: Source, ManifestS: Source> {
	pub repo_id: i64,
	pub finding_id: i64,
	pub verification_id: i64,
	pub rung: Rung,
	pub pinned_commit_sha: &'a BoundedText<RevisionText, RevisionS>,
	pub manifest: &'a BoundedJson<Payload, ManifestS>,
}
/// The capture/transport layer enforces the job's artifact-size budget.
/// Blob identity and length are derived here, never accepted from the agent.
pub struct ArtifactBytes<'a, S: Source> {
	bytes: &'a [u8],
	source: std::marker::PhantomData<S>,
}
impl<'a, S: Source> ArtifactBytes<'a, S> {
	pub fn new(_: &Mark<'_, S>, bytes: &'a [u8]) -> Self {
		Self { bytes, source: std::marker::PhantomData }
	}
}
pub fn insert_blob<S: Source>(
	tx: &Transaction<'_>, repo: i64, content: &ArtifactBytes<'_, S>, now: i64,
) -> Result<i64> {
	let content = content.bytes;
	let hash: [u8; 32] = Sha256::digest(content).into();
	let len = i64::try_from(content.len()).map_err(|_| {
		loupe_core::text::Error::new("artifact_content", loupe_core::text::Rule::Bytes)
	})?;
	match tx.execute("INSERT INTO proof_artifact_blobs (repo_id,sha256,byte_len,content,created_at) VALUES (?1,?2,?3,?4,?5)",params![repo,hash.as_slice(),len,content,now]){
  Ok(_)=>Ok(tx.last_insert_rowid()),
  Err(error) if is_unique(&error,"proof_artifact_blobs.repo_id, proof_artifact_blobs.sha256")=>Ok(tx.query_row("SELECT proof_artifact_blob_id FROM proof_artifact_blobs WHERE repo_id=?1 AND sha256=?2",params![repo,hash.as_slice()],|r|r.get(0))?),
  Err(error)=>Err(error.into())
 }
}
fn blob(tx: &Transaction<'_>, repo: i64, id: i64) -> Result<()> {
	ownership::require(
		tx,
		"SELECT repo_id FROM proof_artifact_blobs WHERE proof_artifact_blob_id=?1",
		[id],
		Scope::repository(repo),
		Ownership::ArtifactBlob,
		ownership::repository_row,
	)
}
fn job(tx: &Transaction<'_>, repo: i64, id: i64, relation: Ownership) -> Result<()> {
	ownership::require(
		tx,
		"SELECT repo_id FROM jobs WHERE id=?1",
		[id],
		Scope::repository(repo),
		relation,
		ownership::repository_row,
	)
}
pub fn insert_artifact<MetadataS: Source>(
	tx: &Transaction<'_>, new: &NewArtifact<'_, MetadataS>, now: i64,
) -> Result<i64> {
	blob(tx, new.repo_id, new.blob_id)?;
	if let Some(id) = new.produced_by_job {
		job(tx, new.repo_id, id, Ownership::ArtifactJob)?;
	}
	tx.execute("INSERT INTO proof_artifacts (repo_id,proof_artifact_blob_id,artifact_role,media_type,label,original_name,sha256,byte_len,produced_by_job_id,created_at,source)
 SELECT ?1,?2,?3,?4,?5,?6,sha256,byte_len,?7,?8,?9 FROM proof_artifact_blobs WHERE repo_id=?1 AND proof_artifact_blob_id=?2",params![new.repo_id,new.blob_id,new.role.as_str(),new.media_type.expose(),new.label.map(Identifier::expose),new.original_name.expose(),new.produced_by_job,now,MetadataS::NAME])?;
	Ok(tx.last_insert_rowid())
}
pub fn insert_staged_artifact<MetadataS: Source>(
	tx: &Transaction<'_>, new: &NewStagedArtifact<'_, MetadataS>, now: i64,
) -> Result<i64> {
	blob(tx, new.repo_id, new.blob_id)?;
	job(tx, new.repo_id, new.job_id, Ownership::ArtifactJob)?;
	tx.execute("INSERT INTO staged_proof_artifacts (job_id,repo_id,proof_artifact_blob_id,artifact_role,media_type,label,original_name,created_at,source) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![new.job_id,new.repo_id,new.blob_id,new.role.as_str(),new.media_type.expose(),new.label.map(Identifier::expose),new.original_name.expose(),now,MetadataS::NAME])?;
	Ok(tx.last_insert_rowid())
}
pub fn insert_execution<RevisionS: Source, RequestS: Source, PolicyS: Source>(
	tx: &Transaction<'_>, new: &NewExecution<'_, RevisionS, RequestS, PolicyS>, now: i64,
) -> Result<i64> {
	job(tx, new.repo_id, new.produced_by_job, Ownership::ExecutionJob)?;
	for id in [new.stdout_artifact, new.stderr_artifact].into_iter().flatten() {
		ownership::require(
			tx,
			"SELECT repo_id FROM proof_artifacts WHERE proof_artifact_id=?1",
			[id],
			Scope::repository(new.repo_id),
			Ownership::ExecutionArtifact,
			ownership::repository_row,
		)?;
	}
	if let Some(fixtures) = new.fixture_artifact_ids {
		check_fixtures(tx, new.repo_id, new.produced_by_job, fixtures)?;
	}
	tx.execute("INSERT INTO proof_executions (repo_id,produced_by_job_id,target_commit_sha,clean_tree,argv,working_dir,env_names,fixture_artifact_ids,network_policy,limits,timeout_seconds,started_at,duration_ms,exit_status,term_signal,stdout_artifact_id,stderr_artifact_id,output_truncated,created_at,source)
 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",params![new.repo_id,new.produced_by_job,new.target_commit_sha.expose(),new.clean_tree,new.argv.expose(),new.working_dir.expose(),new.env_names.expose(),new.fixture_artifact_ids.map(BoundedJson::expose),new.network_policy.as_str(),new.limits.expose(),new.timeout_seconds,new.started_at,new.duration_ms,new.exit_status,new.term_signal,new.stdout_artifact,new.stderr_artifact,new.output_truncated,now,RequestS::NAME])?;
	Ok(tx.last_insert_rowid())
}
pub fn insert_proof<RevisionS: Source, ManifestS: Source>(
	tx: &Transaction<'_>, new: &NewProof<'_, RevisionS, ManifestS>, now: i64,
) -> Result<i64> {
	ownership::finding(tx, new.finding_id, new.repo_id, Ownership::ProofFinding)?;
	ownership::require(
		tx,
		"SELECT f.repo_id,v.finding_id FROM finding_verifications v JOIN findings f ON f.id=v.finding_id WHERE v.id=?1",
		[new.verification_id],
		Scope { assignment: Some(Assignment::Finding(new.finding_id)), ..Scope::repository(new.repo_id) },
		Ownership::ProofVerification,
		|r| Ok(Subject { kind: SubjectKind::Assigned(Assignment::Finding(r.get(1)?)), ..Subject::repository(r.get(0)?) }),
	)?;
	tx.execute("INSERT INTO verification_proofs (finding_id,verification_id,repo_id,rung,pinned_commit_sha,manifest,manifest_digest,created_at,source) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![new.finding_id,new.verification_id,new.repo_id,new.rung.as_str(),new.pinned_commit_sha.expose(),new.manifest.expose(),new.manifest.digest().as_slice(),now,ManifestS::NAME])?;
	Ok(tx.last_insert_rowid())
}
pub fn link_artifact(tx: &Transaction<'_>, repo: i64, proof: i64, artifact: i64) -> Result<()> {
	ownership::require(
		tx,
		"SELECT repo_id FROM verification_proofs WHERE verification_proof_id=?1",
		[proof],
		Scope::repository(repo),
		Ownership::ProofArtifact,
		ownership::repository_row,
	)?;
	ownership::require(
		tx,
		"SELECT repo_id FROM proof_artifacts WHERE proof_artifact_id=?1",
		[artifact],
		Scope::repository(repo),
		Ownership::ProofArtifact,
		ownership::repository_row,
	)?;
	tx.execute("INSERT INTO verification_proof_artifacts (repo_id,verification_proof_id,proof_artifact_id) VALUES (?1,?2,?3)",params![repo,proof,artifact])?;
	Ok(())
}
pub fn link_execution(tx: &Transaction<'_>, repo: i64, proof: i64, execution: i64) -> Result<()> {
	ownership::require(
		tx,
		"SELECT repo_id FROM verification_proofs WHERE verification_proof_id=?1",
		[proof],
		Scope::repository(repo),
		Ownership::ProofExecution,
		ownership::repository_row,
	)?;
	ownership::require(
		tx,
		"SELECT repo_id FROM proof_executions WHERE proof_execution_id=?1",
		[execution],
		Scope::repository(repo),
		Ownership::ProofExecution,
		ownership::repository_row,
	)?;
	tx.execute("INSERT INTO verification_proof_executions (repo_id,verification_proof_id,proof_execution_id) VALUES (?1,?2,?3)",params![repo,proof,execution])?;
	Ok(())
}
standalone! {insert_blob<S>(repo:i64,content:&ArtifactBytes<'_, S>,now:i64)->i64;insert_artifact<MetadataS>(new:&NewArtifact<'_, MetadataS>,now:i64)->i64;
insert_staged_artifact<MetadataS>(new:&NewStagedArtifact<'_, MetadataS>,now:i64)->i64;insert_execution<RevisionS, RequestS, PolicyS>(new:&NewExecution<'_, RevisionS, RequestS, PolicyS>,now:i64)->i64;
insert_proof<RevisionS, ManifestS>(new:&NewProof<'_, RevisionS, ManifestS>,now:i64)->i64;link_artifact(repo:i64,proof:i64,artifact:i64)->();link_execution(repo:i64,proof:i64,execution:i64)->();}

fn check_fixtures<S: Source>(
	conn: &Connection, repo: i64, job: i64, fixtures: &BoundedJson<Payload, S>,
) -> Result<()> {
	let ids: Vec<i64> = serde_json::from_str(fixtures.expose()).map_err(|_| {
		loupe_core::text::Error::new("fixture_artifact_ids", loupe_core::text::Rule::JsonSyntax)
	})?;
	let scope = Scope { assignment: Some(Assignment::Job(job)), ..Scope::repository(repo) };
	for id in ids {
		let subject = conn.query_row("SELECT repo_id,job_id FROM staged_proof_artifacts WHERE staged_proof_artifact_id=?1",
			[id],|r|Ok(Subject {kind:SubjectKind::Assigned(Assignment::Job(r.get(1)?)),..Subject::repository(r.get(0)?)})).optional()?;
		scope
			.check(subject.as_ref(), Ownership::ExecutionArtifact)
			.map_err(crate::Error::Ownership)?;
	}
	Ok(())
}

pub(crate) fn validate_stored_blobs(conn: &Connection) -> Result<()> {
	// No artifact-content text policy or new size budget: these bytes are opaque.
	crate::migrations::admission::scan(
		conn,
		"proof_artifact_blobs",
		"proof_artifact_blob_id,repo_id,sha256,byte_len,content,created_at",
		|_| Ok::<_, rusqlite::Error>(()),
	)
}

fn artifact_metadata(r: &rusqlite::Row<'_>) -> rusqlite::Result<()> {
	crate::ingress::require_known_source(r, 4)?;
	crate::review::parsed::<Role>(r, 0)?;
	crate::ingress::media_type(r, 1)?;
	crate::ingress::optional_label(r, 2)?;
	crate::ingress::original_name(r, 3)?;
	Ok(())
}
pub(crate) fn validate_stored_artifacts(conn: &Connection) -> Result<()> {
	crate::migrations::admission::scan(conn,"proof_artifacts",
		"artifact_role,media_type,label,original_name,source,proof_artifact_id,repo_id,proof_artifact_blob_id,sha256,byte_len,produced_by_job_id,created_at",artifact_metadata)
}
pub(crate) fn validate_stored_staged(conn: &Connection) -> Result<()> {
	crate::migrations::admission::scan(conn,"staged_proof_artifacts",
		"artifact_role,media_type,label,original_name,source,staged_proof_artifact_id,job_id,repo_id,proof_artifact_blob_id,created_at",artifact_metadata)
}
pub(crate) fn validate_stored_executions(conn: &Connection) -> Result<()> {
	crate::migrations::admission::scan(conn,"proof_executions",
		"proof_execution_id,repo_id,produced_by_job_id,target_commit_sha,clean_tree,argv,working_dir,env_names,fixture_artifact_ids,network_policy,limits,timeout_seconds,started_at,duration_ms,exit_status,term_signal,stdout_artifact_id,stderr_artifact_id,output_truncated,staged,created_at,source",|r| -> Result<()> {
		crate::ingress::require_known_source(r,21)?;
		crate::ingress::revision(r,3)?;
		crate::ingress::db_payload(r,5)?;
		crate::ingress::working_directory(r,6)?;
		crate::ingress::db_payload(r,7)?;
		let fixtures = crate::ingress::optional_db_payload(r,8)?;
		crate::review::parsed::<NetworkPolicy>(r,9)?;
		crate::ingress::db_payload(r,10)?;
		if let Some(fixtures) = fixtures {
			check_fixtures(conn,r.get(1)?,r.get(2)?,&fixtures).map_err(|error| {
				let reason = match error {
					crate::Error::Validation(error) => crate::migrations::MigrationReason::TextPolicy(error.rule),
					_ => crate::migrations::MigrationReason::ForeignKeyViolation,
				};
				crate::migrations::MigrationFailure::new(crate::migrations::MigrationStage::Admission,reason)
					.at("proof_executions","fixture_artifact_ids",None)
			})?;
		}
		Ok(())
	})
}
pub(crate) fn validate_stored_proofs(conn: &Connection) -> Result<()> {
	crate::migrations::admission::scan(conn,"verification_proofs",
		"verification_proof_id,finding_id,verification_id,repo_id,rung,pinned_commit_sha,manifest,manifest_digest,created_at,source",|r| {
		crate::ingress::require_known_source(r,9)?;
		crate::review::parsed::<Rung>(r,4)?;
		crate::ingress::revision(r,5)?;
		crate::ingress::db_payload(r,6)?;
		Ok::<_,rusqlite::Error>(())
	})
}
