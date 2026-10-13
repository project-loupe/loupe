//! Canonical review identity and verification-attempt provenance.
use loupe_core::text::policy::{Argument, Payload, Reason, RevisionText};
use loupe_core::text::{BoundedJson, BoundedText};
use loupe_provenance::{Agent, Source};
use rusqlite::params;

use crate::identity::Identity;
use crate::review::{classify, is_unique, string_enum};
use crate::scope::{Assignment, Scope, Subject, SubjectKind};
use crate::{ownership, Conflict, Error, Ownership, Result};
string_enum!(Confidence { Low=>"low", Medium=>"medium", High=>"high" });
string_enum!(SubmittedRung { L2=>"L2", L3=>"L3" });
string_enum!(EstablishedRung { L2=>"L2", L3=>"L3", L4=>"L4" });
string_enum!(Applicability { Applicable=>"applicable", NotApplicable=>"not_applicable" });
pub struct NewReview<'a, RevisionS: Source> {
	pub finding_id: i64,
	pub workflow_contract_version: i64,
	pub profile_version: i64,
	pub profile_digest: Option<&'a [u8; 32]>,
	pub reviewed_commit_sha: &'a BoundedText<RevisionText, RevisionS>,
	pub identity: &'a Identity<Agent>,
	pub l2_argument: &'a BoundedJson<Payload, Agent>,
	pub counterevidence: &'a BoundedText<Argument, Agent>,
	pub assumptions_gaps: &'a BoundedText<Argument, Agent>,
	pub confidence: Confidence,
	pub submitted_rung: SubmittedRung,
	pub origin_lead: Option<i64>,
}
pub struct NewAttempt<'a, RevisionS: Source, NarrativeS: Source> {
	pub verification_id: i64,
	pub workflow_contract_version: i64,
	pub checkout_commit_sha: &'a BoundedText<RevisionText, RevisionS>,
	pub established_rung: Option<EstablishedRung>,
	pub e2e_applicability: Applicability,
	pub e2e_rationale: Option<&'a BoundedText<Reason, NarrativeS>>,
	pub blocker: Option<&'a BoundedText<Reason, NarrativeS>>,
	pub retry_condition: Option<&'a BoundedText<Reason, NarrativeS>>,
	pub verification_proof: Option<i64>,
	pub terminal_digest: &'a [u8; 32],
}
pub fn insert_review_details<RevisionS: Source>(
	scope: &crate::scope::RepoScope<'_>, new: &NewReview<'_, RevisionS>, now: i64,
) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	ownership::finding(tx, new.finding_id, scope.repo_id, Ownership::Finding)?;
	if let Some(lead) = new.origin_lead {
		ownership::lead_in_repo(tx, lead, scope.repo_id, Ownership::FindingLead)?;
	}
	let fingerprint = new.identity.fingerprint();
	let result=tx.execute("INSERT INTO finding_review_details (finding_id,repo_id,workflow_contract_version,profile_version,profile_digest,reviewed_commit_sha,identity_family,identity_anchor,identity_instance_key,identity_fingerprint,l2_argument,counterevidence,assumptions_gaps,confidence,submitted_rung,origin_lead_id,created_at,source)
 SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18 WHERE EXISTS(SELECT 1 FROM findings WHERE id=?1 AND repo_id=?2)",params![new.finding_id,scope.repo_id,new.workflow_contract_version,new.profile_version,new.profile_digest.map(|d|d.as_slice()),new.reviewed_commit_sha.expose(),new.identity.family.expose(),new.identity.anchor.expose(),new.identity.instance.as_ref().map(|v|v.expose()),fingerprint.as_slice(),new.l2_argument.expose(),new.counterevidence.expose(),new.assumptions_gaps.expose(),new.confidence.as_str(),new.submitted_rung.as_str(),new.origin_lead,now,Agent::NAME]);
	match result {
		Ok(_) => Ok(()),
		Err(error) if is_unique(&error, "finding_review_details.finding_id") => {
			Err(Error::Conflict(Conflict::FindingDetails))
		},
		Err(error)
			if is_unique(
				&error,
				"finding_review_details.repo_id, finding_review_details.identity_fingerprint",
			) =>
		{
			let existing=tx.query_row("SELECT finding_id FROM finding_review_details WHERE repo_id=?1 AND identity_fingerprint=?2",params![scope.repo_id,fingerprint.as_slice()],|r|r.get(0))?;
			Err(Error::Conflict(Conflict::FindingIdentity(existing)))
		},
		Err(error) => Err(error.into()),
	}
}
pub fn insert_attempt_details<RevisionS: Source, NarrativeS: Source>(
	scope: &crate::scope::RepoScope<'_>, new: &NewAttempt<'_, RevisionS, NarrativeS>, now: i64,
) -> Result<()> {
	scope.require_operator()?;
	let tx = scope.conn;
	ownership::require(tx,"SELECT f.repo_id FROM finding_verifications v JOIN findings f ON f.id=v.finding_id WHERE v.id=?1",[new.verification_id],Scope::repository(scope.repo_id),Ownership::Verification,ownership::repository_row)?;
	if let Some(proof) = new.verification_proof {
		ownership::require(tx,"SELECT repo_id,verification_id FROM verification_proofs WHERE verification_proof_id=?1",[proof],Scope { assignment: Some(Assignment::Verification(new.verification_id)), ..Scope::repository(scope.repo_id) },Ownership::VerificationProof,|r| Ok(Subject { kind: SubjectKind::Assigned(Assignment::Verification(r.get(1)?)), ..Subject::repository(r.get(0)?) }))?;
	}
	if new.e2e_applicability == Applicability::NotApplicable && new.e2e_rationale.is_none() {
		return Err(
			loupe_core::text::Error::new("e2e_rationale", loupe_core::text::Rule::Empty).into()
		);
	}
	tx.execute("INSERT INTO verification_attempt_details (verification_id,workflow_contract_version,checkout_commit_sha,established_rung,e2e_applicability,e2e_rationale,blocker,retry_condition,verification_proof_id,terminal_digest,created_at,source)
 SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12 WHERE EXISTS(SELECT 1 FROM finding_verifications v JOIN findings f ON f.id=v.finding_id WHERE v.id=?1 AND f.repo_id=?13)",params![new.verification_id,new.workflow_contract_version,new.checkout_commit_sha.expose(),new.established_rung.map(EstablishedRung::as_str),new.e2e_applicability.as_str(),new.e2e_rationale.map(BoundedText::expose),new.blocker.map(BoundedText::expose),new.retry_condition.map(BoundedText::expose),new.verification_proof,new.terminal_digest.as_slice(),now,NarrativeS::NAME,scope.repo_id])
	.map_err(|e| classify(e, "verification_attempt_details.verification_id", Conflict::AttemptDetails))?;
	Ok(())
}

pub(crate) fn validate_stored_reviews(conn: &rusqlite::Connection) -> Result<()> {
	crate::migrations::admission::scan(conn,"finding_review_details",
		"finding_id,repo_id,workflow_contract_version,profile_version,profile_digest,reviewed_commit_sha,identity_family,identity_anchor,identity_instance_key,identity_fingerprint,l2_argument,counterevidence,assumptions_gaps,confidence,submitted_rung,origin_lead_id,created_at,source",|r| {
		// This is NewReview's designated Agent group; the revision is Db.
		crate::ingress::require_agent_source(r,17)?;
		crate::ingress::revision(r,5)?;
		crate::ingress::family(r,6)?;
		crate::ingress::anchor(r,7)?;
		crate::ingress::optional_instance(r,8)?;
		crate::ingress::agent_payload(r,10)?;
		crate::ingress::argument(r,11)?;
		crate::ingress::argument(r,12)?;
		crate::review::parsed::<Confidence>(r,13)?;
		crate::review::parsed::<SubmittedRung>(r,14)?;
		Ok::<_,rusqlite::Error>(())
	})
}

pub(crate) fn validate_stored_attempts(conn: &rusqlite::Connection) -> Result<()> {
	crate::migrations::admission::scan(conn,"verification_attempt_details",
		"verification_id,workflow_contract_version,checkout_commit_sha,established_rung,e2e_applicability,e2e_rationale,blocker,retry_condition,verification_proof_id,terminal_digest,created_at,source",|r| {
		crate::ingress::require_known_source(r,11)?;
		crate::ingress::revision(r,2)?;
		crate::review::optional::<EstablishedRung>(r,3)?;
		let applicability = crate::review::parsed::<Applicability>(r,4)?;
		let rationale = crate::ingress::optional_reason(r,5)?;
		crate::ingress::optional_reason(r,6)?;
		crate::ingress::optional_reason(r,7)?;
		if applicability == Applicability::NotApplicable && rationale.is_none() {
			return Err(crate::ingress::missing_value(5,"e2e_rationale"));
		}
		Ok::<_,rusqlite::Error>(())
	})
}
