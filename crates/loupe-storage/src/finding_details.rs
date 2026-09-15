//! Canonical review identity and verification-attempt provenance.
use loupe_core::text::policy::{Argument, Payload, Reason};
use loupe_core::text::{BoundedJson, BoundedText};
use rusqlite::{params, Transaction};

use crate::identity::Identity;
use crate::review::{classify, is_unique, standalone, string_enum};
use crate::{ownership, Conflict, Error, Ownership, Result};
string_enum!(Confidence { Low=>"low", Medium=>"medium", High=>"high" });
string_enum!(SubmittedRung { L2=>"L2", L3=>"L3" });
string_enum!(EstablishedRung { L2=>"L2", L3=>"L3", L4=>"L4" });
string_enum!(Applicability { Applicable=>"applicable", NotApplicable=>"not_applicable" });
pub struct NewReview<'a> {
	pub finding_id: i64,
	pub repo_id: i64,
	pub workflow_contract_version: i64,
	pub profile_version: i64,
	pub profile_digest: Option<&'a [u8; 32]>,
	pub reviewed_commit_sha: &'a str,
	pub identity: &'a Identity,
	pub l2_argument: &'a BoundedJson<Payload>,
	pub counterevidence: &'a BoundedText<Argument>,
	pub assumptions_gaps: &'a BoundedText<Argument>,
	pub confidence: Confidence,
	pub submitted_rung: SubmittedRung,
	pub origin_lead: Option<i64>,
}
pub struct NewAttempt<'a> {
	pub verification_id: i64,
	pub repo_id: i64,
	pub workflow_contract_version: i64,
	pub checkout_commit_sha: &'a str,
	pub established_rung: Option<EstablishedRung>,
	pub e2e_applicability: Applicability,
	pub e2e_rationale: Option<&'a BoundedText<Reason>>,
	pub blocker: Option<&'a BoundedText<Reason>>,
	pub retry_condition: Option<&'a BoundedText<Reason>>,
	pub verification_proof: Option<i64>,
	pub terminal_digest: &'a [u8; 32],
}
pub fn insert_review_details(tx: &Transaction<'_>, new: &NewReview<'_>, now: i64) -> Result<()> {
	ownership::finding(tx, new.finding_id, new.repo_id, Ownership::Finding)?;
	if let Some(lead) = new.origin_lead {
		ownership::lead_in_repo(tx, lead, new.repo_id, Ownership::FindingLead)?;
	}
	let fingerprint = new.identity.fingerprint();
	let result=tx.execute("INSERT INTO finding_review_details (finding_id,repo_id,workflow_contract_version,profile_version,profile_digest,reviewed_commit_sha,identity_family,identity_anchor,identity_instance_key,identity_fingerprint,l2_argument,counterevidence,assumptions_gaps,confidence,submitted_rung,origin_lead_id,created_at)
 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",params![new.finding_id,new.repo_id,new.workflow_contract_version,new.profile_version,new.profile_digest.map(|d|d.as_slice()),new.reviewed_commit_sha,new.identity.family.expose(),new.identity.anchor.expose(),new.identity.instance.as_ref().map(|v|v.expose()),fingerprint.as_slice(),new.l2_argument.expose(),new.counterevidence.expose(),new.assumptions_gaps.expose(),new.confidence.as_str(),new.submitted_rung.as_str(),new.origin_lead,now]);
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
			let existing=tx.query_row("SELECT finding_id FROM finding_review_details WHERE repo_id=?1 AND identity_fingerprint=?2",params![new.repo_id,fingerprint.as_slice()],|r|r.get(0))?;
			Err(Error::Conflict(Conflict::FindingIdentity(existing)))
		},
		Err(error) => Err(error.into()),
	}
}
pub fn insert_attempt_details(tx: &Transaction<'_>, new: &NewAttempt<'_>, now: i64) -> Result<()> {
	ownership::require(tx,"SELECT EXISTS(SELECT 1 FROM finding_verifications v JOIN findings f ON f.id=v.finding_id WHERE v.id=?1 AND f.repo_id=?2)",params![new.verification_id,new.repo_id],Ownership::Verification)?;
	if let Some(proof) = new.verification_proof {
		ownership::require(tx,"SELECT EXISTS(SELECT 1 FROM verification_proofs WHERE verification_proof_id=?1 AND verification_id=?2 AND repo_id=?3)",params![proof,new.verification_id,new.repo_id],Ownership::VerificationProof)?;
	}
	if new.e2e_applicability == Applicability::NotApplicable && new.e2e_rationale.is_none() {
		return Err(
			loupe_core::text::Error::new("e2e_rationale", loupe_core::text::Rule::Empty).into()
		);
	}
	tx.execute("INSERT INTO verification_attempt_details (verification_id,workflow_contract_version,checkout_commit_sha,established_rung,e2e_applicability,e2e_rationale,blocker,retry_condition,verification_proof_id,terminal_digest,created_at)
 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",params![new.verification_id,new.workflow_contract_version,new.checkout_commit_sha,new.established_rung.map(EstablishedRung::as_str),new.e2e_applicability.as_str(),new.e2e_rationale.map(BoundedText::expose),new.blocker.map(BoundedText::expose),new.retry_condition.map(BoundedText::expose),new.verification_proof,new.terminal_digest.as_slice(),now])
	.map_err(|e| classify(e, "verification_attempt_details.verification_id", Conflict::AttemptDetails))?;
	Ok(())
}
standalone! {insert_review_details(new:&NewReview<'_>,now:i64)->();insert_attempt_details(new:&NewAttempt<'_>,now:i64)->();}
