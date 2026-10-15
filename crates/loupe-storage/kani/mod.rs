//! Bounded proofs of the decisions used by the storage SQL paths.
use crate::checkpoints::{replay_decision, Operation, Replay, Stored};
use crate::scope::{Assignment, Scope, Subject, SubjectKind};
use crate::Ownership;

fn assignment() -> Assignment {
	let tag: u8 = kani::any();
	kani::assume(tag < 3);
	let id: i64 = kani::any();
	match tag {
		0 => Assignment::Job(id),
		1 => Assignment::Finding(id),
		_ => Assignment::Verification(id),
	}
}

fn facts() -> (Scope, Subject) {
	let scope = Scope {
		repo: kani::any(),
		generation: kani::any(),
		campaign: kani::any(),
		assignment: if kani::any() { Some(assignment()) } else { None },
	};
	let tag: u8 = kani::any();
	kani::assume(tag < 3);
	let kind = match tag {
		0 => SubjectKind::Record,
		1 => SubjectKind::Job { campaign_repo: kani::any() },
		_ => SubjectKind::Assigned(assignment()),
	};
	let subject =
		Subject { repo: kani::any(), generation: kani::any(), campaign: kani::any(), kind };
	// ownership::job_for_generation loads campaign_repo with a LEFT JOIN on
	// jobs.campaign_id. A matched campaign cannot accompany a NULL join key.
	if matches!(kind, SubjectKind::Job { campaign_repo: Some(_) }) {
		kani::assume(subject.campaign.is_some());
	}
	(scope, subject)
}

const RELATIONS: [Ownership; 37] = [
	Ownership::CampaignRoot,
	Ownership::CampaignContinuation,
	Ownership::CampaignGeneration,
	Ownership::CampaignSummary,
	Ownership::GenerationPredecessor,
	Ownership::CampaignJob,
	Ownership::InventoryGeneration,
	Ownership::CarriedUnit,
	Ownership::UnitJob,
	Ownership::ResultJob,
	Ownership::ResultUnit,
	Ownership::CorroboratedResult,
	Ownership::CorroboratedExclusion,
	Ownership::LeadUnit,
	Ownership::LeadJob,
	Ownership::ObservationJob,
	Ownership::SupersededLead,
	Ownership::DuplicateLead,
	Ownership::DuplicateFinding,
	Ownership::PromotedFinding,
	Ownership::FindingLead,
	Ownership::Finding,
	Ownership::Verification,
	Ownership::VerificationProof,
	Ownership::JobGeneration,
	Ownership::JobLead,
	Ownership::JobFinding,
	Ownership::JobContinuation,
	Ownership::Assignment,
	Ownership::ArtifactBlob,
	Ownership::ArtifactJob,
	Ownership::ExecutionJob,
	Ownership::ExecutionArtifact,
	Ownership::ProofFinding,
	Ownership::ProofVerification,
	Ownership::ProofArtifact,
	Ownership::ProofExecution,
];

fn relation() -> Ownership {
	let index: usize = kani::any();
	kani::assume(index < RELATIONS.len());
	RELATIONS[index]
}

// Bound: all i64 ownership IDs, all optional fields/subject and assignment tags,
// and all 37 diagnostic labels, under the LEFT JOIN coherence above. Labels
// establish error coverage, not 37 distinct policies. No truncated ID domains.
// Generation-less campaign-authored jobs use the campaign repository fallback;
// every explicit generation, campaign and assignment is checked exactly.
// ci: fast
#[kani::proof]
fn scope_admits_is_sound() {
	let (scope, subject) = facts();
	let relation = relation();
	let admitted = scope.admits(&subject, relation);
	let fallback = subject.generation.is_none()
		&& matches!(subject.kind, SubjectKind::Job { campaign_repo: Some(repo) } if repo == scope.repo);
	let generation_matches = match scope.generation {
		None => true,
		Some(generation) => subject.generation == Some(generation) || fallback,
	};
	let campaign_matches = match scope.campaign {
		None => true,
		Some(campaign) => subject.campaign == Some(campaign),
	};
	let assignment_matches = match (scope.assignment, subject.kind) {
		(None, _) => true,
		(Some(Assignment::Job(wanted)), SubjectKind::Assigned(Assignment::Job(actual)))
		| (Some(Assignment::Finding(wanted)), SubjectKind::Assigned(Assignment::Finding(actual)))
		| (
			Some(Assignment::Verification(wanted)),
			SubjectKind::Assigned(Assignment::Verification(actual)),
		) => wanted == actual,
		_ => false,
	};
	assert_eq!(
		admitted,
		subject.repo == scope.repo && generation_matches && campaign_matches && assignment_matches
	);
	if admitted {
		assert_eq!(scope.repo, subject.repo);
		if subject.generation.is_some() && scope.generation.is_some() {
			assert_eq!(scope.generation, subject.generation);
		}
	}
	macro_rules! cover_relation {
		($name:ident) => {
			kani::cover!(relation == Ownership::$name && admitted);
			kani::cover!(relation == Ownership::$name && !admitted);
		};
	}
	cover_relation!(CampaignRoot);
	cover_relation!(CampaignContinuation);
	cover_relation!(CampaignGeneration);
	cover_relation!(CampaignSummary);
	cover_relation!(GenerationPredecessor);
	cover_relation!(CampaignJob);
	cover_relation!(InventoryGeneration);
	cover_relation!(CarriedUnit);
	cover_relation!(UnitJob);
	cover_relation!(ResultJob);
	cover_relation!(ResultUnit);
	cover_relation!(CorroboratedResult);
	cover_relation!(CorroboratedExclusion);
	cover_relation!(LeadUnit);
	cover_relation!(LeadJob);
	cover_relation!(ObservationJob);
	cover_relation!(SupersededLead);
	cover_relation!(DuplicateLead);
	cover_relation!(DuplicateFinding);
	cover_relation!(PromotedFinding);
	cover_relation!(FindingLead);
	cover_relation!(Finding);
	cover_relation!(Verification);
	cover_relation!(VerificationProof);
	cover_relation!(JobGeneration);
	cover_relation!(JobLead);
	cover_relation!(JobFinding);
	cover_relation!(JobContinuation);
	cover_relation!(Assignment);
	cover_relation!(ArtifactBlob);
	cover_relation!(ArtifactJob);
	cover_relation!(ExecutionJob);
	cover_relation!(ExecutionArtifact);
	cover_relation!(ProofFinding);
	cover_relation!(ProofVerification);
	cover_relation!(ProofArtifact);
	cover_relation!(ProofExecution);
	kani::cover!(
		admitted && scope.generation.is_some() && fallback,
		"same-repository campaign fallback admitted"
	);
	kani::cover!(
		!admitted
			&& scope.repo == subject.repo
			&& scope.generation.is_some()
			&& subject.generation.is_some()
			&& scope.generation != subject.generation,
		"explicit generation mismatch cannot fall back"
	);
	kani::cover!(admitted && scope.assignment.is_some(), "matching assignment admitted");
	kani::cover!(
		!admitted && scope.repo == subject.repo && !assignment_matches,
		"mismatching assignment denied"
	);
}

// Bound: all i64 facts and all 37 relations; both missing and any denied loaded
// row flow through the same pure check called by ownership::require.
// ci: fast
#[kani::proof]
fn scope_denial_is_uniform() {
	let (scope, subject) = facts();
	let relation = relation();
	let exists = scope.check(Some(&subject), relation);
	let missing = scope.check(None, relation);
	assert_eq!(missing, Err(relation));
	if !scope.admits(&subject, relation) {
		assert_eq!(exists, missing);
	} else {
		assert_eq!(exists, Ok(()));
	}
	kani::cover!(exists.is_ok(), "admitted subject remains distinguishable from denial");
	kani::cover!(
		exists.is_err() && subject.repo != scope.repo,
		"foreign and missing errors coincide"
	);
	kani::cover!(
		exists.is_err() && subject.repo == scope.repo,
		"same-repository narrower-scope denial is uniform"
	);
}

// Bound: all 32-byte incoming/stored digests, stored lengths 0..=33, all nine
// known operation identities and an unknown stored operation. Length 33 reaches
// the first overlong digest; slice equality rejects every length != 32.
// Unwind 34 covers the 32-byte oracle and the longest operation string.
// ci: fast
#[kani::proof]
#[kani::unwind(34)]
fn replay_decision_is_exact() {
	let incoming_choice: u8 = kani::any();
	let stored_choice: u8 = kani::any();
	kani::assume(incoming_choice < 9 && stored_choice < 10);
	let operation = match incoming_choice {
		0 => Operation::SubmitReviewUnit,
		1 => Operation::SubmitLead,
		2 => Operation::SubmitUnitResult,
		3 => Operation::SubmitObservation,
		4 => Operation::StageArtifact,
		5 => Operation::RecordExecution,
		6 => Operation::ValidateFixPatch,
		7 => Operation::SubmitSiblingLead,
		_ => Operation::InitializeSurveyBatch,
	};
	// Independent stored spelling table: do not derive the oracle from as_str.
	let stored_operation = match stored_choice {
		0 => "submit_review_unit",
		1 => "submit_lead",
		2 => "submit_unit_result",
		3 => "submit_observation",
		4 => "stage_proof_artifact",
		5 => "record_execution",
		6 => "validate_fix_patch",
		7 => "submit_sibling_lead",
		8 => "initialize_survey_batch",
		_ => "unknown",
	};
	let incoming: [u8; 32] = kani::any();
	let bytes: [u8; 33] = kani::any();
	let length: usize = kani::any();
	kani::assume(length <= bytes.len());
	let stored = Stored { operation: stored_operation, digest: &bytes[..length] };
	let present: bool = kani::any();
	let verdict = replay_decision(present.then_some(&stored), operation, &incoming);
	let mut equal = length == 32;
	for index in 0..32 {
		if bytes[index] != incoming[index] {
			equal = false;
		}
	}
	let expected = if !present {
		Replay::Miss
	} else if stored_choice == incoming_choice && equal {
		Replay::Hit
	} else {
		Replay::Conflict
	};
	assert_eq!(verdict, expected);
	kani::cover!(verdict == Replay::Miss, "missing row permits first submission");
	kani::cover!(verdict == Replay::Hit, "identical operation and digest replay");
	kani::cover!(
		present && length == 32 && equal && stored_choice != incoming_choice,
		"operation mismatch conflicts with identical digest"
	);
	kani::cover!(
		present && length == 32 && !equal && stored_choice == incoming_choice,
		"digest mismatch conflicts for same operation"
	);
	kani::cover!(
		present && length < 32 && verdict == Replay::Conflict,
		"short stored digest conflicts"
	);
	kani::cover!(
		present && length > 32 && verdict == Replay::Conflict,
		"long stored digest conflicts"
	);
}
