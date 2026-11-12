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

// Bound: Symbolic capability well-formedness, binding result, 32-byte stored
// and requested digests, and failure of either read. The receipt is an opaque
// symbolic id, so identity of the returned value proves it is the loaded one.
// No loops besides the fixed 32-byte comparison.
// invariant: I5
// ci: fast
#[kani::proof]
#[kani::unwind(33)]
fn terminal_replay_returns_sealed_result_only() {
	use crate::terminal_receipt::{replay_decision, Reject};
	let well_formed: bool = kani::any();
	let bound: bool = kani::any();
	let bound_fails: bool = kani::any();
	let load_fails: bool = kani::any();
	let stored: (u64, [u8; 32]) = (kani::any(), kani::any());
	let requested: [u8; 32] = kani::any();
	let mut bound_calls = 0u8;
	let mut loads = 0u8;
	let result = replay_decision(
		well_formed,
		|| {
			bound_calls += 1;
			if bound_fails {
				Err(crate::Error::Conflict(crate::Conflict::TerminalReceipt))
			} else {
				Ok(bound)
			}
		},
		|| {
			loads += 1;
			if load_fails {
				Err(crate::Error::Conflict(crate::Conflict::TerminalReceipt))
			} else {
				Ok(stored)
			}
		},
		|receipt: &(u64, [u8; 32])| receipt.1.as_slice(),
		&requested,
	);
	assert!(loads <= 1 && bound_calls <= 1);
	if loads == 1 {
		assert!(well_formed && bound && !bound_fails);
	}
	match result {
		Ok(Ok(receipt)) => {
			assert!(well_formed && bound && !bound_fails && !load_fails);
			assert_eq!(receipt, stored);
			assert_eq!(stored.1, requested);
		},
		Ok(Err(Reject::Denied)) => assert!(!well_formed || !bound),
		Ok(Err(Reject::WrongDigest)) => {
			assert!(well_formed && bound && !load_fails && stored.1 != requested)
		},
		Err(_) => assert!(bound_fails || load_fails),
	}
	kani::cover!(matches!(result, Ok(Ok(_))), "sealed receipt replayed");
	kani::cover!(matches!(result, Ok(Err(Reject::WrongDigest))), "divergent digest");
	kani::cover!(matches!(result, Ok(Err(Reject::Denied))), "unbound identity denied");
}

fn policy_v2() -> crate::admission_policy::CampaignPolicyV2 {
	crate::admission_policy::CampaignPolicyV2 {
		version: kani::any(),
		survey_units_per_job: kani::any(),
		survey_deadline_seconds: kani::any(),
		survey_submit_margin_seconds: kani::any(),
		drilldown_deadline_seconds: kani::any(),
		drilldown_submit_margin_seconds: kani::any(),
		verify_deadline_seconds: kani::any(),
		verify_submit_margin_seconds: kani::any(),
		max_attempts: kani::any(),
		retry_backoff_base_seconds: kani::any(),
		retry_backoff_cap_seconds: kani::any(),
		campaign_deadline_seconds: kani::any(),
		campaign_max_jobs: kani::any(),
		survey_token_budget: kani::any(),
		drilldown_token_budget: kani::any(),
		verify_token_budget: kani::any(),
		max_units_per_survey: kani::any(),
		max_leads_per_survey: kani::any(),
		max_sibling_leads_per_drilldown: kani::any(),
		campaign_urgent_reserve: kani::any(),
		campaign_verification_reserve: kani::any(),
		priority_policy_version: kani::any(),
	}
}

fn phase_is_usable(deadline: i64, margin: i64, budget: Option<u64>, campaign: i64) -> bool {
	deadline > 0
		&& margin >= 0
		&& margin < deadline
		&& campaign >= deadline
		&& budget.is_none_or(|tokens| tokens > 0 && tokens <= i64::MAX as u64)
}

// Bound: version, priority version, survey units, attempts, backoff base and
// cap, campaign_max_jobs, both reserves and the three per-phase list caps
// range over their full types, negative i64 values included. The nine phase
// deadline, margin, token-budget and campaign-deadline fields are fixed at
// the accepted defaults: with them symbolic too the proof timed out at 600s,
// and they feed only the shared execution-policy phase check. The oracle
// restates the storage contract independently of validate(): general
// capacity is not stored, so the two reserves and the derived general pool
// partition campaign_max_jobs with at least one general job (contract
// example: 64 = 4 urgent + 4 verification + 56 general). Sums are in i128,
// so the oracle cannot overflow where the code must not.
// Unwind 4: the three-phase loop in validate() plus termination; it also cuts
// drop glue of storage error variants never built on these paths.
// invariant: I6
#[kani::proof]
#[kani::unwind(4)]
fn policy_validate_rejects_inconsistent_limits() {
	let defaults = crate::admission_policy::CampaignPolicyV2::default();
	let policy = crate::admission_policy::CampaignPolicyV2 {
		survey_deadline_seconds: defaults.survey_deadline_seconds,
		survey_submit_margin_seconds: defaults.survey_submit_margin_seconds,
		drilldown_deadline_seconds: defaults.drilldown_deadline_seconds,
		drilldown_submit_margin_seconds: defaults.drilldown_submit_margin_seconds,
		verify_deadline_seconds: defaults.verify_deadline_seconds,
		verify_submit_margin_seconds: defaults.verify_submit_margin_seconds,
		campaign_deadline_seconds: defaults.campaign_deadline_seconds,
		survey_token_budget: defaults.survey_token_budget,
		drilldown_token_budget: defaults.drilldown_token_budget,
		verify_token_budget: defaults.verify_token_budget,
		..policy_v2()
	};
	let accepted = policy.validate().is_ok();
	let urgent = i128::from(policy.campaign_urgent_reserve);
	let verification = i128::from(policy.campaign_verification_reserve);
	let total = i128::from(policy.campaign_max_jobs);
	let capacity = urgent >= 0 && verification >= 0 && urgent + verification < total;
	let other = policy.version == 2
		&& policy.priority_policy_version == 1
		&& (1..=32).contains(&policy.survey_units_per_job)
		&& policy.max_attempts > 0
		&& policy.retry_backoff_base_seconds >= 1
		&& policy.retry_backoff_base_seconds <= policy.retry_backoff_cap_seconds
		&& policy.max_units_per_survey > 0
		&& policy.max_leads_per_survey > 0
		&& policy.max_sibling_leads_per_drilldown > 0
		&& phase_is_usable(
			policy.survey_deadline_seconds,
			policy.survey_submit_margin_seconds,
			policy.survey_token_budget,
			policy.campaign_deadline_seconds,
		)
		&& phase_is_usable(
			policy.drilldown_deadline_seconds,
			policy.drilldown_submit_margin_seconds,
			policy.drilldown_token_budget,
			policy.campaign_deadline_seconds,
		)
		&& phase_is_usable(
			policy.verify_deadline_seconds,
			policy.verify_submit_margin_seconds,
			policy.verify_token_budget,
			policy.campaign_deadline_seconds,
		);
	assert_eq!(accepted, capacity && other);
	let general = policy.general_capacity();
	assert_eq!(general.is_ok(), accepted);
	if let Ok(general) = general {
		assert!(general >= 1);
		assert_eq!(i128::from(general) + urgent + verification, total);
	}
	kani::cover!(accepted && urgent + verification + 1 == total, "single general job accepted");
	kani::cover!(
		other && urgent >= 0 && verification >= 0 && urgent + verification == total,
		"reserves taking every job rejected"
	);
	kani::cover!(
		other && urgent + verification > i128::from(i64::MAX),
		"overflowing reserve sum rejected"
	);
	kani::cover!(other && !capacity && urgent < 0, "negative reserve rejected");
}

// Bound: retry_backoff_base_seconds and retry_backoff_cap_seconds range over
// every pair validate() accepts (1 <= base <= cap, full i64); attempts and
// sequences are all u32/u64 and now is all i64. The other fields stay at the
// accepted defaults because the delay functions read only base and cap, and
// validate() is what logical_delay re-runs. Two ordered arguments per call
// establish monotonicity. checked_pow loops over the exponent's 32 bits;
// unwind 34 covers it plus one.
// invariant: I6
#[kani::proof]
#[kani::unwind(34)]
fn retry_and_logical_delays_never_overflow() {
	let mut policy = crate::admission_policy::CampaignPolicyV2::default();
	policy.retry_backoff_base_seconds = kani::any();
	policy.retry_backoff_cap_seconds = kani::any();
	kani::assume(policy.validate().is_ok());
	let base = policy.retry_backoff_base_seconds;
	let cap = policy.retry_backoff_cap_seconds;

	let first: u32 = kani::any();
	let second: u32 = kani::any();
	kani::assume(first <= second);
	let (early, late) = (policy.retry_delay(first), policy.retry_delay(second));
	assert!(base <= early && early <= late && late <= cap);

	let sequence: u64 = kani::any();
	let later: u64 = kani::any();
	kani::assume(sequence <= later);
	let delay = policy.logical_delay(sequence);
	assert_eq!(delay.is_err(), sequence == 0);
	if let Ok(delay) = delay {
		let Ok(later_delay) = policy.logical_delay(later) else { panic!("later sequence refused") };
		assert!(base <= delay && delay <= later_delay && later_delay <= cap);
		let now: i64 = kani::any();
		let not_before = policy.logical_not_before(now, sequence);
		match now.checked_add(delay) {
			Some(sum) => assert_eq!(not_before.as_ref().ok(), Some(&sum)),
			None => assert!(not_before.is_err()),
		}
		kani::cover!(not_before.is_err(), "not_before refuses instead of wrapping");
		kani::cover!(delay == cap && sequence > 1, "logical delay saturates at the cap");
	}
	kani::cover!(early < late, "retry delay grows");
	kani::cover!(late == cap && second == u32::MAX, "retry delay saturates at the cap");
	kani::cover!(sequence == 0, "sequence zero is refused");
}

// Bound: all 4 impacts x 3 access levels x 2 reachabilities x 2 boundary flags
// x 2 support flags, i.e. the whole input domain. The oracle is the contract's
// priority policy 1 table written out independently: urgent needs high or
// critical impact, remote access, traced reachability and a cited boundary;
// high needs high or critical impact and tracing; low impact is background;
// unsupported structure falls back to normal with score zero.
// invariant: I6
// ci: fast
#[kani::proof]
fn classify_priority_is_total() {
	use loupe_core::review_priority::{Access, Impact, Reachability};

	use crate::scheduler::Band;
	let impact_choice: u8 = kani::any();
	let access_choice: u8 = kani::any();
	kani::assume(impact_choice < 4 && access_choice < 3);
	let impact =
		[Impact::Low, Impact::Medium, Impact::High, Impact::Critical][impact_choice as usize];
	let access = [Access::Privileged, Access::Local, Access::Remote][access_choice as usize];
	let traced: bool = kani::any();
	let reachability = if traced { Reachability::Traced } else { Reachability::Plausible };
	let boundary: bool = kani::any();
	let supported: bool = kani::any();
	let priority = crate::admission_policy::classify_priority(
		impact,
		access,
		reachability,
		boundary,
		supported,
	);
	let severe = impact_choice >= 2;
	let (band, score) = if !supported {
		(Band::Normal, 0)
	} else {
		let band = if severe && access_choice == 2 && traced && boundary {
			Band::Urgent
		} else if severe && traced {
			Band::High
		} else if impact_choice == 0 {
			Band::Background
		} else {
			Band::Normal
		};
		let score = 100 * u32::from(impact_choice)
			+ 50 * u32::from(access_choice)
			+ if traced { 100 } else { 0 }
			+ if boundary { 50 } else { 0 };
		(band, score)
	};
	assert_eq!(priority.band, band);
	assert_eq!(priority.score, score);
	assert!(priority.score <= 550);
	kani::cover!(priority.band == Band::Urgent && priority.score == 550, "maximum urgent");
	kani::cover!(priority.band == Band::High, "high band");
	kani::cover!(priority.band == Band::Background, "background band");
	kani::cover!(priority.band == Band::Normal && supported, "supported normal band");
	kani::cover!(!supported && severe && traced && boundary, "unsupported urgent shape falls back");
}
