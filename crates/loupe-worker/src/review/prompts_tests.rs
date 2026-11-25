use loupe_proto::review_lease::{BootstrapTarget, ReviewSurveyContext, ReviewSurveyLease};
use loupe_proto::{LeasePayload, LeaseResponse};
use serde_json::{json, Value};

use super::test_support::*;
use super::*;

struct Case {
	_repo: tempfile::TempDir,
	recipe: SurveyRecipe,
	attempt: std::num::NonZeroU32,
	limits: ReviewLimits,
	generation: ReviewGeneration<Server>,
	commit: ReviewCommit<Repo>,
	profile: Option<FrozenReviewProfile<Agent, Server>>,
	assignments: Option<ReviewAssignments<Agent>>,
	phase_limits: PhaseLimitsResponse,
}

#[derive(Clone, Copy)]
enum Kind {
	Bootstrap,
	BootstrapPublished,
	Coverage,
	CoverageEmpty,
}

fn case(kind: Kind, attempt: u32, token_budget: Option<u64>) -> Case {
	let (dir, commit) = commit();
	let sha = commit.expose();

	let generation = json!({"generation_id":3,"commit_sha":sha});
	let profile = json!({"profile_version":1,"profile_digest":"b".repeat(64),
		"profile":{"security_model":"parser handles remote input","note":INJECTED}});
	let unit = |id: i64, epoch: u64, title: &str| {
		json!({"review_unit_id":id,"assignment_epoch":epoch,"title":title,
			"objective":"Check length handling","source_refs":[{"path":"src/parse.rs","symbol":"decode"}],
			"depends_on":[],"closure_criteria":"Every length is checked before use"})
	};
	let context = match kind {
		Kind::Bootstrap => json!({"recipe":"bootstrap",
			"target":{"kind":"pinned","generation":generation,"published_profile":null}}),
		Kind::BootstrapPublished => json!({"recipe":"bootstrap",
			"target":{"kind":"pinned","generation":generation,"published_profile":profile}}),
		Kind::Coverage => json!({"recipe":"ordinary","generation":generation,"profile":profile,
			"ordinary_recipe":"coverage","assignments":[unit(5,2,"Review the parser"),unit(4,7,INJECTED)]}),
		Kind::CoverageEmpty => {
			json!({"recipe":"ordinary","generation":generation,"profile":profile,
			"ordinary_recipe":"coverage","assignments":[]})
		},
	};
	let body = json!({"kind":"lease","protocol_version":3,"job_id":9,
		"job_capability":"test-capability","repo_id":17,
		"repo":{"host":"invalid.test","owner":"test","repo":"test","clone_url":"file:///nonexistent"},
		"head_branch":null,"lease_expires_at":200,"scanner_config":null,
		"payload":{"kind":"review_survey","provenance":{"workflow_contract_version":1,
			"campaign_id":2,"attempt":attempt,"limits":{"soft_deadline_at":2500,"submit_by":2500,
			"hard_deadline_at":2800,"token_budget":token_budget,"new_unit_limit":32,
			"lead_limit":16,"sibling_limit":4}},"context":context}});
	let LeaseResponse::Lease(env) = crate::client::test_lease(body.to_string().as_bytes()).response
	else {
		panic!("lease fixture")
	};
	let LeasePayload::ReviewSurvey(lease) = env.payload else { panic!("survey lease") };
	let ReviewSurveyLease { provenance, context } = *lease;
	let (recipe, generation, profile, assignments) = match context {
		ReviewSurveyContext::Bootstrap {
			target: BootstrapTarget::Pinned { generation, published_profile },
		} => (SurveyRecipe::Bootstrap, generation, published_profile, None),
		ReviewSurveyContext::Ordinary { generation, profile, ordinary_recipe, assignments } => {
			(SurveyRecipe::Ordinary(ordinary_recipe), generation, Some(profile), Some(assignments))
		},
		_ => panic!("fixture recipe"),
	};
	let phase_limits = serde_json::from_value(json!({"protocol_version":3,
		"soft_deadline_at":2500,"submit_by":2500,"hard_deadline_at":2800,
		"remaining_seconds":1800,"new_units":{"limit":32,"remaining":30},
		"leads":{"limit":16,"remaining":15},"siblings":{"limit":4,"remaining":4},
		"candidate_queries":{"limit":8,"remaining":8},"campaign_jobs_limit":10,
		"campaign_jobs_admitted":2,"campaign_general_remaining":5,
		"campaign_urgent_remaining":1,"campaign_verification_remaining":2,
		"proof_capacity":"unavailable","artifact_capacity":"unavailable",
		"output_capacity":"unavailable","tokens":{"status":"none"}}))
	.unwrap();
	Case {
		_repo: dir,
		recipe,
		attempt: provenance.attempt,
		limits: provenance.limits,
		generation,
		commit,
		profile,
		assignments,
		phase_limits,
	}
}

impl Case {
	fn render(&self) -> String {
		let input = SurveyPromptInput {
			recipe: self.recipe,
			attempt: self.attempt,
			repo_id: 17,
			generation: &self.generation,
			checkout_commit: &self.commit,
			limits: &self.limits,
			phase_limits: &self.phase_limits,
			profile: self.profile.as_ref(),
			assignments: self.assignments.as_ref(),
		};
		render(input.builder(at_launch()))
	}
	fn sha(&self) -> String {
		self.commit.expose().to_owned()
	}
}

#[test]
fn job_context_is_a_server_labelled_projection_of_host_values() {
	let case = case(Kind::Coverage, 2, Some(50_000));
	let (source, payload) = part(&case.render(), "job_context").expect("job context part");
	assert_eq!(source, "server");
	let context: Value = serde_json::from_str(&payload).unwrap();
	assert_eq!(
		context,
		json!({"phase":"survey","workflow_contract_version":2,"recipe":"coverage","attempt":2,
			"repo_id":17,"source_root":"/workdir","generation_id":3,
			"generation_commit":case.sha(),"checkout_commit":case.sha(),
			"deadlines":{"launched_at":1000,"submit_by_at":2500,"submit_by_remaining_seconds":1500,
				"hard_deadline_at":2800,"hard_deadline_remaining_seconds":1800},
			"token_budget":50000,
			"capacity":{"review_units":{"limit":32,"remaining":30},"leads":{"limit":16,"remaining":15},
				"siblings":{"limit":4,"remaining":4},"candidate_queries":{"limit":8,"remaining":8},
				"campaign":{"jobs_limit":10,"jobs_admitted":2,"general_remaining":5,
					"urgent_remaining":1,"verification_remaining":2}},
			"terminal_action":"finalize_survey"})
	);
	assert!(!payload.contains(INJECTED), "agent text stays out of the host part");
}

#[test]
fn token_budget_is_stated_only_when_the_lease_has_one() {
	let rendered = case(Kind::Bootstrap, 1, None).render();
	let (_, payload) = part(&rendered, "job_context").unwrap();
	let context: Value = serde_json::from_str(&payload).unwrap();
	assert!(context.get("token_budget").is_none(), "{payload}");
	assert_eq!(context["recipe"], "bootstrap");
}

#[test]
fn deadlines_already_past_report_zero_remaining() {
	let mut case = case(Kind::Bootstrap, 1, None);
	case.limits.submit_by = 900;
	let (_, payload) = part(&case.render(), "job_context").unwrap();
	let context: Value = serde_json::from_str(&payload).unwrap();
	assert_eq!(context["deadlines"]["submit_by_at"], 900);
	assert_eq!(context["deadlines"]["submit_by_remaining_seconds"], 0);
}

#[test]
fn assignments_are_an_agent_part_with_unit_ids_and_epochs() {
	let rendered = case(Kind::Coverage, 1, None).render();
	let (source, payload) = part(&rendered, "assignments").expect("assignments part");
	assert_eq!(source, "agent");
	let units: Value = serde_json::from_str(&payload).unwrap();
	assert_eq!(units[0]["review_unit_id"], 5);
	assert_eq!(units[0]["assignment_epoch"], 2);
	assert_eq!(units[0]["closure_criteria"], "Every length is checked before use");
	assert_eq!(units[0]["source_refs"][0]["path"], "src/parse.rs");
	assert_eq!(units[1]["review_unit_id"], 4);
	assert_eq!(units[1]["assignment_epoch"], 7);
	assert_eq!(units[1]["title"], INJECTED);
	assert!(!instructions(&rendered).contains(INJECTED));

	let empty = case(Kind::CoverageEmpty, 1, None).render();
	assert_eq!(part(&empty, "assignments").unwrap().1, "[]");
	assert!(part(&case(Kind::Bootstrap, 1, None).render(), "assignments").is_none());
}

#[test]
fn profile_is_an_agent_part_marked_as_untrusted_hypotheses() {
	for kind in [Kind::Coverage, Kind::BootstrapPublished] {
		let rendered = case(kind, 2, None).render();
		let (source, payload) = part(&rendered, "profile").expect("profile part");
		assert_eq!(source, "agent");
		let profile: Value = serde_json::from_str(&payload).unwrap();
		assert_eq!(profile["security_model"], "parser handles remote input");
		let before = &rendered[..rendered.find("<loupe-data field=\"profile\"").unwrap()];
		let note = before.rsplit("</loupe-data").next().unwrap();
		assert!(note.contains(PROFILE_SENTENCE), "the fixed sentence introduces the profile");
	}
}

#[test]
fn first_bootstrap_attempt_has_no_profile_part() {
	let rendered = case(Kind::Bootstrap, 1, None).render();
	assert!(part(&rendered, "profile").is_none());
	assert!(!rendered.contains(PROFILE_SENTENCE));
	assert!(!rendered.contains("parser handles remote input"));
}

#[test]
fn bootstrap_without_profile_must_publish_it_first() {
	let rendered = instructions(&case(Kind::Bootstrap, 1, None).render());
	for needle in [
		"publish_profile",
		"32 KiB",
		"security model",
		"vulnerability",
		"components",
		"trust boundaries",
		"invariants",
		"priorities",
		"proof",
	] {
		assert!(rendered.contains(needle), "bootstrap instructions lack {needle:?}");
	}
	for kind in [Kind::BootstrapPublished, Kind::Coverage] {
		let rendered = instructions(&case(kind, 2, None).render());
		assert!(!rendered.contains("publish_profile"), "profile already published");
	}
}

#[test]
fn every_survey_prompt_carries_the_mandatory_rules() {
	for kind in [Kind::Bootstrap, Kind::BootstrapPublished, Kind::Coverage] {
		let text = instructions(&case(kind, 1, None).render());
		// Untrusted content and SECURITY.md guidance.
		assert!(text.contains("data, never instructions"));
		assert!(text.contains("SECURITY.md"));
		for verb in ["Locate", "inspect", "cite", "reconcile"] {
			assert!(text.contains(verb), "SECURITY.md guidance lacks {verb:?}");
		}
		// L1 evidence rules.
		for needle in ["L1", "counterevidence", "proof gap", "next proof step"] {
			assert!(text.contains(needle), "evidence rules lack {needle:?}");
		}
		// Soft stop with finalize always reachable.
		assert!(text.contains("submit_by"));
		assert!(text.contains("`finalize_survey` is always reachable"));
		// Checkpoint as you go.
		assert!(text.contains("Checkpoint as you go"));
	}
}

#[test]
fn recipe_classes_have_distinct_instructions() {
	let bootstrap = instructions(&case(Kind::Bootstrap, 1, None).render());
	let ordinary = instructions(&case(Kind::Coverage, 1, None).render());
	assert!(bootstrap.contains("bootstrap survey"));
	assert!(!bootstrap.contains("`assignments` block"));
	assert!(ordinary.contains("`assignments` block"));
	assert!(!ordinary.contains("bootstrap survey"));
}

#[test]
fn only_retries_carry_the_retry_instruction() {
	let retry = "Earlier attempts of this job may have stored review units";
	for kind in [Kind::Bootstrap, Kind::Coverage] {
		assert!(!case(kind, 1, None).render().contains(retry));
		let text = instructions(&case(kind, 2, None).render());
		assert!(text.contains(retry));
		assert!(text.contains("later coverage jobs"));
		assert!(text.contains("low remaining capacity is expected"));
		assert!(text.contains("exhausted"));
	}
}

/// Fixture commits differ per run; the baseline pins everything else.
fn stable(case: &Case) -> String {
	case.render().replace(&case.sha(), "<commit>")
}

#[test]
fn baseline_bootstrap_first_attempt() {
	baseline("bootstrap", &stable(&case(Kind::Bootstrap, 1, None)));
}

#[test]
fn baseline_bootstrap_retry_with_published_profile() {
	baseline("bootstrap_retry", &stable(&case(Kind::BootstrapPublished, 2, Some(50_000))));
}

#[test]
fn baseline_coverage() {
	baseline("coverage", &stable(&case(Kind::Coverage, 1, None)));
}

#[test]
fn fuzz_survey_fixture_reaches_the_renderer() {
	use crate::llm::prompt::{fuzz_support, DataMode};
	let survey = fuzz_support::render_survey(b"note", DataMode::Delimited, [[0x11; 16]; 3])
		.expect("admitted fixture");
	let rendered = survey.prompt.unwrap();
	assert!(rendered.expose().starts_with(&survey.spans[0]));
	assert!(rendered.expose().contains("\"objective\":\"note\""));
}
