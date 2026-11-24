//! Synthetic original Server fixture passed through the actual lease owner.
//! No production raw prompt constructor or source-selecting serializer exists.

use super::*;

pub fn render(
	raw: &[u8], mode: DataMode, projection: bool, candidates: [[u8; 16]; 3],
) -> Option<Result<Prompt, PromptError>> {
	if raw.len() > 2 * 1024 * 1024 {
		return None;
	}
	let description = std::str::from_utf8(raw).ok()?;
	let original = serde_json::to_vec(&serde_json::json!({
		"kind": "lease", "protocol_version": 1, "job_id": 42, "repo_id": 1,
		"job_capability": "test-capability", "scanner_config": null,
		"repo": {"host": "github.com", "owner": "a", "repo": "b", "clone_url": "https://github.com/a/b.git"},
		"lease_expires_at": 300,
		"payload": {"kind": "verify", "finding_id": 7, "finding": {
			"scanner_id": "llm-code-review", "severity": "high", "title": "OOB index",
			"description": description, "file_path": "src/lib.rs", "line_start": 1,
			"line_end": 2, "cwe": null, "patch_unified": null, "poc_unified": null, "fingerprint": "fp1"
		}}
	})).ok()?;
	let loupe_proto::LeaseResponse::Lease(env) =
		crate::client::fuzz_support::lease_response(&original)?
	else {
		return None;
	};
	let loupe_proto::LeasePayload::Verify { finding, .. } = env.payload else {
		return None;
	};
	assert_eq!(finding.description.expose().as_bytes(), raw);
	let mut builder = PromptBuilder::new(PREAMBLE).mode(mode);
	let added = if projection {
		builder.verification(7, &finding)
	} else {
		builder.data("description", &finding.description)
	};
	if let Err(error) = added {
		return Some(Err(error));
	}
	Some(render_drawing(builder, candidates))
}

/// One real commit of a throwaway repository, created once per process.
fn fixture_commit(
) -> &'static (tempfile::TempDir, loupe_core::review_metadata::ReviewCommit<loupe_provenance::Repo>)
{
	static COMMIT: std::sync::OnceLock<(
		tempfile::TempDir,
		loupe_core::review_metadata::ReviewCommit<loupe_provenance::Repo>,
	)> = std::sync::OnceLock::new();
	COMMIT.get_or_init(|| {
		let dir = tempfile::tempdir().unwrap();
		let repo = git2::Repository::init_bare(dir.path().join("cache.git")).unwrap();
		let tree = repo.find_tree(repo.treebuilder(None).unwrap().write().unwrap()).unwrap();
		let sig = git2::Signature::new("t", "t@example.com", &git2::Time::new(0, 0)).unwrap();
		let sha = repo.commit(None, &sig, &sig, "fixture", &tree, &[]).unwrap().to_string();
		let commit = crate::runner::observe_commit(
			repo.path(),
			&sha,
			crate::review::inventory::CommitDecoder,
		)
		.unwrap();
		(dir, commit)
	})
}

/// Render with `candidates` as the successive boundary draws.
fn render_drawing(
	builder: PromptBuilder<'_>, candidates: [[u8; 16]; 3],
) -> Result<Prompt, PromptError> {
	let mut draw = 0;
	builder.render_with(|| {
		let candidate = candidates[draw];
		draw += 1;
		Ok(candidate)
	})
}

/// A retry prompt of one phase whose assigned subject and profile note carry
/// the same raw text, passed through the actual lease owner.
pub struct PhaseRender {
	pub prompt: Result<Prompt, PromptError>,
	/// The exact static spans before the `job_context`, subject and
	/// `profile` parts.
	pub spans: [String; 3],
	pub commit: String,
	/// The text as the lease owner admitted it, as the subject and the
	/// profile note carry it.
	pub admitted: String,
}

/// `payload` as a second attempt's lease of `kind`, if the lease owner
/// admits it.
fn phase_lease(
	kind: &str, mut payload: serde_json::Value,
) -> Option<loupe_proto::LeasePayload<Agent, Server>> {
	payload["kind"] = kind.into();
	payload["provenance"] = serde_json::json!({"workflow_contract_version":1,
		"campaign_id":2,"attempt":2,"limits":{"soft_deadline_at":2500,"submit_by":2500,
		"hard_deadline_at":2800,"token_budget":7,"new_unit_limit":32,"lead_limit":16,
		"sibling_limit":4}});
	let original = serde_json::to_vec(&serde_json::json!({
		"kind":"lease","protocol_version":3,"job_id":9,"job_capability":"test-capability",
		"repo_id":17,"repo":{"host":"invalid.test","owner":"t","repo":"t","clone_url":"file:///x"},
		"head_branch":null,"lease_expires_at":200,"scanner_config":null,"payload":payload
	}))
	.ok()?;
	match crate::client::fuzz_support::lease_response(&original)? {
		loupe_proto::LeaseResponse::Lease(env) => Some(env.payload),
		_ => None,
	}
}

/// `quotas` are `(limit, remaining)` of units, leads, siblings and candidate
/// queries.
fn phase_limits(quotas: [(u64, u64); 4]) -> loupe_proto::review_api::PhaseLimitsResponse {
	let [units, leads, siblings, queries] =
		quotas.map(|(limit, remaining)| serde_json::json!({"limit":limit,"remaining":remaining}));
	serde_json::from_value(serde_json::json!({"protocol_version":3,
		"soft_deadline_at":2500,"submit_by":2500,"hard_deadline_at":2800,
		"remaining_seconds":1800,"new_units":units,"leads":leads,"siblings":siblings,
		"candidate_queries":queries,"campaign_jobs_limit":10,
		"campaign_jobs_admitted":2,"campaign_general_remaining":5,
		"campaign_urgent_remaining":1,"campaign_verification_remaining":2,
		"proof_capacity":"unavailable","artifact_capacity":"unavailable",
		"output_capacity":"unavailable","tokens":{"status":"none"}}))
	.unwrap()
}

fn at_launch() -> std::time::SystemTime {
	std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000)
}

/// A coverage survey prompt whose assignment objective is `raw`.
pub fn render_survey(raw: &[u8], mode: DataMode, candidates: [[u8; 16]; 3]) -> Option<PhaseRender> {
	use loupe_proto::review_lease::{ReviewSurveyContext, ReviewSurveyLease};

	use crate::review::prepare::SurveyRecipe;
	use crate::review::prompts::{self, SurveyPromptInput};

	let text = std::str::from_utf8(raw).ok()?;
	let (_, commit) = fixture_commit();
	let sha = commit.expose();
	let payload = serde_json::json!({
		"context":{"recipe":"ordinary","generation":{"generation_id":3,"commit_sha":sha},
			"profile":{"profile_version":1,"profile_digest":"b".repeat(64),"profile":{"note":text}},
			"ordinary_recipe":"coverage","assignments":[{"review_unit_id":5,"assignment_epoch":2,
				"title":"Unit","objective":text,"source_refs":[{"path":"src/lib.rs"}],
				"depends_on":[],"closure_criteria":null}]}
	});
	let loupe_proto::LeasePayload::ReviewSurvey(lease) = phase_lease("review_survey", payload)?
	else {
		return None;
	};
	let ReviewSurveyLease { provenance, context } = *lease;
	let ReviewSurveyContext::Ordinary { generation, profile, ordinary_recipe, assignments } =
		context
	else {
		return None;
	};
	let phase_limits = phase_limits([(32, 1), (16, 0), (4, 4), (8, 8)]);
	let admitted = assignments.as_slice().first()?.objective.expose().to_owned();
	let input = SurveyPromptInput {
		recipe: SurveyRecipe::Ordinary(ordinary_recipe),
		attempt: provenance.attempt,
		repo_id: 17,
		generation: &generation,
		checkout_commit: commit,
		limits: &provenance.limits,
		phase_limits: &phase_limits,
		profile: Some(&profile),
		assignments: Some(&assignments),
	};
	let prompt = input
		.builder(at_launch())
		.and_then(|builder| render_drawing(builder.mode(mode), candidates));
	Some(PhaseRender { prompt, spans: prompts::fuzz_spans(), commit: sha.to_owned(), admitted })
}

/// A drilldown prompt whose lead hypothesis is `raw`.
pub fn render_drilldown(
	raw: &[u8], mode: DataMode, candidates: [[u8; 16]; 3],
) -> Option<PhaseRender> {
	use loupe_proto::review_lease::ReviewDrilldownLease;

	use crate::review::prompts::{self, DrilldownPromptInput};

	let text = std::str::from_utf8(raw).ok()?;
	let (_, commit) = fixture_commit();
	let sha = commit.expose();
	let payload = serde_json::json!({
		"generation":{"generation_id":3,"commit_sha":sha},
		"profile":{"profile_version":1,"profile_digest":"b".repeat(64),"profile":{"note":text}},
		"lead":{"lead_id":4,"producer_commit_sha":sha,"identity_family":"memory-safety",
			"identity_anchor":"request allocation","hypothesis":text,
			"source_refs":[{"path":"src/lib.rs"}],"next_proof_step":"Trace allocation",
			"counterevidence":"None found","proof_gaps":"No reproducer"}
	});
	let loupe_proto::LeasePayload::ReviewDrilldown(lease) =
		phase_lease("review_drilldown", payload)?
	else {
		return None;
	};
	let ReviewDrilldownLease { provenance, generation, profile, lead } = *lease;
	let phase_limits = phase_limits([(0, 0), (0, 0), (4, 0), (8, 8)]);
	let admitted = lead.hypothesis.expose().to_owned();
	let input = DrilldownPromptInput {
		attempt: provenance.attempt,
		repo_id: 17,
		generation: &generation,
		checkout_commit: commit,
		limits: &provenance.limits,
		phase_limits: &phase_limits,
		lead: &lead,
		profile: &profile,
	};
	let prompt = input
		.builder(at_launch())
		.and_then(|builder| render_drawing(builder.mode(mode), candidates));
	Some(PhaseRender {
		prompt,
		spans: prompts::drilldown_fuzz_spans(),
		commit: sha.to_owned(),
		admitted,
	})
}

/// A verify prompt whose finding description, reachable path and profile note
/// are `raw`.
pub fn render_verify(raw: &[u8], mode: DataMode, candidates: [[u8; 16]; 3]) -> Option<PhaseRender> {
	use loupe_proto::review_lease::ReviewVerifyLease;

	use crate::review::prompts::{self, VerifyPromptInput};

	let text = std::str::from_utf8(raw).ok()?;
	let (_, commit) = fixture_commit();
	let sha = commit.expose();
	let payload = serde_json::json!({
		"generation":{"generation_id":3,"commit_sha":sha},
		"profile":{"profile_version":1,"profile_digest":"b".repeat(64),"profile":{"note":text}},
		"finding":{"finding_id":5,"reviewed_commit_sha":sha,"severity":"high",
			"title":"Unbounded allocation","description":text,
			"identity_family":"memory-safety","identity_anchor":"request allocation",
			"evidence":{"version":1,"l2_argument":{"attacker_source":"Remote request",
				"control":"None","sink":"Allocation","reachable_path":text,
				"trust_boundary":"Request to memory"},
				"material_locations":[{"role":"sink","file":"src/lib.rs"}],
				"counterevidence":"None found","assumptions_gaps":"Defaults",
				"confidence":"medium"}}
	});
	let loupe_proto::LeasePayload::ReviewVerify(lease) = phase_lease("review_verify", payload)?
	else {
		return None;
	};
	let ReviewVerifyLease { provenance, generation, profile, finding } = *lease;
	let phase_limits = phase_limits([(0, 0); 4]);
	let admitted = finding.evidence.l2_argument.reachable_path.expose().to_owned();
	let input = VerifyPromptInput {
		attempt: provenance.attempt,
		repo_id: 17,
		generation: &generation,
		checkout_commit: commit,
		limits: &provenance.limits,
		phase_limits: &phase_limits,
		finding: &finding,
		profile: &profile,
	};
	let prompt = input
		.builder(at_launch())
		.and_then(|builder| render_drawing(builder.mode(mode), candidates));
	Some(PhaseRender {
		prompt,
		spans: prompts::verify_fuzz_spans(),
		commit: sha.to_owned(),
		admitted,
	})
}
