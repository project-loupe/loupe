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
	let mut draw = 0;
	Some(builder.render_with(|| {
		let candidate = candidates[draw];
		draw += 1;
		Ok(candidate)
	}))
}

/// A coverage survey prompt whose agent-authored assignment objective and
/// profile note are both `raw`, passed through the actual lease owner.
pub struct SurveyRender {
	pub prompt: Result<Prompt, PromptError>,
	/// The exact static spans before the `job_context`, `assignments` and
	/// `profile` parts of an ordinary retry.
	pub spans: [String; 3],
	pub commit: String,
	/// The objective as the lease owner admitted it; the profile note
	/// carries the same admitted text.
	pub admitted: String,
}

pub fn render_survey(
	raw: &[u8], mode: DataMode, candidates: [[u8; 16]; 3],
) -> Option<SurveyRender> {
	use std::sync::OnceLock;
	use std::time::{Duration, UNIX_EPOCH};

	use loupe_proto::review_lease::{ReviewSurveyContext, ReviewSurveyLease};

	use crate::review::prepare::SurveyRecipe;
	use crate::review::prompts::{self, SurveyPromptInput};

	static COMMIT: OnceLock<(
		tempfile::TempDir,
		loupe_core::review_metadata::ReviewCommit<loupe_provenance::Repo>,
	)> = OnceLock::new();
	let text = std::str::from_utf8(raw).ok()?;
	let (_, commit) = COMMIT.get_or_init(|| {
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
	});
	let sha = commit.expose();
	let original = serde_json::to_vec(&serde_json::json!({
		"kind":"lease","protocol_version":3,"job_id":9,"job_capability":"test-capability",
		"repo_id":17,"repo":{"host":"invalid.test","owner":"t","repo":"t","clone_url":"file:///x"},
		"head_branch":null,"lease_expires_at":200,"scanner_config":null,
		"payload":{"kind":"review_survey","provenance":{"workflow_contract_version":1,
			"campaign_id":2,"attempt":2,"limits":{"soft_deadline_at":2500,"submit_by":2500,
			"hard_deadline_at":2800,"token_budget":7,"new_unit_limit":32,"lead_limit":16,
			"sibling_limit":4}},
		"context":{"recipe":"ordinary","generation":{"generation_id":3,"commit_sha":sha},
			"profile":{"profile_version":1,"profile_digest":"b".repeat(64),"profile":{"note":text}},
			"ordinary_recipe":"coverage","assignments":[{"review_unit_id":5,"assignment_epoch":2,
				"title":"Unit","objective":text,"source_refs":[{"path":"src/lib.rs"}],
				"depends_on":[],"closure_criteria":null}]}}
	}))
	.ok()?;
	let loupe_proto::LeaseResponse::Lease(env) =
		crate::client::fuzz_support::lease_response(&original)?
	else {
		return None;
	};
	let loupe_proto::LeasePayload::ReviewSurvey(lease) = env.payload else {
		return None;
	};
	let ReviewSurveyLease { provenance, context } = *lease;
	let ReviewSurveyContext::Ordinary { generation, profile, ordinary_recipe, assignments } =
		context
	else {
		return None;
	};
	let phase_limits = serde_json::from_value(serde_json::json!({"protocol_version":3,
		"soft_deadline_at":2500,"submit_by":2500,"hard_deadline_at":2800,
		"remaining_seconds":1800,"new_units":{"limit":32,"remaining":1},
		"leads":{"limit":16,"remaining":0},"siblings":{"limit":4,"remaining":4},
		"candidate_queries":{"limit":8,"remaining":8},"campaign_jobs_limit":10,
		"campaign_jobs_admitted":2,"campaign_general_remaining":5,
		"campaign_urgent_remaining":1,"campaign_verification_remaining":2,
		"proof_capacity":"unavailable","artifact_capacity":"unavailable",
		"output_capacity":"unavailable","tokens":{"status":"none"}}))
	.unwrap();
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
	let prompt = input.builder(UNIX_EPOCH + Duration::from_secs(1_000)).and_then(|builder| {
		let mut draw = 0;
		builder.mode(mode).render_with(|| {
			let candidate = candidates[draw];
			draw += 1;
			Ok(candidate)
		})
	});
	Some(SurveyRender { prompt, spans: prompts::fuzz_spans(), commit: sha.to_owned(), admitted })
}
