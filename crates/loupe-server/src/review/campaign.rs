//! Resolve deployment policy; storage owns campaign selection and mutation.
use loupe_provenance::Source;
pub use loupe_storage::campaign_workflow::{
	activate_generation, cancel, pin, replenish, try_finish, Finish, KindHint, OpenCampaign,
	Opened, RequestedRef, TickReport,
};
use loupe_storage::scope::RepoScope;
use loupe_storage::{Conflict, Db, Error, Result};

use super::policy::ReviewPolicy;

pub fn open<S: Source>(
	scope: &RepoScope<'_>, new: &OpenCampaign<'_, S>, policy: &ReviewPolicy, now: i64,
) -> Result<Opened> {
	let policy = policy.snapshot().map_err(|_| Error::Conflict(Conflict::CampaignPolicy))?;
	loupe_storage::campaign_workflow::open(scope, new, &policy, now)
}

pub fn tick(db: &Db, now: i64) -> Result<TickReport> {
	let report = loupe_storage::campaign_workflow::tick(db, now)?;
	if report.failed != 0 {
		tracing::warn!(failed = report.failed, "campaign transactions rolled back");
	}
	if report.budget_exhausted != 0 {
		tracing::info!(
			exhausted = report.budget_exhausted,
			"campaign survey budgets exhausted with uncovered units"
		);
	}
	Ok(report)
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn actual_campaign_budget_admission_emits_closed_event() {
		let (_guard, events) = crate::test_support::capture_security_events();
		let db = Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests()).unwrap();
		let authority = crate::test_support::operator();
		let loupe_storage::registry::ReportingWrite::Done(repo) =
			loupe_storage::registry::register_repository(
				&db,
				&authority,
				&loupe_storage::repos::NewRepo {
					clone_url: crate::test_support::text("u"),
					host: crate::test_support::text("h"),
					owner: crate::test_support::text("o"),
					repo: crate::test_support::text("r"),
					default_branch: None,
					scan_interval_seconds: None,
					scanner_config: crate::test_support::scanner(serde_json::Value::Null),
					reporting: loupe_core::ReportingDestination::Manual,
					verification_enabled: false,
					require_approval: None,
				},
				None,
				0,
			)
			.unwrap()
		else {
			panic!("manual")
		};
		loupe_storage::scope::with_operator_repository(
			&db,
			&authority,
			loupe_storage::scope::OperatorTarget::Repository(repo),
			|scope| {
				let policy = ReviewPolicy {
					campaign_max_jobs: 2,
					campaign_handoff_reserve: 1,
					..Default::default()
				};
				let Opened::Created { campaign_id, .. } = open(
					scope,
					&OpenCampaign {
						trigger: loupe_storage::campaigns::Trigger::Manual,
						requested_ref: RequestedRef::Branch(&crate::test_support::text("main")),
						base_sha: None,
						kind_hint: KindHint::Incremental,
					},
					&policy,
					0,
				)?
				else {
					panic!("created")
				};
				assert!(
					events.lock().unwrap().is_empty(),
					"admitted jobs must not emit budget exhaustion"
				);
				let denied = loupe_storage::scheduler::enqueue_phase(
					scope,
					&loupe_storage::scheduler::NewPhaseJob {
						kind: loupe_core::JobKind::<loupe_provenance::Db>::Survey,
						campaign_id,
						generation_id: None,
						assigned_lead_id: None,
						target_finding_id: None,
						continuation_of_job_id: None,
						band: loupe_storage::scheduler::Band::Normal,
						effective_priority: 0,
						eligible_at: 0,
						token_budget: None,
						recipe: loupe_storage::scheduler::PhaseRecipeInput::Survey(
							loupe_storage::scheduler::SurveyRecipe::Bootstrap,
						),
						handoff: false,
					},
					1,
				);
				assert!(matches!(denied, Err(Error::Conflict(Conflict::CampaignBudget))));
				let rows = events.lock().unwrap();
				assert_eq!(
					rows.len(),
					1,
					"actual campaign budget rejection must emit the closed event"
				);
				assert_eq!(rows[0]["resource"], "campaign_jobs");
				assert_eq!(rows[0]["repo_id"], repo.to_string());
				assert_eq!(rows[0]["campaign_id"], campaign_id.to_string());
				assert!(!rows[0].contains_key("worker_id"));
				Ok(())
			},
		)
		.unwrap();
	}
}
