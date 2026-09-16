//! Strict decoding of the immutable campaign-owned policy.
use loupe_core::text::policy::Payload;
use loupe_core::text::BoundedJson;
use loupe_core::JobKind;
use serde::{Deserialize, Serialize};

use crate::{Conflict, Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignPolicy {
	pub version: u32,
	pub survey_units_per_job: i64,
	pub survey_deadline_seconds: i64,
	pub survey_submit_margin_seconds: i64,
	pub drilldown_deadline_seconds: i64,
	pub drilldown_submit_margin_seconds: i64,
	pub verify_deadline_seconds: i64,
	pub verify_submit_margin_seconds: i64,
	pub max_attempts: u32,
	pub retry_backoff_base_seconds: i64,
	pub retry_backoff_cap_seconds: i64,
	pub campaign_handoff_reserve: i64,
	pub campaign_deadline_seconds: i64,
	pub campaign_max_jobs: i64,
	pub survey_token_budget: Option<u64>,
	pub drilldown_token_budget: Option<u64>,
	pub verify_token_budget: Option<u64>,
}
impl Default for CampaignPolicy {
	fn default() -> Self {
		Self {
			version: 1,
			survey_units_per_job: 4,
			survey_deadline_seconds: 1800,
			survey_submit_margin_seconds: 300,
			drilldown_deadline_seconds: 2700,
			drilldown_submit_margin_seconds: 420,
			verify_deadline_seconds: 3600,
			verify_submit_margin_seconds: 600,
			max_attempts: 3,
			retry_backoff_base_seconds: 60,
			retry_backoff_cap_seconds: 3600,
			campaign_handoff_reserve: 2,
			campaign_deadline_seconds: 21600,
			campaign_max_jobs: 64,
			survey_token_budget: None,
			drilldown_token_budget: None,
			verify_token_budget: None,
		}
	}
}

/// Per-attempt deadlines and token budget from the owning campaign.
#[derive(Debug, Clone, Copy)]
pub struct PhasePolicy {
	pub deadline_seconds: i64,
	pub submit_margin_seconds: i64,
	pub token_budget: Option<u64>,
}

impl CampaignPolicy {
	pub fn from_snapshot(snapshot: &BoundedJson<Payload>) -> Result<Self> {
		let policy: Self = serde_json::from_str(snapshot.expose())
			.map_err(|_| Error::Conflict(Conflict::CampaignPolicy))?;
		let valid = policy.version == 1
			&& (1..=32).contains(&policy.survey_units_per_job)
			&& policy.max_attempts > 0
			&& policy.campaign_max_jobs > 0
			&& policy.campaign_handoff_reserve >= 0
			&& policy.campaign_handoff_reserve < policy.campaign_max_jobs
			&& policy.retry_backoff_base_seconds >= 1
			&& policy.retry_backoff_base_seconds <= policy.retry_backoff_cap_seconds
			&& [JobKind::Survey, JobKind::Drilldown, JobKind::Verify].iter().all(|kind| {
				let phase = policy.phase(kind).expect("known phase");
				phase.deadline_seconds > 0
					&& phase.submit_margin_seconds >= 0
					&& phase.submit_margin_seconds < phase.deadline_seconds
					&& policy.campaign_deadline_seconds >= phase.deadline_seconds
					&& phase.token_budget.is_none_or(|n| n > 0 && n <= i64::MAX as u64)
			});
		if valid {
			Ok(policy)
		} else {
			Err(Error::Conflict(Conflict::CampaignPolicy))
		}
	}

	pub fn phase(&self, kind: &JobKind) -> Result<PhasePolicy> {
		let (deadline_seconds, submit_margin_seconds, token_budget) = match kind {
			JobKind::Survey => (
				self.survey_deadline_seconds,
				self.survey_submit_margin_seconds,
				self.survey_token_budget,
			),
			JobKind::Drilldown => (
				self.drilldown_deadline_seconds,
				self.drilldown_submit_margin_seconds,
				self.drilldown_token_budget,
			),
			JobKind::Verify => (
				self.verify_deadline_seconds,
				self.verify_submit_margin_seconds,
				self.verify_token_budget,
			),
			_ => return Err(super::invalid("job_kind")),
		};
		Ok(PhasePolicy { deadline_seconds, submit_margin_seconds, token_budget })
	}

	pub fn retry_delay(&self, attempts: u32) -> i64 {
		let multiplier = 2_i64.checked_pow(attempts.saturating_sub(1)).unwrap_or(i64::MAX);
		self.retry_backoff_base_seconds
			.saturating_mul(multiplier)
			.min(self.retry_backoff_cap_seconds)
	}
}
