//! Validated deployment configuration and immutable campaign snapshots.
use std::fmt;

use loupe_core::text::policy::Payload;
use loupe_core::text::BoundedJson;
use loupe_storage::scheduler::{ClaimPolicy, PRIORITY_MAX};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewPolicy {
	pub active_jobs_per_repo: i64,
	pub active_jobs_total: Option<i64>,
	pub active_surveys_per_repo: i64,
	pub active_drilldowns_per_repo: i64,
	pub active_verifications_per_repo: i64,
	pub verify_reserved_slots: i64,
	pub survey_units_per_job: i64,
	pub survey_deadline_seconds: i64,
	pub survey_submit_margin_seconds: i64,
	pub drilldown_deadline_seconds: i64,
	pub drilldown_submit_margin_seconds: i64,
	pub verify_deadline_seconds: i64,
	pub verify_submit_margin_seconds: i64,
	pub lease_seconds: i64,
	pub lease_report_grace_seconds: i64,
	pub max_attempts: u32,
	pub retry_backoff_base_seconds: i64,
	pub retry_backoff_cap_seconds: i64,
	pub urgency_burst_length: i64,
	pub campaign_handoff_reserve: i64,
	pub campaign_deadline_seconds: i64,
	pub campaign_max_jobs: i64,
	pub priority_aging_interval_seconds: i64,
	pub priority_aging_cap: i64,
	pub survey_token_budget: Option<u64>,
	pub drilldown_token_budget: Option<u64>,
	pub verify_token_budget: Option<u64>,
}
impl Default for ReviewPolicy {
	fn default() -> Self {
		Self {
			active_jobs_per_repo: 3,
			active_jobs_total: None,
			active_surveys_per_repo: 1,
			active_drilldowns_per_repo: 2,
			active_verifications_per_repo: 2,
			verify_reserved_slots: 1,
			survey_units_per_job: 4,
			survey_deadline_seconds: 1800,
			survey_submit_margin_seconds: 300,
			drilldown_deadline_seconds: 2700,
			drilldown_submit_margin_seconds: 420,
			verify_deadline_seconds: 3600,
			verify_submit_margin_seconds: 600,
			lease_seconds: 600,
			lease_report_grace_seconds: 60,
			max_attempts: 3,
			retry_backoff_base_seconds: 60,
			retry_backoff_cap_seconds: 3600,
			urgency_burst_length: 4,
			campaign_handoff_reserve: 2,
			campaign_deadline_seconds: 21600,
			campaign_max_jobs: 64,
			priority_aging_interval_seconds: 3600,
			priority_aging_cap: 8,
			survey_token_budget: None,
			drilldown_token_budget: None,
			verify_token_budget: None,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
	pub violations: Vec<String>,
}
impl fmt::Display for PolicyError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "invalid review policy: {}", self.violations.join("; "))
	}
}
impl std::error::Error for PolicyError {}

impl ReviewPolicy {
	pub fn validate(&self) -> Result<(), PolicyError> {
		let mut violations = Vec::new();
		let mut require = |valid: bool, rule: &str| {
			if !valid {
				violations.push(rule.to_owned());
			}
		};
		require(self.active_jobs_per_repo >= 1, "active_jobs_per_repo must be at least 1");
		require(self.active_surveys_per_repo >= 1, "active_surveys_per_repo must be at least 1");
		require(
			self.active_drilldowns_per_repo >= 1,
			"active_drilldowns_per_repo must be at least 1",
		);
		require(
			self.active_verifications_per_repo >= 1,
			"active_verifications_per_repo must be at least 1",
		);
		require(self.survey_units_per_job >= 1, "survey_units_per_job must be at least 1");
		require(self.survey_deadline_seconds >= 1, "survey_deadline_seconds must be at least 1");
		require(
			self.drilldown_deadline_seconds >= 1,
			"drilldown_deadline_seconds must be at least 1",
		);
		require(self.verify_deadline_seconds >= 1, "verify_deadline_seconds must be at least 1");
		require(self.lease_seconds >= 1, "lease_seconds must be at least 1");
		require(
			self.lease_report_grace_seconds >= 1,
			"lease_report_grace_seconds must be at least 1",
		);
		require(
			self.retry_backoff_base_seconds >= 1,
			"retry_backoff_base_seconds must be at least 1",
		);
		require(
			self.retry_backoff_cap_seconds >= 1,
			"retry_backoff_cap_seconds must be at least 1",
		);
		require(self.urgency_burst_length >= 1, "urgency_burst_length must be at least 1");
		require(
			self.campaign_deadline_seconds >= 1,
			"campaign_deadline_seconds must be at least 1",
		);
		require(self.campaign_max_jobs >= 1, "campaign_max_jobs must be at least 1");
		require(
			self.priority_aging_interval_seconds >= 1,
			"priority_aging_interval_seconds must be at least 1",
		);
		require(self.max_attempts >= 1, "max_attempts must be at least 1");
		require(self.verify_reserved_slots >= 0, "verify_reserved_slots must be nonnegative");
		require(self.campaign_handoff_reserve >= 0, "campaign_handoff_reserve must be nonnegative");
		require(self.priority_aging_cap >= 0, "priority_aging_cap must be nonnegative");
		require(
			self.survey_submit_margin_seconds >= 0,
			"survey_submit_margin_seconds must be nonnegative",
		);
		require(
			self.drilldown_submit_margin_seconds >= 0,
			"drilldown_submit_margin_seconds must be nonnegative",
		);
		require(
			self.verify_submit_margin_seconds >= 0,
			"verify_submit_margin_seconds must be nonnegative",
		);
		require(
			self.active_surveys_per_repo <= self.active_jobs_per_repo,
			"active_surveys_per_repo must not exceed active_jobs_per_repo",
		);
		require(
			self.active_drilldowns_per_repo <= self.active_jobs_per_repo,
			"active_drilldowns_per_repo must not exceed active_jobs_per_repo",
		);
		require(
			self.active_verifications_per_repo <= self.active_jobs_per_repo,
			"active_verifications_per_repo must not exceed active_jobs_per_repo",
		);
		require(
			self.active_jobs_total.is_none_or(|n| n >= 1),
			"active_jobs_total must be at least 1 when set",
		);
		require(self.verify_reserved_slots <= self.active_verifications_per_repo && self.verify_reserved_slots < self.active_jobs_per_repo, "verify_reserved_slots must not exceed active_verifications_per_repo and must be below active_jobs_per_repo");
		require(self.survey_units_per_job <= 32, "survey_units_per_job must not exceed 32");
		require(
			self.lease_report_grace_seconds <= self.lease_seconds,
			"lease_report_grace_seconds must not exceed lease_seconds",
		);
		require(
			self.campaign_handoff_reserve < self.campaign_max_jobs,
			"campaign_handoff_reserve must be below campaign_max_jobs",
		);
		require(
			self.retry_backoff_base_seconds <= self.retry_backoff_cap_seconds,
			"retry_backoff_base_seconds must not exceed retry_backoff_cap_seconds",
		);
		require(
			self.priority_aging_cap <= i64::MAX - i64::from(PRIORITY_MAX),
			"priority_aging_cap must leave room for the base priority",
		);
		require(
			self.survey_submit_margin_seconds < self.survey_deadline_seconds,
			"survey_submit_margin_seconds must be below survey_deadline_seconds",
		);
		require(
			self.lease_seconds < self.survey_deadline_seconds,
			"lease_seconds must be below survey_deadline_seconds",
		);
		require(
			self.survey_deadline_seconds.checked_add(self.lease_report_grace_seconds).is_some(),
			"survey_deadline_seconds plus lease_report_grace_seconds must not overflow",
		);
		require(
			self.campaign_deadline_seconds >= self.survey_deadline_seconds,
			"campaign_deadline_seconds must cover survey_deadline_seconds",
		);
		require(
			self.survey_token_budget.is_none_or(|n| n > 0 && n <= i64::MAX as u64),
			"survey_token_budget must be positive and fit a SQLite integer when set",
		);
		require(
			self.drilldown_submit_margin_seconds < self.drilldown_deadline_seconds,
			"drilldown_submit_margin_seconds must be below drilldown_deadline_seconds",
		);
		require(
			self.lease_seconds < self.drilldown_deadline_seconds,
			"lease_seconds must be below drilldown_deadline_seconds",
		);
		require(
			self.drilldown_deadline_seconds.checked_add(self.lease_report_grace_seconds).is_some(),
			"drilldown_deadline_seconds plus lease_report_grace_seconds must not overflow",
		);
		require(
			self.campaign_deadline_seconds >= self.drilldown_deadline_seconds,
			"campaign_deadline_seconds must cover drilldown_deadline_seconds",
		);
		require(
			self.drilldown_token_budget.is_none_or(|n| n > 0 && n <= i64::MAX as u64),
			"drilldown_token_budget must be positive and fit a SQLite integer when set",
		);
		require(
			self.verify_submit_margin_seconds < self.verify_deadline_seconds,
			"verify_submit_margin_seconds must be below verify_deadline_seconds",
		);
		require(
			self.lease_seconds < self.verify_deadline_seconds,
			"lease_seconds must be below verify_deadline_seconds",
		);
		require(
			self.verify_deadline_seconds.checked_add(self.lease_report_grace_seconds).is_some(),
			"verify_deadline_seconds plus lease_report_grace_seconds must not overflow",
		);
		require(
			self.campaign_deadline_seconds >= self.verify_deadline_seconds,
			"campaign_deadline_seconds must cover verify_deadline_seconds",
		);
		require(
			self.verify_token_budget.is_none_or(|n| n > 0 && n <= i64::MAX as u64),
			"verify_token_budget must be positive and fit a SQLite integer when set",
		);
		if violations.is_empty() {
			Ok(())
		} else {
			Err(PolicyError { violations })
		}
	}

	pub fn claim_policy(&self) -> ClaimPolicy {
		ClaimPolicy {
			active_jobs_per_repo: self.active_jobs_per_repo,
			active_jobs_total: self.active_jobs_total,
			active_surveys_per_repo: self.active_surveys_per_repo,
			active_drilldowns_per_repo: self.active_drilldowns_per_repo,
			active_verifications_per_repo: self.active_verifications_per_repo,
			verify_reserved_slots: self.verify_reserved_slots,
			lease_seconds: self.lease_seconds,
			lease_report_grace_seconds: self.lease_report_grace_seconds,
			urgency_burst_length: self.urgency_burst_length,
			priority_aging_interval_seconds: self.priority_aging_interval_seconds,
			priority_aging_cap: self.priority_aging_cap,
		}
	}

	pub fn snapshot(&self) -> Result<BoundedJson<Payload>, PolicyError> {
		self.validate()?;
		let value = serde_json::json!({
			"version": 1,
			"survey_units_per_job": self.survey_units_per_job,
			"survey_deadline_seconds": self.survey_deadline_seconds,
			"survey_submit_margin_seconds": self.survey_submit_margin_seconds,
			"drilldown_deadline_seconds": self.drilldown_deadline_seconds,
			"drilldown_submit_margin_seconds": self.drilldown_submit_margin_seconds,
			"verify_deadline_seconds": self.verify_deadline_seconds,
			"verify_submit_margin_seconds": self.verify_submit_margin_seconds,
			"max_attempts": self.max_attempts,
			"retry_backoff_base_seconds": self.retry_backoff_base_seconds,
			"retry_backoff_cap_seconds": self.retry_backoff_cap_seconds,
			"campaign_handoff_reserve": self.campaign_handoff_reserve,
			"campaign_deadline_seconds": self.campaign_deadline_seconds,
			"campaign_max_jobs": self.campaign_max_jobs,
			"survey_token_budget": self.survey_token_budget,
			"drilldown_token_budget": self.drilldown_token_budget,
			"verify_token_budget": self.verify_token_budget,
		});
		BoundedJson::new(&value.to_string())
			.map_err(|error| PolicyError { violations: vec![error.to_string()] })
	}
}

impl crate::config::ReviewSection {
	pub fn resolve(&self) -> Result<ReviewPolicy, PolicyError> {
		let defaults = ReviewPolicy::default();
		let policy = ReviewPolicy {
			active_jobs_per_repo: self
				.active_jobs_per_repo
				.unwrap_or(defaults.active_jobs_per_repo),
			active_jobs_total: self.active_jobs_total.or(defaults.active_jobs_total),
			active_surveys_per_repo: self
				.active_surveys_per_repo
				.unwrap_or(defaults.active_surveys_per_repo),
			active_drilldowns_per_repo: self
				.active_drilldowns_per_repo
				.unwrap_or(defaults.active_drilldowns_per_repo),
			active_verifications_per_repo: self
				.active_verifications_per_repo
				.unwrap_or(defaults.active_verifications_per_repo),
			verify_reserved_slots: self
				.verify_reserved_slots
				.unwrap_or(defaults.verify_reserved_slots),
			survey_units_per_job: self
				.survey_units_per_job
				.unwrap_or(defaults.survey_units_per_job),
			survey_deadline_seconds: self
				.survey_deadline_seconds
				.unwrap_or(defaults.survey_deadline_seconds),
			survey_submit_margin_seconds: self
				.survey_submit_margin_seconds
				.unwrap_or(defaults.survey_submit_margin_seconds),
			drilldown_deadline_seconds: self
				.drilldown_deadline_seconds
				.unwrap_or(defaults.drilldown_deadline_seconds),
			drilldown_submit_margin_seconds: self
				.drilldown_submit_margin_seconds
				.unwrap_or(defaults.drilldown_submit_margin_seconds),
			verify_deadline_seconds: self
				.verify_deadline_seconds
				.unwrap_or(defaults.verify_deadline_seconds),
			verify_submit_margin_seconds: self
				.verify_submit_margin_seconds
				.unwrap_or(defaults.verify_submit_margin_seconds),
			lease_seconds: self.lease_seconds.unwrap_or(defaults.lease_seconds),
			lease_report_grace_seconds: self
				.lease_report_grace_seconds
				.unwrap_or(defaults.lease_report_grace_seconds),
			max_attempts: self.max_attempts.unwrap_or(defaults.max_attempts),
			retry_backoff_base_seconds: self
				.retry_backoff_base_seconds
				.unwrap_or(defaults.retry_backoff_base_seconds),
			retry_backoff_cap_seconds: self
				.retry_backoff_cap_seconds
				.unwrap_or(defaults.retry_backoff_cap_seconds),
			urgency_burst_length: self
				.urgency_burst_length
				.unwrap_or(defaults.urgency_burst_length),
			campaign_handoff_reserve: self
				.campaign_handoff_reserve
				.unwrap_or(defaults.campaign_handoff_reserve),
			campaign_deadline_seconds: self
				.campaign_deadline_seconds
				.unwrap_or(defaults.campaign_deadline_seconds),
			campaign_max_jobs: self.campaign_max_jobs.unwrap_or(defaults.campaign_max_jobs),
			priority_aging_interval_seconds: self
				.priority_aging_interval_seconds
				.unwrap_or(defaults.priority_aging_interval_seconds),
			priority_aging_cap: self.priority_aging_cap.unwrap_or(defaults.priority_aging_cap),
			survey_token_budget: self.survey_token_budget.or(defaults.survey_token_budget),
			drilldown_token_budget: self.drilldown_token_budget.or(defaults.drilldown_token_budget),
			verify_token_budget: self.verify_token_budget.or(defaults.verify_token_budget),
		};
		policy.validate()?;
		Ok(policy)
	}
}
