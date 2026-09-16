//! Phase-aware queue policy. Campaign-owned limits are separate from live caps.
pub use crate::review_units::Priority as Band;

pub const PRIORITY_MAX: u32 = 1000;

/// Live deployment knobs; never substituted for campaign-owned budgets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimPolicy {
	pub active_jobs_per_repo: i64,
	pub active_jobs_total: Option<i64>,
	pub active_surveys_per_repo: i64,
	pub active_drilldowns_per_repo: i64,
	pub active_verifications_per_repo: i64,
	pub verify_reserved_slots: i64,
	pub lease_seconds: i64,
	pub lease_report_grace_seconds: i64,
	pub urgency_burst_length: i64,
	pub priority_aging_interval_seconds: i64,
	pub priority_aging_cap: i64,
}
impl Default for ClaimPolicy {
	fn default() -> Self {
		Self {
			active_jobs_per_repo: 3,
			active_jobs_total: None,
			active_surveys_per_repo: 1,
			active_drilldowns_per_repo: 2,
			active_verifications_per_repo: 2,
			verify_reserved_slots: 1,
			lease_seconds: 600,
			lease_report_grace_seconds: 60,
			urgency_burst_length: 4,
			priority_aging_interval_seconds: 3600,
			priority_aging_cap: 8,
		}
	}
}
