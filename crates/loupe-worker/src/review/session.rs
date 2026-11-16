//! Per-attempt survey host state. The handler owns it and shares it with the
//! MCP broker, so it outlives any one agent connection.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use loupe_proto::review_api::PhaseLimitsResponse;
use loupe_proto::review_terminal::SurveyTerminalResponse;
use loupe_proto::JobCapability;
use loupe_provenance::Server;

use super::gate::{admit, Admission, RecipeClass, SurveyTool};
use crate::client::PhaseJob;

pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// What the handler knows about an attempt when it launches the agent.
pub struct SurveySessionParts {
	pub job_id: i64,
	pub capability: JobCapability,
	pub recipe: RecipeClass,
	/// Bootstrap: whether this generation already has a published profile.
	/// Ordinary surveys always have one.
	pub profile_published: bool,
	pub submit_by: SystemTime,
	pub hard_deadline: SystemTime,
	/// `(review_unit_id, assignment_epoch)` from the lease or pin response.
	pub assignments: Vec<(i64, u64)>,
	/// The `/limits` read taken before launch, if any.
	pub limits: Option<PhaseLimitsResponse>,
}

pub struct SurveySession {
	job_id: i64,
	capability: JobCapability,
	recipe: RecipeClass,
	submit_by: SystemTime,
	hard_deadline: SystemTime,
	clock: Clock,
	state: Mutex<State>,
}
impl std::fmt::Debug for SurveySession {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("SurveySession").field("job_id", &self.job_id).finish_non_exhaustive()
	}
}

#[derive(Default)]
struct State {
	epochs: HashMap<i64, u64>,
	revisions: HashMap<String, u64>,
	profile_published: bool,
	receipt: Option<SurveyTerminalResponse<Server>>,
	units_remaining: Option<u32>,
	leads_remaining: Option<u32>,
	authority_lost: bool,
}

impl SurveySession {
	pub fn new(parts: SurveySessionParts) -> Self {
		Self::with_clock(parts, Arc::new(SystemTime::now))
	}

	pub fn with_clock(parts: SurveySessionParts, clock: Clock) -> Self {
		let mut state = State {
			epochs: parts.assignments.into_iter().collect(),
			profile_published: parts.profile_published || parts.recipe == RecipeClass::Ordinary,
			..State::default()
		};
		if let Some(limits) = &parts.limits {
			state.apply_limits(limits);
		}
		Self {
			job_id: parts.job_id,
			capability: parts.capability,
			recipe: parts.recipe,
			submit_by: parts.submit_by,
			hard_deadline: parts.hard_deadline,
			clock,
			state: Mutex::new(state),
		}
	}

	fn state(&self) -> MutexGuard<'_, State> {
		// The state holds plain values; a panicked holder cannot leave it torn
		// in a way later readers rely on.
		self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
	}

	pub fn job_id(&self) -> i64 {
		self.job_id
	}

	pub fn recipe(&self) -> RecipeClass {
		self.recipe
	}

	/// Phase calls never start past the hard deadline.
	pub fn phase_job(&self) -> PhaseJob<'_> {
		PhaseJob { job_id: self.job_id, capability: &self.capability, deadline: self.hard_deadline }
	}

	pub fn now(&self) -> SystemTime {
		(self.clock)()
	}

	pub(crate) fn admission(&self, tool: SurveyTool) -> Admission {
		let state = self.state();
		admit(
			tool,
			self.recipe,
			state.profile_published,
			self.now() >= self.submit_by,
			state.receipt.is_some(),
		)
	}

	/// The assignment epoch to pair with `review_unit_id`. Units a bootstrap
	/// job proposes always have epoch 0, including those from an earlier
	/// attempt that this session never saw.
	pub fn epoch(&self, review_unit_id: i64) -> Option<u64> {
		let known = self.state().epochs.get(&review_unit_id).copied();
		match self.recipe {
			RecipeClass::Bootstrap => Some(known.unwrap_or(0)),
			RecipeClass::Ordinary => known,
		}
	}

	pub fn record_unit(&self, review_unit_id: i64, assignment_epoch: u64) {
		let mut state = self.state();
		if state.epochs.insert(review_unit_id, assignment_epoch).is_none() {
			state.units_remaining = state.units_remaining.map(|n| n.saturating_sub(1));
		}
	}

	pub fn record_lead_created(&self) {
		let mut state = self.state();
		state.leads_remaining = state.leads_remaining.map(|n| n.saturating_sub(1));
	}

	/// The last known revision of an inventory entry, 0 until a response or
	/// conflict reports one.
	pub fn revision(&self, path: &str) -> u64 {
		self.state().revisions.get(path).copied().unwrap_or(0)
	}

	pub fn record_revision(&self, path: &str, revision: u64) {
		self.state().revisions.insert(path.to_owned(), revision);
	}

	pub fn profile_published(&self) -> bool {
		self.state().profile_published
	}

	pub fn record_profile_published(&self) {
		self.state().profile_published = true;
	}

	pub fn seal(&self, receipt: SurveyTerminalResponse<Server>) {
		self.state().receipt.get_or_insert(receipt);
	}

	pub fn receipt(&self) -> Option<SurveyTerminalResponse<Server>> {
		self.state().receipt.clone()
	}

	pub fn record_authority_lost(&self) {
		self.state().authority_lost = true;
	}

	/// Whether any phase call was denied after preparation: the attempt can
	/// no longer write.
	pub fn authority_lost(&self) -> bool {
		self.state().authority_lost
	}

	pub fn record_limits(&self, limits: &PhaseLimitsResponse) {
		self.state().apply_limits(limits);
	}

	/// The host-authored line every survey tool result ends with.
	pub fn status_line(&self) -> String {
		let now = self.now();
		let state = self.state();
		let count =
			|value: Option<u32>| value.map_or_else(|| "unknown".to_owned(), |n| n.to_string());
		format!(
			"[loupe status] submit_by: {}; hard deadline: {}; review units remaining: {}; leads remaining: {}",
			remaining(now, self.submit_by),
			remaining(now, self.hard_deadline),
			count(state.units_remaining),
			count(state.leads_remaining),
		)
	}
}

impl State {
	fn apply_limits(&mut self, limits: &PhaseLimitsResponse) {
		self.units_remaining = Some(limits.new_units.remaining);
		self.leads_remaining = Some(limits.leads.remaining);
	}
}

fn remaining(now: SystemTime, at: SystemTime) -> String {
	let seconds = |time: SystemTime| time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
	match at.duration_since(now) {
		Ok(left) if !left.is_zero() => format!("{}s left (at {})", left.as_secs(), seconds(at)),
		_ => format!("passed (at {})", seconds(at)),
	}
}
