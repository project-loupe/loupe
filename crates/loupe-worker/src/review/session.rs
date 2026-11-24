//! Per-attempt review-phase host state. The handler owns it and shares it
//! with the MCP broker, so it outlives any one agent connection.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use loupe_proto::review_api::PhaseLimitsResponse;
use loupe_proto::review_drilldown::DrilldownTerminalResponse;
use loupe_proto::review_terminal::SurveyTerminalResponse;
use loupe_proto::JobCapability;
use loupe_provenance::Server;
use tokio_util::sync::CancellationToken;

use super::gate::{admit, admit_drilldown, Admission, DrilldownTool, RecipeClass, SurveyTool};
use super::prepare::{at, PreparedDrilldown, PreparedSurvey, SurveyRecipe};
use crate::client::PhaseJob;

pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// What the handler knows about an attempt when it launches the agent.
pub struct SurveySessionParts {
	pub job_id: i64,
	pub capability: JobCapability,
	pub recipe: RecipeClass,
	/// Whether this generation already has a published profile.
	pub profile_published: bool,
	pub submit_by: SystemTime,
	pub hard_deadline: SystemTime,
	/// `(review_unit_id, assignment_epoch)` from the lease or pin response.
	pub assignments: Vec<(i64, u64)>,
	/// The `/limits` read taken before launch, if any.
	pub limits: Option<PhaseLimitsResponse>,
	/// The agent invocation's token, cancelled once the attempt loses its
	/// authority.
	pub cancel: CancellationToken,
}

impl SurveySessionParts {
	pub fn from_prepared(prepared: &PreparedSurvey, cancel: CancellationToken) -> Self {
		let assignments = prepared.assignments.as_ref().map_or_else(Vec::new, |batch| {
			batch
				.as_slice()
				.iter()
				.map(|unit| (i64::from(unit.review_unit_id), unit.assignment_epoch.get()))
				.collect()
		});
		Self {
			job_id: prepared.job_id,
			capability: prepared.job_capability.clone(),
			recipe: match prepared.recipe {
				SurveyRecipe::Bootstrap => RecipeClass::Bootstrap,
				SurveyRecipe::ResolveTarget | SurveyRecipe::Ordinary(_) => RecipeClass::Ordinary,
			},
			profile_published: prepared.profile_published(),
			submit_by: at(prepared.limits.submit_by),
			hard_deadline: at(prepared.limits.hard_deadline_at),
			assignments,
			limits: Some(prepared.phase_limits.clone()),
			cancel,
		}
	}
}

/// The state every review phase's attempt shares: who it is, when it must
/// stop, and whether it can still write.
pub struct PhaseSession {
	job_id: i64,
	capability: JobCapability,
	submit_by: SystemTime,
	hard_deadline: SystemTime,
	clock: Clock,
	cancel: CancellationToken,
	/// Stops the phase heartbeat once a receipt is sealed.
	heartbeat: Option<CancellationToken>,
	authority_lost: AtomicBool,
	limits: Mutex<Option<PhaseLimitsResponse>>,
}

impl PhaseSession {
	/// `cancel` is the agent invocation's token, cancelled once the attempt
	/// loses its authority.
	pub fn new(
		job_id: i64, capability: JobCapability, submit_by: SystemTime, hard_deadline: SystemTime,
		clock: Clock, cancel: CancellationToken,
	) -> Self {
		Self {
			job_id,
			capability,
			submit_by,
			hard_deadline,
			clock,
			cancel,
			heartbeat: None,
			authority_lost: AtomicBool::new(false),
			limits: Mutex::new(None),
		}
	}

	pub fn job_id(&self) -> i64 {
		self.job_id
	}

	/// Phase calls never start past the hard deadline.
	pub fn phase_job(&self) -> PhaseJob<'_> {
		PhaseJob { job_id: self.job_id, capability: &self.capability, deadline: self.hard_deadline }
	}

	pub fn now(&self) -> SystemTime {
		(self.clock)()
	}

	pub fn past_submit_by(&self) -> bool {
		self.now() >= self.submit_by
	}

	/// The heartbeat token to cancel once a receipt is sealed.
	pub fn set_heartbeat(&mut self, heartbeat: CancellationToken) {
		self.heartbeat = Some(heartbeat);
	}

	/// Stop the phase heartbeat; called once a receipt is sealed.
	pub fn stop_heartbeat(&self) {
		if let Some(heartbeat) = &self.heartbeat {
			heartbeat.cancel();
		}
	}

	/// Mark the attempt as unable to write and stop its agent.
	pub fn record_authority_lost(&self) {
		self.authority_lost.store(true, Ordering::SeqCst);
		self.cancel.cancel();
	}

	/// Whether any phase call was denied after preparation: the attempt can
	/// no longer write.
	pub fn authority_lost(&self) -> bool {
		self.authority_lost.load(Ordering::SeqCst)
	}

	/// Whether the hard deadline, less the host's kill margin, has passed.
	pub fn hard_deadline_reached(&self) -> bool {
		self.now() + super::deadline::KILL_MARGIN >= self.hard_deadline
	}

	pub fn record_limits(&self, limits: &PhaseLimitsResponse) {
		*self.limits.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
			Some(limits.clone());
	}

	/// The last `/limits` read, if any.
	pub fn limits(&self) -> Option<PhaseLimitsResponse> {
		self.limits.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
	}

	/// The host-authored status line: the shared deadline part followed by
	/// the phase's `capacity` part.
	pub fn status_line(&self, now: SystemTime, capacity: &str) -> String {
		format!(
			"[loupe status] submit_by: {}; hard deadline: {}; {capacity}",
			remaining(now, self.submit_by),
			remaining(now, self.hard_deadline),
		)
	}
}

pub struct SurveySession {
	phase: PhaseSession,
	recipe: RecipeClass,
	/// Whether the catalog lists `publish_profile`: fixed at session start,
	/// whatever the agent publishes later.
	lists_publish_profile: bool,
	state: Mutex<State>,
}
impl std::fmt::Debug for SurveySession {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("SurveySession").field("job_id", &self.phase.job_id).finish_non_exhaustive()
	}
}

#[derive(Default)]
struct State {
	epochs: HashMap<i64, u64>,
	/// Leads this attempt saw created, so a replayed creation is counted
	/// once.
	created_leads: HashSet<i64>,
	revisions: HashMap<String, u64>,
	profile_published: bool,
	receipt: Option<SurveyTerminalResponse<Server>>,
	units_remaining: Option<u32>,
	leads_remaining: Option<u32>,
}

impl SurveySession {
	pub fn new(parts: SurveySessionParts) -> Self {
		Self::with_clock(parts, Arc::new(SystemTime::now))
	}

	/// The session of a prepared attempt: its deadlines, assignments, profile
	/// state and capacity all come from the preparation.
	pub fn from_prepared(
		prepared: &PreparedSurvey, clock: Clock, cancel: CancellationToken,
	) -> Self {
		Self::with_clock(SurveySessionParts::from_prepared(prepared, cancel), clock)
	}

	pub fn with_clock(parts: SurveySessionParts, clock: Clock) -> Self {
		let mut state = State {
			epochs: parts.assignments.into_iter().collect(),
			profile_published: parts.profile_published,
			..State::default()
		};
		let phase = PhaseSession::new(
			parts.job_id,
			parts.capability,
			parts.submit_by,
			parts.hard_deadline,
			clock,
			parts.cancel,
		);
		if let Some(limits) = &parts.limits {
			phase.record_limits(limits);
			state.apply_limits(limits);
		}
		Self {
			phase,
			recipe: parts.recipe,
			lists_publish_profile: parts.recipe == RecipeClass::Bootstrap
				&& !parts.profile_published,
			state: Mutex::new(state),
		}
	}

	/// Stop the phase heartbeat through `heartbeat` once a receipt is sealed.
	pub fn with_heartbeat(mut self, heartbeat: CancellationToken) -> Self {
		self.phase.set_heartbeat(heartbeat);
		self
	}

	pub fn phase(&self) -> &PhaseSession {
		&self.phase
	}

	fn state(&self) -> MutexGuard<'_, State> {
		// The state holds plain values; a panicked holder cannot leave it torn
		// in a way later readers rely on.
		self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
	}

	pub fn recipe(&self) -> RecipeClass {
		self.recipe
	}

	pub(crate) fn admission(&self, tool: SurveyTool) -> Admission {
		let state = self.state();
		admit(
			tool,
			self.recipe,
			state.profile_published,
			self.phase.past_submit_by(),
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

	pub fn record_lead_created(&self, lead_id: i64) {
		let mut state = self.state();
		if state.created_leads.insert(lead_id) {
			state.leads_remaining = state.leads_remaining.map(|n| n.saturating_sub(1));
		}
	}

	/// The server refused `tool`'s checkpoint for its exhausted quota.
	pub(crate) fn record_exhausted(&self, tool: SurveyTool) {
		let mut state = self.state();
		match tool {
			SurveyTool::ProposeUnit => state.units_remaining = Some(0),
			SurveyTool::Lead => state.leads_remaining = Some(0),
			_ => {},
		}
	}

	/// The last known revision of an inventory entry, 0 until a response or
	/// conflict reports one.
	pub fn revision(&self, path: &str) -> u64 {
		self.state().revisions.get(path).copied().unwrap_or(0)
	}

	pub fn record_revision(&self, path: &str, revision: u64) {
		self.state().revisions.insert(path.to_owned(), revision);
	}

	pub fn lists_publish_profile(&self) -> bool {
		self.lists_publish_profile
	}

	pub fn profile_published(&self) -> bool {
		self.state().profile_published
	}

	pub fn record_profile_published(&self) {
		self.state().profile_published = true;
	}

	pub fn seal(&self, receipt: SurveyTerminalResponse<Server>) {
		self.state().receipt.get_or_insert(receipt);
		self.phase.stop_heartbeat();
	}

	pub fn receipt(&self) -> Option<SurveyTerminalResponse<Server>> {
		self.state().receipt.clone()
	}

	pub fn record_limits(&self, limits: &PhaseLimitsResponse) {
		self.phase.record_limits(limits);
		self.state().apply_limits(limits);
	}

	/// The host-authored line every survey tool result ends with.
	pub fn status_line(&self) -> String {
		let now = self.phase.now();
		let state = self.state();
		let count =
			|value: Option<u32>| value.map_or_else(|| "unknown".to_owned(), |n| n.to_string());
		let capacity = format!(
			"review units remaining: {}; leads remaining: {}",
			count(state.units_remaining),
			count(state.leads_remaining),
		);
		self.phase.status_line(now, &capacity)
	}
}

/// A drilldown attempt's host state: its phase core, the lead it
/// investigates, the capacity shown to the agent and the sealed receipt.
pub struct DrilldownSession {
	phase: PhaseSession,
	lead_id: i64,
	state: Mutex<DrilldownState>,
}
impl std::fmt::Debug for DrilldownSession {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("DrilldownSession")
			.field("job_id", &self.phase.job_id)
			.field("lead_id", &self.lead_id)
			.finish_non_exhaustive()
	}
}

#[derive(Default)]
struct DrilldownState {
	receipt: Option<DrilldownTerminalResponse<Server>>,
	/// Client keys and queries this attempt saw accepted; the server counts
	/// each once, so a replay is not counted again.
	sibling_keys: HashSet<String>,
	queries: HashSet<(String, u8)>,
	siblings_remaining: Option<u32>,
	queries_remaining: Option<u32>,
}

impl DrilldownSession {
	/// `limits` is the `/limits` read taken before launch, if any.
	pub fn new(phase: PhaseSession, lead_id: i64, limits: Option<&PhaseLimitsResponse>) -> Self {
		let session = Self { phase, lead_id, state: Mutex::default() };
		if let Some(limits) = limits {
			session.record_limits(limits);
		}
		session
	}

	/// The session of a prepared attempt: deadlines, lead and capacity come
	/// from the preparation.
	pub fn from_prepared(
		prepared: &PreparedDrilldown, clock: Clock, cancel: CancellationToken,
	) -> Self {
		let phase = PhaseSession::new(
			prepared.job_id,
			prepared.job_capability.clone(),
			at(prepared.limits.submit_by),
			at(prepared.limits.hard_deadline_at),
			clock,
			cancel,
		);
		Self::new(phase, i64::from(prepared.lead.lead_id), Some(&prepared.phase_limits))
	}

	/// Stop the phase heartbeat through `heartbeat` once a receipt is sealed.
	pub fn with_heartbeat(mut self, heartbeat: CancellationToken) -> Self {
		self.phase.set_heartbeat(heartbeat);
		self
	}

	pub fn phase(&self) -> &PhaseSession {
		&self.phase
	}

	pub fn lead_id(&self) -> i64 {
		self.lead_id
	}

	fn state(&self) -> MutexGuard<'_, DrilldownState> {
		// Plain values only; a panicked holder leaves nothing torn.
		self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
	}

	pub(crate) fn admission(&self, tool: DrilldownTool) -> Admission {
		admit_drilldown(tool, self.phase.past_submit_by(), self.state().receipt.is_some())
	}

	pub fn record_limits(&self, limits: &PhaseLimitsResponse) {
		self.phase.record_limits(limits);
		let mut state = self.state();
		state.siblings_remaining = Some(limits.siblings.remaining);
		state.queries_remaining = Some(limits.candidate_queries.remaining);
	}

	/// A sibling checkpoint under `key` was accepted.
	pub fn record_sibling(&self, key: &str) {
		let mut state = self.state();
		if state.sibling_keys.insert(key.to_owned()) {
			state.siblings_remaining = state.siblings_remaining.map(|n| n.saturating_sub(1));
		}
	}

	/// A candidate query for `query` and `limit` was answered.
	pub fn record_query(&self, query: &str, limit: u8) {
		let mut state = self.state();
		if state.queries.insert((query.to_owned(), limit)) {
			state.queries_remaining = state.queries_remaining.map(|n| n.saturating_sub(1));
		}
	}

	/// The server refused `tool`'s call for its exhausted quota.
	pub(crate) fn record_exhausted(&self, tool: DrilldownTool) {
		let mut state = self.state();
		match tool {
			DrilldownTool::SiblingLead => state.siblings_remaining = Some(0),
			DrilldownTool::Candidates => state.queries_remaining = Some(0),
			DrilldownTool::JobLimits | DrilldownTool::Finalize => {},
		}
	}

	pub fn seal(&self, receipt: DrilldownTerminalResponse<Server>) {
		self.state().receipt.get_or_insert(receipt);
		self.phase.stop_heartbeat();
	}

	pub fn receipt(&self) -> Option<DrilldownTerminalResponse<Server>> {
		self.state().receipt.clone()
	}

	/// The host-authored line every drilldown tool result ends with.
	pub fn status_line(&self) -> String {
		let now = self.phase.now();
		let state = self.state();
		let count =
			|value: Option<u32>| value.map_or_else(|| "unknown".to_owned(), |n| n.to_string());
		let capacity = format!(
			"sibling leads remaining: {}; candidate queries remaining: {}",
			count(state.siblings_remaining),
			count(state.queries_remaining),
		);
		self.phase.status_line(now, &capacity)
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

#[cfg(test)]
mod tests {
	use super::*;

	fn parts(cancel: CancellationToken) -> SurveySessionParts {
		let now = SystemTime::now();
		SurveySessionParts {
			job_id: 7,
			capability: JobCapability::from_secret("session-capability"),
			recipe: RecipeClass::Ordinary,
			profile_published: true,
			submit_by: now,
			hard_deadline: now,
			assignments: Vec::new(),
			limits: None,
			cancel,
		}
	}

	#[test]
	fn losing_authority_cancels_the_agent() {
		let cancel = CancellationToken::new();
		let session = SurveySession::new(parts(cancel.clone()));
		assert!(!cancel.is_cancelled());
		session.phase().record_authority_lost();
		assert!(session.phase().authority_lost());
		assert!(cancel.is_cancelled(), "a denied attempt must stop its agent");
	}

	#[test]
	fn sealing_stops_the_heartbeat_but_not_the_agent() {
		let (cancel, heartbeat) = (CancellationToken::new(), CancellationToken::new());
		let session = SurveySession::new(parts(cancel.clone())).with_heartbeat(heartbeat.clone());
		let receipt = serde_json::json!({"protocol_version":3,"receipt":{"receipt_id":11,
			"job_id":7,"commit_sha":"a".repeat(40),"result_digest":"b".repeat(64),
			"terminal_reason":"completed","summary":{"version":1,"coverage":"complete",
			"corroboration_satisfied":true,"missing_results":0,"needs_follow_up":0,
			"unresolved_inventory":0,"follow_up_batches":0,"follow_up_units":0}}});
		let receipt = crate::client::fuzz_support::review_response(
			loupe_proto::review_terminal::SurveyTerminalResponseDecoder,
			receipt.to_string().as_bytes(),
		)
		.unwrap();
		assert!(!heartbeat.is_cancelled());
		session.seal(receipt);
		assert!(heartbeat.is_cancelled(), "a sealed attempt must not heartbeat");
		assert!(!cancel.is_cancelled());
	}

	#[test]
	fn sealing_a_drilldown_stops_the_heartbeat_and_closes_its_tools() {
		let (cancel, heartbeat) = (CancellationToken::new(), CancellationToken::new());
		let now = SystemTime::now();
		let phase = PhaseSession::new(
			7,
			JobCapability::from_secret("session-capability"),
			now + std::time::Duration::from_secs(60),
			now + std::time::Duration::from_secs(120),
			Arc::new(SystemTime::now),
			cancel.clone(),
		);
		let session = DrilldownSession::new(phase, 4, None).with_heartbeat(heartbeat.clone());
		assert_eq!(session.admission(DrilldownTool::SiblingLead), Admission::Allow);
		assert!(session
			.status_line()
			.ends_with("sibling leads remaining: unknown; candidate queries remaining: unknown"));
		let receipt = serde_json::json!({"protocol_version":3,"receipt":{"receipt_id":21,
			"job_id":7,"commit_sha":"a".repeat(40),"result_digest":"b".repeat(64),
			"summary":{"version":1,"lead_id":4,"disposition":"rejected"}}});
		let receipt = crate::client::fuzz_support::review_response(
			loupe_proto::review_drilldown::DrilldownTerminalResponseDecoder,
			receipt.to_string().as_bytes(),
		)
		.unwrap();
		session.seal(receipt);
		assert!(heartbeat.is_cancelled(), "a sealed attempt must not heartbeat");
		assert!(!cancel.is_cancelled());
		assert_ne!(session.admission(DrilldownTool::SiblingLead), Admission::Allow);
		assert_eq!(session.admission(DrilldownTool::Finalize), Admission::Allow);
	}
}
