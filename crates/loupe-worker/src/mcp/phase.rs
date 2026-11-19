//! What every review-phase dispatcher shares: the phase session a request
//! carries, the fixed model text for a failed phase call, and the framing
//! of candidate-query answers.

use std::sync::Arc;

use loupe_core::review_candidates::CandidateQuery;
use loupe_proto::review_api::{CandidatesResponse, PhaseLimitsResponse, ReviewErrorCode};
use loupe_provenance::{Agent, Server};

use super::ServerClient;
use crate::client::PhaseError;
use crate::review::session::{DrilldownSession, PhaseSession, SurveySession};

/// The host state of the review phase an MCP session serves.
#[derive(Clone)]
pub enum PhaseTools {
	Survey(Arc<SurveySession>),
	Drilldown(Arc<DrilldownSession>),
}

impl PhaseTools {
	/// The catalog this phase's sessions serve.
	pub fn mode(&self) -> super::McpMode {
		match self {
			Self::Survey(_) => super::McpMode::Survey,
			Self::Drilldown(_) => super::McpMode::Drilldown,
		}
	}

	pub fn phase(&self) -> &PhaseSession {
		match self {
			Self::Survey(survey) => survey.phase(),
			Self::Drilldown(drilldown) => drilldown.phase(),
		}
	}

	/// Whether the attempt sealed its receipt.
	pub fn sealed(&self) -> bool {
		match self {
			Self::Survey(survey) => survey.receipt().is_some(),
			Self::Drilldown(drilldown) => drilldown.receipt().is_some(),
		}
	}
}

/// A phase's own wording for the failures whose text names the phase or
/// its tools.
pub(super) struct PhaseTexts {
	pub authority_lost: &'static str,
	/// A 403 while `/limits` still answers: a reference outside the job's
	/// scope.
	pub reference_refused: &'static str,
	pub exhausted: &'static str,
	pub state_refused: &'static str,
	pub terminal_conflict: &'static str,
	pub not_found: &'static str,
}

pub(super) const UNREACHABLE: &str = "the server could not be reached after retries; retry later with the SAME client key and identical content";
/// For calls that only read, so carry neither a client key nor content.
pub(super) const READ_UNREACHABLE: &str =
	"the server could not be reached after retries; retry later";
const INVALID: &str =
	"the server rejected the request as invalid; check the arguments against the tool schema";

pub(super) fn forbidden(error: &PhaseError) -> bool {
	matches!(error, PhaseError::Rejected { status: 403, .. } | PhaseError::Status { status: 403 })
}

/// What the shared failure text needs from one phase's session.
pub(super) trait PhaseCalls {
	type Tool: Copy;
	const TEXTS: PhaseTexts;

	fn phase(&self) -> &PhaseSession;
	/// Whether a rejection with `code` exhausts the capacity `tool` uses.
	fn exhausts(code: ReviewErrorCode) -> bool;
	fn record_exhausted(&self, tool: Self::Tool);
	fn record_limits(&self, limits: &PhaseLimitsResponse);
	/// Whether `tool` is the `/limits` call itself.
	fn limits_call(tool: Self::Tool) -> bool;
	/// The call's own text for a server that could not be reached.
	fn unreachable(tool: Self::Tool) -> &'static str;
	/// The phase's own text for a non-403 error, ahead of the shared table.
	fn own_text(_tool: Self::Tool, _error: &PhaseError) -> Option<&'static str> {
		None
	}
}

/// The fixed text for a failed phase call. The server answers 403 both
/// for lost authority and for a reference outside the job's scope, so a
/// 403 is told apart by reading `/limits` under the same capability and
/// the session records that read. A failed `/limits` call itself needs no
/// probe.
pub(super) async fn phase_error<P: PhaseCalls>(
	client: &ServerClient, session: &P, tool: P::Tool, error: PhaseError,
) -> String {
	if !forbidden(&error)
		&& let PhaseError::Rejected { code, .. } = &error
		&& P::exhausts(*code)
	{
		session.record_exhausted(tool);
	}
	if let Some(text) = P::own_text(tool, &error) {
		return text.to_owned();
	}
	let phase = session.phase();
	let texts = &P::TEXTS;
	let limits_call = P::limits_call(tool);
	let unreachable = P::unreachable(tool);
	if forbidden(&error) {
		if limits_call {
			phase.record_authority_lost();
			return texts.authority_lost.to_owned();
		}
		return match client.limits(&phase.phase_job()).await {
			Ok(limits) => {
				session.record_limits(&limits);
				texts.reference_refused
			},
			Err(probe) if forbidden(&probe) => {
				phase.record_authority_lost();
				texts.authority_lost
			},
			Err(_) => unreachable,
		}
		.to_owned();
	}
	let text = match &error {
		PhaseError::Rejected { code, current_revision, .. } => match code {
			ReviewErrorCode::CheckpointConflict => {
				"this client key was already used with different content; resend the identical content to replay it, or use a new key for new content"
			},
			ReviewErrorCode::CheckpointLimit | ReviewErrorCode::InventoryLimit => texts.exhausted,
			ReviewErrorCode::Denied => {
				phase.record_authority_lost();
				texts.authority_lost
			},
			ReviewErrorCode::InventoryRevisionConflict => {
				return match current_revision.and_then(|revision| u64::try_from(revision).ok()) {
					Some(revision) => format!(
						"inventory entry conflict: the entry changed and is now at revision {revision}; re-check whether your disposition still applies before submitting it again"
					),
					None => "inventory entry conflict: the host cannot recover this entry's current revision; leave this entry and continue with the others".to_owned(),
				};
			},
			ReviewErrorCode::TerminalConflict => texts.terminal_conflict,
			ReviewErrorCode::UnitResultExists => {
				"a different result for this review unit already exists"
			},
			ReviewErrorCode::NotFound => texts.not_found,
			ReviewErrorCode::InvalidRequest
			| ReviewErrorCode::RequestTooLarge
			| ReviewErrorCode::ContentType
			| ReviewErrorCode::ContentEncoding
			| ReviewErrorCode::MethodNotAllowed => INVALID,
			ReviewErrorCode::InternalError
			| ReviewErrorCode::ResponseTooLarge
			| ReviewErrorCode::Unauthenticated
			| ReviewErrorCode::RequestFailed => unreachable,
			ReviewErrorCode::CheckoutConflict
			| ReviewErrorCode::CompatibilityKeyConflict
			| ReviewErrorCode::CompatibilityPolicy
			| ReviewErrorCode::FindingIdentityConflict
			| ReviewErrorCode::IncompatibleReviewState
			| ReviewErrorCode::InvalidLimits
			| ReviewErrorCode::RevalidationRequired
			| ReviewErrorCode::StateConflict
			| ReviewErrorCode::Other => texts.state_refused,
		},
		PhaseError::Timeout
		| PhaseError::Connection
		| PhaseError::Status { .. }
		| PhaseError::Response(_)
		| PhaseError::Decode(_) => unreachable,
	};
	text.to_owned()
}

/// A candidate-query answer framed as agent data under the job's tool
/// boundary.
pub(super) fn render_candidates(
	session: &super::Session, query: &CandidateQuery<Agent>,
	response: &CandidatesResponse<Agent, Server>,
) -> anyhow::Result<String> {
	let rendered = (|| {
		let mut builder = crate::llm::prompt::PromptBuilder::new("").mode(session.data_mode);
		if response.candidates.as_slice().is_empty() {
			builder.instruction("No same-project lead or finding matches.\n")?;
		}
		builder.data("query", &query.query)?;
		builder.lead_candidates(response.candidates.as_slice())?;
		builder.render_fixed(session.tool_boundary)
	})();
	rendered.map(crate::llm::prompt::Prompt::into_tool_text).map_err(
		|_: crate::llm::prompt::PromptError| {
			anyhow::anyhow!("tool response cannot be safely framed")
		},
	)
}
