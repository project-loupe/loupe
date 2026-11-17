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

/// Phase host state accompanies exactly the phase modes, each its own.
pub(crate) fn mode_matches(mode: super::McpMode, phase: Option<&PhaseTools>) -> anyhow::Result<()> {
	match (mode, phase) {
		(super::McpMode::Survey, Some(PhaseTools::Survey(_)))
		| (super::McpMode::Drilldown, Some(PhaseTools::Drilldown(_)))
		| (super::McpMode::LegacyDiscovery { .. } | super::McpMode::LegacyVerify { .. }, None) => Ok(()),
		_ => anyhow::bail!("MCP mode and phase session state disagree"),
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
const INVALID: &str =
	"the server rejected the request as invalid; check the arguments against the tool schema";

pub(super) fn forbidden(error: &PhaseError) -> bool {
	matches!(error, PhaseError::Rejected { status: 403, .. } | PhaseError::Status { status: 403 })
}

/// The fixed text for a failed phase call. The server answers 403 both
/// for lost authority and for a reference outside the job's scope, so a
/// 403 is told apart by reading `/limits` under the same capability;
/// `record_limits` receives that read. `limits_call` marks a failed
/// `/limits` call itself, whose 403 needs no probe. `unreachable` is the
/// call's own text for a server that could not be reached.
pub(super) async fn phase_error(
	client: &ServerClient, phase: &PhaseSession, texts: &PhaseTexts, limits_call: bool,
	unreachable: &'static str, record_limits: impl FnOnce(&PhaseLimitsResponse), error: PhaseError,
) -> String {
	if forbidden(&error) {
		if limits_call {
			phase.record_authority_lost();
			return texts.authority_lost.to_owned();
		}
		return match client.limits(&phase.phase_job()).await {
			Ok(limits) => {
				record_limits(&limits);
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
