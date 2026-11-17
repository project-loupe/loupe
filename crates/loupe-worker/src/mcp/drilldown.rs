//! Drilldown tool dispatch: gate, build the phase request, call the phase
//! client, update the attempt state and answer with fixed host text. Server
//! response bodies never reach the model.

use loupe_proto::review_api::{ReviewErrorCode, ReviewProtocol};
use loupe_proto::review_drilldown::FinalizeDrilldownRequest;
use loupe_proto::review_evidence::{LeadCheckpointRequest, LeadOutcome};

use super::phase::{forbidden, PhaseTexts};
use super::*;
use crate::client::PhaseError;
use crate::review::gate::{Admission, DrilldownTool};
use crate::review::session::DrilldownSession;

pub(super) fn tool(name: &ingress::ToolName) -> Option<DrilldownTool> {
	use ingress::ToolName;
	Some(match name {
		ToolName::JobLimits => DrilldownTool::JobLimits,
		ToolName::Candidates => DrilldownTool::Candidates,
		ToolName::SiblingLead => DrilldownTool::SiblingLead,
		ToolName::FinalizeDrilldown => DrilldownTool::Finalize,
		_ => return None,
	})
}

/// A refusal or failure shown to the model as fixed host text.
// debug-ok: fixed host text only.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct DrilldownRefusal(String);

fn refuse(text: impl Into<String>) -> anyhow::Error {
	DrilldownRefusal(text.into()).into()
}

const TEXTS: PhaseTexts = PhaseTexts {
	authority_lost: "this drilldown attempt no longer has authority to write (superseded, campaign inactive or hard deadline passed); stop working and end the session",
	reference_refused: "the server refused a referenced lead or finding for this job: a duplicate target must be a lead or finding returned by this job's own query_same_project_lead_candidates calls, and never the lead under investigation; a duplicate_of_lead_id must name a lead the server knows for this job; correct the reference and call again",
	exhausted: SIBLINGS_EXHAUSTED,
	state_refused: "the server rejected the request in the drilldown's current state",
	terminal_conflict: "the drilldown is already finalized with a different payload; it cannot be finalized again; end the session",
	not_found: "the referenced object does not exist for this drilldown",
};

pub(super) const SIBLINGS_EXHAUSTED: &str =
	"sibling lead capacity is exhausted; record nothing further as a sibling and finalize with finalize_drilldown";
pub(super) const QUERIES_EXHAUSTED: &str =
	"candidate queries are exhausted for this job; finalize with finalize_drilldown without a new query (a query you already made still replays its answer)";
pub(super) const REVALIDATION_REQUIRED: &str =
	"finalizing was refused as revalidation required: re-inspect the lead on this checkout, then call finalize_drilldown again with `revalidation` (current_source_refs and rationale)";
pub(super) const IDENTITY_CONFLICT: &str =
	"a finding with this identity already exists, so this promotion was not recorded; query query_same_project_lead_candidates with different text than before, such as the full identity anchor, and finalize as duplicate of that finding (target kind finding), or promote under a distinct supported identity_instance_key, or defer";
pub(super) const COMPATIBILITY_CONFLICT: &str =
	"a legacy finding with this identity already exists, so this promotion was not recorded; legacy findings are never candidates and cannot be a duplicate target: promote under a distinct supported identity_instance_key, or defer";
pub(super) const INCOMPATIBLE_STATE: &str =
	"the lead can no longer be finalized by this job; stop working and end the session";
/// `finalize_drilldown` carries no client key; replaying the identical
/// payload is what makes a retry safe.
pub(super) const FINALIZE_UNREACHABLE: &str =
	"the server could not be reached after retries; retry later with the identical finalize_drilldown call";
pub(super) const INVALID: &str =
	"the server refused a field or source path: every path must exist in the pinned checkout exactly as written; check the arguments against the tool schema and call again";

/// The drilldown's own wording for the codes whose text names its tools;
/// everything else goes through the shared table.
fn own_text(tool: DrilldownTool, error: &PhaseError) -> Option<&'static str> {
	let PhaseError::Rejected { code, .. } = error else { return None };
	if forbidden(error) {
		return None;
	}
	Some(match code {
		ReviewErrorCode::CheckpointLimit if tool == DrilldownTool::Candidates => QUERIES_EXHAUSTED,
		ReviewErrorCode::RevalidationRequired => REVALIDATION_REQUIRED,
		ReviewErrorCode::FindingIdentityConflict => IDENTITY_CONFLICT,
		ReviewErrorCode::CompatibilityKeyConflict => COMPATIBILITY_CONFLICT,
		ReviewErrorCode::IncompatibleReviewState => INCOMPATIBLE_STATE,
		ReviewErrorCode::InvalidRequest => INVALID,
		_ => return None,
	})
}

async fn phase_error(
	client: &ServerClient, drilldown: &DrilldownSession, tool: DrilldownTool, error: PhaseError,
) -> String {
	if !forbidden(&error)
		&& let PhaseError::Rejected { code: ReviewErrorCode::CheckpointLimit, .. } = error
	{
		drilldown.record_exhausted(tool);
	}
	if let Some(text) = own_text(tool, &error) {
		return text.to_owned();
	}
	let limits_call = tool == DrilldownTool::JobLimits;
	let record_limits = |limits: &_| drilldown.record_limits(limits);
	let unreachable =
		if tool == DrilldownTool::Finalize { FINALIZE_UNREACHABLE } else { phase::UNREACHABLE };
	phase::phase_error(
		client,
		drilldown.phase(),
		&TEXTS,
		limits_call,
		unreachable,
		record_limits,
		error,
	)
	.await
}

async fn settle<T>(
	client: &ServerClient, drilldown: &DrilldownSession, tool: DrilldownTool,
	result: Result<T, PhaseError>,
) -> Result<T> {
	match result {
		Ok(value) => Ok(value),
		Err(error) => Err(refuse(phase_error(client, drilldown, tool, error).await)),
	}
}

pub(super) async fn dispatch(
	session: &Session, drilldown: &DrilldownSession, tool: DrilldownTool,
	arguments: Result<ingress::Arguments>,
) -> Result<String> {
	if let Admission::Deny(reason) = drilldown.admission(tool) {
		return Err(refuse(reason.text()));
	}
	let arguments = arguments?;
	session.security.admit(operation(tool))?;
	let client = &session.client;
	let job = drilldown.phase().phase_job();
	match arguments {
		ingress::Arguments::JobLimits => {
			let limits = settle(client, drilldown, tool, client.limits(&job).await).await?;
			drilldown.record_limits(&limits);
			Ok(serde_json::to_string(&limits).context("encoding limits")?)
		},
		ingress::Arguments::Candidates(query) => {
			let response =
				settle(client, drilldown, tool, client.lead_candidates(&job, &query).await).await?;
			drilldown.record_query(query.query.expose(), query.limit);
			phase::render_candidates(session, &query, &response)
		},
		ingress::Arguments::SiblingLead(args) => {
			let args = *args;
			let key = args.key.expose().to_owned();
			let request = LeadCheckpointRequest {
				protocol_version: ReviewProtocol,
				client_lead_key: args.key,
				evidence: args.evidence,
			};
			let response =
				settle(client, drilldown, tool, client.sibling_lead(&job, &request).await).await?;
			drilldown.record_sibling(&key);
			let outcome = match response.outcome {
				LeadOutcome::Created => "created; it gets its own drilldown",
				LeadOutcome::Attached => "attached to an existing lead",
				LeadOutcome::ClosedExists => "matches a closed lead",
			};
			Ok(format!("sibling lead {outcome}: lead_id={}", i64::from(response.lead_id)))
		},
		ingress::Arguments::FinalizeDrilldown(payload) => {
			let request =
				FinalizeDrilldownRequest { protocol_version: ReviewProtocol, payload: *payload };
			let response =
				settle(client, drilldown, tool, client.finalize_drilldown(&job, &request).await)
					.await?;
			let receipt_id = i64::from(response.receipt.receipt_id);
			let summary = &response.receipt.summary;
			let finding = summary
				.promoted_finding_id
				.map(|id| format!("; finding_id={}", i64::from(id)))
				.unwrap_or_default();
			let text = format!(
				"drilldown finalized as {}: receipt_id={receipt_id}{finding}; the session is complete, end it now",
				summary.disposition.as_str()
			);
			drilldown.seal(response);
			Ok(text)
		},
		_ => Err(anyhow::anyhow!("tool is not available in this session")),
	}
}

fn operation(tool: DrilldownTool) -> Operation {
	match tool {
		DrilldownTool::JobLimits => Operation::McpGetJobLimits,
		DrilldownTool::Candidates => Operation::McpQuerySameProjectLeadCandidates,
		DrilldownTool::SiblingLead => Operation::McpSubmitSiblingLead,
		DrilldownTool::Finalize => Operation::McpFinalizeDrilldown,
	}
}
