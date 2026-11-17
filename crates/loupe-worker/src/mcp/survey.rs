//! Survey tool dispatch: gate, build the phase request with host-supplied
//! epochs and revisions, call the phase client, update the attempt state and
//! answer with fixed host text. Server response bodies never reach the model.

use loupe_proto::review_api::{PublishProfileRequest, ReviewErrorCode, ReviewProtocol};
use loupe_proto::review_evidence::{
	LeadCheckpointRequest, LeadOutcome, UnitResultCheckpointRequest,
};
use loupe_proto::review_inventory::{InventoryDispositionRequest, UnitMapping};
use loupe_proto::review_lease::LeaseList;
use loupe_proto::review_terminal::FinalizeSurveyRequest;

use super::phase::{forbidden, PhaseTexts};
use super::*;
use crate::client::PhaseError;
use crate::review::gate::{Admission, SurveyTool};
use crate::review::session::SurveySession;

pub(super) fn tool(name: &ingress::ToolName) -> Option<SurveyTool> {
	use ingress::ToolName;
	Some(match name {
		ToolName::JobLimits => SurveyTool::JobLimits,
		ToolName::PublishProfile => SurveyTool::PublishProfile,
		ToolName::ProposeUnit => SurveyTool::ProposeUnit,
		ToolName::Lead => SurveyTool::Lead,
		ToolName::UnitResult => SurveyTool::UnitResult,
		ToolName::Disposition => SurveyTool::Disposition,
		ToolName::Candidates => SurveyTool::Candidates,
		ToolName::Finalize => SurveyTool::Finalize,
		_ => return None,
	})
}

/// A refusal or failure shown to the model as fixed host text.
// debug-ok: fixed host text only.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(super) struct SurveyRefusal(pub(super) String);

fn refuse(text: impl Into<String>) -> anyhow::Error {
	SurveyRefusal(text.into()).into()
}

const UNKNOWN_UNIT: &str =
	"review_unit_id is not a unit assigned to or proposed by this survey; use an id from the job context or a propose_review_unit result";

const TEXTS: PhaseTexts = PhaseTexts {
	authority_lost: "this survey attempt no longer has authority to write (superseded, campaign inactive or hard deadline passed); stop working and end the session",
	reference_refused: "the server refused a referenced unit, lead or path for this job; check the ids you used — units must be ones this job proposed or was assigned",
	exhausted: "capacity for this kind of checkpoint is exhausted; record what remains elsewhere and call finalize_survey",
	state_refused: "the server rejected the request in the survey's current state",
	terminal_conflict: "the survey is already finalized with a different payload; it cannot be finalized again",
	not_found: "the referenced object does not exist for this survey",
};

async fn phase_error(
	client: &ServerClient, survey: &SurveySession, tool: SurveyTool, error: PhaseError,
) -> String {
	if !forbidden(&error)
		&& let PhaseError::Rejected {
			code: ReviewErrorCode::CheckpointLimit | ReviewErrorCode::InventoryLimit,
			..
		} = error
	{
		survey.record_exhausted(tool);
	}
	let limits_call = tool == SurveyTool::JobLimits;
	let record_limits = |limits: &_| survey.record_limits(limits);
	phase::phase_error(client, survey.phase(), &TEXTS, limits_call, record_limits, error).await
}

/// A phase call's result, with a failure turned into fixed model text.
async fn settle<T>(
	client: &ServerClient, survey: &SurveySession, tool: SurveyTool, result: Result<T, PhaseError>,
) -> Result<T> {
	match result {
		Ok(value) => Ok(value),
		Err(error) => Err(refuse(phase_error(client, survey, tool, error).await)),
	}
}

pub(super) async fn dispatch(
	session: &Session, survey: &SurveySession, tool: SurveyTool,
	arguments: Result<ingress::Arguments>,
) -> Result<String> {
	if let Admission::Deny(reason) = survey.admission(tool) {
		return Err(refuse(reason.text()));
	}
	let arguments = arguments?;
	session.security.admit(operation(tool))?;
	let client = &session.client;
	let job = survey.phase_job();
	match arguments {
		ingress::Arguments::JobLimits => {
			let limits = settle(client, survey, tool, client.limits(&job).await).await?;
			survey.record_limits(&limits);
			Ok(serde_json::to_string(&limits).context("encoding limits")?)
		},
		ingress::Arguments::PublishProfile(profile) => {
			let request = PublishProfileRequest { protocol_version: ReviewProtocol, profile };
			let published =
				settle(client, survey, tool, client.publish_profile(&job, &request).await).await?;
			survey.record_profile_published();
			Ok(format!("profile published as version {}", published.profile_version))
		},
		ingress::Arguments::ProposeUnit(request) => {
			let response =
				settle(client, survey, tool, client.review_unit(&job, &request).await).await?;
			let id = i64::from(response.review_unit_id);
			survey.record_unit(id, response.assignment_epoch);
			Ok(format!("review unit accepted: review_unit_id={id}"))
		},
		ingress::Arguments::Lead(args) => {
			let args = *args;
			let mut evidence = args.evidence;
			if let Some(unit) = args.review_unit_id.map(i64::from) {
				let epoch = survey.epoch(unit).ok_or_else(|| refuse(UNKNOWN_UNIT))?;
				evidence.review_unit_id = Some(unit);
				evidence.assignment_epoch = Some(sqlite_epoch(epoch)?);
			}
			let request = LeadCheckpointRequest {
				protocol_version: ReviewProtocol,
				client_lead_key: args.key,
				evidence,
			};
			let response = settle(client, survey, tool, client.lead(&job, &request).await).await?;
			if response.outcome == LeadOutcome::Created {
				survey.record_lead_created(i64::from(response.lead_id));
			}
			let outcome = match response.outcome {
				LeadOutcome::Created => "created",
				LeadOutcome::Attached => "attached to an existing lead",
				LeadOutcome::ClosedExists => "matches a closed lead",
			};
			Ok(format!("lead {outcome}: lead_id={}", i64::from(response.lead_id)))
		},
		ingress::Arguments::UnitResult(args) => {
			let args = *args;
			let mut result = args.result;
			let epoch = survey.epoch(result.review_unit_id).ok_or_else(|| refuse(UNKNOWN_UNIT))?;
			result.assignment_epoch = sqlite_epoch(epoch)?;
			let request = UnitResultCheckpointRequest {
				protocol_version: ReviewProtocol,
				client_result_key: args.key,
				result,
			};
			let response =
				settle(client, survey, tool, client.unit_result(&job, &request).await).await?;
			Ok(format!(
				"review unit result recorded: result_id={} review_unit_id={}",
				i64::from(response.result_id),
				i64::from(response.review_unit_id)
			))
		},
		ingress::Arguments::Disposition(args) => {
			let args = *args;
			let mut mappings = Vec::with_capacity(args.mapped_review_unit_ids.len());
			for review_unit_id in args.mapped_review_unit_ids {
				let assignment_epoch =
					survey.epoch(i64::from(review_unit_id)).ok_or_else(|| refuse(UNKNOWN_UNIT))?;
				mappings.push(UnitMapping { review_unit_id, assignment_epoch });
			}
			let path = args.path.expose().to_owned();
			let expected_revision = sqlite_epoch(survey.revision(&path))?;
			let request = InventoryDispositionRequest {
				protocol_version: ReviewProtocol,
				client_inventory_disposition_key: args.key,
				source_path: args.path,
				expected_revision,
				disposition: args.disposition,
				reason: args.reason,
				mappings: LeaseList::new(mappings).map_err(anyhow::Error::msg)?,
			};
			request.validate().map_err(anyhow::Error::msg)?;
			match client.inventory_disposition(&job, &request).await {
				Ok(response) => {
					survey.record_revision(&path, response.revision);
					Ok(format!("inventory disposition recorded at revision {}", response.revision))
				},
				Err(error) => {
					if let PhaseError::Rejected {
						code: ReviewErrorCode::InventoryRevisionConflict,
						current_revision: Some(revision),
						..
					} = error
						&& let Ok(revision) = u64::try_from(revision)
					{
						survey.record_revision(&path, revision);
					}
					Err(refuse(phase_error(client, survey, tool, error).await))
				},
			}
		},
		ingress::Arguments::Candidates(query) => {
			let response =
				settle(client, survey, tool, client.lead_candidates(&job, &query).await).await?;
			let rendered = (|| {
				let mut builder =
					crate::llm::prompt::PromptBuilder::new("").mode(session.data_mode);
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
		},
		ingress::Arguments::Finalize(payload) => {
			let request =
				FinalizeSurveyRequest { protocol_version: ReviewProtocol, payload: *payload };
			let response =
				settle(client, survey, tool, client.finalize_survey(&job, &request).await).await?;
			let receipt_id = i64::from(response.receipt.receipt_id);
			survey.seal(response);
			Ok(format!(
				"survey finalized: receipt_id={receipt_id}; the session is complete, end it now"
			))
		},
		_ => Err(anyhow::anyhow!("tool is not available in this session")),
	}
}

fn sqlite_epoch(value: u64) -> Result<i64> {
	i64::try_from(value).map_err(|_| anyhow::anyhow!("host value exceeds the protocol range"))
}

fn operation(tool: SurveyTool) -> Operation {
	match tool {
		SurveyTool::JobLimits => Operation::McpGetJobLimits,
		SurveyTool::PublishProfile => Operation::McpPublishProfile,
		SurveyTool::ProposeUnit => Operation::McpProposeReviewUnit,
		SurveyTool::Lead => Operation::McpSubmitLead,
		SurveyTool::UnitResult => Operation::McpSubmitReviewUnitResult,
		SurveyTool::Disposition => Operation::McpSubmitInventoryDisposition,
		SurveyTool::Candidates => Operation::McpQuerySameProjectLeadCandidates,
		SurveyTool::Finalize => Operation::McpFinalizeSurvey,
	}
}
