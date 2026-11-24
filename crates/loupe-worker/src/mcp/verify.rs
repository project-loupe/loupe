//! Verify tool dispatch: build the phase request, call the phase client,
//! keep the sealed receipt and answer with fixed host text. Server response
//! bodies never reach the model.
//!
//! Neither tool opens inquiry and both stay open after a sealed receipt, as
//! the server decides a finalize replay, so a verify call has no admission
//! gate.

use loupe_proto::review_api::{ReviewErrorCode, ReviewProtocol};
use loupe_proto::review_verification::FinalizeVerificationRequest;

use super::phase::{settle, PhaseTexts};
use super::*;
use crate::client::PhaseError;
use crate::review::session::{PhaseSession, VerifySession};

/// The verify catalog's tools.
// debug-ok: closed tool names only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VerifyTool {
	JobLimits,
	Finalize,
}

pub(super) fn tool(name: &ingress::ToolName) -> Option<VerifyTool> {
	use ingress::ToolName;
	Some(match name {
		ToolName::JobLimits => VerifyTool::JobLimits,
		ToolName::FinalizeVerification => VerifyTool::Finalize,
		_ => return None,
	})
}

const STATE_REFUSED: &str = "the server rejected the request in the finding's current state";

const TEXTS: PhaseTexts = PhaseTexts {
	authority_lost: "this verification attempt no longer has authority to write (superseded, campaign inactive or hard deadline passed); stop working and end the session",
	exhausted: STATE_REFUSED,
	state_refused: STATE_REFUSED,
	terminal_conflict: "the verification is already finalized with a different payload; it cannot be finalized again; end the session",
	not_found: "the referenced object does not exist for this verification",
};

pub(super) const REVALIDATION_REQUIRED: &str =
	"finalizing was refused as revalidation required: re-inspect the finding on this checkout, then call finalize_verification again with `revalidation` (current_source_refs and rationale)";
pub(super) const INCOMPATIBLE_STATE: &str =
	"the finding can no longer be verified by this job; stop working and end the session";
pub(super) const INVALID: &str =
	"the server refused a field or source path: every path must exist in the pinned checkout exactly as written; check the arguments against the tool schema and call again";
pub(super) const FINALIZE_UNREACHABLE: &str =
	"the server could not be reached after retries; retry the identical finalize_verification call";

impl phase::PhaseCalls for VerifySession {
	type Tool = VerifyTool;

	const TEXTS: PhaseTexts = TEXTS;

	fn phase(&self) -> &PhaseSession {
		VerifySession::phase(self)
	}

	fn reference_refused(_tool: VerifyTool) -> Option<&'static str> {
		None
	}

	fn unreachable(tool: VerifyTool) -> &'static str {
		match tool {
			VerifyTool::JobLimits => phase::READ_UNREACHABLE,
			VerifyTool::Finalize => FINALIZE_UNREACHABLE,
		}
	}

	fn own_text(_tool: VerifyTool, error: &PhaseError) -> Option<&'static str> {
		let PhaseError::Rejected { code, .. } = error else { return None };
		Some(match code {
			ReviewErrorCode::RevalidationRequired => REVALIDATION_REQUIRED,
			ReviewErrorCode::IncompatibleReviewState => INCOMPATIBLE_STATE,
			ReviewErrorCode::InvalidRequest => INVALID,
			_ => return None,
		})
	}
}

pub(super) async fn dispatch(
	session: &Session, verify: &VerifySession, tool: VerifyTool,
	arguments: Result<ingress::Arguments>,
) -> Result<String> {
	let arguments = arguments?;
	session.security.admit(operation(tool))?;
	let client = &session.client;
	let job = verify.phase().phase_job();
	match arguments {
		ingress::Arguments::JobLimits => {
			let limits = settle(client, verify, tool, client.limits(&job).await).await?;
			verify.phase().record_limits(&limits);
			Ok(serde_json::to_string(&limits).context("encoding limits")?)
		},
		ingress::Arguments::FinalizeVerification(payload) => {
			let request =
				FinalizeVerificationRequest { protocol_version: ReviewProtocol, payload: *payload };
			let response =
				settle(client, verify, tool, client.finalize_verification(&job, &request).await)
					.await?;
			let summary = &response.receipt.summary;
			let text = format!(
				"verification finalized as {}: receipt_id={}; finding is {}; the session is complete, end it now",
				summary.verdict.as_str(),
				i64::from(response.receipt.receipt_id),
				summary.finding_state.as_str(),
			);
			verify.seal(response);
			Ok(text)
		},
		_ => Err(anyhow::anyhow!("tool is not available in this session")),
	}
}

fn operation(tool: VerifyTool) -> Operation {
	match tool {
		VerifyTool::JobLimits => Operation::McpGetJobLimits,
		VerifyTool::Finalize => Operation::McpFinalizeVerification,
	}
}
