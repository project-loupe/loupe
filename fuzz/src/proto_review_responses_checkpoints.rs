//! Checkpoint, terminal, context and error responses decoded by the worker
//! from original Server bytes (`loupe_worker::client::fuzz_support`).
//!
//! Byte zero below 10 selects a decoder for the rest: review unit (0), lead
//! (1), unit result (2), inventory disposition (3), survey terminal (4),
//! lead candidates (5), phase limits (6), phase control (7) or the error
//! envelope (8). 10 builds a structured response from the rest that must be
//! admitted. Every input runs the shared `proto_review_response_oracle`
//! checks; all but candidates must re-serialize to exactly the received JSON.
//! An error envelope's code is `Other` exactly when it is not a known code.

use loupe_proto::review_api::{
	CandidatesResponseDecoder, PhaseLimitsResponseDecoder, ReviewErrorCode,
	ReviewErrorResponseDecoder,
};
use loupe_proto::review_evidence::{
	LeadCheckpointResponseDecoder, UnitResultCheckpointResponseDecoder,
};
use loupe_proto::review_inventory::InventoryDispositionResponseDecoder;
use loupe_proto::review_lifecycle::PhaseControlResponseDecoder;
use loupe_proto::review_terminal::SurveyTerminalResponseDecoder;
use loupe_proto::review_units::ReviewUnitResponseDecoder;
use loupe_worker::client::fuzz_support::{review_response, review_response_carrying};
use serde_json::{json, Value};

use crate::proto_review_common::{hex, review_id};
use crate::proto_review_response_oracle::{accept, check, SENTINEL};
use crate::utils::input::ByteSource;
use crate::utils::test_logger;

const PROTOCOL: u64 = loupe_proto::PROTOCOL_VERSION as u64;

fn free(selector: u8, raw: &[u8]) -> Option<Value> {
	match selector {
		0 => check(&|raw| review_response(ReviewUnitResponseDecoder, raw), raw, true),
		1 => check(&|raw| review_response(LeadCheckpointResponseDecoder, raw), raw, true),
		2 => check(&|raw| review_response(UnitResultCheckpointResponseDecoder, raw), raw, true),
		3 => check(&|raw| review_response(InventoryDispositionResponseDecoder, raw), raw, true),
		4 => check(&|raw| review_response(SurveyTerminalResponseDecoder, raw), raw, true),
		5 => check(&|raw| review_response_carrying(CandidatesResponseDecoder, raw), raw, false),
		6 => check(&|raw| review_response(PhaseLimitsResponseDecoder, raw), raw, true),
		7 => check(&|raw| review_response(PhaseControlResponseDecoder, raw), raw, true),
		8 => error(raw),
		_ => None,
	}
}

fn error(raw: &[u8]) -> Option<Value> {
	let decoded = review_response(ReviewErrorResponseDecoder, raw).ok()?;
	let received: Value =
		serde_json::from_slice(raw).unwrap_or_else(|_| panic!("accepted error is JSON"));
	let code = received["error"]["code"].as_str().unwrap_or_else(|| panic!("string code"));
	let known = ReviewErrorCode::KNOWN.into_iter().find(|known| json!(known) == json!(code));
	assert_eq!(decoded.code, known.unwrap_or(ReviewErrorCode::Other), "error code classification");
	assert_eq!(decoded.current_revision, received["error"]["current_revision"].as_i64());
	Some(received)
}

fn pick<'a>(input: &mut ByteSource<'_>, names: &[&'a str]) -> Option<&'a str> {
	Some(names[usize::from(input.u8()?) % names.len()])
}

fn structured(input: &mut ByteSource<'_>) -> Option<()> {
	let choice = input.u8()? % 9;
	let (_, id) = review_id(input)?;
	let epoch = u64::from(input.u32()?);
	match choice {
		0 => accept(
			&|raw| review_response(ReviewUnitResponseDecoder, raw),
			json!({"protocol_version": PROTOCOL, "review_unit_id": id, "assignment_epoch": epoch,
				"accepted_priority_band": pick(input, &["urgent", "high", "normal", "background"])?}),
			true,
		),
		1 => {
			let observation = if epoch & 1 == 0 { Value::Null } else { json!(id) };
			accept(
				&|raw| review_response(LeadCheckpointResponseDecoder, raw),
				json!({"protocol_version": PROTOCOL, "lead_id": id,
					"outcome": pick(input, &["created", "attached", "closed_exists"])?,
					"observation_id": observation, "accepted_priority": {
						"band": pick(input, &["urgent", "high", "normal", "background"])?,
						"score": epoch}}),
				true,
			)
		},
		2 => accept(
			&|raw| review_response(UnitResultCheckpointResponseDecoder, raw),
			json!({"protocol_version": PROTOCOL, "result_id": id, "review_unit_id": id,
				"assignment_epoch": epoch, "disposition": pick(input,
					&["lead_created", "no_lead_found", "not_applicable", "needs_follow_up"])?}),
			true,
		),
		3 => accept(
			&|raw| review_response(InventoryDispositionResponseDecoder, raw),
			json!({"protocol_version": PROTOCOL, "inventory_entry_id": id, "revision": epoch}),
			true,
		),
		4 => accept(
			&|raw| review_response(SurveyTerminalResponseDecoder, raw),
			json!({"protocol_version": PROTOCOL, "receipt": {"receipt_id": id, "job_id": id,
				"commit_sha": hex(input, 20)?, "result_digest": hex(input, 32)?,
				"terminal_reason": pick(input, &["completed", "partial", "deferred"])?,
				"summary": {"version": 1, "coverage": pick(input, &["complete", "partial"])?,
					"corroboration_satisfied": epoch & 1 == 1, "missing_results": epoch,
					"needs_follow_up": 0, "unresolved_inventory": epoch, "follow_up_batches": 0,
					"follow_up_units": 0}}}),
			true,
		),
		5 => {
			let count = usize::from(input.u8()?) % 21;
			let commit = hex(input, 20)?;
			let candidates = (0..count)
				.map(|index| {
					json!({"kind": if index % 2 == 0 { "lead" } else { "finding" },
					"id": index + 1, "producer_job_id": id, "commit_sha": commit,
					"created_at": epoch, "identity_family": "allocation",
					"identity_anchor": format!("{SENTINEL} {index}"),
					"identity_instance_key": if index % 3 == 0 { Value::Null } else {
						json!(SENTINEL)
					}})
				})
				.collect::<Vec<_>>();
			accept(
				&|raw| review_response_carrying(CandidatesResponseDecoder, raw),
				json!({"protocol_version": PROTOCOL, "candidates": candidates}),
				false,
			)
		},
		6 => {
			let capacity = |limit: u64| json!({"limit": limit, "remaining": limit / 2});
			let tokens = if epoch & 1 == 0 {
				json!({"status": "none"})
			} else {
				json!({"status": "host_enforced", "limit": epoch, "spent": "unknown"})
			};
			accept(
				&|raw| review_response(PhaseLimitsResponseDecoder, raw),
				json!({"protocol_version": PROTOCOL, "soft_deadline_at": id, "submit_by": id,
					"hard_deadline_at": id + 1, "remaining_seconds": epoch,
					"new_units": capacity(epoch), "leads": capacity(epoch),
					"siblings": capacity(1), "candidate_queries": capacity(2),
					"campaign_jobs_limit": epoch, "campaign_jobs_admitted": 0,
					"campaign_general_remaining": epoch, "campaign_urgent_remaining": 0,
					"campaign_verification_remaining": 1, "proof_capacity": "unavailable",
					"artifact_capacity": "unavailable", "output_capacity": "unavailable",
					"tokens": tokens}),
				true,
			)
		},
		7 => accept(
			&|raw| review_response(PhaseControlResponseDecoder, raw),
			json!({"protocol_version": PROTOCOL, "job_id": id,
				"state": pick(input, &["queued", "failed", "cancelled"])?,
				"eligible_at": if epoch & 1 == 0 { Value::Null } else { json!(epoch) }}),
			true,
		),
		_ => {
			let code = String::from_utf8_lossy(input.rest()).into_owned();
			let mut body = json!({"code": code, "detail": null});
			if code == "inventory_revision_conflict" || epoch & 1 == 1 {
				body["current_revision"] = json!(epoch);
			}
			let raw = crate::proto_review_common::render(
				&json!({"protocol_version": PROTOCOL, "error": body}),
			);
			let known = ReviewErrorCode::KNOWN.into_iter().any(|known| json!(known) == json!(code));
			let permitted = !known || code == "inventory_revision_conflict" || epoch & 1 == 0;
			assert_eq!(error(&raw).is_some(), permitted, "error envelope admission");
		},
	}
	Some(())
}

pub fn do_test(data: &[u8]) {
	let Some((&selector, rest)) = data.split_first() else { return };
	if selector == 10 {
		structured(&mut ByteSource::new(rest));
	} else {
		free(selector, rest);
	}
}

pub fn proto_review_responses_checkpoints_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proto_review_responses_checkpoints_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn every_structured_response_is_admitted() {
		for choice in 0..9u8 {
			for fill in [0u8, 1, 0x7f, 0xff] {
				let mut data = vec![10, choice];
				data.extend([fill; 80]);
				do_test(&data);
			}
		}
		let mut known = vec![10, 8, 0, 0, 0, 0, 0, 0, 0, 0];
		known.extend(b"denied");
		do_test(&known);
		assert!(
			free(8, br#"{"protocol_version":3,"error":{"code":"denied","detail":null}}"#).is_some()
		);
		assert!(free(0, b"{}").is_none());
	}
}
