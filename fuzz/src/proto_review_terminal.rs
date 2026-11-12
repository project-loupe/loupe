//! Byte zero 0 decodes the rest as an original Worker survey finalize
//! request; 0x80 reads a u32 target size and wraps a schema-valid survey
//! terminal payload of about that size (see `proto_review_common::terminal`);
//! 1 builds a `SurveyTerminalResponse` from the rest and compares it with an
//! independent rendering. Payload cap 32 KiB, request cap 128 KiB.

use loupe_core::review_payload::{SurveyTerminalReason, Version1, SURVEY_TERMINAL_MAX_BYTES};
use loupe_proto::review_terminal::{
	FinalizeSurveyRequest, FinalizeSurveyRequestDecoder, SurveyCoverage, SurveyReceipt,
	SurveySummary, SurveyTerminalResponse,
};
use loupe_provenance::Agent;
use loupe_server::fuzz_support::review_request;
use serde_json::json;

use crate::proto_review_common::{assert_response, receipt_metadata, review_id, terminal};
use crate::utils::input::ByteSource;
use crate::utils::test_logger;

fn decode(raw: &[u8]) -> Option<FinalizeSurveyRequest<Agent>> {
	review_request(FinalizeSurveyRequestDecoder, raw).ok()
}

pub fn do_test(data: &[u8]) {
	let Some((&selector, rest)) = data.split_first() else { return };
	match selector {
		0 | 0x80 => {
			terminal(&decode, 2, (SURVEY_TERMINAL_MAX_BYTES, 128 * 1024), selector != 0, rest)
		},
		1 => response(&mut ByteSource::new(rest)),
		_ => {},
	}
}

fn response(input: &mut ByteSource<'_>) {
	let Some((receipt_id, raw_receipt)) = review_id(input) else { return };
	let Some((job_id, raw_job)) = review_id(input) else { return };
	let Some((commit, digest, raw_commit, raw_digest)) = receipt_metadata(input) else { return };
	let Some(choice) = input.u8() else { return };
	let mut counts = [0_u64; 5];
	for count in &mut counts {
		let Some(value) = input.u32() else { return };
		*count = u64::from(value);
	}
	let (reason, reason_name) = match choice % 3 {
		0 => (SurveyTerminalReason::Completed, "completed"),
		1 => (SurveyTerminalReason::Partial, "partial"),
		_ => (SurveyTerminalReason::Deferred, "deferred"),
	};
	let (coverage, coverage_name) = if choice & 0x10 == 0 {
		(SurveyCoverage::Complete, "complete")
	} else {
		(SurveyCoverage::Partial, "partial")
	};
	let corroborated = choice & 0x20 != 0;
	let value = SurveyTerminalResponse {
		protocol_version: loupe_proto::review_api::ReviewProtocol,
		receipt: SurveyReceipt {
			receipt_id,
			job_id,
			commit_sha: commit,
			result_digest: digest,
			terminal_reason: reason,
			summary: SurveySummary {
				version: Version1,
				coverage,
				corroboration_satisfied: corroborated,
				missing_results: counts[0],
				needs_follow_up: counts[1],
				unresolved_inventory: counts[2],
				follow_up_batches: counts[3],
				follow_up_units: counts[4],
			},
		},
	};
	assert_response(
		&value,
		json!({"protocol_version": loupe_proto::PROTOCOL_VERSION, "receipt": {
			"receipt_id": raw_receipt, "job_id": raw_job, "commit_sha": raw_commit,
			"result_digest": raw_digest, "terminal_reason": reason_name,
			"summary": {"version": 1, "coverage": coverage_name,
				"corroboration_satisfied": corroborated, "missing_results": counts[0],
				"needs_follow_up": counts[1], "unresolved_inventory": counts[2],
				"follow_up_batches": counts[3], "follow_up_units": counts[4]}}}),
	);
}

pub fn proto_review_terminal_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proto_review_terminal_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn sized_requests_and_a_response_pass() {
		for target in [0, SURVEY_TERMINAL_MAX_BYTES as u32, u32::MAX] {
			do_test(&[&[0x80][..], &target.to_le_bytes()].concat());
		}
		let mut response = vec![1, 1, 0, 0, 0, 2, 0, 0, 0, 0];
		response.extend([7; 20]);
		response.extend([8; 32]);
		response.push(0x31);
		response.extend([1; 20]);
		do_test(&response);
	}

	#[test]
	fn malformed_requests_are_refused() {
		for raw in [
			br#"{"protocol_version":3,"payload":{}}"#.as_slice(),
			br#"{"protocol_version":3,"payload":{"version":1,"terminal_reason":"completed","continuation":"x","security_model_notes":"y","extra":1}}"#,
		] {
			assert!(decode(raw).is_none());
			do_test(&[&[0][..], raw].concat());
		}
	}
}
