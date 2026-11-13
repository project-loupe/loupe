//! Byte zero 0 decodes the rest as an original Worker verification finalize
//! request; 0x80 reads a u32 target size and wraps a schema-valid
//! verification terminal payload of about that size (see
//! `proto_review_common::terminal`); 1 builds a
//! `VerificationTerminalResponse` from the rest and compares it with an
//! independent rendering. Payload cap 128 KiB, request cap 512 KiB.

use loupe_core::review_payload::{Version1, EVIDENCE_MAX_BYTES};
use loupe_core::FindingState;
use loupe_proto::review_verification::{
	FinalizeVerificationRequest, FinalizeVerificationRequestDecoder, VerificationReceipt,
	VerificationSummary, VerificationTerminalResponse, VerificationVerdict,
};
use loupe_provenance::Agent;
use loupe_server::fuzz_support::review_request;
use serde_json::json;

use crate::proto_review_common::{
	assert_response, continuation, receipt_header, review_id, terminal,
};
use crate::utils::input::ByteSource;
use crate::utils::test_logger;

fn decode(raw: &[u8]) -> Option<FinalizeVerificationRequest<Agent>> {
	review_request(FinalizeVerificationRequestDecoder, raw).ok()
}

pub fn do_test(data: &[u8]) {
	let Some((&selector, rest)) = data.split_first() else { return };
	match selector {
		0 | 0x80 => terminal(&decode, 4, (EVIDENCE_MAX_BYTES, 512 * 1024), selector != 0, rest),
		1 => response(&mut ByteSource::new(rest)),
		_ => {},
	}
}

fn response(input: &mut ByteSource<'_>) {
	let Some(header) = receipt_header(input) else { return };
	let Some((finding_id, raw_finding)) = review_id(input) else { return };
	let Some((verification_id, raw_verification)) = review_id(input) else { return };
	let Some(choice) = input.u8() else { return };
	let (verdict, verdict_name) = match choice % 3 {
		0 => (VerificationVerdict::Verified, "verified"),
		1 => (VerificationVerdict::Rejected, "rejected"),
		_ => (VerificationVerdict::Inconclusive, "inconclusive"),
	};
	assert_eq!(verdict.as_str(), verdict_name);
	let (state, state_name) = match (choice >> 2) % 6 {
		0 => (FindingState::Pending, "pending"),
		1 => (FindingState::Validating, "validating"),
		2 => (FindingState::AwaitingApproval, "awaiting_approval"),
		3 => (FindingState::Confirmed, "confirmed"),
		4 => (FindingState::Dismissed, "dismissed"),
		_ => (FindingState::Reported, "reported"),
	};
	let continued = if choice & 0x80 != 0 { continuation(input) } else { None };
	let mut summary = json!({"version": 1, "finding_id": raw_finding,
		"verification_id": raw_verification, "verdict": verdict_name, "finding_state": state_name});
	if let Some((_, rendered)) = &continued {
		summary["continuation"] = rendered.clone();
	}
	let value = VerificationTerminalResponse {
		protocol_version: loupe_proto::review_api::ReviewProtocol,
		receipt: VerificationReceipt {
			receipt_id: header.receipt_id,
			job_id: header.job_id,
			commit_sha: header.commit_sha,
			result_digest: header.result_digest,
			summary: VerificationSummary {
				version: Version1,
				finding_id,
				verification_id,
				verdict,
				finding_state: state,
				continuation: continued.map(|(value, _)| value),
			},
		},
	};
	assert_response(&value, header.rendered.response(json!({"summary": summary})));
}

pub fn proto_review_verification_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proto_review_verification_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn sized_requests_and_a_response_pass() {
		for target in [0, EVIDENCE_MAX_BYTES as u32, u32::MAX] {
			do_test(&[&[0x80][..], &target.to_le_bytes()].concat());
		}
		let mut response = vec![1, 1, 0, 0, 0, 2, 0, 0, 0, 0];
		response.extend([7; 20]);
		response.extend([8; 32]);
		response.extend([3, 0, 0, 0, 4, 0, 0, 0, 0x85, 0x81]);
		response.extend([1; 12]);
		do_test(&response);
	}

	#[test]
	fn malformed_requests_are_refused() {
		for raw in [
			br#"{"protocol_version":3,"payload":{}}"#.as_slice(),
			br#"{"protocol_version":3,"payload":{"version":1,"verdict":"verified"},"x":1}"#,
		] {
			assert!(decode(raw).is_none());
			do_test(&[&[0][..], raw].concat());
		}
	}
}
