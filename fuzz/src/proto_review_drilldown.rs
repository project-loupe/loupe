//! Byte zero 0 decodes the rest as an original Worker drilldown finalize
//! request; 0x80 reads a u32 target size and wraps a schema-valid drilldown
//! terminal payload of about that size (see `proto_review_common::terminal`);
//! 1 builds a `DrilldownTerminalResponse` from the rest and compares it with
//! an independent rendering. Payload cap 128 KiB, request cap 512 KiB.

use loupe_core::review_payload::{Version1, EVIDENCE_MAX_BYTES};
use loupe_proto::review_drilldown::{
	DrilldownDisposition, DrilldownReceipt, DrilldownSummary, DrilldownTerminalResponse,
	FinalizeDrilldownRequest, FinalizeDrilldownRequestDecoder,
};
use loupe_provenance::Agent;
use loupe_server::fuzz_support::review_request;
use serde_json::json;

use crate::proto_review_common::{
	assert_response, continuation, receipt_metadata, review_id, terminal,
};
use crate::utils::input::ByteSource;
use crate::utils::test_logger;

fn decode(raw: &[u8]) -> Option<FinalizeDrilldownRequest<Agent>> {
	review_request(FinalizeDrilldownRequestDecoder, raw).ok()
}

pub fn do_test(data: &[u8]) {
	let Some((&selector, rest)) = data.split_first() else { return };
	match selector {
		0 | 0x80 => terminal(&decode, 3, (EVIDENCE_MAX_BYTES, 512 * 1024), selector != 0, rest),
		1 => response(&mut ByteSource::new(rest)),
		_ => {},
	}
}

fn response(input: &mut ByteSource<'_>) {
	let Some((receipt_id, raw_receipt)) = review_id(input) else { return };
	let Some((job_id, raw_job)) = review_id(input) else { return };
	let Some((commit, digest, raw_commit, raw_digest)) = receipt_metadata(input) else { return };
	let Some((lead_id, raw_lead)) = review_id(input) else { return };
	let Some(choice) = input.u8() else { return };
	let disposition = match choice % 5 {
		0 => DrilldownDisposition::Promoted,
		1 => DrilldownDisposition::Rejected,
		2 => DrilldownDisposition::Duplicate,
		3 => DrilldownDisposition::Hardening,
		_ => DrilldownDisposition::Deferred,
	};
	let name =
		["promoted", "rejected", "duplicate", "hardening", "deferred"][usize::from(choice % 5)];
	assert_eq!(disposition.as_str(), name);
	let promoted = if choice & 0x20 != 0 { review_id(input) } else { None };
	let continued = if choice & 0x40 != 0 { continuation(input) } else { None };
	let mut summary = json!({"version": 1, "lead_id": raw_lead, "disposition": name});
	if let Some((_, raw)) = promoted {
		summary["promoted_finding_id"] = json!(raw);
	}
	if let Some((_, rendered)) = &continued {
		summary["continuation"] = rendered.clone();
	}
	let value = DrilldownTerminalResponse {
		protocol_version: loupe_proto::review_api::ReviewProtocol,
		receipt: DrilldownReceipt {
			receipt_id,
			job_id,
			commit_sha: commit,
			result_digest: digest,
			summary: DrilldownSummary {
				version: Version1,
				lead_id,
				disposition,
				promoted_finding_id: promoted.map(|(id, _)| id),
				continuation: continued.map(|(value, _)| value),
			},
		},
	};
	assert_response(
		&value,
		json!({"protocol_version": loupe_proto::PROTOCOL_VERSION, "receipt": {
			"receipt_id": raw_receipt, "job_id": raw_job, "commit_sha": raw_commit,
			"result_digest": raw_digest, "summary": summary}}),
	);
}

pub fn proto_review_drilldown_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proto_review_drilldown_run(data: *const u8, datalen: usize) {
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
		response.extend([3, 0, 0, 0, 0x61, 4, 0, 0, 0, 0x81]);
		response.extend([1; 12]);
		do_test(&response);
	}

	#[test]
	fn malformed_requests_are_refused() {
		for raw in [
			br#"{"protocol_version":3,"payload":{}}"#.as_slice(),
			br#"{"protocol_version":3,"payload":{"version":1,"disposition":"reject"},"x":1}"#,
		] {
			assert!(decode(raw).is_none());
			do_test(&[&[0][..], raw].concat());
		}
	}
}
