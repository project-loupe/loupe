//! Verification terminal responses decoded by the worker from original Server
//! bytes (`loupe_worker::client::fuzz_support`).
//!
//! Byte zero 0 decodes the rest freely; 1 builds a receipt from the rest
//! with every verdict and continuation shape that must be admitted.
//! Every input runs the shared `proto_review_response_oracle` checks, and
//! an admitted receipt must re-serialize to exactly the received JSON. No
//! admitted body exceeds 16 KiB.

use loupe_proto::review_verification::VerificationTerminalResponseDecoder;
use loupe_worker::client::fuzz_support::review_response;
use serde_json::{json, Value};

use crate::proto_review_common::{continuation, hex, review_id};
use crate::proto_review_response_oracle::{accept, check};
use crate::utils::input::ByteSource;
use crate::utils::test_logger;

const PROTOCOL: u64 = loupe_proto::PROTOCOL_VERSION as u64;
const RESPONSE_CAP: usize = 16 * 1024;

fn decode(raw: &[u8]) -> Option<Value> {
	let admitted =
		check(&|raw| review_response(VerificationTerminalResponseDecoder, raw), raw, true);
	assert!(admitted.is_none() || raw.len() <= RESPONSE_CAP, "oversized response admitted");
	admitted
}

fn structured(input: &mut ByteSource<'_>) -> Option<()> {
	let (_, id) = review_id(input)?;
	let (_, finding) = review_id(input)?;
	let (_, verification) = review_id(input)?;
	let choice = input.u8()?;
	let (verdict, state) = [
		("verified", "confirmed"),
		("verified", "awaiting_approval"),
		("rejected", "dismissed"),
		("inconclusive", "validating"),
	][usize::from(choice) % 4];
	let mut summary = json!({"version": 1, "finding_id": finding,
		"verification_id": verification, "verdict": verdict, "finding_state": state});
	if verdict == "inconclusive" {
		summary["continuation"] = continuation(input)?.1;
	}
	accept(
		&|raw| review_response(VerificationTerminalResponseDecoder, raw),
		json!({"protocol_version": PROTOCOL, "receipt": {"receipt_id": id, "job_id": id,
			"commit_sha": hex(input, 20)?, "result_digest": hex(input, 32)?,
			"summary": summary}}),
		true,
	);
	Some(())
}

pub fn do_test(data: &[u8]) {
	match data.split_first() {
		Some((0, rest)) => {
			decode(rest);
		},
		Some((1, rest)) => {
			structured(&mut ByteSource::new(rest));
		},
		_ => {},
	}
}

pub fn proto_review_responses_verification_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proto_review_responses_verification_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn every_structured_receipt_is_admitted() {
		for verdict in 0..4u8 {
			for fill in [0u8, 1, 0x7f, 0x80, 0xff] {
				let mut data = vec![1];
				data.extend([fill; 12]);
				data.push(verdict);
				data.extend([fill; 80]);
				do_test(&data);
			}
		}
		let valid =
			include_bytes!("../test_cases/proto_review_responses_verification/valid-inconclusive");
		assert!(decode(&valid[1..]).is_some());
		let malformed =
			include_bytes!("../test_cases/proto_review_responses_verification/malformed");
		assert!(decode(&malformed[1..]).is_none());
		let mut padded = valid[1..].to_vec();
		padded.resize(RESPONSE_CAP, b' ');
		assert!(decode(&padded).is_some());
		padded.push(b' ');
		assert!(decode(&padded).is_none());
	}
}
