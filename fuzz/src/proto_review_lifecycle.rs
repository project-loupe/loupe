//! Byte zero selects the phase failure request (0) or the phase heartbeat
//! request (1), each decoded by its route decoder from the rest as original
//! Worker bytes, or a `PhaseControlResponse` (2) built from the rest.
//! Requests run the shared `proto_review_common` oracles; the failure reason
//! is also checked against its `Reason` policy bound. The response is
//! compared with an independent `serde_json::Value` rendering.

use loupe_core::text::policy::Reason;
use loupe_core::text::TextPolicy;
use loupe_proto::review_lifecycle::{
	PhaseControlResponse, PhaseControlState, PhaseFailureRequest, PhaseFailureRequestDecoder,
	PhaseHeartbeatRequest, PhaseHeartbeatRequestDecoder,
};
use loupe_server::fuzz_support::review_request;
use serde_json::json;

use crate::proto_review_common::{assert_response, closed, review_id, Request};
use crate::utils::input::ByteSource;
use crate::utils::test_logger;

const PROTOCOL: u64 = loupe_proto::PROTOCOL_VERSION as u64;
const FAILURE_SEED: &[u8] = br#"{"protocol_version":3,"outcome":"failed","error":"seed reason"}"#;
const HEARTBEAT_SEED: &[u8] = br#"{"protocol_version":3}"#;

fn failure(raw: &[u8]) -> Option<PhaseFailureRequest> {
	review_request(PhaseFailureRequestDecoder, raw).ok()
}
fn heartbeat(raw: &[u8]) -> Option<PhaseHeartbeatRequest> {
	review_request(PhaseHeartbeatRequestDecoder, raw).ok()
}

pub fn do_test(data: &[u8]) {
	let Some((&selector, rest)) = data.split_first() else { return };
	match selector {
		0 => {
			let baseline =
				format!("{:?}", failure(FAILURE_SEED).unwrap_or_else(|| panic!("failure seed")));
			let request = Request {
				decode: &failure,
				versions: &[("protocol_version", PROTOCOL)],
				baseline: &baseline,
				exact_debug: true,
				open: &closed,
			};
			if let Some(value) = request.check(rest) {
				assert!(rest.len() <= 8192, "phase control request above its byte cap");
				if let Some(error) = &value.error {
					assert!(error.expose().len() <= Reason::MAX_BYTES);
				}
			}
		},
		1 => {
			let baseline = format!(
				"{:?}",
				heartbeat(HEARTBEAT_SEED).unwrap_or_else(|| panic!("heartbeat seed"))
			);
			let request = Request {
				decode: &heartbeat,
				versions: &[("protocol_version", PROTOCOL)],
				baseline: &baseline,
				exact_debug: true,
				open: &closed,
			};
			if request.check(rest).is_some() {
				assert!(rest.len() <= 8192, "phase control request above its byte cap");
			}
		},
		2 => response(&mut ByteSource::new(rest)),
		_ => {},
	}
}

fn response(input: &mut ByteSource<'_>) {
	let Some((job_id, job)) = review_id(input) else { return };
	let Some(choice) = input.u8() else { return };
	let (state, name) = match choice % 3 {
		0 => (PhaseControlState::Queued, "queued"),
		1 => (PhaseControlState::Failed, "failed"),
		_ => (PhaseControlState::Cancelled, "cancelled"),
	};
	let eligible_at = input
		.take(8)
		.map(|raw| i64::from_le_bytes(raw.try_into().unwrap_or_else(|_| panic!("8 bytes"))));
	let value = PhaseControlResponse {
		protocol_version: loupe_proto::review_api::ReviewProtocol,
		job_id,
		state,
		eligible_at,
	};
	assert_response(
		&value,
		json!({"protocol_version": PROTOCOL, "job_id": job, "state": name, "eligible_at": eligible_at}),
	);
}

pub fn proto_review_lifecycle_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proto_review_lifecycle_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	fn with(selector: u8, raw: &[u8]) -> Vec<u8> {
		let mut data = vec![selector];
		data.extend_from_slice(raw);
		data
	}

	#[test]
	fn seeds_are_accepted_and_checked() {
		assert!(failure(FAILURE_SEED).is_some());
		assert!(heartbeat(HEARTBEAT_SEED).is_some());
		do_test(&with(0, FAILURE_SEED));
		do_test(&with(0, br#"{"protocol_version":3,"outcome":"failed","error":null}"#));
		do_test(&with(1, HEARTBEAT_SEED));
		do_test(&with(2, &[1, 0, 0, 0, 2, 9, 9, 9, 9, 9, 9, 9, 9]));
		do_test(&with(2, &[1, 0, 0, 0, 0]));
	}

	#[test]
	fn malformed_requests_are_refused() {
		for raw in [
			br#"{"protocol_version":3,"outcome":"failed","extra":1}"#.as_slice(),
			br#"{"protocol_version":2,"outcome":"failed"}"#,
			br#"{"protocol_version":3,"outcome":"succeeded"}"#,
		] {
			assert!(failure(raw).is_none());
		}
		assert!(heartbeat(br#"{"protocol_version":3,"x":1}"#).is_none());
	}
}
