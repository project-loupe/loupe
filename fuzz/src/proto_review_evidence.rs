//! Byte zero: bit 0 selects the lead checkpoint (0) or the unit result
//! checkpoint (1) request, bit 7 the mode, and 2 selects a response.
//!
//! Free mode decodes the rest as original Worker bytes with the route
//! decoder. Sized mode reads a little-endian u32 target length and wraps a
//! schema-valid payload of about that canonical size (the generator of
//! `core_review_payload`) in a request; it must be accepted iff the payload
//! fits its 64 KiB cap. Every accepted request runs the shared
//! `proto_review_common` oracles, which reach into the carried payload.
//! Response mode builds a lead (bit 0 of the next byte clear) or unit result
//! checkpoint response and compares it with an independent rendering.

use loupe_core::review_payload::UnitResultDisposition;
use loupe_proto::review_evidence::{
	AcceptedPriority, LeadCheckpointRequest, LeadCheckpointRequestDecoder, LeadCheckpointResponse,
	LeadOutcome, PriorityBand, UnitResultCheckpointRequest, UnitResultCheckpointRequestDecoder,
	UnitResultCheckpointResponse,
};
use loupe_server::fuzz_support::review_request;
use serde::Serialize;
use serde_json::{json, Value};

use crate::proto_review_common::{assert_response, closed, render, review_id, Request};
use crate::utils::input::ByteSource;
use crate::utils::test_logger;

const PROTOCOL: u64 = loupe_proto::PROTOCOL_VERSION as u64;
const PAYLOAD_CAP: usize = 64 * 1024;
const VERSIONS: &[(&str, u64)] = &[("protocol_version", PROTOCOL), ("version", 1)];

fn lead(raw: &[u8]) -> Option<LeadCheckpointRequest> {
	review_request(LeadCheckpointRequestDecoder, raw).ok()
}
fn result(raw: &[u8]) -> Option<UnitResultCheckpointRequest> {
	review_request(UnitResultCheckpointRequestDecoder, raw).ok()
}

/// The request envelope around a sized payload; kinds follow `core_review_payload`.
fn envelope(unit_result: bool, target: u32) -> (Vec<u8>, usize) {
	let kind = if unit_result { 6 } else { 5 };
	let payload = crate::core_review_payload::sized_value(kind, target)
		.unwrap_or_else(|| panic!("payload kind"));
	let size = render(&payload).len();
	let request = if unit_result {
		json!({"protocol_version": PROTOCOL, "client_result_key": "result-1", "result": payload})
	} else {
		json!({"protocol_version": PROTOCOL, "client_lead_key": "lead-1", "evidence": payload})
	};
	(render(&request), size)
}

fn check<T: Serialize + PartialEq + std::fmt::Debug>(
	decode: &dyn Fn(&[u8]) -> Option<T>, seed: &[u8], raw: &[u8],
) -> bool {
	let baseline = format!("{:?}", decode(seed).unwrap_or_else(|| panic!("evidence seed")));
	let oracle = Request {
		decode,
		versions: VERSIONS,
		baseline: &baseline,
		exact_debug: true,
		open: &closed,
	};
	let accepted = oracle.check(raw).is_some();
	assert!(!accepted || raw.len() <= 256 * 1024, "evidence request above its byte cap");
	accepted
}

pub fn do_test(data: &[u8]) {
	let Some((&selector, rest)) = data.split_first() else { return };
	if selector == 2 {
		return response(&mut ByteSource::new(rest));
	}
	if selector & 0x7e != 0 {
		return;
	}
	let unit_result = selector & 1 == 1;
	let (lead_seed, _) = envelope(false, 0);
	let (result_seed, _) = envelope(true, 0);
	let run = |raw: &[u8]| {
		if unit_result {
			check(&result, &result_seed, raw)
		} else {
			check(&lead, &lead_seed, raw)
		}
	};
	if selector & 0x80 == 0 {
		run(rest);
		return;
	}
	let Some(target) = ByteSource::new(rest).u32() else { return };
	let (raw, size) = envelope(unit_result, target);
	assert_eq!(run(&raw), size <= PAYLOAD_CAP, "sized payload of {size} bytes");
}

fn response(input: &mut ByteSource<'_>) {
	let Some(kind) = input.u8() else { return };
	let Some((first, raw_first)) = review_id(input) else { return };
	let Some(choice) = input.u8() else { return };
	if kind & 1 == 0 {
		let Some(score) = input.u32() else { return };
		let observation = review_id(input);
		let (outcome, outcome_name) = match choice % 3 {
			0 => (LeadOutcome::Created, "created"),
			1 => (LeadOutcome::Attached, "attached"),
			_ => (LeadOutcome::ClosedExists, "closed_exists"),
		};
		let (band, band_name) = match (choice / 3) % 4 {
			0 => (PriorityBand::Urgent, "urgent"),
			1 => (PriorityBand::High, "high"),
			2 => (PriorityBand::Normal, "normal"),
			_ => (PriorityBand::Background, "background"),
		};
		let value = LeadCheckpointResponse {
			protocol_version: loupe_proto::review_api::ReviewProtocol,
			lead_id: first,
			outcome,
			observation_id: observation.map(|(id, _)| id),
			accepted_priority: AcceptedPriority { band, score },
		};
		assert_response(
			&value,
			json!({"protocol_version": PROTOCOL, "lead_id": raw_first, "outcome": outcome_name,
				"observation_id": observation.map(|(_, raw)| raw),
				"accepted_priority": {"band": band_name, "score": score}}),
		);
		return;
	}
	let Some((unit, raw_unit)) = review_id(input) else { return };
	let Some(epoch) = input.take(8) else { return };
	let epoch = u64::from_le_bytes(epoch.try_into().unwrap_or_else(|_| panic!("8 bytes")));
	let (disposition, name) = match choice % 4 {
		0 => (UnitResultDisposition::LeadCreated, "lead_created"),
		1 => (UnitResultDisposition::NoLeadFound, "no_lead_found"),
		2 => (UnitResultDisposition::NotApplicable, "not_applicable"),
		_ => (UnitResultDisposition::NeedsFollowUp, "needs_follow_up"),
	};
	let value = UnitResultCheckpointResponse {
		protocol_version: loupe_proto::review_api::ReviewProtocol,
		result_id: first,
		review_unit_id: unit,
		assignment_epoch: epoch,
		disposition,
	};
	assert_response(
		&value,
		json!({"protocol_version": PROTOCOL, "result_id": raw_first, "review_unit_id": raw_unit,
			"assignment_epoch": epoch, "disposition": Value::from(name)}),
	);
}

pub fn proto_review_evidence_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proto_review_evidence_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn sized_envelopes_cover_minimal_cap_and_maximal_payloads() {
		for selector in [0x80_u8, 0x81] {
			for target in [0, PAYLOAD_CAP as u32, PAYLOAD_CAP as u32 + 1, u32::MAX] {
				let mut data = vec![selector];
				data.extend(target.to_le_bytes());
				do_test(&data);
			}
		}
	}

	#[test]
	fn free_seeds_and_responses_pass() {
		let (lead_seed, _) = envelope(false, 0);
		let (result_seed, _) = envelope(true, 0);
		do_test(&[&[0][..], &lead_seed].concat());
		do_test(&[&[1][..], &result_seed].concat());
		do_test(&[2, 0, 1, 0, 0, 0, 5, 9, 0, 0, 0, 2, 0, 0, 0]);
		do_test(&[2, 1, 1, 0, 0, 0, 3, 2, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
	}

	#[test]
	fn malformed_requests_are_refused() {
		let (seed, _) = envelope(false, 0);
		let seed = String::from_utf8(seed).unwrap_or_else(|_| panic!("UTF-8 seed"));
		for raw in [
			seed.replace("\"lead-1\"", "\"-lead\""),
			seed.replace("\"protocol_version\":3", "\"protocol_version\":4"),
			seed.replacen('{', "{\"extra\":1,", 1),
		] {
			assert!(lead(raw.as_bytes()).is_none());
		}
	}
}
