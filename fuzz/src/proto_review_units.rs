//! Byte zero selects the review unit proposal (0), decoded by its route
//! decoder from the rest as original Worker bytes with Agent-carried
//! content, or a `ReviewUnitResponse` (1) built from the rest.
//!
//! The request runs the shared `proto_review_common` oracles; an accepted
//! proposal also has 1..=32 source refs and at most 8 distinct dependencies,
//! re-derived here from its serialization.

use loupe_proto::review_units::{
	PriorityBand, ReviewUnitRequest, ReviewUnitRequestDecoder, ReviewUnitResponse,
};
use loupe_provenance::{Agent, Worker};
use loupe_server::fuzz_support::review_request;
use serde_json::json;

use crate::proto_review_common::{assert_response, closed, review_id, to_value, Request};
use crate::utils::input::ByteSource;
use crate::utils::test_logger;

const PROTOCOL: u64 = loupe_proto::PROTOCOL_VERSION as u64;
const SEED: &[u8] = br#"{"protocol_version":3,"client_review_unit_key":"unit-1","title":"Parser bounds","objective":"Check every parser bound","priority_band":"high","priority_rationale":"Reachable from input","source_refs":[{"path":"src/lib.rs","symbol":"parse"}],"depends_on_review_unit_ids":[2,3],"closure_criteria":"Each bound has a test","semantic_context":null}"#;

fn decode(raw: &[u8]) -> Option<ReviewUnitRequest<Agent, Worker>> {
	review_request(ReviewUnitRequestDecoder, raw).ok()
}

pub fn do_test(data: &[u8]) {
	let Some((&selector, rest)) = data.split_first() else { return };
	match selector {
		0 => request(rest),
		1 => response(&mut ByteSource::new(rest)),
		_ => {},
	}
}

fn request(raw: &[u8]) {
	let baseline = format!("{:?}", decode(SEED).unwrap_or_else(|| panic!("unit seed")));
	let oracle = Request {
		decode: &decode,
		versions: &[("protocol_version", PROTOCOL)],
		baseline: &baseline,
		exact_debug: true,
		open: &closed,
	};
	let Some(value) = oracle.check(raw) else { return };
	assert!(raw.len() <= 256 * 1024, "review unit proposal above its byte cap");
	let rendered = to_value(&value);
	let refs = rendered["source_refs"].as_array().unwrap_or_else(|| panic!("source refs"));
	assert!((1..=32).contains(&refs.len()));
	let dependencies =
		rendered["depends_on_review_unit_ids"].as_array().unwrap_or_else(|| panic!("dependencies"));
	assert!(dependencies.len() <= 8);
	let distinct: std::collections::BTreeSet<_> = dependencies
		.iter()
		.map(|id| id.as_i64().unwrap_or_else(|| panic!("positive id")))
		.collect();
	assert_eq!(distinct.len(), dependencies.len(), "duplicate dependency accepted");
	assert!(distinct.iter().all(|id| *id > 0));
}

fn response(input: &mut ByteSource<'_>) {
	let Some((unit, raw_unit)) = review_id(input) else { return };
	let Some(epoch) = input.take(8) else { return };
	let epoch = u64::from_le_bytes(epoch.try_into().unwrap_or_else(|_| panic!("8 bytes")));
	let Some(choice) = input.u8() else { return };
	let (band, name) = match choice % 4 {
		0 => (PriorityBand::Urgent, "urgent"),
		1 => (PriorityBand::High, "high"),
		2 => (PriorityBand::Normal, "normal"),
		_ => (PriorityBand::Background, "background"),
	};
	let value = ReviewUnitResponse {
		protocol_version: loupe_proto::review_api::ReviewProtocol,
		review_unit_id: unit,
		assignment_epoch: epoch,
		accepted_priority_band: band,
	};
	assert_response(
		&value,
		json!({"protocol_version": PROTOCOL, "review_unit_id": raw_unit,
			"assignment_epoch": epoch, "accepted_priority_band": name}),
	);
}

pub fn proto_review_units_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proto_review_units_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn seed_passes_the_oracles() {
		assert!(decode(SEED).is_some());
		do_test(&[&[0][..], SEED].concat());
		do_test(&[1, 4, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 3]);
	}

	#[test]
	fn malformed_requests_are_refused() {
		let seed = std::str::from_utf8(SEED).unwrap_or_else(|_| panic!("UTF-8 seed"));
		for raw in [
			seed.replace("[2,3]", "[2,2]"),
			seed.replace("\"symbol\":\"parse\"", "\"symbol\":\"parse\",\"line\":1"),
			seed.replace("[{\"path\":\"src/lib.rs\",\"symbol\":\"parse\"}]", "[]"),
		] {
			assert!(decode(raw.as_bytes()).is_none());
		}
	}
}
