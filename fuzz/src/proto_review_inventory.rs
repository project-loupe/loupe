//! Byte zero selects the inventory disposition request (0), decoded by its
//! route decoder from the rest as original Worker bytes, or an
//! `InventoryDispositionResponse` (1) built from the rest.
//!
//! The request runs the shared `proto_review_common` oracles. An accepted
//! request must also satisfy the disposition rules, re-derived here from its
//! serialization: a nonnegative revision; mappings iff `mapped`; a reason for
//! `context` and `excluded`; distinct mapped units; SQLite-range epochs.

use loupe_proto::review_inventory::{
	InventoryDispositionRequest, InventoryDispositionRequestDecoder, InventoryDispositionResponse,
	MAX_REQUEST_BYTES,
};
use loupe_provenance::Worker;
use loupe_server::fuzz_support::review_request;
use serde_json::{json, Value};

use crate::proto_review_common::{assert_response, closed, review_id, Request};
use crate::utils::input::ByteSource;
use crate::utils::test_logger;

const PROTOCOL: u64 = loupe_proto::PROTOCOL_VERSION as u64;
const SEED: &[u8] = br#"{"protocol_version":3,"client_inventory_disposition_key":"key-1","source_path":"src/lib.rs","expected_revision":0,"disposition":"mapped","reason":null,"mappings":[{"review_unit_id":1,"assignment_epoch":1}]}"#;

fn decode(raw: &[u8]) -> Option<InventoryDispositionRequest<Worker>> {
	review_request(InventoryDispositionRequestDecoder, raw).ok()
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
	let baseline = format!("{:?}", decode(SEED).unwrap_or_else(|| panic!("inventory seed")));
	let oracle = Request {
		decode: &decode,
		versions: &[("protocol_version", PROTOCOL)],
		baseline: &baseline,
		exact_debug: true,
		open: &closed,
	};
	let Some(value) = oracle.check(raw) else { return };
	assert!(raw.len() <= MAX_REQUEST_BYTES, "inventory request above its byte cap");
	let rendered = crate::proto_review_common::to_value(&value);
	assert!(rendered["expected_revision"].as_i64().is_some_and(|revision| revision >= 0));
	let disposition =
		rendered["disposition"].as_str().unwrap_or_else(|| panic!("closed disposition"));
	let mappings = rendered["mappings"].as_array().unwrap_or_else(|| panic!("mappings array"));
	assert_eq!(disposition == "mapped", !mappings.is_empty(), "mappings iff mapped");
	if matches!(disposition, "context" | "excluded") {
		assert!(!rendered["reason"].is_null(), "context and excluded need a reason");
	}
	let mut units = std::collections::BTreeSet::new();
	for mapping in mappings {
		assert!(units.insert(mapping["review_unit_id"].as_i64()), "duplicate mapped unit");
		assert!(mapping["assignment_epoch"].as_u64().is_some_and(|e| e <= i64::MAX as u64));
	}
	assert!(matches!(&rendered["source_path"], Value::String(path) if !path.is_empty()));
}

fn response(input: &mut ByteSource<'_>) {
	let Some((entry, raw_entry)) = review_id(input) else { return };
	let Some(revision) = input.take(8) else { return };
	let revision = u64::from_le_bytes(revision.try_into().unwrap_or_else(|_| panic!("8 bytes")));
	let value = InventoryDispositionResponse {
		protocol_version: loupe_proto::review_api::ReviewProtocol,
		inventory_entry_id: entry,
		revision,
	};
	assert_response(
		&value,
		json!({"protocol_version": PROTOCOL, "inventory_entry_id": raw_entry, "revision": revision}),
	);
}

pub fn proto_review_inventory_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proto_review_inventory_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn seed_and_variants_pass_the_oracles() {
		assert!(decode(SEED).is_some());
		let seed = std::str::from_utf8(SEED).unwrap_or_else(|_| panic!("UTF-8 seed"));
		let excluded = seed
			.replace("\"mapped\"", "\"excluded\"")
			.replace("\"reason\":null", "\"reason\":\"generated\"")
			.replace("{\"review_unit_id\":1,\"assignment_epoch\":1}", "");
		assert!(decode(excluded.as_bytes()).is_some());
		for raw in [seed.to_owned(), excluded] {
			do_test(&[&[0][..], raw.as_bytes()].concat());
		}
		do_test(&[1, 4, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
	}

	#[test]
	fn malformed_requests_are_refused() {
		let seed = std::str::from_utf8(SEED).unwrap_or_else(|_| panic!("UTF-8 seed"));
		for raw in [
			seed.replace("\"mapped\"", "\"context\""),
			seed.replace("\"expected_revision\":0", "\"expected_revision\":-1"),
			seed.replace("\"assignment_epoch\":1", "\"assignment_epoch\":1,\"x\":1"),
		] {
			assert!(decode(raw.as_bytes()).is_none());
		}
	}
}
