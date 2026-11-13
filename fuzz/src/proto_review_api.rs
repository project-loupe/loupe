//! Byte zero selects a preparation request decoded by its route decoder from
//! the rest as original Worker bytes: pin target (0), inventory batch (1),
//! seal inventory (2), publish profile (3, the profile carried as Agent).
//! Selectors 4..=7 build a response from the rest and compare it with an
//! independent rendering: phase limits (4), manifest progress (5),
//! published profile (6), deferred pin target (7).
//!
//! Requests run the shared `proto_review_common` oracles. The generated
//! profile is open JSON by its schema, so unknown keys are only required to
//! be refused around it. An accepted inventory batch also has at most 4096
//! entries whose raw path hex is non-empty, even-length, lowercase hex.

use loupe_core::review_metadata::ReviewDigest;
use loupe_proto::review_api::{
	Capacity, InventoryBatchRequest, InventoryBatchRequestDecoder, ManifestProgress,
	PhaseLimitsResponse, PinTargetRequest, PinTargetRequestDecoder, PinTargetResponse,
	PreparationDeferral, PublishProfileRequest, PublishProfileRequestDecoder, PublishedProfile,
	ReviewProtocol, SealInventoryRequest, SealInventoryRequestDecoder, TokenCapacity, Unavailable,
	UnknownSpend, UnsupportedRecipe,
};
use loupe_provenance::{Agent, Worker};
use loupe_server::fuzz_support::review_request;
use serde::Serialize;
use serde_json::{json, Value};

use crate::proto_review_common::{
	assert_response, hex, receipt_metadata, review_id, to_value, Request,
};
use crate::utils::input::ByteSource;
use crate::utils::test_logger;

const PROTOCOL: u64 = loupe_proto::PROTOCOL_VERSION as u64;
const PIN_SEED: &[u8] =
	br#"{"protocol_version":3,"commit_sha":"0123456789abcdef0123456789abcdef01234567"}"#;
const BATCH_SEED: &[u8] = br#"{"protocol_version":3,"format_version":1,"expected_entry_count":2,"expected_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","start_position":0,"entries":[{"raw_path_hex":"61","git_mode":33188,"object_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},{"raw_path_hex":"612f62","git_mode":40960,"object_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}"#;
const SEAL_SEED: &[u8] = br#"{"protocol_version":3}"#;
const PROFILE_SEED: &[u8] =
	br#"{"protocol_version":3,"profile":{"purpose":"seed","areas":[{"name":"parser"}]}}"#;

fn pin(raw: &[u8]) -> Option<PinTargetRequest<Worker>> {
	review_request(PinTargetRequestDecoder, raw).ok()
}
fn batch(raw: &[u8]) -> Option<InventoryBatchRequest<Worker>> {
	review_request(InventoryBatchRequestDecoder, raw).ok()
}
fn seal(raw: &[u8]) -> Option<SealInventoryRequest> {
	review_request(SealInventoryRequestDecoder, raw).ok()
}
fn profile(raw: &[u8]) -> Option<PublishProfileRequest<Agent>> {
	review_request(PublishProfileRequestDecoder, raw).ok()
}

fn check<T: Serialize + PartialEq + std::fmt::Debug>(
	decode: &dyn Fn(&[u8]) -> Option<T>, seed: &[u8], raw: &[u8],
) -> Option<T> {
	let baseline = format!("{:?}", decode(seed).unwrap_or_else(|| panic!("review api seed")));
	Request {
		decode,
		versions: &[("protocol_version", PROTOCOL), ("format_version", 1)],
		baseline: &baseline,
		exact_debug: true,
		open: &|keys: &[&str]| keys.first() == Some(&"profile"),
	}
	.check(raw)
}

pub fn do_test(data: &[u8]) {
	let Some((&selector, rest)) = data.split_first() else { return };
	let mut input = ByteSource::new(rest);
	match selector {
		0 => drop(check(&pin, PIN_SEED, rest)),
		1 => {
			let Some(value) = check(&batch, BATCH_SEED, rest) else { return };
			let rendered = to_value(&value);
			let entries = rendered["entries"].as_array().unwrap_or_else(|| panic!("entries"));
			assert!(entries.len() <= 4096);
			for entry in entries {
				let path = entry["raw_path_hex"].as_str().unwrap_or_else(|| panic!("raw path hex"));
				assert!(!path.is_empty() && path.len() % 2 == 0);
				assert!(path.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
			}
		},
		2 => drop(check(&seal, SEAL_SEED, rest)),
		3 => drop(check(&profile, PROFILE_SEED, rest)),
		4 => limits(&mut input),
		5 => progress(&mut input),
		6 => published(&mut input),
		7 => deferred(&mut input),
		_ => {},
	}
}

fn capacity(input: &mut ByteSource<'_>) -> Option<(Capacity, Value)> {
	let (limit, remaining) = (input.u32()?, input.u32()?);
	Some((Capacity { limit, remaining }, json!({"limit": limit, "remaining": remaining})))
}

fn limits(input: &mut ByteSource<'_>) {
	let mut times = [0_i64; 3];
	for time in &mut times {
		let Some(raw) = input.take(8) else { return };
		*time = i64::from_le_bytes(raw.try_into().unwrap_or_else(|_| panic!("8 bytes")));
	}
	let mut counts = [0_u64; 6];
	for count in &mut counts {
		let Some(raw) = input.take(8) else { return };
		*count = u64::from_le_bytes(raw.try_into().unwrap_or_else(|_| panic!("8 bytes")));
	}
	let mut capacities = Vec::new();
	for _ in 0..4 {
		let Some(capacity) = capacity(input) else { return };
		capacities.push(capacity);
	}
	let tokens = match input.take(8) {
		Some(raw) => {
			let limit = u64::from_le_bytes(raw.try_into().unwrap_or_else(|_| panic!("8 bytes")));
			(
				TokenCapacity::HostEnforced { limit, spent: UnknownSpend::Unknown },
				json!({"status": "host_enforced", "limit": limit, "spent": "unknown"}),
			)
		},
		None => (TokenCapacity::None, json!({"status": "none"})),
	};
	let rendered: Vec<Value> = capacities.iter().map(|(_, value)| value.clone()).collect();
	let mut values = capacities.into_iter().map(|(value, _)| value);
	let mut next = || values.next().unwrap_or_else(|| panic!("four capacities"));
	let value = PhaseLimitsResponse {
		protocol_version: ReviewProtocol,
		soft_deadline_at: times[0],
		submit_by: times[1],
		hard_deadline_at: times[2],
		remaining_seconds: counts[0],
		new_units: next(),
		leads: next(),
		siblings: next(),
		candidate_queries: next(),
		campaign_jobs_limit: counts[1],
		campaign_jobs_admitted: counts[2],
		campaign_general_remaining: counts[3],
		campaign_urgent_remaining: counts[4],
		campaign_verification_remaining: counts[5],
		proof_capacity: Unavailable::Unavailable,
		artifact_capacity: Unavailable::Unavailable,
		output_capacity: Unavailable::Unavailable,
		tokens: tokens.0,
	};
	assert_response(
		&value,
		json!({"protocol_version": PROTOCOL, "soft_deadline_at": times[0],
			"submit_by": times[1], "hard_deadline_at": times[2], "remaining_seconds": counts[0],
			"new_units": rendered[0], "leads": rendered[1], "siblings": rendered[2],
			"candidate_queries": rendered[3], "campaign_jobs_limit": counts[1],
			"campaign_jobs_admitted": counts[2], "campaign_general_remaining": counts[3],
			"campaign_urgent_remaining": counts[4],
			"campaign_verification_remaining": counts[5], "proof_capacity": "unavailable",
			"artifact_capacity": "unavailable", "output_capacity": "unavailable",
			"tokens": tokens.1}),
	);
}

fn digest(input: &mut ByteSource<'_>) -> Option<(ReviewDigest<Agent>, String)> {
	let raw = hex(input, 32)?;
	let value = crate::fixtures::identifier(&raw).unwrap_or_else(|_| panic!("hex digest"));
	Some((value, raw))
}

fn progress(input: &mut ByteSource<'_>) {
	let Some((expected_digest, raw_digest)) = digest(input) else { return };
	let mut counts = [0_u64; 3];
	for count in &mut counts {
		let Some(raw) = input.take(8) else { return };
		*count = u64::from_le_bytes(raw.try_into().unwrap_or_else(|_| panic!("8 bytes")));
	}
	let Some(sealed) = input.u8().map(|byte| byte & 1 == 1) else { return };
	let value = ManifestProgress {
		protocol_version: ReviewProtocol,
		expected_entry_count: counts[0],
		expected_digest,
		received_entry_count: counts[1],
		received_canonical_bytes: counts[2],
		sealed,
	};
	assert_response(
		&value,
		json!({"protocol_version": PROTOCOL, "expected_entry_count": counts[0],
			"expected_digest": raw_digest, "received_entry_count": counts[1],
			"received_canonical_bytes": counts[2], "sealed": sealed}),
	);
}

fn published(input: &mut ByteSource<'_>) {
	let Some(version) = input.u32() else { return };
	let Some((profile_digest, raw_digest)) = digest(input) else { return };
	let value = PublishedProfile {
		protocol_version: ReviewProtocol,
		profile_version: version,
		profile_digest,
	};
	assert_response(
		&value,
		json!({"protocol_version": PROTOCOL, "profile_version": version,
			"profile_digest": raw_digest}),
	);
}

fn deferred(input: &mut ByteSource<'_>) {
	let Some((receipt_id, raw_receipt)) = review_id(input) else { return };
	let Some((commit_sha, _, raw_commit, _)) = receipt_metadata(input) else { return };
	let value: PinTargetResponse<Agent, Agent> = PinTargetResponse::Deferred {
		protocol_version: ReviewProtocol,
		receipt: PreparationDeferral {
			receipt_id,
			commit_sha,
			reason: UnsupportedRecipe::UnsupportedRecipe,
		},
	};
	assert_response(
		&value,
		json!({"outcome": "deferred", "protocol_version": PROTOCOL, "receipt": {
			"receipt_id": raw_receipt, "commit_sha": raw_commit,
			"reason": "unsupported_recipe"}}),
	);
}

pub fn proto_review_api_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proto_review_api_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn request_seeds_pass_the_oracles() {
		for (selector, seed) in [(0, PIN_SEED), (1, BATCH_SEED), (2, SEAL_SEED), (3, PROFILE_SEED)]
		{
			do_test(&[&[selector][..], seed].concat());
		}
	}

	#[test]
	fn responses_match_their_independent_rendering() {
		let bytes: Vec<u8> = (0..=255).collect();
		for selector in 4..=7 {
			do_test(&[&[selector][..], &bytes].concat());
		}
		do_test(&[&[4][..], &bytes[..104]].concat());
	}

	#[test]
	fn malformed_requests_are_refused() {
		let batch_seed = std::str::from_utf8(BATCH_SEED).unwrap_or_else(|_| panic!("UTF-8 seed"));
		assert!(batch(batch_seed.replace("\"61\"", "\"6\"").as_bytes()).is_none());
		assert!(batch(
			batch_seed.replace("\"format_version\":1", "\"format_version\":2").as_bytes()
		)
		.is_none());
		assert!(pin(br#"{"protocol_version":3,"commit_sha":"ABC"}"#).is_none());
		assert!(profile(br#"{"protocol_version":3,"profile":{"a":1,"a":2}}"#).is_none());
	}
}
