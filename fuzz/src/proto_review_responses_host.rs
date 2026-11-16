//! Host-preparation responses decoded by the worker from original Server
//! bytes (`loupe_worker::client::fuzz_support`).
//!
//! Byte zero selects the `pin-target` (0), manifest progress (1) or
//! published profile (2) decoder for the rest, or a structured response (3)
//! built from the rest that must be admitted. Every input runs the shared
//! `proto_review_response_oracle` checks; progress and profile responses
//! must also re-serialize to exactly the received JSON.

use loupe_proto::review_api::{
	ManifestProgressDecoder, PinTargetResponseDecoder, PublishedProfileDecoder,
};
use loupe_worker::client::fuzz_support::{review_response, review_response_carrying};
use serde_json::{json, Value};

use crate::proto_review_common::{hex, review_id};
use crate::proto_review_response_oracle::{accept, check, SENTINEL};
use crate::utils::input::ByteSource;
use crate::utils::test_logger;

const PROTOCOL: u64 = loupe_proto::PROTOCOL_VERSION as u64;

fn pin(raw: &[u8]) -> Option<Value> {
	check(&|raw| review_response_carrying(PinTargetResponseDecoder, raw), raw, false)
}
fn progress(raw: &[u8]) -> Option<Value> {
	check(&|raw| review_response(ManifestProgressDecoder, raw), raw, true)
}
fn profile(raw: &[u8]) -> Option<Value> {
	check(&|raw| review_response(PublishedProfileDecoder, raw), raw, true)
}

fn structured(input: &mut ByteSource<'_>) -> Option<()> {
	match input.u8()? % 3 {
		0 => {
			let (_, generation) = review_id(input)?;
			let commit = hex(input, 20)?;
			let shape = input.u8()?;
			let response = if shape & 1 == 0 {
				let units = (0..usize::from(shape >> 1) % 4)
					.map(|index| {
						json!({"review_unit_id": index + 1, "assignment_epoch": index + 1,
							"title": format!("{SENTINEL} title"), "objective": SENTINEL,
							"source_refs": [{"path": "src/lib.rs", "symbol": null}],
							"depends_on": [], "closure_criteria": null})
					})
					.collect::<Vec<_>>();
				let digest = hex(input, 32)?;
				json!({"outcome": "prepared", "protocol_version": PROTOCOL,
					"generation": {"generation_id": generation, "commit_sha": commit},
					"profile": if shape & 2 == 0 { Value::Null } else {
						json!({"profile_version": 1, "profile_digest": digest,
							"profile": {"purpose": SENTINEL}})
					},
					"assignments": if shape & 4 == 0 { Value::Null } else { Value::from(units) }})
			} else {
				json!({"outcome": "deferred", "protocol_version": PROTOCOL,
					"receipt": {"receipt_id": generation, "commit_sha": commit,
						"reason": "unsupported_recipe"}})
			};
			accept(&|raw| review_response_carrying(PinTargetResponseDecoder, raw), response, false);
		},
		1 => {
			let counts = [input.u32()?, input.u32()?, input.u32()?];
			let response = json!({"protocol_version": PROTOCOL,
				"expected_entry_count": counts[0], "expected_digest": hex(input, 32)?,
				"received_entry_count": counts[1], "received_canonical_bytes": counts[2],
				"sealed": counts[0] & 1 == 1});
			accept(&|raw| review_response(ManifestProgressDecoder, raw), response, true);
		},
		_ => {
			let version = input.u32()?;
			let response = json!({"protocol_version": PROTOCOL, "profile_version": version,
				"profile_digest": hex(input, 32)?});
			accept(&|raw| review_response(PublishedProfileDecoder, raw), response, true);
		},
	}
	Some(())
}

pub fn do_test(data: &[u8]) {
	let Some((&selector, rest)) = data.split_first() else { return };
	match selector {
		0 => {
			pin(rest);
		},
		1 => {
			progress(rest);
		},
		2 => {
			profile(rest);
		},
		3 => {
			structured(&mut ByteSource::new(rest));
		},
		_ => {},
	}
}

pub fn proto_review_responses_host_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proto_review_responses_host_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	pub(super) const PIN: &str = r#"{"outcome":"prepared","protocol_version":3,"generation":{"generation_id":3,"commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"profile":{"profile_version":1,"profile_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","profile":{"purpose":"test"}},"assignments":[{"review_unit_id":5,"assignment_epoch":2,"title":"Review parser","objective":"Check input bounds","source_refs":[{"path":"src/lib.rs","symbol":"parse"}],"depends_on":[4],"closure_criteria":null}]}"#;
	pub(super) const PROGRESS: &str = r#"{"protocol_version":3,"expected_entry_count":2,"expected_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","received_entry_count":1,"received_canonical_bytes":80,"sealed":false}"#;
	pub(super) const PROFILE: &str = r#"{"protocol_version":3,"profile_version":1,"profile_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#;

	#[test]
	fn seeds_exercise_admission_and_refusal() {
		assert!(pin(PIN.as_bytes()).is_some());
		assert!(progress(PROGRESS.as_bytes()).is_some());
		assert!(profile(PROFILE.as_bytes()).is_some());
		assert!(pin(br#"{"outcome":0}"#).is_none());
		assert!(progress(&PROGRESS.as_bytes()[1..]).is_none());
		for shape in 0..8u8 {
			let mut data = vec![3, 0, 0, 0, 0, 1];
			data.extend([7; 20]);
			data.push(shape);
			data.extend([9; 32]);
			do_test(&data);
		}
		for choice in [1u8, 2] {
			let mut data = vec![3, choice];
			data.extend([5; 48]);
			do_test(&data);
		}
	}
}
