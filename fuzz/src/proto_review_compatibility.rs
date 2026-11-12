//! The generation-reset route admits original authenticated Operator bytes
//! through its own decoder (`loupe-server` `ingress::review_compatibility`),
//! not through a Worker phase decoder. Byte zero selects that request (0),
//! decoded from the rest, or a `ResetGenerationResponse` (1) built from it.
//!
//! The request runs the shared `proto_review_common` oracles, and acceptance
//! must equal an independent decision: at most 8 KiB, and a JSON document
//! without duplicate keys whose value is exactly `{"protocol_version":3}`.
//! A refusal of an oversized body is 413, of any other body 400.

use loupe_proto::review_compatibility::{ResetGenerationRequest, ResetGenerationResponse};
use loupe_server::fuzz_support::reset_generation;
use serde_json::{json, Value};

use crate::proto_review_common::{assert_response, closed, Request};
use crate::utils::input::ByteSource;
use crate::utils::test_logger;

const PROTOCOL: u64 = loupe_proto::PROTOCOL_VERSION as u64;
const LIMIT: usize = 8192;
const SEED: &[u8] = br#"{"protocol_version":3}"#;

fn reset(raw: &[u8]) -> Option<ResetGenerationRequest> {
	reset_generation(raw).ok()
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
	let baseline = format!("{:?}", reset(SEED).unwrap_or_else(|| panic!("reset seed")));
	let oracle = Request {
		decode: &reset,
		versions: &[("protocol_version", PROTOCOL)],
		baseline: &baseline,
		exact_debug: true,
		open: &closed,
	};
	let accepted = oracle.check(raw).is_some();
	let expected = raw.len() <= LIMIT
		&& strict_value(raw).is_some_and(|value| value == json!({"protocol_version": PROTOCOL}));
	assert_eq!(accepted, expected, "reset acceptance differs from the independent decision");
	if let Err(status) = reset_generation(raw) {
		assert_eq!(status, if raw.len() > LIMIT { 413 } else { 400 });
	}
}

fn response(input: &mut ByteSource<'_>) {
	let mut counts = [0_u64; 4];
	for count in &mut counts {
		let Some(raw) = input.take(8) else { return };
		*count = u64::from_le_bytes(raw.try_into().unwrap_or_else(|_| panic!("8 bytes")));
	}
	let value = ResetGenerationResponse {
		protocol_version: loupe_proto::review_api::ReviewProtocol,
		inventory_entries_removed: counts[0],
		review_units_removed: counts[1],
		leads_removed: counts[2],
		verification_intents_blocked: counts[3],
	};
	assert_response(
		&value,
		json!({"protocol_version": PROTOCOL, "inventory_entries_removed": counts[0],
			"review_units_removed": counts[1], "leads_removed": counts[2],
			"verification_intents_blocked": counts[3]}),
	);
}

/// Independent JSON parse that refuses a duplicate key in any object.
fn strict_value(raw: &[u8]) -> Option<Value> {
	serde_json::from_slice::<Strict>(raw).ok().map(|strict| strict.0)
}

struct Strict(Value);
impl<'de> serde::Deserialize<'de> for Strict {
	fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		struct Visitor;
		impl<'de> serde::de::Visitor<'de> for Visitor {
			type Value = Strict;
			fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				f.write_str("JSON without duplicate keys")
			}
			fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
				Ok(Strict(Value::Bool(v)))
			}
			fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
				Ok(Strict(Value::from(v)))
			}
			fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
				Ok(Strict(Value::from(v)))
			}
			fn visit_f64<E>(self, v: f64) -> Result<Strict, E> {
				Ok(Strict(Value::from(v)))
			}
			fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
				Ok(Strict(Value::String(v.to_owned())))
			}
			fn visit_unit<E>(self) -> Result<Strict, E> {
				Ok(Strict(Value::Null))
			}
			fn visit_seq<A: serde::de::SeqAccess<'de>>(
				self, mut seq: A,
			) -> Result<Strict, A::Error> {
				let mut values = Vec::new();
				while let Some(Strict(value)) = seq.next_element()? {
					values.push(value);
				}
				Ok(Strict(Value::Array(values)))
			}
			fn visit_map<A: serde::de::MapAccess<'de>>(
				self, mut map: A,
			) -> Result<Strict, A::Error> {
				let mut fields = serde_json::Map::new();
				while let Some(key) = map.next_key::<String>()? {
					let Strict(value) = map.next_value()?;
					if fields.insert(key, value).is_some() {
						return Err(serde::de::Error::custom("duplicate key"));
					}
				}
				Ok(Strict(Value::Object(fields)))
			}
		}
		deserializer.deserialize_any(Visitor)
	}
}

pub fn proto_review_compatibility_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proto_review_compatibility_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn strict_value_refuses_nested_duplicates() {
		assert!(strict_value(br#"{"a":{"b":1,"c":2}}"#).is_some());
		assert!(strict_value(br#"{"a":{"b":1,"b":2}}"#).is_none());
		assert!(strict_value(br#"[{"a":1,"a":2}]"#).is_none());
	}

	#[test]
	fn boundaries_and_malformed_requests_match_the_independent_decision() {
		let mut padded = SEED.to_vec();
		padded.resize(LIMIT, b' ');
		for raw in [
			SEED.to_vec(),
			padded.clone(),
			[padded.as_slice(), b" "].concat(),
			br#"{"protocol_version":3,"protocol_version":3}"#.to_vec(),
			br#"{"protocol_version":3,"actor":"x"}"#.to_vec(),
			br#"{"protocol_version":2}"#.to_vec(),
			b"{}".to_vec(),
			b"[3]".to_vec(),
		] {
			do_test(&[&[0][..], &raw].concat());
		}
		do_test(&[1; 33]);
	}
}
