//! Stable retransmission bytes, not semantic deduplication or RFC 8785.

use std::collections::BTreeMap;

use serde::{Serialize, Serializer};
use serde_json::Value;

/// Sort object keys recursively while preserving array order and serde_json's
/// number rendering. This does not validate or normalize untrusted text.
pub fn canonical_bytes(value: &Value) -> Vec<u8> {
	#[expect(
		clippy::expect_used,
		reason = "Ordered serializes only JSON values and string keys into a Vec; neither custom serializers nor failing writers are accepted"
	)]
	let bytes = serde_json::to_vec(&Ordered(value)).expect("JSON values serialize infallibly");
	bytes
}

/// BLAKE3-256 of already canonicalized payloads (or other domain-separated bytes).
pub fn digest(bytes: &[u8]) -> [u8; 32] {
	*blake3::hash(bytes).as_bytes()
}

struct Ordered<'a>(&'a Value);

/// The object-ordering decision, shared by recursive serialization and proofs.
pub(crate) fn ordered_fields(fields: &serde_json::Map<String, Value>) -> BTreeMap<&String, &Value> {
	fields.iter().collect()
}

impl Serialize for Ordered<'_> {
	fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		match self.0 {
			Value::Object(fields) => serializer.collect_map(
				ordered_fields(fields).into_iter().map(|(key, value)| (key, Ordered(value))),
			),
			Value::Array(values) => serializer.collect_seq(values.iter().map(Ordered)),
			value => value.serialize(serializer),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn canonical_rendering_has_a_fixed_vector() {
		let value =
			serde_json::from_str(r#" { "z": [12,12.0,1e3,1000], "a": {"b":"é", "a":true} } "#)
				.unwrap();
		let bytes = canonical_bytes(&value);
		assert_eq!(
			std::str::from_utf8(&bytes).unwrap(),
			r#"{"a":{"a":true,"b":"é"},"z":[12,12.0,1000.0,1000]}"#,
			"canonical bytes must pin sorted keys, UTF-8, and serde_json number rendering"
		);
		assert_eq!(canonical_bytes(&serde_json::from_slice(&bytes).unwrap()), bytes);
	}

	#[test]
	fn object_order_and_whitespace_do_not_affect_replay() {
		let left = serde_json::from_str(r#" {"b": [2,1], "a": null} "#).unwrap();
		let right = serde_json::from_str(r#"{"a":null,"b":[2,1]}"#).unwrap();
		let reordered = serde_json::from_str(r#"{"a":null,"b":[1,2]}"#).unwrap();
		assert_eq!(canonical_bytes(&left), canonical_bytes(&right));
		assert_ne!(canonical_bytes(&left), canonical_bytes(&reordered));
		for (a, b) in [("12", "12.0"), ("1e3", "1000")] {
			assert_ne!(
				canonical_bytes(&serde_json::from_str(a).unwrap()),
				canonical_bytes(&serde_json::from_str(b).unwrap())
			);
		}
	}

	#[test]
	fn floating_point_retransmission_keeps_its_canonical_digest() {
		// This value requires float_roundtrip to survive serialization unchanged.
		let value: Value = serde_json::from_str("-9223372036855078478").unwrap();
		let first = canonical_bytes(&value);
		let replay: Value = serde_json::from_slice(&first).unwrap();
		assert_eq!(canonical_bytes(&replay), first, "canonical float bytes changed on replay");
		assert_eq!(digest(&canonical_bytes(&replay)), digest(&first));
	}

	#[test]
	fn blake3_matches_the_published_empty_input_vector() {
		let hex: String = digest(b"").iter().map(|byte| format!("{byte:02x}")).collect();
		assert_eq!(hex, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
	}
}
