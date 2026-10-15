//! Raw JSON input; recursion is bounded by serde_json's normal parser limit.
//! The 64 KiB input budget bounds all oracle allocations linearly in input size.
//! Enable serde_json's preserve_order feature in the fuzz workspace so reversed
//! key insertion can detect a production regression that omits sorting.

use loupe_core::canonical::{canonical_bytes, digest};
use serde_json::Value;

use crate::utils::test_logger;

const MAX_INPUT_BYTES: usize = 64 * 1024;

pub fn do_test(data: &[u8]) {
	if data.len() > MAX_INPUT_BYTES {
		return;
	}
	let Ok(value) = serde_json::from_slice::<Value>(data) else { return };
	let canonical = canonical_bytes(&value);
	let mut expected = Vec::new();
	write_json(&value, &mut expected, false);
	assert_eq!(canonical, expected, "canonical bytes disagree with independent sorted renderer");
	let decoded: Value = serde_json::from_slice(&canonical)
		.unwrap_or_else(|_| panic!("canonical serialization must be valid JSON"));
	assert_eq!(canonical_bytes(&decoded), canonical, "canonical serialization must be idempotent");
	// JSON escaping and number rendering can grow the input by only a constant
	// factor; this deliberately loose bound also covers zero-length scalars.
	assert!(canonical.len() <= data.len().saturating_mul(12).saturating_add(32));

	let mut different_wire = Vec::new();
	write_json(&value, &mut different_wire, true);
	let reordered: Value = serde_json::from_slice(&different_wire)
		.unwrap_or_else(|_| panic!("independent reordered serialization must be valid JSON"));
	assert_eq!(
		canonical_bytes(&reordered),
		canonical,
		"object order and insignificant whitespace must not affect canonical bytes"
	);
	assert_eq!(digest(&canonical).len(), 32);
	assert_eq!(
		digest(&canonical),
		*blake3::hash(&canonical).as_bytes(),
		"digest must be BLAKE3-256"
	);
}

// Serialize containers explicitly instead of using production's Serialize
// wrapper. Primitive spelling deliberately follows the serde_json contract.
fn write_json(value: &Value, output: &mut Vec<u8>, reverse_and_space: bool) {
	match value {
		Value::Object(fields) => {
			let mut fields: Vec<_> = fields.iter().collect();
			fields.sort_unstable_by_key(|(key, _)| *key);
			if reverse_and_space {
				fields.reverse();
			}
			output.push(b'{');
			for (index, (key, nested)) in fields.into_iter().enumerate() {
				if index != 0 {
					output.push(b',');
				}
				if reverse_and_space {
					output.extend_from_slice(b" \n\t");
				}
				serde_json::to_writer(&mut *output, key)
					.unwrap_or_else(|_| panic!("JSON keys must serialize"));
				output.push(b':');
				write_json(nested, output, reverse_and_space);
			}
			output.push(b'}');
		},
		Value::Array(values) => {
			output.push(b'[');
			for (index, nested) in values.iter().enumerate() {
				if index != 0 {
					output.push(b',');
				}
				if reverse_and_space {
					output.extend_from_slice(b" \n\t");
				}
				write_json(nested, output, reverse_and_space);
			}
			output.push(b']');
		},
		_ => {
			serde_json::to_writer(output, value)
				.unwrap_or_else(|_| panic!("JSON primitives must serialize"));
		},
	}
}

pub fn core_canonical_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn core_canonical_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
