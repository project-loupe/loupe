//! Strict object shape for JSON request bodies.
//!
//! serde's derived struct impls also accept the sequence of field values,
//! e.g. `[3]` for `{"protocol_version":3}`, and the variant content of a
//! tagged enum is buffered and decoded the same way. [`objects_only`]
//! compares the original bytes with the decoded value's own serialization
//! and refuses any position where the value serializes to an object but the
//! input carried another JSON shape, so each request has one structural
//! encoding.
use serde::Serialize;
use serde_json::Value;

// debug-ok: unit rejection marker, carries no input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotAnObject;

/// Refuses `raw` unless every object of `decoded`'s serialization was an
/// object in `raw` as well.
pub fn objects_only<T: Serialize>(raw: &[u8], decoded: &T) -> Result<(), NotAnObject> {
	let raw: Value = serde_json::from_slice(raw).map_err(|_| NotAnObject)?;
	let expected = serde_json::to_value(decoded).map_err(|_| NotAnObject)?;
	if same_objects(&raw, &expected) {
		Ok(())
	} else {
		Err(NotAnObject)
	}
}

fn same_objects(raw: &Value, expected: &Value) -> bool {
	match (raw, expected) {
		(Value::Object(raw), Value::Object(expected)) => expected
			.iter()
			.all(|(key, value)| raw.get(key).is_none_or(|nested| same_objects(nested, value))),
		(_, Value::Object(_)) => false,
		(Value::Array(raw), Value::Array(expected)) => {
			raw.iter().zip(expected).all(|(raw, expected)| same_objects(raw, expected))
		},
		_ => true,
	}
}

#[cfg(test)]
mod tests {
	use serde_json::json;

	use super::*;

	#[test]
	fn sequences_in_place_of_objects_are_refused_at_any_depth() {
		let decoded = json!({"a": 1, "b": [{"c": 2}], "d": {"e": [3]}});
		assert!(objects_only(br#"{"a":1,"b":[{"c":2}],"d":{"e":[3]}}"#, &decoded).is_ok());
		for raw in [
			r#"[1,[{"c":2}],{"e":[3]}]"#,
			r#"{"a":1,"b":[[2]],"d":{"e":[3]}}"#,
			r#"{"a":1,"b":[{"c":2}],"d":[[3]]}"#,
		] {
			assert_eq!(objects_only(raw.as_bytes(), &decoded), Err(NotAnObject), "{raw}");
		}
	}
}
