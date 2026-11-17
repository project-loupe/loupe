//! Shared oracles for the `proto_review_responses_*` targets.
//!
//! A response admitted by its decoder from original Server bytes must
//! serialize to JSON that the same decoder admits again with identical
//! serialization, after the independent canonical renderer re-encodes it.
//! Metadata-only responses must serialize to exactly the received JSON. An
//! unknown top-level field must be refused. `Debug` and errors must never
//! show the sentinel that structured inputs place in carried text.

use std::fmt::Debug;

use loupe_proto::review_api::ReviewResponseDecodeError;
use serde::Serialize;
use serde_json::Value;

use crate::proto_review_common::{render, to_value, UNKNOWN_FIELD};

/// Placed in carried text by structured inputs; never shown by `Debug`.
pub(crate) const SENTINEL: &str = "loupe-fuzz-sentinel";

pub(crate) type Decode<'a, T> = &'a dyn Fn(&[u8]) -> Result<T, ReviewResponseDecodeError>;

/// Runs the response oracles on `raw`; returns the accepted rendering.
pub(crate) fn check<T: Serialize + Debug>(
	decode: Decode<'_, T>, raw: &[u8], exact: bool,
) -> Option<Value> {
	let value = match decode(raw) {
		Ok(value) => value,
		Err(error) => {
			assert!(!format!("{error:?} {error}").contains(SENTINEL), "error shows response text");
			return None;
		},
	};
	assert!(!format!("{value:?}").contains(SENTINEL), "Debug shows carried text");
	let rendered = to_value(&value);
	if exact {
		let received: Value =
			serde_json::from_slice(raw).unwrap_or_else(|_| panic!("accepted response is JSON"));
		assert_eq!(rendered, received, "metadata response admitted in another form");
	}
	let again = decode(&render(&rendered))
		.unwrap_or_else(|_| panic!("canonical re-encoding of an accepted response is refused"));
	assert_eq!(to_value(&again), rendered, "re-decoded response serializes differently");
	if let Value::Object(map) = &rendered {
		let mut extended = map.clone();
		extended.insert(UNKNOWN_FIELD.to_owned(), Value::Null);
		assert!(
			decode(&render(&Value::Object(extended))).is_err(),
			"unknown response field admitted"
		);
	}
	Some(rendered)
}

/// A structured response built to the server's schema must be admitted.
pub(crate) fn accept<T: Serialize + Debug>(decode: Decode<'_, T>, expected: Value, exact: bool) {
	let raw = render(&expected);
	let rendered =
		check(decode, &raw, exact).unwrap_or_else(|| panic!("structured server response refused"));
	if exact {
		assert_eq!(rendered, expected);
	}
}
