//! Shared oracles for the `proto_review_*` targets.
//!
//! A request admitted by its route decoder must serialize to JSON that the
//! same decoder admits again as an equal value with identical serialization,
//! after the independent canonical renderer of `core_canonical` re-encodes it.
//! On that canonical form, an unknown field added to any object, and any
//! other value in a closed version field, must be refused. `Debug` output
//! must contain no string the request carries unless the fixed baseline
//! value's `Debug` contains it as well, i.e. it is schema text, not payload.

use std::fmt::Debug;

use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::core_canonical::write_json;

pub(crate) const UNKNOWN_FIELD: &str = "loupe_fuzz_unknown";
/// Bounds the per-input mutation work; the fixed seeds stay far below it.
const MAX_MUTATED_OBJECTS: usize = 48;

pub(crate) fn render(value: &Value) -> Vec<u8> {
	let mut out = Vec::new();
	write_json(value, &mut out, false);
	out
}

pub(crate) fn to_value(value: &impl Serialize) -> Value {
	serde_json::to_value(value).unwrap_or_else(|_| panic!("accepted value must serialize"))
}

pub(crate) struct Request<'a, T> {
	pub decode: &'a dyn Fn(&[u8]) -> Option<T>,
	/// Object keys holding a closed version, with the only accepted value.
	pub versions: &'a [(&'a str, u64)],
	/// `Debug` of the decoded fixed seed; strings it shows are schema text.
	pub baseline: &'a str,
	/// Whether `Debug` must equal the baseline exactly, for any payload.
	pub exact_debug: bool,
	/// Whether the object at this key path (array indices dropped) is open
	/// JSON by its schema, e.g. inside a generated profile, or belongs to a
	/// legacy envelope outside the phase schema: it has no closed field set.
	pub open: &'a dyn Fn(&[&str]) -> bool,
}

impl<T: Serialize + PartialEq + Debug> Request<'_, T> {
	/// Run every request oracle on `raw`. Returns the accepted value.
	pub(crate) fn check(&self, raw: &[u8]) -> Option<T> {
		let value = (self.decode)(raw)?;
		let rendered = to_value(&value);
		let canonical = render(&rendered);
		let again = (self.decode)(&canonical)
			.unwrap_or_else(|| panic!("canonical re-encoding of an accepted request is refused"));
		assert!(again == value, "canonical re-encoding decodes to a different request");
		assert_eq!(to_value(&again), rendered, "re-decoded request serializes differently");

		let mut objects = 0;
		each_object(&rendered, &mut Vec::new(), &mut |path| {
			if objects == MAX_MUTATED_OBJECTS || self.inside_open(path) {
				return;
			}
			objects += 1;
			let mut mutated = rendered.clone();
			object_at(&mut mutated, path).insert(UNKNOWN_FIELD.to_owned(), Value::Null);
			assert!(
				(self.decode)(&render(&mutated)).is_none(),
				"unknown field accepted at depth {}",
				path.len()
			);
		});
		self.versions_closed(&rendered);
		self.objects_only(&rendered);

		let debug = format!("{value:?}");
		if self.exact_debug {
			let baseline = crate::utils::redact::Redaction::baseline(self.baseline);
			crate::utils::redact::assert_redacted(&debug, raw, &baseline);
		}
		assert_debug_hides(&debug, &rendered, self.baseline);
		Some(value)
	}

	fn inside_open(&self, path: &[Step]) -> bool {
		let keys: Vec<&str> = path
			.iter()
			.filter_map(|step| match step {
				Step::Key(key) => Some(key.as_str()),
				Step::Index(_) => None,
			})
			.collect();
		(self.open)(&keys)
	}

	/// serde's derived structs also accept a sequence of field values; every
	/// closed object must be refused in that array form.
	fn objects_only(&self, rendered: &Value) {
		let mut objects = 0;
		each_object(rendered, &mut Vec::new(), &mut |path| {
			if objects == MAX_MUTATED_OBJECTS || self.inside_open(path) {
				return;
			}
			objects += 1;
			let mut mutated = rendered.clone();
			let fields = object_at(&mut mutated, path);
			let sequence =
				Value::Array(std::mem::take(fields).into_iter().map(|(_, v)| v).collect());
			*value_at(&mut mutated, path) = sequence;
			assert!(
				(self.decode)(&render(&mutated)).is_none(),
				"array form of an object accepted at depth {}",
				path.len()
			);
		});
	}

	fn versions_closed(&self, rendered: &Value) {
		for &(key, accepted) in self.versions {
			each_object(rendered, &mut Vec::new(), &mut |path| {
				if self.inside_open(path) {
					return;
				}
				let mut mutated = rendered.clone();
				if !object_at(&mut mutated, path).contains_key(key) {
					return;
				}
				for other in other_versions(accepted) {
					object_at(&mut mutated, path).insert(key.to_owned(), other);
					assert!(
						(self.decode)(&render(&mutated)).is_none(),
						"closed version field {key} accepts another value"
					);
				}
				object_at(&mut mutated, path).remove(key);
				assert!(
					(self.decode)(&render(&mutated)).is_none(),
					"closed version field {key} may be omitted"
				);
			});
		}
	}
}

/// Every object of the schema is closed.
pub(crate) fn closed(_: &[&str]) -> bool {
	false
}

fn other_versions(accepted: u64) -> Vec<Value> {
	let mut values: Vec<Value> = [0, 1, 2, 3, 4, u64::from(u16::MAX) + 1, u64::from(u32::MAX) + 1]
		.into_iter()
		.filter(|value| *value != accepted)
		.map(Value::from)
		.collect();
	values.extend([
		json!(-1),
		json!(accepted as f64 + 0.5),
		json!(accepted.to_string()),
		Value::Null,
		json!([accepted]),
		json!({ accepted.to_string(): null }),
	]);
	values
}

/// Every string the value carries is absent from `debug`, unless the fixed
/// baseline rendering shows it too. Short strings are skipped: they match
/// schema text by coincidence and carry little payload.
pub(crate) fn assert_debug_hides(debug: &str, rendered: &Value, baseline: &str) {
	each_string(rendered, &mut |text| {
		if text.len() >= 4 && debug.contains(text) && !baseline.contains(text) {
			panic!("Debug rendering shows a carried string");
		}
	});
}

fn each_string(value: &Value, visit: &mut impl FnMut(&str)) {
	match value {
		Value::String(text) => visit(text),
		Value::Array(values) => values.iter().for_each(|nested| each_string(nested, visit)),
		Value::Object(fields) => fields.values().for_each(|nested| each_string(nested, visit)),
		_ => {},
	}
}

#[derive(Clone)]
pub(crate) enum Step {
	Key(String),
	Index(usize),
}

pub(crate) fn each_object(value: &Value, path: &mut Vec<Step>, visit: &mut impl FnMut(&[Step])) {
	match value {
		Value::Object(fields) => {
			visit(path);
			for (key, nested) in fields {
				path.push(Step::Key(key.clone()));
				each_object(nested, path, visit);
				path.pop();
			}
		},
		Value::Array(values) => {
			for (index, nested) in values.iter().enumerate() {
				path.push(Step::Index(index));
				each_object(nested, path, visit);
				path.pop();
			}
		},
		_ => {},
	}
}

pub(crate) fn object_at<'a>(value: &'a mut Value, path: &[Step]) -> &'a mut Map<String, Value> {
	value_at(value, path).as_object_mut().unwrap_or_else(|| panic!("visited path is an object"))
}

fn value_at<'a>(value: &'a mut Value, path: &[Step]) -> &'a mut Value {
	let mut current = value;
	for step in path {
		current = match step {
			Step::Key(key) => current.get_mut(key.as_str()),
			Step::Index(index) => current.get_mut(*index),
		}
		.unwrap_or_else(|| panic!("visited path exists"));
	}
	current
}

/// Serialize-only response oracle: production serialization equals the
/// independent rendering, and that rendering is valid canonical JSON.
pub(crate) fn assert_response(response: &impl Serialize, expected: Value) {
	let actual = to_value(response);
	assert_eq!(actual, expected, "response serialization differs from the independent rendering");
	let bytes = render(&expected);
	let reparsed: Value = serde_json::from_slice(&bytes)
		.unwrap_or_else(|_| panic!("independent response rendering is JSON"));
	assert_eq!(reparsed, expected);
}

/// A positive review identifier drawn from the input, with its wire value.
pub(crate) fn review_id(
	input: &mut crate::utils::input::ByteSource<'_>,
) -> Option<(loupe_proto::review_lease::ReviewId, i64)> {
	let raw = i64::from(input.u32()?) + 1;
	Some((loupe_proto::review_lease::ReviewId::try_from(raw).ok()?, raw))
}

/// A terminal finalize request is `{"protocol_version", "payload"}` around one
/// `core_review_payload` kind. Free mode decodes `rest`; sized mode wraps a
/// schema-valid payload of about the requested size, which must be accepted
/// iff it fits `payload_cap`. Accepted requests run the request oracles.
pub(crate) fn terminal<T: Serialize + PartialEq + Debug>(
	decode: &dyn Fn(&[u8]) -> Option<T>, kind: u8, caps: (usize, usize), sized: bool, rest: &[u8],
) {
	let (payload_cap, request_cap) = caps;
	let envelope = |target: u32| {
		let payload = crate::core_review_payload::sized_value(kind, target)
			.unwrap_or_else(|| panic!("payload kind"));
		let size = render(&payload).len();
		(
			render(&json!({"protocol_version": loupe_proto::PROTOCOL_VERSION, "payload": payload})),
			size,
		)
	};
	let baseline =
		format!("{:?}", decode(&envelope(0).0).unwrap_or_else(|| panic!("terminal seed")));
	let oracle = Request {
		decode,
		versions: &[("protocol_version", u64::from(loupe_proto::PROTOCOL_VERSION)), ("version", 1)],
		baseline: &baseline,
		exact_debug: true,
		open: &closed,
	};
	if !sized {
		if oracle.check(rest).is_some() {
			assert!(rest.len() <= request_cap, "terminal request above its byte cap");
		}
		return;
	}
	let Some(target) = crate::utils::input::ByteSource::new(rest).u32() else { return };
	let (raw, size) = envelope(target);
	assert_eq!(oracle.check(&raw).is_some(), size <= payload_cap, "sized payload of {size} bytes");
}

/// `bytes` input bytes as lowercase hex, e.g. a commit (20) or digest (32).
pub(crate) fn hex(input: &mut crate::utils::input::ByteSource<'_>, bytes: usize) -> Option<String> {
	Some(input.take(bytes)?.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub(crate) fn continuation(
	input: &mut crate::utils::input::ByteSource<'_>,
) -> Option<(loupe_proto::review_terminal::ContinuationSummary, Value)> {
	use loupe_core::review_payload::ContinuationClass as Class;
	use loupe_proto::review_terminal::{ContinuationBlockReason as Reason, ContinuationSummary};
	let choice = input.u8()?;
	let revision = u64::from(input.u32()?);
	let sequence = u64::from(input.u32()?);
	let (class, class_name) = match choice % 4 {
		0 => (Class::SourceAnalysisRemaining, "source_analysis_remaining"),
		1 => (Class::AwaitingProofInfrastructure, "awaiting_proof_infrastructure"),
		2 => (Class::ExternalDependency, "external_dependency"),
		_ => (Class::RequiresSuccessor, "requires_successor"),
	};
	if choice & 0x80 == 0 {
		let not_before = i64::from(input.u32()? as i32);
		let value = ContinuationSummary::Pending {
			class,
			revision,
			logical_sequence: sequence,
			not_before,
		};
		return Some((
			value,
			json!({"state": "pending", "class": class_name, "revision": revision,
				"logical_sequence": sequence, "not_before": not_before}),
		));
	}
	let (reason, reason_name) = match (choice >> 2) % 3 {
		0 => (Reason::AwaitingProofInfrastructure, "awaiting_proof_infrastructure"),
		1 => (Reason::ExternalDependency, "external_dependency"),
		_ => (Reason::RequiresSuccessor, "requires_successor"),
	};
	let value =
		ContinuationSummary::Blocked { class, revision, logical_sequence: sequence, reason };
	Some((
		value,
		json!({"state": "blocked", "class": class_name, "revision": revision,
			"logical_sequence": sequence, "reason": reason_name}),
	))
}

/// A receipt's server-owned commit and digest, labelled with the fixed fuzz
/// source; responses are generic over their metadata source.
pub(crate) fn receipt_metadata(
	input: &mut crate::utils::input::ByteSource<'_>,
) -> Option<(
	loupe_core::review_metadata::ReviewCommit<loupe_provenance::Agent>,
	loupe_core::review_metadata::ReviewDigest<loupe_provenance::Agent>,
	String,
	String,
)> {
	let commit_len = if input.u8()? & 1 == 0 { 20 } else { 32 };
	let commit = hex(input, commit_len)?;
	let digest = hex(input, 32)?;
	Some((
		crate::fixtures::identifier(&commit).unwrap_or_else(|_| panic!("hex commit is admitted")),
		crate::fixtures::identifier(&digest).unwrap_or_else(|_| panic!("hex digest is admitted")),
		commit,
		digest,
	))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn other_versions_never_include_the_accepted_value() {
		for accepted in [1, 3] {
			assert!(!other_versions(accepted).contains(&json!(accepted)));
		}
	}

	#[test]
	fn every_nested_object_is_visited_once() {
		let value = json!({"a": {"b": [{"c": 1}, 2, {"d": {}}]}});
		let mut count = 0;
		each_object(&value, &mut Vec::new(), &mut |_| count += 1);
		assert_eq!(count, 5);
	}

	#[test]
	#[should_panic(expected = "Debug rendering shows a carried string")]
	fn debug_leak_is_detected() {
		assert_debug_hides("Request(\"secret-text\")", &json!({"x": "secret-text"}), "Request");
	}

	#[test]
	fn schema_text_in_the_baseline_is_not_a_leak() {
		assert_debug_hides("Request<Worker>", &json!({"x": "Worker"}), "Request<Worker>");
	}
}
