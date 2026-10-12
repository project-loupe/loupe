//! Raw UTF-8 JSON, capped at 128 KiB to exercise the 64 KiB raw-byte boundary.
//! A duplicate-preserving tree separates parsing from an independent budget
//! walk. Leaf/key policies have their own acceptance targets; this target
//! checks their composition, normalization, and all aggregate limits.

use std::collections::BTreeSet;
use std::fmt;

use loupe_core::text::policy::{JsonKey, JsonLeaf, Payload};
use loupe_core::text::{JsonPolicy, Rule};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{Number, Value};

use crate::utils::test_logger;

enum Raw {
	Scalar(Value),
	Text(String),
	Array(Vec<Raw>),
	Object(Vec<(String, Raw)>),
}

impl<'de> Deserialize<'de> for Raw {
	fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		deserializer.deserialize_any(RawVisitor)
	}
}

struct RawVisitor;
impl<'de> Visitor<'de> for RawVisitor {
	type Value = Raw;
	fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("JSON retaining every object entry")
	}
	fn visit_unit<E: serde::de::Error>(self) -> Result<Raw, E> {
		Ok(Raw::Scalar(Value::Null))
	}
	fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Raw, E> {
		Ok(Raw::Scalar(Value::Bool(value)))
	}
	fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Raw, E> {
		Ok(Raw::Scalar(Value::Number(value.into())))
	}
	fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Raw, E> {
		Ok(Raw::Scalar(Value::Number(value.into())))
	}
	fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Raw, E> {
		Number::from_f64(value)
			.map(|number| Raw::Scalar(Value::Number(number)))
			.ok_or_else(|| E::custom("non-finite JSON number"))
	}
	fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Raw, E> {
		Ok(Raw::Text(value.to_owned()))
	}
	fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Raw, E> {
		Ok(Raw::Text(value))
	}
	fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Raw, A::Error> {
		let mut items = Vec::new();
		while let Some(item) = sequence.next_element()? {
			items.push(item);
		}
		Ok(Raw::Array(items))
	}
	fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Raw, A::Error> {
		let mut entries = Vec::new();
		while let Some(entry) = map.next_entry()? {
			entries.push(entry);
		}
		Ok(Raw::Object(entries))
	}
}

#[derive(Default)]
struct Budget {
	nodes: usize,
	text_bytes: usize,
}

fn normalize(tree: &Raw, depth: usize, budget: &mut Budget) -> Option<Value> {
	budget.nodes += 1;
	if depth > Payload::MAX_DEPTH || budget.nodes > Payload::MAX_NODES {
		return None;
	}
	let result = match tree {
		Raw::Scalar(value) => value.clone(),
		Raw::Text(raw) => {
			budget.text_bytes += raw.len();
			Value::String(crate::fixtures::text::<JsonLeaf>(raw).ok()?.expose().to_owned())
		},
		Raw::Array(items) => Value::Array(
			items.iter().map(|item| normalize(item, depth + 1, budget)).collect::<Option<_>>()?,
		),
		Raw::Object(entries) => {
			let mut seen = BTreeSet::new();
			for (key, _) in entries {
				budget.text_bytes += key.len();
				crate::fixtures::identifier::<JsonKey>(key).ok()?;
				if !seen.insert(key) {
					return None;
				}
			}
			// Insert sorted keys even with serde_json preserve_order enabled.
			let mut entries: Vec<_> = entries.iter().collect();
			entries.sort_unstable_by_key(|(key, _)| key);
			let mut object = serde_json::Map::new();
			for (key, value) in entries {
				object.insert(key.clone(), normalize(value, depth + 1, budget)?);
			}
			Value::Object(object)
		},
	};
	(budget.text_bytes <= Payload::MAX_BYTES).then_some(result)
}

pub fn do_test(data: &[u8]) {
	if data.len() > 128 * 1024 {
		return;
	}
	let Ok(raw) = std::str::from_utf8(data) else { return };
	let expected = serde_json::from_str::<Raw>(raw)
		.ok()
		.and_then(|tree| normalize(&tree, 1, &mut Budget::default()))
		.and_then(|value| serde_json::to_vec(&value).ok())
		.filter(|bytes| bytes.len() <= Payload::MAX_BYTES);
	let direct = crate::fixtures::json::<Payload>(raw);
	let embedded = loupe_core::text::fuzz_payload_visitor(raw);
	assert_eq!(
		direct.is_ok(),
		expected.is_some() && raw.len() <= Payload::MAX_BYTES,
		"raw bounded JSON acceptance disagrees with independent tree walk"
	);
	assert_eq!(
		embedded.is_some(),
		expected.is_some(),
		"embedded bounded JSON acceptance disagrees with independent tree walk"
	);
	if raw.len() <= Payload::MAX_BYTES {
		assert_eq!(
			direct.as_ref().ok().map(|value| (value.expose(), *value.digest())),
			embedded.as_ref().map(|(text, digest)| (text.as_str(), *digest)),
			"JSON entry points must agree"
		);
	}
	if let Some((canonical, digest)) = &embedded {
		assert_eq!(Some(canonical.as_bytes()), expected.as_deref());
		assert_eq!(digest, blake3::hash(canonical.as_bytes()).as_bytes());
		assert_eq!(loupe_core::text::fuzz_payload_visitor(canonical).as_ref(), embedded.as_ref());
	}
	if let Ok(accepted) = &direct {
		assert_eq!(Some(accepted.canonical()), expected.as_deref());
		assert_eq!(accepted.expose().as_bytes(), accepted.canonical());
		assert_eq!(accepted.digest(), blake3::hash(accepted.canonical()).as_bytes());
		assert_eq!(
			format!("{accepted:?}"),
			format!("BoundedJson<payload, agent>(len={}, [redacted])", accepted.canonical().len())
		);
		assert_eq!(
			crate::fixtures::json::<Payload>(accepted.expose()).as_ref().ok(),
			Some(accepted)
		);
	}
	if let Err(error) = direct {
		assert!(matches!(error.field, "payload" | "json_leaf" | "json_key"));
		let rule = match error.rule {
			Rule::Character => "Character",
			Rule::Chars => "Chars",
			Rule::Bytes => "Bytes",
			Rule::Whitespace => "Whitespace",
			Rule::Identifier => "Identifier",
			Rule::JsonSyntax => "JsonSyntax",
			Rule::JsonDepth => "JsonDepth",
			Rule::JsonNodes => "JsonNodes",
			Rule::JsonDuplicateKey => "JsonDuplicateKey",
			_ => panic!("unexpected bounded JSON error rule"),
		};
		let mut expected = format!("{}: {rule}", error.field);
		if let Some(point) = error.code_point {
			assert_eq!(error.rule, Rule::Character);
			expected.push_str(&format!(" (U+{point:04X})"));
		} else {
			assert_ne!(error.rule, Rule::Character);
		}
		assert_eq!(error.to_string(), expected, "JSON error must contain only metadata");
		assert_eq!(format!("{error:?}"), expected);
	}
}

pub fn core_text_json_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn core_text_json_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
