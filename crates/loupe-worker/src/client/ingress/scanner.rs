//! The leased scanner document has its own schema and forwarding semantics.

use std::collections::HashMap;

use loupe_core::source_migration::text::BoundedText;
use loupe_provenance::{Mark, Server};
use serde_json::value::RawValue;
use serde_json::Value;

use crate::ingress_text::{json_text, DecodeError, ScannerExcludePattern, ScannerExtension};

struct MarkedPatch {
	include_extensions: Option<Vec<BoundedText<ScannerExtension, Server>>>,
	exclude_path_substrings: Option<Vec<BoundedText<ScannerExcludePattern, Server>>>,
}

pub(super) struct LeasedScannerDocument {
	value: Value,
	patch: Option<MarkedPatch>,
}

pub(super) fn decode(
	mark: &Mark<'_, Server>, token: &RawValue,
) -> Result<LeasedScannerDocument, DecodeError> {
	let mut fields = [None; 5];
	let shape_valid = if token.get().starts_with('{') {
		// Map collection intentionally preserves the prior Value's last-key-wins
		// behavior. Select tokens before decoding or checking their text policy.
		let map: HashMap<String, &RawValue> = serde_json::from_str(token.get())?;
		for (slot, name) in fields.iter_mut().zip([
			"max_concurrent_files",
			"max_file_bytes",
			"per_request_timeout_seconds",
			"include_extensions",
			"exclude_path_substrings",
		]) {
			*slot = map.get(name).copied();
		}
		true
	} else if token.get().starts_with('[') {
		let values: Vec<&RawValue> = serde_json::from_str(token.get())?;
		for (slot, value) in fields.iter_mut().zip(&values) {
			*slot = Some(*value);
		}
		values.len() <= 5
	} else {
		false
	};
	// Check every selected known text string even if a different known member
	// has a legacy schema error. New admission failures never fall back to raw
	// Value acceptance; non-string members still cause the old whole-patch fallback.
	macro_rules! list {
		($field:expr, $policy:ty) => {{
			let mut valid = true;
			let result = match $field {
				None => None,
				Some(raw) if raw.get() == "null" => None,
				Some(raw) if raw.get().starts_with('[') => {
					let values: Vec<&RawValue> = serde_json::from_str(raw.get())?;
					let mut texts = Vec::new();
					for value in values {
						if value.get().starts_with('"') {
							texts.push(json_text::<$policy, Server>(mark, value)?);
						} else {
							valid = false;
						}
					}
					Some(texts)
				},
				Some(_) => {
					valid = false;
					None
				},
			};
			(result, valid)
		}};
	}
	let (include_extensions, includes_valid) = list!(fields[3], ScannerExtension);
	let (exclude_path_substrings, excludes_valid) = list!(fields[4], ScannerExcludePattern);
	let concurrency_valid =
		fields[0].is_none_or(|t| serde_json::from_str::<Option<usize>>(t.get()).is_ok());
	let scalars_valid = fields[1..3]
		.iter()
		.all(|v| v.is_none_or(|t| serde_json::from_str::<Option<u64>>(t.get()).is_ok()));
	let patch =
		(shape_valid && includes_valid && excludes_valid && concurrency_valid && scalars_valid)
			.then_some(MarkedPatch { include_extensions, exclude_path_substrings });
	let value = serde_json::from_str(token.get())?;
	Ok(LeasedScannerDocument { value, patch })
}

impl LeasedScannerDocument {
	/// The sole private Value exit until M adopts the operational list owner.
	pub(super) fn into_legacy_value(mut self) -> Value {
		if let Some(patch) = self.patch {
			for (name, index, values) in [
				(
					"include_extensions",
					3,
					patch.include_extensions.map(|v| {
						v.into_iter()
							.map(|s| Value::String(s.expose().to_owned()))
							.collect::<Vec<_>>()
					}),
				),
				(
					"exclude_path_substrings",
					4,
					patch.exclude_path_substrings.map(|v| {
						v.into_iter()
							.map(|s| Value::String(s.expose().to_owned()))
							.collect::<Vec<_>>()
					}),
				),
			] {
				if let Some(values) = values {
					match &mut self.value {
						Value::Object(map) => {
							map.insert(name.into(), Value::Array(values));
						},
						Value::Array(items) => {
							if let Some(slot) = items.get_mut(index) {
								*slot = Value::Array(values);
							}
						},
						_ => {},
					}
				}
			}
		}
		self.value
	}
}
