//! The leased scanner document has its own schema and forwarding semantics.

use std::collections::HashMap;

use loupe_provenance::{Mark, Server};
use serde_json::value::RawValue;

use crate::ingress_text::{json_text, DecodeError, ScannerExcludePattern, ScannerExtension};
use crate::source_discovery::{ScannerConfigPatch, ScannerList};

pub(super) struct LeasedScannerDocument {
	pub(super) document: loupe_proto::ScannerDocument<Server>,
	pub(super) patch: Option<ScannerConfigPatch>,
}

pub(super) fn decode(
	mark: &Mark<'_, Server>, token: &RawValue,
) -> Result<LeasedScannerDocument, DecodeError> {
	let mut fields = [None; 5];
	let shape_valid = if token.get().starts_with('{') {
		// Duplicate keys use the last value. Select tokens before decoding or
		// checking their text policy so overwritten fields do not affect admission.
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
	// has a schema error. Text-policy failures reject the document; malformed
	// patch shapes retain the raw document and use the default scanner settings.
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
			.then(|| ScannerConfigPatch {
				max_concurrent_files: fields[0]
					.and_then(|t| serde_json::from_str(t.get()).ok())
					.flatten(),
				max_file_bytes: fields[1]
					.and_then(|t| serde_json::from_str(t.get()).ok())
					.flatten(),
				per_request_timeout_seconds: fields[2]
					.and_then(|t| serde_json::from_str(t.get()).ok())
					.flatten(),
				include_extensions: include_extensions.map(ScannerList::Leased),
				exclude_path_substrings: exclude_path_substrings.map(ScannerList::Leased),
			});
	let value: serde_json::Value = serde_json::from_str(token.get())?;
	if patch.is_none() && !value.is_null() {
		tracing::warn!("ignoring scanner_config: not a ScannerConfigPatch");
	}
	Ok(LeasedScannerDocument { document: loupe_proto::ScannerDocument::leased(mark, value), patch })
}
