//! Byte zero selects the 32/64-item policy; the rest is UTF-8 JSON. Input is
//! capped at 128 KiB so both sides of the 64 KiB raw/canonical limits are tested.

use loupe_core::text::policy::Symbol;
use loupe_core::text::{BoundedText, Error, Rule, SourceRef};
use loupe_storage::source_refs::SourceRefs;
use serde::Deserialize;
use unicode_general_category::{get_general_category, GeneralCategory};

use crate::utils::test_logger;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRef {
	path: String,
	symbol: Option<String>,
}

pub fn do_test(data: &[u8]) {
	let Some((&policy, bytes)) = data.split_first() else { return };
	if bytes.len() > 128 * 1024 {
		return;
	}
	let Ok(raw) = std::str::from_utf8(bytes) else { return };
	if policy & 1 == 0 {
		check::<32>(raw);
	} else {
		check::<64>(raw);
	}
}

fn valid_path(path: &str) -> bool {
	!path.is_empty()
		&& path.len() <= 512
		&& !path.contains('\\')
		&& path.split('/').all(|piece| !piece.is_empty() && piece != "." && piece != "..")
		&& path.chars().all(|character| {
			let point = u32::from(character);
			!matches!(
				get_general_category(character),
				GeneralCategory::Control
					| GeneralCategory::Format
					| GeneralCategory::Unassigned
					| GeneralCategory::PrivateUse
					| GeneralCategory::LineSeparator
					| GeneralCategory::ParagraphSeparator
			) && !(0xfdd0..=0xfdef).contains(&point)
				&& !matches!(point % 65536, 65534 | 65535)
		})
}

fn check<const MAX: usize>(raw: &str) {
	let decoded = serde_json::from_str::<Vec<RawRef>>(raw);
	let expected_items = decoded.as_ref().ok().and_then(|refs| {
		refs.iter()
			.map(|entry| {
				if !valid_path(&entry.path) {
					return None;
				}
				let symbol = entry
					.symbol
					.as_deref()
					.map(crate::fixtures::text::<Symbol>)
					.transpose()
					.ok()?;
				Some(
					serde_json::json!({"path": entry.path, "symbol": symbol.as_ref().map(BoundedText::expose)}),
				)
			})
			.collect::<Option<Vec<_>>>()
	});
	let expected = expected_items.map(|items| {
		let count = items.len();
		(count, loupe_core::canonical::canonical_bytes(&serde_json::Value::Array(items)))
	});
	let bounded =
		expected.as_ref().is_some_and(|(count, bytes)| *count <= MAX && bytes.len() <= 65536);
	let parsed = loupe_storage::source_refs::fuzz_decode::<MAX>(raw.as_bytes());
	assert_eq!(
		parsed.is_ok(),
		bounded && raw.len() <= 65536,
		"source reference admission disagrees with oracle"
	);
	if let Ok(value) = &parsed {
		check_output(value, &decoded, &expected);
	}

	// Construct independently admitted source-owned items; this tests new()'s
	// canonical budget separately from the actual column decoder's raw cap.
	let items = decoded.as_ref().ok().and_then(|items| {
		items
			.iter()
			.map(|item| {
				Some(SourceRef {
					path: crate::fixtures::path(&item.path).ok()?,
					symbol: item
						.symbol
						.as_deref()
						.map(crate::fixtures::text::<Symbol>)
						.transpose()
						.ok()?,
				})
			})
			.collect::<Option<Vec<_>>>()
	});
	if let Some(items) = items {
		let count = items.len();
		let built = crate::fixtures::agent(raw, |mark, _| SourceRefs::<MAX, _>::new(mark, items));
		assert_eq!(built.is_ok(), bounded, "source reference constructor disagrees with oracle");
		if let Ok(value) = &built {
			check_output(value, &decoded, &expected);
		}
		if raw.len() <= 65536 {
			if count > MAX {
				// The constructor reports its count policy; the actual SQL
				// envelope parser maps the same excess to fixed schema metadata.
				assert_eq!(built, Err(Error::new("source_refs", Rule::JsonNodes)));
				assert_eq!(parsed, Err(Error::new("stored_value", Rule::JsonSyntax)));
			} else {
				assert_eq!(
					built, parsed,
					"constructor and column decoder must agree within raw budget"
				);
			}
		}
	}
}

fn check_output<const MAX: usize>(
	value: &SourceRefs<MAX, loupe_provenance::Agent>,
	decoded: &Result<Vec<RawRef>, serde_json::Error>, expected: &Option<(usize, Vec<u8>)>,
) {
	let Some((count, bytes)) = expected else { panic!("accepted refs need a valid oracle value") };
	assert_eq!(value.expose().as_bytes(), bytes);
	assert_eq!(value.as_slice().len(), *count);
	assert!(*count <= MAX && bytes.len() <= 65536);
	assert_eq!(format!("{value:?}"), format!("SourceRefs(count={count})"));
	let refs = decoded.as_ref().unwrap_or_else(|_| panic!("accepted refs must decode"));
	for (original, stored) in refs.iter().zip(value.as_slice()) {
		assert_eq!(original.path, stored.path.expose(), "repository path bytes must be preserved");
	}
	let replay = loupe_storage::source_refs::fuzz_decode::<MAX>(value.expose().as_bytes());
	assert_eq!(replay.as_ref().ok(), Some(value), "stored source references must round-trip");
}

pub fn storage_source_refs_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn storage_source_refs_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	fn count(policy: u8, count: usize) {
		let items = vec![serde_json::json!({"path": "src/file.rs", "symbol": "symbol"}); count];
		let raw =
			serde_json::to_vec(&items).unwrap_or_else(|error| panic!("fixture JSON: {error}"));
		let mut input = vec![policy];
		input.extend_from_slice(&raw);
		super::do_test(&input);
	}

	#[test]
	fn unit_refs_below_limit() {
		count(0, 31);
	}
	#[test]
	fn unit_refs_at_limit() {
		count(0, 32);
	}
	#[test]
	fn unit_refs_excess_valid_item_has_each_owners_fixed_error() {
		count(0, 33);
	}
	#[test]
	fn inspected_refs_below_limit() {
		count(1, 63);
	}
	#[test]
	fn inspected_refs_at_limit() {
		count(1, 64);
	}
	#[test]
	fn inspected_refs_excess_valid_item_has_each_owners_fixed_error() {
		count(1, 65);
	}
}
