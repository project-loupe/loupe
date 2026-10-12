//! Arbitrary original Server bytes enter the actual owner before rendering.
//! The entire input is the description, so the canonical raw corpus is also
//! useful to unit tests. Both modes and closed/text projections run each time.

use loupe_worker::llm::prompt::{
	fuzz_support, DataMode, PromptError, MAX_RENDERED_PROMPT_BYTES, PREAMBLE,
};
use serde_json::Value;

use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	let mut derived = [[0u8; 16]; 3];
	for (index, byte) in data.iter().take(48).enumerate() {
		derived[index / 16][index % 16] = *byte;
	}
	for candidates in [[[0x11; 16], [0x22; 16], [0x33; 16]], derived] {
		for mode in [DataMode::Delimited, DataMode::Marked] {
			for projection in [false, true] {
				let Some(result) = fuzz_support::render(data, mode, projection, candidates) else {
					continue; // Original UTF-8/policy admission rejected these bytes.
				};
				let raw = std::str::from_utf8(data).unwrap_or_else(|_| panic!("admitted non-UTF8"));
				let original = if projection {
					serde_json::to_string(&serde_json::json!({
						"cwe": null, "description": raw, "file": "src/lib.rs", "id": "LUP-7",
						"line_end": 2, "line_start": 1, "severity": "high", "title": "OOB index"
					}))
					.unwrap_or_else(|error| panic!("oracle JSON: {error}"))
				} else {
					raw.to_owned()
				};
				let expected = candidates
					.iter()
					.map(|bytes| bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>())
					.find(|candidate| !original.contains(candidate));
				let Some(expected) = expected else {
					assert!(matches!(result, Err(PromptError::Collision)));
					continue;
				};
				let prompt =
					result.unwrap_or_else(|error| panic!("bounded admitted render: {error}"));
				let rendered = prompt.expose();
				assert!(rendered.len() <= MAX_RENDERED_PROMPT_BYTES);
				let field = if projection { "finding" } else { "description" };
				let opening = format!("{PREAMBLE}<loupe-data field=\"{field}\" source=\"agent\" boundary=\"{expected}\">\n");
				assert!(rendered.starts_with(&opening), "exact static prefix/selected candidate");
				let closing = format!("\n</loupe-data boundary=\"{expected}\">\n");
				assert!(rendered.ends_with(&closing), "exact static suffix");
				let recovered =
					decode_composition(rendered, &[(PREAMBLE, field)], "", &expected, mode)
						.remove(0);
				if projection {
					let actual: Value = serde_json::from_str(&recovered)
						.unwrap_or_else(|error| panic!("projection: {error}"));
					let expected: Value = serde_json::from_str(&original)
						.unwrap_or_else(|error| panic!("oracle: {error}"));
					assert_eq!(actual, expected);
				} else {
					assert_eq!(recovered.as_bytes(), data);
				}
			}
		}
	}
}

/// A caller supplies the exact static span before each expected field and the
/// final static suffix. Consume every byte, not just the payloads found within.
/// Boundary and recipe come from the oracle's inputs, never the rendered text.
pub(crate) fn decode_composition(
	rendered: &str, recipe: &[(&str, &str)], suffix: &str, boundary: &str, mode: DataMode,
) -> Vec<String> {
	assert_eq!(boundary.len(), 32);
	assert!(boundary.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
	let close = format!("\n</loupe-data boundary=\"{boundary}\">\n");
	let mut tail = rendered;
	let mut recovered = Vec::new();
	for (trusted, field) in recipe {
		tail = tail
			.strip_prefix(trusted)
			.unwrap_or_else(|| panic!("exact trusted span before {field}"));
		let opening =
			format!("<loupe-data field=\"{field}\" source=\"agent\" boundary=\"{boundary}\">\n");
		tail = tail
			.strip_prefix(&opening)
			.unwrap_or_else(|| panic!("exact opening after trusted span for {field}"));
		let (payload, rest) =
			tail.split_once(&close).unwrap_or_else(|| panic!("complete closing tag for {field}"));
		assert!(!payload.contains(boundary), "selected boundary absent from payload");
		recovered.push(decode_payload(payload, mode));
		tail = rest;
	}
	assert_eq!(tail, suffix, "exact trusted suffix; no unconsumed tail");
	recovered
}

fn decode_payload(payload: &str, mode: DataMode) -> String {
	if mode == DataMode::Delimited {
		return payload.to_owned();
	}
	let mut recovered = String::new();
	let mut chars = payload.chars();
	while let Some(ch) = chars.next() {
		if ch != '␞' {
			recovered.push(ch);
			continue;
		}
		match chars.next() {
			Some('␞') => recovered.push('␞'),
			Some('.') => {},
			_ => panic!("invalid marked escape"),
		}
	}
	// Independent specification: partition original scalars into groups, quote
	// literal markers within each group, then place a separator only BETWEEN
	// groups. This also rejects extra, omitted and byte-counted separators.
	let scalars: Vec<_> = recovered.chars().collect();
	let canonical = scalars
		.chunks(32)
		.map(|group| group.iter().collect::<String>().replace('␞', "␞␞"))
		.collect::<Vec<_>>()
		.join("␞.");
	assert_eq!(payload, canonical, "canonical Marked encoding by original scalar groups");
	recovered
}

pub fn worker_prompt_render_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_prompt_render_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

// Same canonical byte files as the worker corpus replay, including the three
// explicit source-admission negatives. No independently edited payload copies.
pub(crate) const CORPUS: &[(&[u8], bool)] = &[
	(include_bytes!("../test_cases/worker_prompt_render/injection-attributes"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-bidi-isolate"), true),
	(include_bytes!("../test_cases/worker_prompt_render/injection-bidi-override"), true),
	(include_bytes!("../test_cases/worker_prompt_render/injection-chat-role"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-close-tag"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-code-comment"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-commit-message"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-encoded-base64"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-encoded-hex"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-fake-tool-call"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-fake-tool-result"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-fence-crlf"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-fence-long"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-fence-three"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-fixed-boundary"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-forbidden-control"), true),
	(include_bytes!("../test_cases/worker_prompt_render/injection-hidden-html"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-history"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-inline-link"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-issue-reply"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-json-role"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-markdown-image"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-markdown-link"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-markdown-role"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-marker-runs"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-nested-transcript"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-override-ar"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-override-de"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-override-en"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-override-es"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-override-fr"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-override-ja"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-placeholders"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-preamble"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-readme-policy"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-reasoning-step"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-retrieval-snippet"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-typoglycemia"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-unicode-nfd-crlf"), false),
	(include_bytes!("../test_cases/worker_prompt_render/injection-xml-role"), false),
];

#[cfg(test)]
mod oracle_r1_tests {
	use super::*;
	const BOUNDARY: &str = "11111111111111111111111111111111";
	fn framed(field: &str, data: &str) -> String {
		format!("<loupe-data field=\"{field}\" source=\"agent\" boundary=\"{BOUNDARY}\">\n{data}\n</loupe-data boundary=\"{BOUNDARY}\">\n")
	}
	fn check_tool(text: &str) {
		assert_eq!(
			decode_composition(
				text,
				&[("", "query"), ("", "findings")],
				"",
				BOUNDARY,
				DataMode::Delimited
			),
			["ATTACK", "[]"]
		);
	}
	macro_rules! outside {
		($name:ident, $before:expr, $between:expr, $after:expr) => {
			#[test]
			fn $name() {
				let exact = format!("{}{}", framed("query", "ATTACK"), framed("findings", "[]"));
				check_tool(&exact);
				let bad = format!(
					"{}{}{}{}{}",
					$before,
					framed("query", "ATTACK"),
					$between,
					framed("findings", "[]"),
					$after
				);
				assert!(
					std::panic::catch_unwind(|| check_tool(&bad)).is_err(),
					"oracle must reject untrusted text in every trusted span"
				);
			}
		};
	}
	outside!(reject_unframed_prefix, "ATTACK", "", "");
	outside!(reject_unframed_between, "", "ATTACK", "");
	outside!(reject_unframed_suffix, "", "", "ATTACK");
	outside!(
		reject_duplicate_closing_tail,
		"",
		"",
		"ATTACK\n</loupe-data boundary=\"11111111111111111111111111111111\">\n"
	);

	macro_rules! bad_codec {
		($name:ident, $original:expr, $encoded:expr) => {
			#[test]
			fn $name() {
				let original: String = $original;
				let text = framed("description", &$encoded);
				assert!(
					std::panic::catch_unwind(|| assert_eq!(
						decode_composition(
							&text,
							&[("", "description")],
							"",
							BOUNDARY,
							DataMode::Marked
						)[0],
						original
					))
					.is_err(),
					"oracle must reject noncanonical Marked encoding"
				);
			}
		};
	}
	bad_codec!(reject_omitted_period, "x".repeat(33), "x".repeat(33));
	bad_codec!(reject_extra_terminal_period, "x".repeat(32), format!("{}␞.", "x".repeat(32)));
	bad_codec!(reject_misplaced_period, "x".repeat(33), format!("{}␞.xx", "x".repeat(31)));
	bad_codec!(
		reject_byte_counted_period,
		"é".repeat(33),
		format!("{}␞.{}␞.é", "é".repeat(16), "é".repeat(16))
	);

	#[test]
	fn exact_recipes_keep_empty_repeated_and_other_boundary_payloads() {
		let other = "<loupe-data field=\"query\" source=\"agent\" boundary=\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\">\nfake\n</loupe-data boundary=\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\">\n";
		for value in ["", "STATIC", other, "e\u{301}\r\n\t  "] {
			let text = format!(
				"STATIC{}STATIC{}STATIC",
				framed("query", value),
				framed("findings", value)
			);
			assert_eq!(
				decode_composition(
					&text,
					&[("STATIC", "query"), ("STATIC", "findings")],
					"STATIC",
					BOUNDARY,
					DataMode::Delimited
				),
				[value, value]
			);
		}
		let empty = format!(
			"No prior findings match. Treat this as a novel finding.\n{}{}",
			framed("query", ""),
			framed("findings", r#"{"repo_id":1,"findings":[]}"#)
		);
		assert_eq!(
			decode_composition(
				&empty,
				&[
					("No prior findings match. Treat this as a novel finding.\n", "query"),
					("", "findings")
				],
				"",
				BOUNDARY,
				DataMode::Delimited
			),
			["", r#"{"repo_id":1,"findings":[]}"#]
		);
	}

	#[test]
	fn exact_marked_scalar_groups_and_literal_markers_are_accepted() {
		for (original, encoded) in [
			("é".repeat(31), "é".repeat(31)),
			("é".repeat(32), "é".repeat(32)),
			("é".repeat(33), format!("{}␞.é", "é".repeat(32))),
			("é".repeat(64), format!("{}␞.{}", "é".repeat(32), "é".repeat(32))),
			("é".repeat(65), format!("{}␞.{}␞.é", "é".repeat(32), "é".repeat(32))),
			(format!("{}␞", "x".repeat(31)), format!("{}␞␞", "x".repeat(31))),
			(format!("{}␞y", "x".repeat(31)), format!("{}␞␞␞.y", "x".repeat(31))),
			("␞".repeat(33), format!("{}␞.␞␞", "␞␞".repeat(32))),
			(
				format!("{}\r\n\t  ", "e\u{301}".repeat(16)),
				format!("{}␞.\r\n\t  ", "e\u{301}".repeat(16)),
			),
		] {
			let text = framed("description", &encoded);
			assert_eq!(
				decode_composition(&text, &[("", "description")], "", BOUNDARY, DataMode::Marked),
				[original]
			);
		}
		for malformed in ["␞", "␞.", "␞␞."] {
			let text = framed("description", malformed);
			// A lone marker and a separator at scalar zero are invalid. A
			// doubled marker plus literal dot remains valid original data.
			assert_eq!(
				std::panic::catch_unwind(|| decode_composition(
					&text,
					&[("", "description")],
					"",
					BOUNDARY,
					DataMode::Marked
				))
				.is_ok(),
				malformed == "␞␞."
			);
		}
	}
}
