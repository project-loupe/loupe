//! The span extractor balances braces without validating JSON.

use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	let Ok(input) = std::str::from_utf8(data) else { return };
	let expected = balanced_span(input);
	let actual = loupe_worker::llm::extract_json_object(input);
	assert_eq!(actual.as_deref(), expected);
}

fn balanced_span(input: &str) -> Option<&str> {
	let start = input.find('{')?;
	let mut depth = 0;
	let mut quoted = false;
	let mut slashes = 0;
	for (index, character) in input.char_indices().filter(|(index, _)| *index >= start) {
		if character == '"' && slashes % 2 == 0 {
			quoted = !quoted;
		}
		if !quoted {
			if character == '{' {
				depth += 1;
			}
			if character == '}' {
				depth -= 1;
				if depth == 0 {
					return input.get(start..index + 1);
				}
			}
		}
		slashes = if quoted && character == '\\' { slashes + 1 } else { 0 };
	}
	None
}

pub fn worker_extract_json_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes during the call.
#[allow(unsafe_code)] // C fuzz entry point.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_extract_json_run(data: *const u8, datalen: usize) {
	// SAFETY: supplied by the caller as documented above.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
