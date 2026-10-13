//! Raw and lexical canary observation against serde's scalar decoder.
//!
//! One length byte selects up to 64 watched bytes; the rest is an original
//! record, capped at 4096 bytes. No record is admitted or interpreted as a map.
use crate::utils::test_logger;

const RECORD_MAX: usize = 4096;
const WATCH_MAX: usize = 64;

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
	!needle.is_empty()
		&& haystack
			.iter()
			.enumerate()
			.any(|(index, _)| haystack.get(index..index + needle.len()) == Some(needle))
}

// Use an independent JSON implementation to decode one complete scalar. The
// longest encoded scalar is a pair of six-byte UTF-16 escapes. Trying bounded
// prefixes also handles UTF-8 without copying production width/surrogate rules.
fn scalar(input: &[u8]) -> Option<(usize, String)> {
	for width in 1..=input.len().min(12) {
		let mut quoted = Vec::with_capacity(width + 2);
		quoted.push(b'"');
		quoted.extend_from_slice(&input[..width]);
		quoted.push(b'"');
		if let Ok(decoded) = serde_json::from_slice::<String>(&quoted)
			&& decoded.chars().count() == 1
		{
			return Some((width, decoded));
		}
	}
	None
}

// A malformed unit breaks the decoded run. Consume its own bytes, preserving
// the next quote or escape as a recovery boundary. In particular an unpaired
// high surrogate never consumes a following non-low Unicode escape.
fn malformed_width(input: &[u8]) -> usize {
	if input.first() != Some(&b'\\') || input.len() == 1 {
		return 1;
	}
	if input.get(1) != Some(&b'u') {
		return 2;
	}
	2 + input.iter().skip(2).take(4).take_while(|byte| !matches!(byte, b'"' | b'\\')).count()
}

fn reference(record: &[u8], watched: &[u8]) -> bool {
	if contains(record, watched) {
		return true;
	}
	let mut remaining = record;
	while let Some(open) = remaining.iter().position(|byte| *byte == b'"') {
		remaining = &remaining[open + 1..];
		let mut run = Vec::new();
		while !remaining.is_empty() {
			if remaining[0] == b'"' {
				remaining = &remaining[1..];
				break;
			}
			if let Some((width, decoded)) = scalar(remaining) {
				run.extend_from_slice(decoded.as_bytes());
				remaining = &remaining[width..];
			} else {
				if contains(&run, watched) {
					return true;
				}
				run.clear();
				remaining = &remaining[malformed_width(remaining)..];
			}
		}
		if contains(&run, watched) {
			return true;
		}
	}
	false
}

pub fn do_test(data: &[u8]) {
	let Some((&length, body)) = data.split_first() else { return };
	let length = usize::from(length) % (WATCH_MAX + 1);
	if body.len() < length || body.len() - length > RECORD_MAX {
		return;
	}
	let (watched, record) = body.split_at(length);
	assert_eq!(
		loupe_worker::canary::fuzz_observes(record, watched),
		reference(record, watched),
		"canary observation differs from independent raw and scalar oracle"
	);
}

pub fn worker_canary_observe_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_canary_observe_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn lexical_controls_cover_hits_and_barriers() {
		let cases: &[(&[u8], &[u8], bool)] = &[
			(b"key", b"key outside JSON", true),
			(b"key", br#"{"ignored":"\u006bey","ignored":"safe"}"#, true),
			(b"key", br#"{"bad":"\uXX","next":"\u006bey"}"#, true),
			(b"key", br#""\u006be\qy""#, false),
			(b"key", br#""\u006be" "y""#, false),
			(b"key", br#""\uD800\u006bey""#, true),
			(b"key", br#""\u006be\uD800y""#, false),
			(b"key", br#""\u006be\uDC00y""#, false),
			(b"key", b"\"\\u006be\xffy\"", false),
			(b"key", b"\"\\u006be\x00y\"", false),
			(b"key", br#""\\u006bey""#, false),
			(b"key", br#"\u006bey"#, false),
			(b"key", br#""\u006bey" trailing broken JSON"#, true),
			(b"key", br#""\u006bey"#, true),
			("😀".as_bytes(), br#""\uD83D\uDE00""#, true),
			(b"\n/\t", br#""\n\/\t""#, true),
			(b"\x08\x0c\r", br#""\b\f\r""#, true),
			(b"a\"b", br#""a\"b""#, true),
			(b"a\\b", br#""a\\b""#, true),
			("e\u{301}".as_bytes(), br#""e\u0301""#, true),
			("é".as_bytes(), br#""e\u0301""#, false),
			(b"", b"anything", false),
		];
		for (watched, record, expected) in cases {
			assert_eq!(reference(record, watched), *expected, "reference fixture {record:?}");
			let mut input = vec![watched.len() as u8];
			input.extend_from_slice(watched);
			input.extend_from_slice(record);
			do_test(&input);
		}
	}

	#[test]
	fn bounded_original_byte_combinations() {
		let mut state = 0x9642_0178_31ef_bca5u64;
		for _ in 0..256 {
			let mut input = [0u8; 160];
			for byte in &mut input {
				state ^= state << 13;
				state ^= state >> 7;
				state ^= state << 17;
				*byte = state as u8;
			}
			do_test(&input);
		}
	}
}
