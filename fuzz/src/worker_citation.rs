//! Independent oracle for the post-admission citation validator. This does not
//! exercise path/descriptor admission, job quarantine, PoC Git checks or egress.
//!
//! Input: flags:u8, read_chunk:u16, cancel_read:u16 (0 = never), start/end:u32,
//! file and description as u16-length-prefixed bytes, then source bytes. All
//! integers are little endian. Flag 0 cancels before validation; flag 1 derives
//! a fence from the first source line to keep exact quotes reachable by mutation.
//! File/description bytes become UTF-8 lossily only to satisfy the seam's string
//! API; source bytes remain exact. Source, description and file are bounded.

use loupe_worker::mcp::citation_fuzzing::{observe, Failure, Input, Observation, Outcome};

use crate::utils::input::ByteSource;
use crate::utils::test_logger;

const MAX_SOURCE: usize = 32_768;
const MAX_DESCRIPTION: usize = 16_384;
const MAX_INPUT: usize = MAX_SOURCE + MAX_DESCRIPTION + 512;

pub fn do_test(data: &[u8]) {
	if data.len() > MAX_INPUT {
		return;
	}
	let mut bytes = ByteSource::new(data);
	let flags = bytes.u8().unwrap_or(0);
	let read_chunk = usize::from(bytes.u16().unwrap_or(8192));
	let cancellation = usize::from(bytes.u16().unwrap_or(0));
	let start = bytes.u32().unwrap_or(1);
	let end = bytes.u32().unwrap_or(start);
	let file = String::from_utf8_lossy(bytes.len_prefixed(256).unwrap_or(b"src/file.rs"));
	let description = String::from_utf8_lossy(bytes.len_prefixed(MAX_DESCRIPTION).unwrap_or(b""));
	let source = bytes.rest();
	let source = &source[..source.len().min(MAX_SOURCE)];
	let generated;
	let description = if flags & 2 != 0 {
		let first = source.split(|byte| *byte == b'\n').next().unwrap_or_default();
		let first = &first[..first.len().min(1024)];
		generated = format!("```\n{}\n```", String::from_utf8_lossy(first));
		generated.as_str()
	} else {
		&description
	};
	let input = Input {
		source,
		file: &file,
		description,
		start,
		end,
		read_chunk,
		cancel_before: flags & 1 != 0,
		cancel_on_read: (cancellation != 0).then_some(cancellation),
	};
	let expected = oracle(&input);
	let actual = observe(input);
	assert_eq!(actual.outcome, expected.outcome, "citation outcome/fingerprint differs");
	assert_eq!(actual.reads, expected.reads, "citation source read count differs");
	assert_eq!(
		actual.maximum_read_request, expected.maximum_read_request,
		"citation source request bound differs"
	);
}

// A row-oriented, whole-description parser: no production fence/search helper.
// Opening tails are unrestricted; a close permits only ASCII space and tab.
fn marker(row: &str) -> Option<(char, usize, &str)> {
	let row = row.strip_suffix('\n').map_or(row, |s| s.strip_suffix('\r').unwrap_or(s));
	let content = row.trim_start_matches(' ');
	if row.len() - content.len() > 3 {
		return None;
	}
	let character = content.chars().next()?;
	if character != '`' && character != '~' {
		return None;
	}
	let tail = content.trim_start_matches(character);
	let length = content.len() - tail.len();
	(length >= 3).then_some((character, length, tail))
}

fn claimed_quotes(description: &str) -> Result<Vec<String>, Failure> {
	let rows: Vec<_> = description.split_inclusive('\n').collect();
	let mut quotes = Vec::new();
	let mut index = 0;
	while index < rows.len() {
		let Some((kind, width, _)) = marker(rows[index]) else {
			index += 1;
			continue;
		};
		let close = (index + 1..rows.len()).find(|at| {
			marker(rows[*at]).is_some_and(|(end_kind, end_width, tail)| {
				kind == end_kind
					&& end_width >= width
					&& tail.bytes().all(|b| b == b' ' || b == b'\t')
			})
		});
		let Some(close) = close else { return Err(Failure::Quote) };
		let mut payload = rows[index + 1..close].concat();
		if payload.ends_with('\n') {
			payload.pop();
			if payload.ends_with('\r') {
				payload.pop();
			}
		}
		if payload.is_empty() {
			return Err(Failure::Quote);
		}
		quotes.push(payload);
		index = close + 1;
	}
	Ok(quotes)
}

// Fingerprint grammar, evaluated over complete selected lines. Using
// whole-string Unicode lowercasing deliberately differs from streaming state.
fn full_window_fingerprint(file: &str, source: &str, start: u32, end: u32) -> String {
	let normalized = source
		.lines()
		.enumerate()
		.filter(|(index, _)| {
			let line = *index as u64 + 1;
			line + 2 >= u64::from(start) && line <= u64::from(end.saturating_add(2))
		})
		.filter_map(|(_, line)| {
			let words = line.split_whitespace().collect::<Vec<_>>();
			(!words.is_empty()).then(|| words.join(" ").to_lowercase())
		})
		.collect::<Vec<_>>()
		.join("\n");
	let framed = [b"llm-code-review\0", file.as_bytes(), b"\0", normalized.as_bytes()].concat();
	blake3::hash(&framed).to_hex().to_string()
}

fn observation(outcome: Outcome, reads: usize) -> Observation {
	Observation { outcome, reads, maximum_read_request: if reads == 0 { 0 } else { 8192 } }
}

fn oracle(input: &Input<'_>) -> Observation {
	let reject = |failure, reads| observation(Outcome::Rejected(failure), reads);
	if input.cancel_before {
		return reject(Failure::Cancelled, 0);
	}
	let quotes = match claimed_quotes(input.description) {
		Ok(quotes) => quotes,
		Err(failure) => return reject(failure, 0),
	};
	let chunk = input.read_chunk.clamp(1, 8192);
	let eof_read = input.source.len().div_ceil(chunk) + 1;
	let decoded = std::str::from_utf8(input.source);
	let utf8_read = decoded.as_ref().err().map(|error| {
		// UTF-8 validity itself comes from std, independently of the production
		// scalar decoder. The validator diagnoses a bad scalar once its nominal
		// width arrives, or on EOF if truncated (even for an early bad tail).
		let at = error.valid_up_to();
		let lead = input.source[at];
		let width = match lead {
			0xc2..=0xdf => 2,
			0xe0..=0xef => 3,
			0xf0..=0xf4 => 4,
			_ => 1,
		};
		if at + width > input.source.len() {
			eof_read
		} else {
			(at + width).div_ceil(chunk)
		}
	});
	let final_read = utf8_read.unwrap_or(eof_read);
	if let Some(cancel) = input.cancel_on_read
		&& cancel != 0
		&& cancel <= final_read
	{
		return reject(Failure::Cancelled, cancel);
	}
	let source = match decoded {
		Ok(source) => source,
		Err(_) => return reject(Failure::Utf8, final_read),
	};
	let lines = source.lines().count().max(1) as u64;
	if input.start == 0 || input.start > input.end || u64::from(input.end) > lines {
		return reject(Failure::Range, eof_read);
	}
	let selected = source
		.split_inclusive('\n')
		.enumerate()
		.filter_map(|(index, line)| {
			let number = index as u64 + 1;
			(number >= u64::from(input.start) && number <= u64::from(input.end)).then_some(line)
		})
		.collect::<String>();
	if quotes.iter().any(|quote| !selected.contains(quote)) {
		return reject(Failure::Quote, eof_read);
	}
	observation(
		Outcome::Accepted {
			fingerprint: full_window_fingerprint(input.file, source, input.start, input.end),
		},
		eof_read,
	)
}

pub fn worker_citation_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// The caller supplies `len` readable bytes at `data` for this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_citation_run(data: *const u8, len: usize) {
	// SAFETY: the C runner guarantees the readable input buffer.
	do_test(unsafe { std::slice::from_raw_parts(data, len) });
}

#[cfg(test)]
mod tests {
	use super::*;

	fn fixture<'a>(source: &'a [u8], description: &'a str, start: u32, end: u32) -> Input<'a> {
		Input {
			source,
			file: "src/file.rs",
			description,
			start,
			end,
			read_chunk: 8192,
			cancel_before: false,
			cancel_on_read: None,
		}
	}

	fn encoded(input: &Input<'_>) -> Vec<u8> {
		let mut data = vec![u8::from(input.cancel_before)];
		data.extend_from_slice(&(input.read_chunk as u16).to_le_bytes());
		data.extend_from_slice(&(input.cancel_on_read.unwrap_or(0) as u16).to_le_bytes());
		data.extend_from_slice(&input.start.to_le_bytes());
		data.extend_from_slice(&input.end.to_le_bytes());
		for field in [input.file.as_bytes(), input.description.as_bytes()] {
			data.extend_from_slice(&(field.len() as u16).to_le_bytes());
			data.extend_from_slice(field);
		}
		data.extend_from_slice(input.source);
		data
	}

	// The expected bytes are authored independently for each fixture, including
	// the scanner/path framing and already-normalized content. They never pass
	// through the reference normalization or range/fence implementation.
	fn accepted(framed: &[u8]) -> Outcome {
		Outcome::Accepted { fingerprint: blake3::hash(framed).to_hex().to_string() }
	}

	fn control(input: Input<'_>, expected: Outcome, reads: usize) {
		let predicted = oracle(&input);
		assert_eq!(predicted.outcome, expected, "oracle fixture outcome");
		assert_eq!(predicted.reads, reads, "oracle fixture read count");
		assert_eq!(predicted.maximum_read_request, if reads == 0 { 0 } else { 8192 });
		// Always exercise the actual byte entry point after checking the oracle.
		do_test(&encoded(&input));
	}

	#[test]
	fn positive_fence_grammar_has_explicit_fingerprints() {
		for description in [
			"plain prose",
			"```rust\nAlpha\n```",
			"   ~~~rust\nAlpha\n  ~~~~ \t\n",
			"```arbitrary`opening tail\nAlpha\n```",
			"```\nAlpha\n```\n~~~\nBeta\n~~~",
			"    ```\nnot a fence\n    ```",
			"\t```\nnot a fence\n\t```",
		] {
			control(
				fixture(b"Alpha\nBeta\n", description, 1, 2),
				accepted(b"llm-code-review\0src/file.rs\0alpha\nbeta"),
				2,
			);
		}
		control(
			fixture(b"prefixAlphaSuffix", "```\nAlpha\n```", 1, 1),
			accepted(b"llm-code-review\0src/file.rs\0prefixalphasuffix"),
			2,
		);
		// A wrong-kind delimiter and a trailing-payload delimiter are quote text
		// until a valid close appears, and are required verbatim in the source.
		control(
			fixture(b"Alpha\n~~~\n```tail\nBeta", "```\nAlpha\n~~~\n```tail\nBeta\n```", 1, 4),
			accepted(b"llm-code-review\0src/file.rs\0alpha\n~~~\n```tail\nbeta"),
			2,
		);
	}

	#[test]
	fn invalid_fences_reject_before_reading() {
		for description in [
			"```\n```",
			"```\r\n```\r\n",
			"```",
			"```\nAlpha",
			"````\nAlpha\n```",
			"```\nAlpha\n~~~",
			"```\nAlpha\n```tail",
			"```\nAlpha\n```\u{a0}",
			"```\nAlpha\n    ```",
			"```\nAlpha\n```\r",
			"```\nAlpha\n```\n```",
		] {
			control(fixture(b"Alpha\n", description, 1, 1), Outcome::Rejected(Failure::Quote), 0);
		}
	}

	#[test]
	fn exact_quote_controls_distinguish_normalization() {
		for (source, description, start, end) in [
			(b"Alpha\nBeta".as_slice(), "```\nInvented\n```", 1, 2),
			(b"Alpha\nBeta", "```\nBeta\n```", 1, 1),
			(b"Alpha\nBeta", "```\nAlpha\nBeta\n```", 1, 1),
			(b"a\r\nb\r\n", "```\na\nb\n```", 1, 2),
			("cafe\u{301}\n".as_bytes(), "```\ncafé\n```", 1, 1),
			("café\n".as_bytes(), "```\ncafe\u{301}\n```", 1, 1),
			(b"Alpha", "```\nalpha\n```", 1, 1),
			(b"Alpha  Beta", "```\nAlpha Beta\n```", 1, 1),
		] {
			control(fixture(source, description, start, end), Outcome::Rejected(Failure::Quote), 2);
		}
		control(
			fixture(b"a\r\nb\r\n", "```\r\na\r\nb\r\n```\r\n", 1, 2),
			accepted(b"llm-code-review\0src/file.rs\0a\nb"),
			2,
		);
		control(
			fixture("cafe\u{301}\n".as_bytes(), "```\ncafe\u{301}\n```", 1, 1),
			accepted("llm-code-review\0src/file.rs\0cafe\u{301}".as_bytes()),
			2,
		);
		control(
			fixture(b"a\n", "```\na\n\n```", 1, 1),
			accepted(b"llm-code-review\0src/file.rs\0a"),
			2,
		);
	}

	#[test]
	fn range_controls_include_empty_source_and_final_lf() {
		for (source, start, end) in [
			(b"Alpha\n".as_slice(), 0, 1),
			(b"Alpha\n", 2, 1),
			(b"Alpha\n", 1, 2),
			(b"Alpha\n", 1, u32::MAX),
			(b"Alpha\n", u32::MAX, u32::MAX),
			(b"", 0, 0),
			(b"", 1, 2),
		] {
			control(
				fixture(source, "", start, end),
				Outcome::Rejected(Failure::Range),
				if source.is_empty() { 1 } else { 2 },
			);
		}
		for source in [b"".as_slice(), b"\n", b"\r", b"\r\n"] {
			control(
				fixture(source, "", 1, 1),
				accepted(b"llm-code-review\0src/file.rs\0"),
				if source.is_empty() { 1 } else { 2 },
			);
		}
		control(
			fixture(b"excluded\n TWO \nTHREE\nFour\nFIVE\nSIX\nexcluded", "", 4, 4),
			accepted(b"llm-code-review\0src/file.rs\0two\nthree\nfour\nfive\nsix"),
			2,
		);
	}

	#[test]
	fn unicode_full_line_lowercase_and_path_framing_are_pinned() {
		let source = "ΟΣ ΑΣ\nAΣ'\u{301}A AΣ'\u{301}.\nΣΣ Σ\n\tİ K 𐐀\u{a0}END\n";
		let expected =
			"llm-code-review\0src/file.rs\0ος ας\naσ'\u{301}a aς'\u{301}.\nσς σ\ni\u{307} k 𐐨 end";
		for chunk in [0, 1, 2, 3, 4, 7, 8191, 8192, 8193, u16::MAX as usize] {
			let mut input = fixture(source.as_bytes(), "", 1, 4);
			input.read_chunk = chunk;
			control(
				input,
				accepted(expected.as_bytes()),
				source.len().div_ceil(chunk.clamp(1, 8192)) + 1,
			);
		}
		let mut input = fixture(b"Alpha", "", 1, 1);
		input.file = "other/Σ\0file.rs";
		control(input, accepted("llm-code-review\0other/Σ\0file.rs\0alpha".as_bytes()), 2);
	}

	#[test]
	fn utf8_errors_keep_read_and_cancellation_precedence() {
		for source in [
			b"\xff".as_slice(),
			b"\xc0\x80",
			b"\xed\xa0\x80",
			b"\xf4\x90\x80\x80",
			b"\xe2\x82",
			b"a\xe2A",
			b"\xe2A\x80",
		] {
			let mut input = fixture(source, "", 0, 0);
			let reads = if source == b"\xe2\x82" || source == b"a\xe2A" { 2 } else { 1 };
			control(fixture(source, "", 0, 0), Outcome::Rejected(Failure::Utf8), reads);
			input.cancel_on_read = Some(1);
			control(input, Outcome::Rejected(Failure::Cancelled), 1);
		}
		let mut input = fixture(b"\xe2A\x80", "", 1, 1);
		input.read_chunk = 1;
		control(input, Outcome::Rejected(Failure::Utf8), 3);
		let mut input = fixture(b"\xe2A\x80", "", 1, 1);
		input.read_chunk = 1;
		input.cancel_on_read = Some(2);
		control(input, Outcome::Rejected(Failure::Cancelled), 2);
		let mut input = fixture(b"\xffabc", "", 1, 1);
		input.read_chunk = 1;
		input.cancel_on_read = Some(2);
		control(input, Outcome::Rejected(Failure::Utf8), 1);
	}

	#[test]
	fn cancellation_controls_stop_before_bytes_and_at_eof() {
		let mut input = fixture(b"Alpha", "```", 0, 0);
		input.cancel_before = true;
		control(input, Outcome::Rejected(Failure::Cancelled), 0);
		let mut input = fixture(b"Alpha", "```", 1, 1);
		input.cancel_on_read = Some(1);
		control(input, Outcome::Rejected(Failure::Quote), 0);
		for read in 1..=4 {
			let mut input = fixture(b"Alpha", "", 1, 1);
			input.read_chunk = 2;
			input.cancel_on_read = Some(read);
			control(input, Outcome::Rejected(Failure::Cancelled), read);
		}
		let mut input = fixture(b"Alpha", "", 1, 1);
		input.read_chunk = 2;
		input.cancel_on_read = Some(5);
		control(input, accepted(b"llm-code-review\0src/file.rs\0alpha"), 4);
		let mut input = fixture(b"", "", 1, 1);
		input.cancel_on_read = Some(1);
		control(input, Outcome::Rejected(Failure::Cancelled), 1);
	}

	#[test]
	fn eight_kib_boundaries_split_quotes_scalars_and_sigma_context() {
		for length in [8191usize, 8192, 8193, 16384, MAX_SOURCE] {
			let source = vec![b'A'; length];
			let expected = format!("llm-code-review\0src/file.rs\0{}", "a".repeat(length));
			control(
				fixture(&source, "```\nAAA\n```", 1, 1),
				accepted(expected.as_bytes()),
				length.div_ceil(8192) + 1,
			);
		}
		for suffix in [".", "A"] {
			let marks = "'".repeat(8192);
			let source = format!("AΣ{marks}{suffix}");
			let sigma = if suffix == "." { 'ς' } else { 'σ' };
			let expected =
				format!("llm-code-review\0src/file.rs\0a{sigma}{marks}{}", suffix.to_lowercase());
			control(fixture(source.as_bytes(), "", 1, 1), accepted(expected.as_bytes()), 3);
		}
		for prefix in [8188, 8189, 8190, 8191, 8192, 8193] {
			let source = format!("{}AΣ'\u{301}A € END", " ".repeat(prefix));
			for chunk in [1, 8191, 8192, 8193] {
				let mut input = fixture(source.as_bytes(), "```\nAΣ'\u{301}A €\n```", 1, 1);
				input.read_chunk = chunk;
				control(
					input,
					accepted("llm-code-review\0src/file.rs\0aσ'\u{301}a € end".as_bytes()),
					source.len().div_ceil(chunk.min(8192)) + 1,
				);
			}
		}
		let mut source = vec![b' '; 8191];
		source.extend_from_slice(b"\xe2A\x80");
		control(fixture(&source, "", 1, 1), Outcome::Rejected(Failure::Utf8), 2);
	}

	#[test]
	fn derived_quote_mode_and_short_inputs_reach_the_entry_point() {
		let mut data = encoded(&fixture(b"Alpha\nBeta", "ignored", 1, 1));
		data[0] = 2;
		do_test(&data);
		for len in 0..data.len() {
			do_test(&data[..len]);
		}
	}
}
