//! A byte observer, deliberately not a JSON parser or source validator.
//! Every valid decoded string run is observed, even in malformed ignored data.
use loupe_provenance::Zeroise;

struct Run(Vec<u8>);
impl Run {
	fn clear(&mut self) {
		// The initialized prefix is wiped before reuse; spare capacity is
		// wiped once on drop. Clearing every allocation on every bad escape
		// would make malformed records take quadratic time.
		self.0.as_mut_slice().zeroise();
		self.0.clear();
	}
}
impl Drop for Run {
	fn drop(&mut self) {
		self.0.zeroise();
	}
}

pub(super) fn contains(record: &[u8], mut matches: impl FnMut(&[u8]) -> bool) -> bool {
	if matches(record) {
		return true;
	}
	// Decoding never expands original JSON bytes. Allocate once so potential
	// secret bytes cannot be left behind by a growing allocation.
	let mut run = Run(Vec::with_capacity(record.len()));
	let mut at = 0;
	while let Some(byte) = record.get(at) {
		at += 1;
		if *byte != b'"' {
			continue;
		}
		while let Some(byte) = record.get(at).copied() {
			if byte == b'"' {
				at += 1;
				break;
			}
			let decoded = unit(record, &mut at);
			if let Some(ch) = decoded {
				let mut bytes = [0u8; 4];
				run.0.extend_from_slice(ch.encode_utf8(&mut bytes).as_bytes());
				bytes.zeroise();
			} else {
				if matches(&run.0) {
					return true;
				}
				run.clear();
			}
		}
		if matches(&run.0) {
			return true;
		}
		run.clear();
	}
	false
}

fn unit(record: &[u8], at: &mut usize) -> Option<char> {
	let byte = *record.get(*at)?;
	*at += 1;
	if byte != b'\\' {
		if byte.is_ascii() {
			return (byte >= 0x20).then_some(char::from(byte));
		}
		let width = match byte {
			0xc2..=0xdf => 2,
			0xe0..=0xef => 3,
			0xf0..=0xf4 => 4,
			_ => return None,
		};
		let end = at.checked_add(width - 1)?;
		let bytes = record.get(*at - 1..end)?;
		let ch = std::str::from_utf8(bytes).ok()?.chars().next()?;
		*at = end;
		return Some(ch);
	}
	let escaped = *record.get(*at)?;
	*at += 1;
	match escaped {
		b'"' => Some('"'),
		b'\\' => Some('\\'),
		b'/' => Some('/'),
		b'b' => Some('\u{8}'),
		b'f' => Some('\u{c}'),
		b'n' => Some('\n'),
		b'r' => Some('\r'),
		b't' => Some('\t'),
		b'u' => {
			let scalar = hex_unit(record, at)?;
			if (0xd800..=0xdbff).contains(&scalar) {
				// A non-low following escape belongs to the next decoded run.
				// Do not consume it as part of the malformed high surrogate.
				let mut next = *at;
				if record.get(next..next + 2) != Some(b"\\u") {
					return None;
				}
				next += 2;
				let low = hex_unit(record, &mut next)?;
				if !(0xdc00..=0xdfff).contains(&low) {
					return None;
				}
				*at = next;
				char::from_u32(0x10000 + ((scalar - 0xd800) << 10) + low - 0xdc00)
			} else {
				char::from_u32(scalar)
			}
		},
		_ => None,
	}
}

fn hex_unit(record: &[u8], at: &mut usize) -> Option<u32> {
	let mut value = 0u32;
	let mut valid = true;
	for _ in 0..4 {
		let byte = *record.get(*at)?;
		// Recover at lexical boundaries instead of swallowing the next string
		// or a later valid escape when an ignored malformed unit is short.
		if matches!(byte, b'"' | b'\\') {
			return None;
		}
		*at += 1;
		match char::from(byte).to_digit(16) {
			Some(digit) => value = value * 16 + digit,
			None => valid = false,
		}
	}
	valid.then_some(value)
}
