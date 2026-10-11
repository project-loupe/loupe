//! Protocol decision proofs; run only through `ci/kani.sh`.

// Bound: Every u16 client/min/max triple, including inverted windows.
// Error fields retain the exact numbers; the separate formatting proof checks
// their rendered representation.
// ci: fast
#[kani::proof]
fn protocol_check_is_total() {
	let version: u16 = kani::any();
	let minimum: u16 = kani::any();
	let maximum: u16 = kani::any();
	let result = crate::check_protocol_version(version, minimum, maximum);
	assert_eq!(result.is_ok(), minimum <= version && version <= maximum);
	if let Err(error) = &result {
		assert_eq!(error.client, version);
		assert_eq!(error.server_min, minimum);
		assert_eq!(error.server_max, maximum);
	}
	kani::cover!(
		minimum == version && version == maximum && result.is_ok(),
		"inclusive singleton window"
	);
	kani::cover!(version < minimum && result.is_err(), "old client");
	kani::cover!(version > maximum && result.is_err(), "future client");
	kani::cover!(minimum > maximum && result.is_err(), "inverted window");
}

struct Message {
	bytes: [u8; 128],
	len: usize,
}

impl Message {
	fn empty() -> Self {
		Self { bytes: [0; 128], len: 0 }
	}
	fn append(&mut self, text: &[u8]) {
		let end = self.len + text.len();
		self.bytes[self.len..end].copy_from_slice(text);
		self.len = end;
	}
	fn decimal(&mut self, mut number: u16) {
		let mut reversed = [0; 5];
		let mut count = 0;
		loop {
			reversed[count] = b'0' + (number % 10) as u8;
			count += 1;
			number /= 10;
			if number == 0 {
				break;
			}
		}
		while count != 0 {
			count -= 1;
			self.append(&[reversed[count]]);
		}
	}
}

impl std::fmt::Write for Message {
	fn write_str(&mut self, text: &str) -> std::fmt::Result {
		self.append(text.as_bytes());
		Ok(())
	}
}

// Bound: All u16 triples, at most five decimal digits per number and
// a fixed 128-byte output buffer (the longest message is below this bound).
// Independent division-by-ten encoding avoids a second formatting call.
// Compare eight 16-byte chunks: unwind 17 covers each memcmp and termination.
#[kani::proof]
#[kani::unwind(17)]
fn protocol_error_names_exact_versions() {
	use std::fmt::Write;
	let client: u16 = kani::any();
	let server_min: u16 = kani::any();
	let server_max: u16 = kani::any();
	let error = crate::ProtocolMismatch { client, server_min, server_max };
	let mut actual = Message::empty();
	write!(&mut actual, "{error}").unwrap();
	let mut expected = Message::empty();
	expected.append(b"loupe protocol version mismatch: client sent ");
	expected.decimal(client);
	expected.append(b", server supports [");
	expected.decimal(server_min);
	expected.append(b", ");
	expected.decimal(server_max);
	expected.append(b"]");
	assert_eq!(actual.len, expected.len);
	for (actual, expected) in actual.bytes.chunks_exact(16).zip(expected.bytes.chunks_exact(16)) {
		assert!(actual == expected);
	}
	kani::cover!(client == 0 && server_min == 0 && server_max == 0, "zero versions");
	kani::cover!(
		client == u16::MAX && server_min == u16::MAX && server_max == u16::MAX,
		"largest versions"
	);
	kani::cover!(
		client == 42 && server_min == 3 && server_max == 1200,
		"three distinct version fields"
	);
}
