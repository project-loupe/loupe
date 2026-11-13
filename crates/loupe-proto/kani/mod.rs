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

// Bound: every i64.
// invariant: I6
// ci: fast
#[kani::proof]
fn review_id_rejects_non_positive_values() {
	use crate::review_lease::ReviewId;
	let raw: i64 = kani::any();
	let id = ReviewId::try_from(raw);
	assert_eq!(id.is_ok(), raw > 0);
	if let Ok(id) = id {
		assert_eq!(i64::from(id), raw);
	}
	kani::cover!(raw == 1 && id.is_ok(), "smallest id accepted");
	kani::cover!(raw == 0 && id.is_err(), "zero id refused");
	kani::cover!(raw == i64::MIN && id.is_err(), "most negative id refused");
}

// Bound: ReviewCommit and ReviewDigest admission
// predicates over every length 0..=65 of a lowercase-hex filler with one
// arbitrary ASCII byte at an arbitrary position: 40 is the SHA-1 commit, 64
// the SHA-256 commit and the digest, 65 the first overlong input, and the
// single byte reaches every per-byte accept/reject case. Fully symbolic
// content timed out at 600s (attempts: arbitrary UTF-8, ASCII through
// from_utf8, ASCII pushed into a String), and so did this single-byte domain
// (listed in ci/kani-no-verdict.txt); ReviewId is proved separately by
// review_id_rejects_non_positive_values. Multi-byte content is the fuzz
// targets'. The marked constructors need a Mark, which this crate cannot mint
// outside tests (forbid(unsafe_code)); review_metadata_identifiers_never_panic
// in loupe-core covers the constructor path. Unwind 67 covers the 65-byte
// loops plus termination.
// invariant: I6
#[kani::proof]
#[kani::unwind(67)]
fn review_id_and_commit_newtypes_never_panic() {
	use loupe_core::text::IdentPolicy;

	use crate::review_lease::{CommitPolicy, DigestPolicy};
	let len: usize = kani::any();
	let position: usize = kani::any();
	let byte: u8 = kani::any();
	kani::assume(len <= 65 && byte.is_ascii());
	let mut bytes = [b'a'; 65];
	if position < len {
		bytes[position] = byte;
	}
	let mut owned = String::with_capacity(bytes.len());
	for byte in &bytes[..len] {
		owned.push(char::from(*byte));
	}
	let text = owned.as_str();
	let hex = position >= len || byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte);
	let commit = CommitPolicy::accepts(text);
	let digest = DigestPolicy::accepts(text);
	assert_eq!(commit, (len == 40 || len == 64) && hex);
	assert_eq!(digest, len == 64 && hex);
	kani::cover!(commit && len == 40, "SHA-1 commit accepted");
	kani::cover!(commit && digest, "64-hex commit and digest accepted");
	kani::cover!(
		!digest && len == 64 && byte == b'A' && position < len,
		"uppercase digest refused"
	);
	kani::cover!(!commit && len == 65, "overlong commit refused");
}
