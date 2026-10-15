//! Redaction checks against a payload-independent rendering.
//!
//! Build the baseline from a sentinel with the same public metadata as
//! the fuzzed value. Fixed redacted renderings must remain byte-for-byte
//! identical for every payload, including payloads that match metadata.
//! Comparing complete renderings also catches a leaked copy of the word
//! `redacted`, which a baseline-filtered substring search would miss.

pub struct Redaction {
	rendering: String,
}

impl Redaction {
	pub fn baseline(rendering: impl Into<String>) -> Self {
		Self { rendering: rendering.into() }
	}
}

/// Assert that changing the payload leaves a redacted rendering unchanged.
///
/// The baseline must have the same public metadata (policy, source, IDs,
/// counts, etc.). A type with variable metadata should construct a matching
/// baseline or check its exact documented rendering directly. The payload
/// argument identifies the source being tested without printing it on failure.
pub fn assert_redacted(text: &str, _payload: &[u8], baseline: &Redaction) {
	assert!(text == baseline.rendering, "redacted rendering depends on payload");
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn redacted_text_passes() {
		let baseline = Redaction::baseline("Untrusted<agent>([redacted])");
		assert_redacted("Untrusted<agent>([redacted])", b"0123456789", &baseline);
	}

	#[test]
	#[should_panic(expected = "redacted rendering depends on payload")]
	fn leaked_text_fails() {
		let baseline = Redaction::baseline("Title([redacted])");
		assert_redacted("Title(\"0123456789\")", b"0123456789", &baseline);
	}

	#[test]
	fn short_payloads_are_checked_whole() {
		assert_redacted("ok", b"zz", &Redaction::baseline("ok"));
		assert_redacted("", b"", &Redaction::baseline(""));
	}

	#[test]
	fn fixed_metadata_is_not_payload_disclosure() {
		assert_redacted("[redacted]", b"redacted", &Redaction::baseline("[redacted]"));
	}

	#[test]
	#[should_panic(expected = "redacted rendering depends on payload")]
	fn leaked_copy_of_static_metadata_is_detected() {
		assert_redacted("[redacted]redacted", b"redacted", &Redaction::baseline("[redacted]"));
	}
}
