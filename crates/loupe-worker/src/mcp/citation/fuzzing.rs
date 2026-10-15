//! Fixture-only observation of the actual post-admission citation validator.
//! File opening/metadata and Agent text admission remain covered at their own
//! ingress boundaries. This seam neither issues provenance nor returns a sink.
use std::io::Read;

use super::{check_source, CitationError};

pub struct Input<'a> {
	pub source: &'a [u8],
	pub file: &'a str,
	pub description: &'a str,
	pub start: u32,
	pub end: u32,
	pub read_chunk: usize,
	pub cancel_before: bool,
	/// One-based read number that publishes cancellation before returning bytes.
	pub cancel_on_read: Option<usize>,
}

// debug-ok: closed categories and a host-computed digest, never input text.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
	Accepted { fingerprint: String },
	Rejected(Failure),
}
// debug-ok: fixed error categories without paths, source text or I/O messages.
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
	Missing,
	NotRegular,
	Range,
	Quote,
	Io,
	Utf8,
	Task,
	Cancelled,
}
// debug-ok: closed outcome plus numerical I/O observations.
#[derive(Debug)]
pub struct Observation {
	pub outcome: Outcome,
	pub reads: usize,
	pub maximum_read_request: usize,
}

struct Chunked<'a> {
	source: &'a [u8],
	chunk: usize,
	reads: usize,
	maximum: usize,
	cancel_on_read: Option<usize>,
	cancel: tokio_util::sync::CancellationToken,
}
impl Read for Chunked<'_> {
	fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
		self.reads += 1;
		self.maximum = self.maximum.max(output.len());
		if self.cancel_on_read == Some(self.reads) {
			self.cancel.cancel();
		}
		let count = output.len().min(self.chunk).min(self.source.len());
		output[..count].copy_from_slice(&self.source[..count]);
		self.source = &self.source[count..];
		Ok(count)
	}
}

pub fn observe(input: Input<'_>) -> Observation {
	let cancel = tokio_util::sync::CancellationToken::new();
	if input.cancel_before {
		cancel.cancel();
	}
	let mut reader = Chunked {
		source: input.source,
		chunk: input.read_chunk.clamp(1, 8192),
		reads: 0,
		maximum: 0,
		cancel_on_read: input.cancel_on_read,
		cancel: cancel.clone(),
	};
	let result = check_source(
		&mut reader,
		input.file,
		input.start,
		input.end,
		input.description.as_bytes(),
		&cancel,
	);
	let outcome = match result {
		Ok(hash) => Outcome::Accepted { fingerprint: hash.to_hex().to_string() },
		Err(error) => Outcome::Rejected(match error {
			CitationError::Missing => Failure::Missing,
			CitationError::NotRegular => Failure::NotRegular,
			CitationError::Range => Failure::Range,
			CitationError::Quote => Failure::Quote,
			CitationError::Io => Failure::Io,
			CitationError::Utf8 => Failure::Utf8,
			CitationError::Task => Failure::Task,
			CitationError::Cancelled => Failure::Cancelled,
		}),
	};
	Observation { outcome, reads: reader.reads, maximum_read_request: reader.maximum }
}
