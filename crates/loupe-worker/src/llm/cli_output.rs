//! Bounded stdout/stderr capture shared by both CLI backends.
//!
//! Keep at most 1 MiB per stream, retaining the beginning and the end for
//! diagnostics. Continue draining discarded bytes so neither pipe can stall
//! the child. The caller's request deadline bounds draining and process wait.

use loupe_provenance::{Ingress, Mark, Sandbox, Untrusted, Unvalidated, Validate};
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) const MAX_CLI_OUTPUT_BYTES: usize = 1024 * 1024;

pub(crate) struct CapturedOutput {
	bytes: Untrusted<Vec<u8>, Sandbox>,
	pub truncated: bool,
	#[cfg(test)]
	capacity: usize,
}

#[derive(Clone)]
pub struct CliOutputText(String);
impl std::fmt::Debug for CliOutputText {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("CliOutputText<Sandbox>([redacted])")
	}
}
impl CliOutputText {
	pub fn char_count(&self) -> usize {
		self.0.chars().count()
	}
	/// Synthetic and integration assertions only; production has no text sink.
	#[cfg(any(test, feature = "test-support"))]
	pub fn for_log(&self) -> &str {
		&self.0
	}
}
struct CliOutputDecoder;
impl Validate<&[u8], Sandbox> for CliOutputDecoder {
	type Output = CliOutputText;
	type Error = std::str::Utf8Error;
	fn validate<'view>(
		self, u: Unvalidated<'view, &[u8]>, _: Mark<'view, Sandbox>,
	) -> Result<Self::Output, Self::Error> {
		Ok(CliOutputText(std::str::from_utf8(u.get())?.to_owned()))
	}
}

/// Explicit synthetic response fixture authority, absent from the default
/// library. This does not call or claim the actual subprocess pipe collector.
#[cfg(any(test, feature = "test-support"))]
pub(super) fn synthetic_output(text: String) -> Result<CliOutputText, std::str::Utf8Error> {
	// SAFETY: this crate's unit tests or the explicitly enabled test-support
	// feature authorize original synthetic Sandbox response fixtures. These
	// bytes come from the stub closure, not from a live subprocess pipe.
	#[allow(unsafe_code)]
	let fixture = Untrusted::new(text.into_bytes(), unsafe { Ingress::<Sandbox>::new() });
	fixture.as_bytes().validate(CliOutputDecoder)
}

pub(crate) struct CliFailureDiagnostic(String);
impl std::fmt::Debug for CliFailureDiagnostic {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("CliFailureDiagnostic<Sandbox>([redacted])")
	}
}

// debug-ok: fixed backend/status plus explicitly redacted stream owners.
#[derive(Debug)]
pub(crate) struct CliProcessFailure {
	pub backend: &'static str,
	pub status: std::process::ExitStatus,
	pub stderr: CliFailureDiagnostic,
	pub stdout: CliFailureDiagnostic,
	#[cfg(test)]
	pub max_chars: usize,
}
impl std::fmt::Display for CliProcessFailure {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"{} CLI exited with {}: stderr(chars={})=[redacted] stdout(chars={})=[redacted]",
			self.backend,
			self.status,
			self.stderr.0.chars().count(),
			self.stdout.0.chars().count()
		)
	}
}
#[cfg(test)]
impl CliProcessFailure {
	/// Preserve exact bounded head/tail assertions without opening a host log sink.
	pub(crate) fn test_diagnostic(&self) -> String {
		format!(
			"{} CLI exited with {}: stderr(chars={})=`{}` stdout(chars={})=`{}`",
			self.backend,
			self.status,
			self.stderr.for_log().chars().count(),
			super::summarize_cli_stream_for_error(self.stderr.for_log(), self.max_chars),
			self.stdout.for_log().chars().count(),
			super::summarize_cli_stream_for_error(self.stdout.for_log(), self.max_chars)
		)
	}
}
impl std::error::Error for CliProcessFailure {}
impl CliFailureDiagnostic {
	#[cfg(test)]
	pub(crate) fn for_log(&self) -> &str {
		&self.0
	}
}
struct CliFailureDecoder;
impl Validate<&[u8], Sandbox> for CliFailureDecoder {
	type Output = CliFailureDiagnostic;
	type Error = std::convert::Infallible;
	fn validate<'view>(
		self, u: Unvalidated<'view, &[u8]>, _: Mark<'view, Sandbox>,
	) -> Result<Self::Output, Self::Error> {
		Ok(CliFailureDiagnostic(String::from_utf8_lossy(u.get()).into_owned()))
	}
}
impl CapturedOutput {
	pub(crate) fn len(&self) -> usize {
		self.bytes.len()
	}
	pub(crate) fn text(&self) -> Result<CliOutputText, std::str::Utf8Error> {
		self.bytes.as_bytes().validate(CliOutputDecoder)
	}
	pub(crate) fn diagnostic(&self) -> CliFailureDiagnostic {
		match self.bytes.as_bytes().validate(CliFailureDecoder) {
			Ok(value) => value,
			Err(never) => match never {},
		}
	}
	#[cfg(any(test, fuzzing))]
	pub(crate) fn fixture_bytes(&self) -> Vec<u8> {
		struct Fixture;
		impl Validate<&[u8], Sandbox> for Fixture {
			type Output = Vec<u8>;
			type Error = std::convert::Infallible;
			fn validate<'view>(
				self, u: Unvalidated<'view, &[u8]>, _: Mark<'view, Sandbox>,
			) -> Result<Vec<u8>, Self::Error> {
				Ok(u.get().to_vec())
			}
		}
		match self.bytes.as_bytes().validate(Fixture) {
			Ok(value) => value,
			Err(never) => match never {},
		}
	}
}

pub(crate) async fn collect_cli_output(
	mut reader: impl AsyncRead + Unpin,
) -> std::io::Result<CapturedOutput> {
	let mut bytes = Vec::new();
	let mut chunk = [0; 8192];
	let mut truncated = false;
	let mut tail_cursor = 0;
	const TAIL_BYTES: usize = MAX_CLI_OUTPUT_BYTES / 2;
	loop {
		let count = reader.read(&mut chunk).await?;
		if count == 0 {
			break;
		}
		let kept = count.min(MAX_CLI_OUTPUT_BYTES - bytes.len());
		let required = bytes.len() + kept;
		if required > bytes.capacity() {
			bytes.reserve_exact(required.next_power_of_two() - bytes.len());
		}
		bytes.extend_from_slice(&chunk[..kept]);
		let mut discarded = &chunk[kept..count];
		truncated |= !discarded.is_empty();
		while !discarded.is_empty() {
			let len = discarded.len().min(TAIL_BYTES - tail_cursor);
			let start = TAIL_BYTES + tail_cursor;
			bytes[start..start + len].copy_from_slice(&discarded[..len]);
			discarded = &discarded[len..];
			tail_cursor = (tail_cursor + len) % TAIL_BYTES;
		}
	}
	if truncated {
		bytes[TAIL_BYTES..].rotate_left(tail_cursor);
	}
	#[cfg(test)]
	let capacity = bytes.capacity();
	// SAFETY: these are the original bounded head/tail bytes just collected
	// from the sandboxed CLI's stdout or stderr pipe, before interpretation.
	#[allow(unsafe_code)]
	let bytes = Untrusted::new(bytes, unsafe { Ingress::<Sandbox>::new() });
	Ok(CapturedOutput {
		bytes,
		truncated,
		#[cfg(test)]
		capacity,
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn synthetic_response_preserves_text_and_redacts_debug() {
		let original = "synthetic stdout\r\n\t\u{1}\u{85} cafe\u{301}";
		let output = synthetic_output(original.to_owned()).unwrap();
		assert_eq!(output.for_log(), original);
		assert_eq!(format!("{output:?}"), "CliOutputText<Sandbox>([redacted])");
	}

	#[tokio::test]
	async fn exact_budget_is_retained_and_not_marked_truncated() {
		let input = vec![b'x'; MAX_CLI_OUTPUT_BYTES];
		let captured = collect_cli_output(input.as_slice()).await.unwrap();
		assert_eq!(captured.fixture_bytes(), input);
		assert!(!captured.truncated);
		assert!(captured.capacity <= MAX_CLI_OUTPUT_BYTES);
	}

	#[tokio::test]
	async fn wrapping_tail_preserves_the_first_and_last_bytes() {
		let input: Vec<_> = (0..MAX_CLI_OUTPUT_BYTES * 3 + 37).map(|i| (i % 251) as u8).collect();
		let captured = collect_cli_output(input.as_slice()).await.unwrap();
		let half = MAX_CLI_OUTPUT_BYTES / 2;
		assert!(captured.truncated);
		assert_eq!(captured.len(), MAX_CLI_OUTPUT_BYTES);
		assert!(captured.capacity <= MAX_CLI_OUTPUT_BYTES);
		let bytes = captured.fixture_bytes();
		assert_eq!(bytes[..half], input[..half]);
		assert_eq!(bytes[half..], input[input.len() - half..]);
	}
}

#[cfg(test)]
#[tokio::test]
async fn public_cli_failure_chain_does_not_disclose_captured_streams() {
	use std::os::unix::process::ExitStatusExt;
	let captured = collect_cli_output(b"captured-private-error-sentinel".as_slice()).await.unwrap();
	let failure = CliProcessFailure {
		backend: "fixture",
		status: std::process::ExitStatus::from_raw(256),
		stderr: captured.diagnostic(),
		stdout: captured.diagnostic(),
		max_chars: 2000,
	};
	let error = anyhow::Error::new(failure).context("CLI failed");
	assert!(
		!format!("{error:#}").contains("captured-private-error-sentinel"),
		"captured sandbox bytes must not reach the public error chain"
	);
}
