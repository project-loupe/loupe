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

pub(crate) struct CliOutputText(String);
impl CliOutputText {
	/// Temporary private backend result exit until the prompt/log consumers migrate.
	pub(crate) fn into_legacy(self) -> String {
		self.0
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
pub(crate) struct CliFailureDiagnostic(String);
impl CliFailureDiagnostic {
	/// Temporary diagnostic exit; these Sandbox bytes are not Agent findings.
	pub(crate) fn into_legacy(self) -> String {
		self.0
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
	pub(crate) fn is_empty(&self) -> bool {
		self.bytes.is_empty()
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
