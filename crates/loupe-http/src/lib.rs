// Keep production safety lints separate from test-only assertions.
#![cfg_attr(
	not(test),
	deny(
		clippy::unwrap_used,
		clippy::expect_used,
		clippy::string_slice,
		clippy::mem_forget,
		clippy::dbg_macro,
		clippy::todo,
		clippy::unimplemented,
		clippy::disallowed_methods
	)
)]
#![forbid(unsafe_code)]
//! Shared response transport budget for worker, CLI, and web clients.
//!
//! This crate handles bytes only. Callers retain protocol checks, error
//! presentation, and JSON decoding in their own layers.

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use loupe_provenance::Zeroise;

/// Explicit response budget, including JSON whitespace and error bodies.
/// Oversized lists fail as a whole; callers must request smaller results.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// A response could not be collected within the transport budget.
#[derive(thiserror::Error)]
pub enum ResponseBodyError {
	#[error("response body exceeds {MAX_RESPONSE_BYTES} bytes")]
	TooLarge,
	#[error("reading response body failed")]
	Transport(reqwest::Error),
}

impl std::fmt::Debug for ResponseBodyError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(match self {
			Self::TooLarge => "TooLarge",
			Self::Transport(_) => "Transport([redacted])",
		})
	}
}

impl From<reqwest::Error> for ResponseBodyError {
	fn from(error: reqwest::Error) -> Self {
		// Keep the transport category inspectable without exposing request
		// URLs or dependency diagnostics through a printable source chain.
		Self::Transport(error)
	}
}

// This private construction/transport owner has mutable storage only while
// collecting. Replacements wipe their predecessors; Bytes retains the final
// allocation until its last clone or slice drops. No filled buffer reallocates.
#[derive(Default)]
struct ResponseBuffer {
	allocation: Box<[u8]>,
	used: usize,
	#[cfg(test)]
	audit: Option<tests::DropAudit>,
}

impl ResponseBuffer {
	fn append(&mut self, chunk: &[u8]) -> Result<(), ResponseBodyError> {
		if chunk.len() > MAX_RESPONSE_BYTES - self.used {
			return Err(ResponseBodyError::TooLarge);
		}
		let required = self.used + chunk.len();
		if required > self.allocation.len() {
			let capacity = required.next_power_of_two().min(MAX_RESPONSE_BYTES);
			let mut replacement = Self {
				allocation: vec![0; capacity].into_boxed_slice(),
				used: self.used,
				#[cfg(test)]
				audit: self.audit.clone(),
			};
			replacement.allocation[..self.used].copy_from_slice(self.as_ref());
			*self = replacement;
		}
		self.allocation[self.used..required].copy_from_slice(chunk);
		self.used = required;
		Ok(())
	}
}

impl AsRef<[u8]> for ResponseBuffer {
	fn as_ref(&self) -> &[u8] {
		&self.allocation[..self.used]
	}
}

impl Drop for ResponseBuffer {
	fn drop(&mut self) {
		self.allocation.zeroise();
		#[cfg(test)]
		if let Some(audit) = &self.audit {
			// Observe still-live storage after the production wipe, before
			// Box frees it. Record only capacity and whether it is all zero.
			audit
				.lock()
				.unwrap()
				.push((self.allocation.len(), self.allocation.iter().all(|byte| *byte == 0)));
		}
	}
}

/// Read a response without allowing its collected buffer to exceed the cap.
///
/// A known oversized length is refused before polling the body. Missing or
/// inaccurate length headers cannot bypass the running check. Transport chunks
/// are checked before copying, and buffer capacity growth is capped as well.
/// Collected storage is wiped on every exit and after the final returned clone
/// drops. Growth temporarily retains the old and replacement allocations;
/// transport-owned chunks and later caller-made copies are outside this guard.
pub async fn read_response_bytes(response: reqwest::Response) -> Result<Bytes, ResponseBodyError> {
	if response.content_length().is_some_and(|length| length > MAX_RESPONSE_BYTES as u64) {
		return Err(ResponseBodyError::TooLarge);
	}
	collect(response.bytes_stream(), ResponseBuffer::default()).await
}

async fn collect(
	chunks: impl Stream<Item = Result<Bytes, reqwest::Error>>, mut body: ResponseBuffer,
) -> Result<Bytes, ResponseBodyError> {
	futures_util::pin_mut!(chunks);
	while let Some(chunk) = chunks.next().await {
		body.append(&chunk?)?;
	}
	Ok(Bytes::from_owner(body))
}

#[cfg(test)]
mod tests;
