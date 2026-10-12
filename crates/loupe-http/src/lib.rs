#![forbid(unsafe_code)]
//! Shared response transport budget for worker, CLI, and web clients.
//!
//! This crate handles bytes only. Callers retain protocol checks, error
//! presentation, and JSON decoding in their own layers.

use futures_util::StreamExt;

/// Explicit response budget, including JSON whitespace and error bodies.
/// Oversized lists fail as a whole; callers must request smaller results.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// A response could not be collected within the transport budget.
#[derive(Debug, thiserror::Error)]
pub enum ResponseBodyError {
	#[error("response body exceeds {MAX_RESPONSE_BYTES} bytes")]
	TooLarge,
	#[error("reading response body: {0}")]
	Transport(#[from] reqwest::Error),
}

/// Read a response without allowing its collected buffer to exceed the cap.
///
/// A known oversized length is refused before polling the body. Missing or
/// inaccurate length headers cannot bypass the running check. Transport chunks
/// are checked before copying, and buffer capacity growth is capped as well.
pub async fn read_response_bytes(
	response: reqwest::Response,
) -> Result<Vec<u8>, ResponseBodyError> {
	if response.content_length().is_some_and(|length| length > MAX_RESPONSE_BYTES as u64) {
		return Err(ResponseBodyError::TooLarge);
	}
	let mut body = Vec::new();
	let mut chunks = response.bytes_stream();
	while let Some(chunk) = chunks.next().await {
		let chunk = chunk?;
		if chunk.len() > MAX_RESPONSE_BYTES - body.len() {
			return Err(ResponseBodyError::TooLarge);
		}
		let required = body.len() + chunk.len();
		if required > body.capacity() {
			let capacity = required.next_power_of_two().min(MAX_RESPONSE_BYTES);
			body.reserve_exact(capacity - body.len());
		}
		body.extend_from_slice(&chunk);
	}
	Ok(body)
}
