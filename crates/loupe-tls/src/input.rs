//! Controlled PEM input and export allocations. Process argument/environment,
//! filesystem/kernel and dependency parser copies remain outside these owners.

use std::convert::Infallible;
use std::fmt;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine as _;
use loupe_provenance::{Secret, Zeroise};

/// Raw or base64 PEM argument storage. Clones share the same wiping allocation
/// for argument parsers that require Clone. This does not validate PEM or grant
/// trust; each application retains its own parsing and precedence rules.
pub struct PemInput(Arc<Secret<String>>);

impl PemInput {
	/// Borrow the exact argument for the named PEM loader.
	pub fn expose(&self) -> &str {
		self.0.expose()
	}

	/// Retire argument storage into its runtime PEM owner. A remaining parser
	/// clone requires a separate guarded allocation; the original stays guarded.
	pub fn into_pem(self) -> Secret<String> {
		Arc::try_unwrap(self.0).unwrap_or_else(|shared| Secret::new(shared.expose().to_owned()))
	}
}

impl Clone for PemInput {
	fn clone(&self) -> Self {
		Self(Arc::clone(&self.0))
	}
}

impl From<String> for PemInput {
	fn from(value: String) -> Self {
		Self(Arc::new(Secret::new(value)))
	}
}

impl From<&str> for PemInput {
	fn from(value: &str) -> Self {
		value.to_owned().into()
	}
}

impl FromStr for PemInput {
	type Err = Infallible;
	fn from_str(value: &str) -> Result<Self, Self::Err> {
		Ok(value.into())
	}
}

impl fmt::Debug for PemInput {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("[redacted]")
	}
}

impl fmt::Display for PemInput {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("[redacted]")
	}
}

// Mutable construction stays private. Replacements allocate before copying and
// wipe the previous live allocation; no populated Vec is ever reallocated.
struct PemBuffer {
	bytes: Vec<u8>,
	used: usize,
}

impl PemBuffer {
	fn new(size: usize) -> Self {
		Self { bytes: vec![0; size], used: 0 }
	}

	fn grow(&mut self) -> Result<()> {
		let size = self.bytes.len().checked_mul(2).context("PEM input size overflow")?;
		let mut replacement = Self::new(size);
		replacement.bytes[..self.used].copy_from_slice(&self.bytes[..self.used]);
		replacement.used = self.used;
		*self = replacement;
		Ok(())
	}

	fn finish(mut self) -> Result<Secret<String>> {
		std::str::from_utf8(&self.bytes[..self.used])
			.map_err(|_| anyhow::anyhow!("PEM input is not valid UTF-8"))?;
		self.bytes.truncate(self.used);
		#[expect(
			clippy::expect_used,
			reason = "the identical byte range passed from_utf8 above, and truncate/take do not alter those bytes"
		)]
		let text = String::from_utf8(std::mem::take(&mut self.bytes))
			.expect("PEM bytes were validated as UTF-8");
		Ok(Secret::new(text))
	}
}

impl Drop for PemBuffer {
	fn drop(&mut self) {
		self.bytes.resize(self.bytes.capacity(), 0);
		self.bytes.as_mut_slice().zeroise();
		#[cfg(test)]
		CLEANUPS.with(|seen| {
			seen.borrow_mut().push((self.bytes.len(), self.bytes.iter().all(|b| *b == 0)))
		});
	}
}

/// Decode standard base64 into guarded PEM text. Callers own trimming and
/// input precedence. Partial decoder output is wiped on every error.
pub fn decode_pem_base64(encoded: &str) -> Result<Secret<String>> {
	let mut buffer = PemBuffer::new(base64::decoded_len_estimate(encoded.len()));
	buffer.used = base64::engine::general_purpose::STANDARD
		.decode_slice(encoded, &mut buffer.bytes)
		.map_err(|_| anyhow::anyhow!("invalid base64 PEM input"))?;
	buffer.finish()
}

/// Encode PEM directly into an exactly sized guarded base64 export buffer.
pub fn encode_pem_base64(pem: &str) -> Result<Secret<String>> {
	let size = base64::encoded_len(pem.len(), true).context("PEM export size overflow")?;
	let mut buffer = PemBuffer::new(size);
	buffer.used = base64::engine::general_purpose::STANDARD
		.encode_slice(pem.as_bytes(), &mut buffer.bytes)
		.map_err(|_| anyhow::anyhow!("PEM export size changed"))?;
	buffer.finish()
}

/// Read PEM text with guarded growth and UTF-8 validation. Certificate inputs
/// need the same owner: accepted mixed bundles can contain private sections.
pub fn read_pem_file(path: &Path) -> Result<Secret<String>> {
	#[allow(
		clippy::disallowed_methods,
		reason = "TLS PEM ingress opens the caller-selected configuration file before guarded reading and validation"
	)]
	let mut file = std::fs::File::open(path).context("opening PEM file")?;
	read_pem(&mut file)
}

fn read_pem(reader: &mut impl Read) -> Result<Secret<String>> {
	let mut buffer = PemBuffer::new(8192);
	loop {
		if buffer.used == buffer.bytes.len() {
			buffer.grow()?;
		}
		match reader.read(&mut buffer.bytes[buffer.used..]) {
			Ok(0) => return buffer.finish(),
			Ok(count) => buffer.used += count,
			Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
			Err(_) => anyhow::bail!("reading PEM input failed"),
		}
	}
}

#[cfg(test)]
thread_local! {
	static CLEANUPS: std::cell::RefCell<Vec<(usize, bool)>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn growth_and_partial_read_error_wipe_live_allocations() {
		struct FailAfterPrefix(std::io::Cursor<Vec<u8>>);
		impl Read for FailAfterPrefix {
			fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
				let count = self.0.read(out)?;
				if count == 0 {
					Err(std::io::Error::other("FAKE_PRIVATE_READ_ERROR"))
				} else {
					Ok(count)
				}
			}
		}
		CLEANUPS.with(|seen| seen.borrow_mut().clear());
		let error =
			read_pem(&mut FailAfterPrefix(std::io::Cursor::new(vec![b'X'; 17000]))).unwrap_err();
		assert_eq!(format!("{error:#}"), "reading PEM input failed");
		CLEANUPS
			.with(|seen| assert_eq!(*seen.borrow(), [(8192, true), (16384, true), (32768, true)]));
	}

	#[test]
	fn invalid_decode_and_utf8_wipe_partial_storage() {
		for encoded in ["QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo!", "/w=="] {
			CLEANUPS.with(|seen| seen.borrow_mut().clear());
			assert!(decode_pem_base64(encoded).is_err());
			CLEANUPS.with(|seen| {
				let seen = seen.borrow();
				assert_eq!(seen.len(), 1);
				assert!(seen[0].0 > 0 && seen[0].1);
			});
		}
	}
}
