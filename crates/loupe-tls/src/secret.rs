//! Private adapters for allocations whose cleanup is actually supported.

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use loupe_provenance::{Secret, Zeroise};
use rustls::pki_types::PrivateKeyDer;
use zeroize::{Zeroize, Zeroizing};

/// Construction is restricted to owned DER: the dependency wipes its Vec's
/// whole capacity. Its ordinary Drop alone would leave those bytes untouched.
pub(crate) struct OwnedDer(pub(crate) PrivateKeyDer<'static>);

impl Zeroise for OwnedDer {
	fn zeroise(&mut self) {
		self.0.zeroize();
		#[cfg(test)]
		DER_CLEANUPS.with(|count| count.set(count.get() + 1));
	}
}

#[cfg(test)]
thread_local! {
	pub(crate) static DER_CLEANUPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// rcgen's cleanup erases only serialized_der. The opaque ring signer and
/// rcgen's generation/parser scratch are outside this owner's guarantee.
/// In particular, this is deliberately not a Loupe Zeroise implementation.
pub(crate) struct RcgenKey(pub(crate) rcgen::KeyPair);

impl Drop for RcgenKey {
	fn drop(&mut self) {
		self.0.zeroize();
	}
}

pub(crate) fn export_key(key: &RcgenKey) -> Result<Secret<String>> {
	let newline = if cfg!(target_family = "windows") { b"\r\n".as_slice() } else { b"\n" };
	encode_private_pem(key.0.serialized_der(), newline)
}

fn encode_private_pem(der: &[u8], newline: &[u8]) -> Result<Secret<String>> {
	const BEGIN: &[u8] = b"-----BEGIN PRIVATE KEY-----";
	const END: &[u8] = b"-----END PRIVATE KEY-----";
	let encoded_len = base64::encoded_len(der.len(), true).context("private PEM size overflow")?;
	let lines = encoded_len.div_ceil(64);
	let len = lines
		.checked_add(2)
		.and_then(|lines| lines.checked_mul(newline.len()))
		.and_then(|separators| separators.checked_add(BEGIN.len() + END.len()))
		.and_then(|envelope| envelope.checked_add(encoded_len))
		.context("private PEM size overflow")?;
	// Reserve before any secret is written: neither this buffer nor an
	// intermediate base64 String can reallocate and leave private bytes behind.
	let mut output = Zeroizing::new(Vec::new());
	output.try_reserve_exact(len).context("allocating private PEM")?;
	output.extend_from_slice(BEGIN);
	output.extend_from_slice(newline);
	for chunk in der.chunks(48) {
		let start = output.len();
		let size = base64::encoded_len(chunk.len(), true).context("private PEM size overflow")?;
		output.resize(start + size, 0);
		STANDARD.encode_slice(chunk, &mut output[start..]).context("encoding private PEM")?;
		output.extend_from_slice(newline);
	}
	output.extend_from_slice(END);
	output.extend_from_slice(newline);
	debug_assert_eq!(output.len(), len);
	// Transfer the finished allocation directly into Secret. Even an internal
	// UTF-8 bug must not leave a FromUtf8Error owning unguarded private bytes.
	match String::from_utf8(std::mem::take(&mut *output)) {
		Ok(pem) => Ok(Secret::new(pem)),
		Err(error) => {
			let _rejected = Secret::new(error.into_bytes());
			anyhow::bail!("invalid private PEM encoding")
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn all_owned_der_variants_clear_with_spare_capacity() {
		for kind in 0..3 {
			let mut bytes = Vec::with_capacity(96);
			bytes.resize(96, 0xa5);
			bytes.truncate(16);
			let before = bytes.as_ptr();
			let mut key = OwnedDer(match kind {
				0 => PrivateKeyDer::Pkcs1(bytes.into()),
				1 => PrivateKeyDer::Pkcs8(bytes.into()),
				_ => PrivateKeyDer::Sec1(bytes.into()),
			});
			assert_eq!(key.0.secret_der().len(), 16);
			key.zeroise();
			assert!(key.0.secret_der().is_empty());
			assert_eq!(key.0.secret_der().as_ptr(), before);
			// This safely observes clearing of the live allocation. Full-capacity
			// overwrite follows the pinned dependency implementation, not a read
			// of spare or freed memory (which would be undefined behavior).
		}
	}

	#[test]
	fn rcgen_cleanup_only_claims_serialized_der() {
		let mut key = RcgenKey(rcgen::KeyPair::generate().unwrap());
		let public = key.0.public_key_der();
		assert!(!key.0.serialized_der().is_empty());
		key.0.zeroize();
		assert!(key.0.serialized_der().is_empty());
		assert_eq!(key.0.public_key_der(), public, "opaque signer is not erased by this method");
		assert!(rcgen::CertificateParams::default().self_signed(&key.0).is_ok());
	}

	#[test]
	fn exact_pem_export_matches_dependency_for_padding_wrapping_and_newlines() {
		for len in [0, 1, 2, 3, 47, 48, 49, 95, 96, 97, 1024] {
			let der = vec![0xa5; len];
			for (newline, ending) in [
				(b"\n".as_slice(), pem::LineEnding::LF),
				(b"\r\n".as_slice(), pem::LineEnding::CRLF),
			] {
				let expected = pem::encode_config(
					&pem::Pem::new("PRIVATE KEY", der.clone()),
					pem::EncodeConfig::new().set_line_ending(ending),
				);
				let actual = encode_private_pem(&der, newline).unwrap();
				assert_eq!(actual.expose(), &expected);
				assert_eq!(format!("{actual:?}"), "[redacted]");
			}
		}
	}
}
