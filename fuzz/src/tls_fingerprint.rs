//! Arbitrary DER bytes are hashed verbatim, without certificate parsing.

use loupe_tls::cert_fingerprint;
use sha2::{Digest, Sha256};

use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	let actual = cert_fingerprint(data);
	let expected: [u8; 32] = Sha256::digest(data).into();
	assert_eq!(actual, expected, "worker identity must be SHA-256 of exact DER bytes");
	assert_eq!(actual, cert_fingerprint(data), "certificate fingerprint must be deterministic");
}

pub fn tls_fingerprint_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tls_fingerprint_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
