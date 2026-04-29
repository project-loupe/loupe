use sha2::{Digest, Sha256};

/// SHA-256 of the DER-encoded certificate. This is what the server
/// stores in `workers.cert_fingerprint` and what the request handler
/// derives from the peer cert during mTLS to identify the worker.
pub fn cert_fingerprint(cert_der: &[u8]) -> [u8; 32] {
	let mut hasher = Sha256::new();
	hasher.update(cert_der);
	hasher.finalize().into()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn empty_input_matches_known_sha256() {
		// Cross-check against a well-known vector for SHA-256("").
		let fp = cert_fingerprint(&[]);
		let hex = fp.iter().map(|b| format!("{b:02x}")).collect::<String>();
		assert_eq!(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	}

	#[test]
	fn fingerprint_is_deterministic() {
		let a = cert_fingerprint(b"loupe");
		let b = cert_fingerprint(b"loupe");
		assert_eq!(a, b);
		let c = cert_fingerprint(b"Loupe");
		assert_ne!(a, c);
	}
}
