use std::sync::Arc;

/// Keep the intended ring algorithms and signer consistent, even when another
/// library has installed a different global provider. This avoids transferring
/// private DER into an unrelated provider with a different ownership contract.
pub(crate) fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
	Arc::new(rustls::crypto::ring::default_provider())
}
