use std::sync::Once;

static INIT: Once = Once::new();

/// rustls 0.23 requires a crypto provider to be installed before any
/// `ServerConfig` / `ClientConfig` builder runs. We pick aws-lc-rs (the
/// upstream default) and install it lazily so the choice stays a
/// loupe-tls implementation detail and tests don't have to call init
/// themselves.
pub(crate) fn ensure_provider_installed() {
	INIT.call_once(|| {
		// `install_default` returns `Err` only if a provider was already
		// installed by someone else — fine for our purposes.
		let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
	});
}
