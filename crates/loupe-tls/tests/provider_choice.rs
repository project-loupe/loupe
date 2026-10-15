//! One process-isolated test for an already installed global provider.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use loupe_tls::{client_config, server_config, Ca};
use rustls::crypto::KeyProvider;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;

static GLOBAL_KEY_LOADS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
struct ObservedGlobalKeyProvider;

impl KeyProvider for ObservedGlobalKeyProvider {
	fn load_private_key(
		&self, key: PrivateKeyDer<'static>,
	) -> Result<Arc<dyn SigningKey>, rustls::Error> {
		GLOBAL_KEY_LOADS.fetch_add(1, Ordering::Relaxed);
		rustls::crypto::ring::default_provider().key_provider.load_private_key(key)
	}
}

#[test]
fn tls_secret_loaders_do_not_transfer_der_to_an_unrelated_global_provider() {
	let mut provider = rustls::crypto::ring::default_provider();
	provider.key_provider = &ObservedGlobalKeyProvider;
	provider.install_default().expect("this integration test has its own process");
	let ca = Ca::new("throwaway-provider-ca").unwrap();
	let server = ca.mint_server("server", &["localhost".into()]).unwrap();
	let client = ca.mint_client("client").unwrap();
	server_config(&server.cert_pem, server.key_pem.expose(), ca.cert_pem()).unwrap();
	client_config(&client.cert_pem, client.key_pem.expose(), ca.cert_pem()).unwrap();
	assert_eq!(
		GLOBAL_KEY_LOADS.load(Ordering::Relaxed),
		0,
		"loaders must borrow guarded DER into their intended ring signer"
	);
}
