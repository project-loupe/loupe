//! Private-key diagnostic redaction and key-selection controls.
//! All keys and sentinel bytes here are disposable, unregistered test material.

use anyhow::Result;
use loupe_tls::{client_config, server_config, Ca, CertBundle};

const PRIVATE_SENTINEL: &str = "FAKE_PRIVATE_PEM_BEGIN_SENTINEL";

fn load(server: bool, cert: &str, key: &str, ca: &str) -> Result<()> {
	if server {
		server_config(cert, key, ca).map(|_| ())
	} else {
		client_config(cert, key, ca).map(|_| ())
	}
}

fn mint(ca: &Ca, server: bool, name: &str) -> CertBundle {
	if server {
		ca.mint_server(name, &["loupe-server".into()]).unwrap()
	} else {
		ca.mint_client(name).unwrap()
	}
}

fn assert_private_parser_errors_are_fixed(server: bool) {
	let ca = Ca::new("throwaway-private-error-ca").unwrap();
	let bundle = mint(&ca, server, "throwaway-private-error-leaf");
	let malformed_key = format!("-----BEGIN PRIVATE KEY {PRIVATE_SENTINEL}\n");
	let error = load(server, &bundle.cert_pem, &malformed_key, ca.cert_pem())
		.expect_err("malformed private BEGIN must be rejected");
	let formats = [
		("Display", format!("{error}")),
		("alternate Display", format!("{error:#}")),
		("Debug", format!("{error:?}")),
		("alternate Debug", format!("{error:#?}")),
		("propagated outer error", format!("{:#}", error.context("initialising TLS"))),
	];
	let leaks: Vec<_> = formats
		.iter()
		.filter(|(_, text)| text.contains(PRIVATE_SENTINEL))
		.map(|(name, _)| *name)
		.collect();
	assert!(leaks.is_empty(), "private BEGIN bytes were disclosed by {leaks:?}");
}

#[test]
fn tls_secret_server_private_parser_errors_are_fixed() {
	assert_private_parser_errors_are_fixed(true);
}

#[test]
fn tls_secret_client_private_parser_errors_are_fixed() {
	assert_private_parser_errors_are_fixed(false);
}

#[test]
fn server_and_client_reject_mismatched_keys() {
	let ca = Ca::new("throwaway-mismatch-ca").unwrap();
	for server in [true, false] {
		let first = mint(&ca, server, "first");
		let second = mint(&ca, server, "second");
		assert!(load(server, &first.cert_pem, first.key_pem.expose(), ca.cert_pem()).is_ok());
		assert!(
			load(server, &first.cert_pem, second.key_pem.expose(), ca.cert_pem()).is_err(),
			"mismatched certificate/key must be rejected (server={server})"
		);
	}
}

#[test]
fn server_and_client_select_the_first_private_key() {
	let ca = Ca::new("throwaway-key-order-ca").unwrap();
	for server in [true, false] {
		let matching = mint(&ca, server, "matching");
		let other = mint(&ca, server, "other");
		let matching_first = format!("{}{}", matching.key_pem.expose(), other.key_pem.expose());
		let other_first = format!("{}{}", other.key_pem.expose(), matching.key_pem.expose());
		assert!(
			load(server, &matching.cert_pem, &matching_first, ca.cert_pem()).is_ok(),
			"matching first key must be selected (server={server})"
		);
		assert!(
			load(server, &matching.cert_pem, &other_first, ca.cert_pem()).is_err(),
			"later matching key must not rescue a mismatched first key (server={server})"
		);
	}
}
