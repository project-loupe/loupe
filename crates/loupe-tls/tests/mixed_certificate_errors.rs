//! Regression guards for private BEGIN lines in certificate/CA inputs.

use anyhow::Result;
use loupe_tls::{client_config, server_config};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

fn load(server: bool, cert: &str, key: &str, ca: &str) -> Result<()> {
	if server {
		server_config(cert, key, ca).map(|_| ())
	} else {
		client_config(cert, key, ca).map(|_| ())
	}
}

fn assert_private_begin_errors_are_fixed(server: bool, ca_argument: bool) {
	let key = KeyPair::generate().unwrap();
	let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	let certificate = params.self_signed(&key).unwrap().pem();
	let private_key = key.serialize_pem();
	// A matching, accepted identity makes the malformed mixed input the only
	// reason for rejection; all material is unregistered test data.
	load(server, &certificate, &private_key, &certificate).unwrap();
	const SENTINEL: &str = "FAKE_PRIVATE_PEM_BEGIN_SENTINEL";
	let mixed = format!("{certificate}-----BEGIN PRIVATE KEY {SENTINEL}\n");
	let (cert, ca) = if ca_argument { (&certificate, &mixed) } else { (&mixed, &certificate) };
	let error = load(server, cert, &private_key, ca)
		.expect_err("malformed private section must be rejected");
	let formats = [
		("Display", format!("{error}")),
		("alternate Display", format!("{error:#}")),
		("Debug", format!("{error:?}")),
		("alternate Debug", format!("{error:#?}")),
		("propagated outer error", format!("{:#}", error.context("initialising TLS"))),
	];
	let leaks: Vec<_> =
		formats.iter().filter(|(_, text)| text.contains(SENTINEL)).map(|(name, _)| *name).collect();
	assert!(leaks.is_empty(), "mixed certificate/CA private BEGIN disclosed by {leaks:?}");
}

#[test]
fn tls_r1_server_certificate_errors_are_fixed() {
	assert_private_begin_errors_are_fixed(true, false);
}

#[test]
fn tls_r1_server_ca_errors_are_fixed() {
	assert_private_begin_errors_are_fixed(true, true);
}

#[test]
fn tls_r1_client_certificate_errors_are_fixed() {
	assert_private_begin_errors_are_fixed(false, false);
}

#[test]
fn tls_r1_client_ca_errors_are_fixed() {
	assert_private_begin_errors_are_fixed(false, true);
}
