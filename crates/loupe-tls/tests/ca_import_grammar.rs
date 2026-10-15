//! CA import grammar and mixed-PEM compatibility checks.

use loupe_tls::Ca;

#[test]
fn certificate_import_is_tag_neutral_for_valid_certificate_der() {
	let ca = Ca::new("tag-neutral-ca").unwrap();
	for label in ["PRIVATE KEY", "PUBLIC KEY", "LOUPE CERTIFICATE"] {
		let input = ca
			.cert_pem()
			.replace("BEGIN CERTIFICATE", &format!("BEGIN {label}"))
			.replace("END CERTIFICATE", &format!("END {label}"));
		let imported = Ca::from_pem(&input, ca.key_pem().expose()).unwrap();
		assert_eq!(imported.cert_pem(), input);
		assert!(imported.mint_client("worker").is_ok());
	}
}

#[test]
fn private_first_block_is_rejected_even_with_a_later_certificate() {
	let ca = Ca::new("first-private-ca").unwrap();
	let input = format!("{}{}", ca.key_pem().expose(), ca.cert_pem());
	assert!(Ca::from_pem(&input, ca.key_pem().expose()).is_err());
}

#[test]
fn certificate_first_then_private_is_accepted_without_discarding_sections() {
	let ca = Ca::new("first-certificate-ca").unwrap();
	let input = format!("{}{}", ca.cert_pem(), ca.key_pem().expose());
	let imported = Ca::from_pem(&input, ca.key_pem().expose()).unwrap();
	assert_eq!(imported.cert_pem(), input);
	assert_eq!(imported.key_pem().expose(), ca.key_pem().expose());
	assert!(imported.mint_server("server", &["localhost".into()]).is_ok());
}

#[test]
fn malformed_first_block_does_not_fall_through_to_a_valid_certificate() {
	let ca = Ca::new("malformed-first-ca").unwrap();
	let input =
		format!("-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n{}", ca.cert_pem());
	assert!(Ca::from_pem(&input, ca.key_pem().expose()).is_err());
}

#[test]
fn imports_retain_exact_original_whitespace_and_newlines() {
	let ca = Ca::new("exact-ca-input").unwrap();
	let cert = format!(" \r\n{}\r\n ", ca.cert_pem().replace('\n', "\r\n"));
	let key = format!(" \r\n{}\r\n ", ca.key_pem().expose().replace('\n', "\r\n"));
	let imported = Ca::from_pem(&cert, &key).unwrap();
	assert_eq!(imported.cert_pem(), cert);
	assert_eq!(imported.key_pem().expose(), &key);
}
