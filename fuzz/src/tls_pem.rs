//! First byte selects certificate, key or roots. Remaining UTF-8 bytes replace
//! that PEM field; the others are a fixed public fixture so each parser is reached.

use loupe_tls::{client_config, reqwest_client_config, server_config, Ca};

use crate::utils::test_logger;

const CERT: &str = include_str!("../fixtures/tls-ca.pem");
const KEY: &str = include_str!("../fixtures/tls-key.pem");

pub fn do_test(data: &[u8]) {
	if data.len() > 64 * 1024 {
		return;
	}
	let Some((&field, text)) = data.split_first() else { return };
	let Ok(text) = std::str::from_utf8(text) else { return };
	let (cert, key, roots) = match field % 3 {
		0 => (text, KEY, CERT),
		1 => (CERT, text, CERT),
		_ => (CERT, KEY, text),
	};
	if let Ok(ca) = Ca::from_pem(cert, key) {
		assert_eq!(ca.cert_pem(), cert);
		assert_eq!(ca.key_pem().expose(), key);
		assert!(
			Ca::from_pem(ca.cert_pem(), ca.key_pem().expose()).is_ok(),
			"accepted CA cannot reload"
		);
	}
	let client = client_config(cert, key, roots);
	let server = server_config(cert, key, roots);
	let adapted = reqwest_client_config(cert, key, roots);
	if let Ok(config) = &adapted {
		assert_eq!(config.alpn_protocols, [b"http/1.1".to_vec()]);
		assert!(config.enable_sni);
		assert!(!config.enable_early_data);
		assert!(!config.key_log.will_log("CLIENT_RANDOM"));
	}
	let adapted = adapted.and_then(|config| {
		reqwest::Client::builder()
			.use_preconfigured_tls(config)
			.no_proxy()
			.build()
			.map_err(Into::into)
	});
	assert_eq!(
		adapted.is_ok(),
		legacy_reqwest_accepts(cert, key, roots),
		"shared reqwest configuration changed legacy admission"
	);
	// Positive fixture and clear invalid-input oracles prevent an always-error
	// implementation from silently reducing the target to parser rejection.
	if cert == CERT && key == KEY && roots == CERT {
		assert!(client.is_ok(), "valid client PEM fixture rejected");
		assert!(server.is_ok(), "valid server PEM fixture rejected");
		assert!(adapted.is_ok(), "valid reqwest PEM fixture rejected");
	}
	// PEM permits spaces among delimiter dashes. Only absence of the required
	// labels proves these fields cannot contain a certificate or private key.
	if !cert.contains("CERTIFICATE") || !key.contains("PRIVATE KEY") {
		assert!(client.is_err(), "missing certificate or key admitted");
		assert!(server.is_err(), "missing certificate or key admitted");
	}
}

fn legacy_reqwest_accepts(cert: &str, key: &str, roots: &str) -> bool {
	// The reqwest reference accepts empty roots and uses the combined identity's
	// last private key, unlike the direct client/server loader contracts.
	let mut combined = cert.to_owned();
	if !combined.ends_with('\n') {
		combined.push('\n');
	}
	combined.push_str(key);
	let Ok(identity) = reqwest::Identity::from_pem(combined.as_bytes()) else { return false };
	let Ok(root) = reqwest::Certificate::from_pem(roots.as_bytes()) else { return false };
	reqwest::Client::builder()
		.identity(identity)
		.add_root_certificate(root)
		.use_rustls_tls()
		.no_proxy()
		.build()
		.is_ok()
}

pub fn tls_pem_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tls_pem_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
