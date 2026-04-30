//! Shared helpers for `loupe-server` integration tests.
//!
//! Each `tests/*.rs` is a separate binary, so this module is pulled
//! in via `mod common;` per file rather than auto-imported. The
//! helpers here aren't part of any public crate surface — they exist
//! only to dedupe what would otherwise be 9× copies of the same
//! reqwest-PEM plumbing.
//!
//! `#[allow(dead_code)]` because a given test file might use only
//! one of these — mod-level dead-code warnings fire per-binary.

#![allow(dead_code)]

/// Wrap a CA-cert PEM in the form `reqwest::Client::builder()
/// .add_root_certificate` expects.
pub fn pem_to_certificate(pem: &str) -> reqwest::Certificate {
	reqwest::Certificate::from_pem(pem.as_bytes()).expect("parse cert PEM")
}

/// Combine an mTLS client cert + key into the single-PEM-blob form
/// `reqwest::Identity::from_pem` expects. Forces a separator newline
/// so back-to-back PEMs without trailing newlines still parse.
pub fn pem_to_identity(cert_pem: &str, key_pem: &str) -> reqwest::Identity {
	let mut combined = String::with_capacity(cert_pem.len() + key_pem.len() + 1);
	combined.push_str(cert_pem);
	if !cert_pem.ends_with('\n') {
		combined.push('\n');
	}
	combined.push_str(key_pem);
	reqwest::Identity::from_pem(combined.as_bytes()).expect("parse client identity PEM")
}
