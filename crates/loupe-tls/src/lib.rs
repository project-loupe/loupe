// Keep production safety lints separate from test-only assertions.
#![cfg_attr(
	not(test),
	deny(
		clippy::unwrap_used,
		clippy::expect_used,
		clippy::string_slice,
		clippy::mem_forget,
		clippy::dbg_macro,
		clippy::todo,
		clippy::unimplemented,
		clippy::disallowed_methods
	)
)]
#![forbid(unsafe_code)]
//! mTLS helpers for loupe: in-memory CA, server/client config builders,
//! and a deterministic cert fingerprint used as the lookup key in the
//! `workers` table.
//!
//! The server runs as its own internal CA: registering a worker mints a
//! client cert + key bundle returned exactly once. Workers and the
//! `loupectl` admin client present these certs on every request; the
//! server identifies them by SHA-256(DER) fingerprint.

mod ca;
mod config;
mod fingerprint;
mod input;
mod provider;
mod secret;

pub use ca::{Ca, CertBundle};
pub use config::{client_config, reqwest_client_config, server_config};
pub use fingerprint::cert_fingerprint;
pub use input::{decode_pem_base64, encode_pem_base64, read_pem_file, PemInput};
