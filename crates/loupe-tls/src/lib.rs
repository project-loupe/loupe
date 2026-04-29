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
mod provider;

pub use ca::{Ca, CertBundle};
pub use config::{client_config, server_config};
pub use fingerprint::cert_fingerprint;
