//! Built-in scanners for M1.
//!
//! `regex_secrets` is intentionally simple — its job is to prove the
//! pipeline (lease → checkout → scan → submit → complete → report)
//! actually produces a finding end-to-end without hand-waving.

pub mod regex_secrets;

pub use regex_secrets::RegexSecretsScanner;
