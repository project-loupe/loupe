//! Built-in scanners for M1.
//!
//! `regex_secrets` is intentionally simple — its job is to prove the
//! pipeline (lease → checkout → scan → submit → complete → report)
//! actually produces a finding end-to-end without hand-waving.

pub mod llm_code_review;
pub mod regex_secrets;

pub use llm_code_review::{LlmCodeReviewScanner, ScannerConfig as LlmScannerConfig};
pub use regex_secrets::RegexSecretsScanner;
