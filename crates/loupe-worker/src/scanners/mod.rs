//! Built-in scan and verify implementations.
//!
//! `regex_secrets` stays as a cheap deterministic scanner and test
//! fixture; the LLM scanners handle agent-driven discovery and
//! cross-model verification.

pub mod llm_code_review;
pub mod llm_verifier;
pub mod regex_secrets;

pub use llm_code_review::LlmCodeReviewScanner;
pub use llm_verifier::LlmVerifierScanner;
pub use regex_secrets::RegexSecretsScanner;

pub use crate::source_discovery::ScannerConfig as LlmScannerConfig;
