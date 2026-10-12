//! Built-in scan and verify implementations.
//!
//! `regex_secrets` stays as a cheap deterministic scanner and test
//! fixture; the LLM scanners handle agent-driven discovery and
//! LLM-backed verification.

pub mod llm_code_review;
pub mod llm_verifier;
pub mod regex_secrets;

pub use llm_code_review::LlmCodeReviewScanner;
pub use llm_verifier::LlmVerifierScanner;
pub use regex_secrets::RegexSecretsScanner;

#[cfg(fuzzing)]
pub use crate::source_discovery::fuzz_support as fuzz_source_discovery;
pub use crate::source_discovery::{
	ScannerConfig as LlmScannerConfig, ScannerConfigPatch, ScannerExcludePattern, ScannerExtension,
	ScannerList,
};
