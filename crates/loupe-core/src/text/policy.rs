//! Field policies shared by domain validation and DAO parameter types.
use super::{AnchorPolicy, IdentPolicy, JsonPolicy, Normalization, TextPolicy, Whitespace};

/// New compatibility ceiling for previously unbounded legacy strings.
/// Route/destination limits still apply, including the smaller LLM PoC cap.
pub const LEGACY_TEXT_MAX_BYTES: usize = 2 * 1024 * 1024;

macro_rules! exact_texts {
	($( $name:ident, $field:literal, $multi:literal; )*) => { $(
		/// Preserves admitted decoded UTF-8, including significant whitespace.
		#[derive(Debug, Clone, Copy, PartialEq, Eq)]
		pub struct $name;
		impl TextPolicy for $name {
			const FIELD: &'static str = $field;
			const MAX_CHARS: usize = LEGACY_TEXT_MAX_BYTES;
			const MAX_BYTES: usize = LEGACY_TEXT_MAX_BYTES;
			const MULTILINE: bool = $multi;
			const ALLOW_EMPTY: bool = true;
			const NORMALIZATION: Normalization = Normalization::Exact;
			const WHITESPACE: Whitespace = Whitespace::Significant;
			const ALLOW_CR: bool = $multi;
		}
	)* };
}

// These policies do not establish diff applicability, URL authorization,
// email-header validity, or the stricter LLM field grammar.
exact_texts! {
	FindingTitle, "finding_title", false;
	FindingDescription, "finding_description", true;
	PocUnified, "poc_unified", true;
	PatchUnified, "patch_unified", true;
	VerdictNotes, "verdict_notes", true;
	VerdictReason, "verdict_reason", true;
	PatchNotes, "patch_notes", true;
	ScannerIdText, "scanner_id", false;
	CweText, "cwe", false;
	FindingFingerprintText, "finding_fingerprint", false;
	RepoHost, "repo_host", false;
	RepoOwner, "repo_owner", false;
	RepoName, "repo_name", false;
	CloneUrl, "clone_url", false;
	GitBranch, "git_branch", false;
	MailAddress, "mail_address", false;
	MailSubjectPrefix, "mail_subject_prefix", false;
}

macro_rules! texts {
	($( $name:ident, $field:literal, $chars:literal, $multi:literal; )*) => { $(
		#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub struct $name;
		impl TextPolicy for $name {
			const FIELD: &'static str = $field;
			const MAX_CHARS: usize = $chars;
			const MAX_BYTES: usize = $chars * 2;
			const MULTILINE: bool = $multi;
		}
	)* };
}
texts! {
	Title, "title", 200, false;
	Objective, "objective", 2000, true;
	Reason, "reason", 1000, false;
	Argument, "argument", 4000, true;
	Symbol, "symbol", 256, false;
	MediaType, "media_type", 100, false;
	OriginalName, "original_name", 512, false;
	AnchorText, "identity_anchor", 300, false;
	InstanceKey, "identity_instance_key", 200, false;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonLeaf;
impl TextPolicy for JsonLeaf {
	const FIELD: &'static str = "json_leaf";
	const MAX_CHARS: usize = 4000;
	const MAX_BYTES: usize = 8000;
	const MULTILINE: bool = true;
	const ALLOW_EMPTY: bool = true;
}
impl AnchorPolicy for AnchorText {}
impl AnchorPolicy for InstanceKey {}

macro_rules! ident {
	($name:ident, $field:literal, $max:literal, $predicate:expr) => {
		#[derive(Debug, Clone, Copy, PartialEq, Eq)]
		pub struct $name;
		impl IdentPolicy for $name {
			const FIELD: &'static str = $field;
			const MAX_LEN: usize = $max;
			fn accepts(s: &str) -> bool {
				($predicate)(s)
			}
		}
	};
}
ident!(ClientKey, "client_key", 128, |s: &str| s
	.as_bytes()
	.first()
	.is_some_and(u8::is_ascii_alphanumeric)
	&& s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)));
ident!(Family, "identity_family", 64, |s: &str| s.len() >= 3
	&& s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
ident!(Label, "label", 64, |s: &str| s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
	&& s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._ -".contains(&b)));
ident!(JsonKey, "json_key", 64, |s: &str| s
	.as_bytes()
	.first()
	.is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
	&& s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Payload;
impl JsonPolicy for Payload {
	const FIELD: &'static str = "payload";
	const MAX_BYTES: usize = 64 * 1024;
	const MAX_DEPTH: usize = 16;
	const MAX_NODES: usize = 4096;
}
