//! Field policies shared by domain validation and DAO parameter types.
use super::{AnchorPolicy, IdentPolicy, JsonPolicy, TextPolicy};

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
