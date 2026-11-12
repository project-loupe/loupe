//! Strict deserialization for closed vocabularies of unit variants.
//!
//! serde's derived enum impls also accept the externally tagged map form
//! `{"variant":null}`. Types declared with
//! [`closed_string_enum!`](crate::closed_string_enum) accept only a JSON
//! string equal to the spelling their `Serialize` impl writes, so each
//! value has exactly one wire encoding.
use std::borrow::Cow;

use serde::de::{Deserializer, Error, Visitor};
use serde::Serialize;

/// Reads a string and rejects every other JSON shape.
pub fn string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Cow<'de, str>, D::Error> {
	struct Only;
	impl<'de> Visitor<'de> for Only {
		type Value = Cow<'de, str>;
		fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			f.write_str("a closed vocabulary string")
		}
		fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<Self::Value, E> {
			Ok(Cow::Borrowed(value))
		}
		fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
			Ok(Cow::Owned(value.to_owned()))
		}
	}
	deserializer.deserialize_str(Only)
}

/// The string a closed variant serializes to.
pub fn spelling<T: Serialize>(value: &T) -> Option<String> {
	match serde_json::to_value(value) {
		Ok(serde_json::Value::String(spelling)) => Some(spelling),
		_ => None,
	}
}

/// Implements string-only `Deserialize` for a unit-variant enum whose
/// spellings come from its derived `Serialize`.
#[macro_export]
macro_rules! closed_string_enum {
	($ty:ident { $($variant:ident),+ $(,)? }) => {
		impl<'de> serde::Deserialize<'de> for $ty {
			fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
				let raw = $crate::closed_string::string(deserializer)?;
				for variant in [$(Self::$variant),+] {
					if $crate::closed_string::spelling(&variant).as_deref() == Some(&*raw) {
						return Ok(variant);
					}
				}
				Err(<D::Error as serde::de::Error>::custom("unknown closed vocabulary value"))
			}
		}
	};
}
