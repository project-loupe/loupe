//! Deliberate plaintext credential delivery in the authenticated wire protocol.
//! These private field adapters do not make Secret generally serializable.

use loupe_provenance::Secret;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod string {
	use super::*;

	pub fn serialize<S: Serializer>(
		value: &Secret<String>, serializer: S,
	) -> Result<S::Ok, S::Error> {
		serializer.serialize_str(value.expose())
	}

	pub fn deserialize<'de, D: Deserializer<'de>>(
		deserializer: D,
	) -> Result<Secret<String>, D::Error> {
		String::deserialize(deserializer).map(Secret::new)
	}
}

pub mod optional {
	use super::*;

	pub fn serialize<S: Serializer>(
		value: &Option<Secret<String>>, serializer: S,
	) -> Result<S::Ok, S::Error> {
		value.as_ref().map(Secret::expose).serialize(serializer)
	}

	pub fn deserialize<'de, D: Deserializer<'de>>(
		deserializer: D,
	) -> Result<Option<Secret<String>>, D::Error> {
		Option::<String>::deserialize(deserializer).map(|value| value.map(Secret::new))
	}
}
