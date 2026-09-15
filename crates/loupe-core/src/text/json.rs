use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

use super::policy::{JsonKey, JsonLeaf};
use super::{BoundedText, Error, Identifier, JsonPolicy, Rule};

#[derive(Clone, PartialEq, Eq)]
pub struct BoundedJson<P: JsonPolicy> {
	value: serde_json::Value,
	canonical: Vec<u8>,
	digest: [u8; 32],
	policy: PhantomData<P>,
}
impl<P: JsonPolicy> BoundedJson<P> {
	/// Use this entry point for raw agent JSON so its byte limit is enforced
	/// before parsing. Embedded Deserialize additionally requires a bounded
	/// request body at the protocol boundary.
	pub fn new(raw: &str) -> Result<Self, Error> {
		if raw.len() > P::MAX_BYTES {
			return Err(Error::new(P::FIELD, Rule::Bytes));
		}
		let mut state = State::<P> { nodes: 0, bytes: 0, error: None, policy: PhantomData };
		let mut deserializer = serde_json::Deserializer::from_str(raw);
		let value =
			Node { state: &mut state, depth: 1 }.deserialize(&mut deserializer).map_err(|_| {
				state.error.take().unwrap_or_else(|| Error::new(P::FIELD, Rule::JsonSyntax))
			})?;
		deserializer.end().map_err(|_| Error::new(P::FIELD, Rule::JsonSyntax))?;
		Self::finish(value)
	}

	fn finish(value: Value) -> Result<Self, Error> {
		let canonical = crate::canonical::canonical_bytes(&value);
		if canonical.len() > P::MAX_BYTES {
			return Err(Error::new(P::FIELD, Rule::Bytes));
		}
		let digest = crate::canonical::digest(&canonical);
		Ok(Self { value, canonical, digest, policy: PhantomData })
	}
	pub fn expose(&self) -> &str {
		std::str::from_utf8(&self.canonical).expect("canonical JSON is UTF-8")
	}
	pub fn canonical(&self) -> &[u8] {
		&self.canonical
	}
	pub fn digest(&self) -> &[u8; 32] {
		&self.digest
	}
}
impl<P: JsonPolicy> fmt::Debug for BoundedJson<P> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "BoundedJson<{}>(len={})", P::FIELD, self.canonical.len())
	}
}
impl<P: JsonPolicy> FromStr for BoundedJson<P> {
	type Err = Error;
	fn from_str(raw: &str) -> Result<Self, Error> {
		Self::new(raw)
	}
}
impl<P: JsonPolicy> TryFrom<String> for BoundedJson<P> {
	type Error = Error;
	fn try_from(raw: String) -> Result<Self, Error> {
		Self::new(&raw)
	}
}
impl<P: JsonPolicy> Serialize for BoundedJson<P> {
	fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		self.value.serialize(s)
	}
}
impl<'de, P: JsonPolicy> Deserialize<'de> for BoundedJson<P> {
	fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		let mut state = State::<P> { nodes: 0, bytes: 0, error: None, policy: PhantomData };
		let value = Node { state: &mut state, depth: 1 }.deserialize(d)?;
		Self::finish(value).map_err(serde::de::Error::custom)
	}
}

struct State<P> {
	nodes: usize,
	bytes: usize,
	error: Option<Error>,
	policy: PhantomData<P>,
}
struct Node<'a, P> {
	state: &'a mut State<P>,
	depth: usize,
}
impl<P: JsonPolicy> State<P> {
	fn charge<E: serde::de::Error>(&mut self, bytes: usize) -> Result<(), E> {
		self.bytes = self.bytes.saturating_add(bytes);
		if self.bytes > P::MAX_BYTES {
			return Err(self.reject(Error::new(P::FIELD, Rule::Bytes)));
		}
		Ok(())
	}
	fn reject<E: serde::de::Error>(&mut self, error: Error) -> E {
		let result = E::custom(&error);
		self.error = Some(error);
		result
	}
}
impl<'de, P: JsonPolicy> DeserializeSeed<'de> for Node<'_, P> {
	type Value = Value;
	fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
		if self.depth > P::MAX_DEPTH {
			return Err(self.state.reject(Error::new(P::FIELD, Rule::JsonDepth)));
		}
		self.state.nodes += 1;
		if self.state.nodes > P::MAX_NODES {
			return Err(self.state.reject(Error::new(P::FIELD, Rule::JsonNodes)));
		}
		d.deserialize_any(self)
	}
}
impl<'de, P: JsonPolicy> Visitor<'de> for Node<'_, P> {
	type Value = Value;
	fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("bounded JSON")
	}
	fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
		Ok(Value::Null)
	}
	fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> {
		Ok(Value::Bool(value))
	}
	fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
		Ok(Value::Number(value.into()))
	}
	fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
		Ok(Value::Number(value.into()))
	}
	fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Value, E> {
		Number::from_f64(value)
			.map(Value::Number)
			.ok_or_else(|| self.state.reject(Error::new(P::FIELD, Rule::JsonSyntax)))
	}
	fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
		self.state.charge(value.len())?;
		let value =
			BoundedText::<JsonLeaf>::new(value).map_err(|error| self.state.reject(error))?;
		Ok(Value::String(value.expose().to_owned()))
	}
	fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
		self.visit_str(&value)
	}
	fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
		let mut values = Vec::new();
		while let Some(value) =
			seq.next_element_seed(Node { state: &mut *self.state, depth: self.depth + 1 })?
		{
			values.push(value);
		}
		Ok(Value::Array(values))
	}
	fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
		let mut fields = Map::new();
		while let Some(key) = map.next_key::<String>()? {
			self.state.charge(key.len())?;
			Identifier::<JsonKey>::new(&key).map_err(|error| self.state.reject(error))?;
			if fields.contains_key(&key) {
				return Err(self.state.reject(Error::new(P::FIELD, Rule::JsonDuplicateKey)));
			}
			let value =
				map.next_value_seed(Node { state: &mut *self.state, depth: self.depth + 1 })?;
			fields.insert(key, value);
		}
		Ok(Value::Object(fields))
	}
}
