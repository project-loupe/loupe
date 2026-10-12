//! Serde owns the grammar. Forward-only values stay encoded; each temporary
//! object projection retains only guarded keys and original borrowed tokens.
use std::collections::BTreeMap;
use std::{fmt, io};

use loupe_provenance::{Secret, Zeroise};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;

use super::Failure;

pub(super) struct Buffer {
	allocation: Box<[u8]>,
	used: usize,
	#[cfg(any(test, fuzzing))]
	audit: Option<audit::Audit>,
}
impl Buffer {
	pub(super) fn new(capacity: usize) -> Self {
		#[cfg(fuzzing)]
		crate::fuzz_support::record(crate::fuzz_support::Observation::BufferAllocation(capacity));
		Self {
			allocation: vec![0; capacity].into_boxed_slice(),
			used: 0,
			#[cfg(any(test, fuzzing))]
			audit: audit::CURRENT.with(|a| a.borrow().clone()),
		}
	}
	pub(super) fn append(&mut self, bytes: &[u8]) -> Result<(), Failure> {
		if bytes.len() > self.allocation.len() - self.used {
			return Err(Failure::TooLarge);
		}
		self.allocation[self.used..self.used + bytes.len()].copy_from_slice(bytes);
		self.used += bytes.len();
		Ok(())
	}
}
impl AsRef<[u8]> for Buffer {
	fn as_ref(&self) -> &[u8] {
		&self.allocation[..self.used]
	}
}
impl Drop for Buffer {
	fn drop(&mut self) {
		self.allocation.zeroise();
		#[cfg(any(test, fuzzing))]
		if let Some(audit) = &self.audit {
			audit.lock().unwrap_or_else(|_| panic!("web drop audit poisoned")).push((
				self.allocation.len(),
				self.used,
				self.allocation.iter().all(|b| *b == 0),
			));
		}
	}
}

#[cfg(any(test, fuzzing))]
pub(crate) mod audit {
	pub(crate) type Audit = std::sync::Arc<std::sync::Mutex<Vec<(usize, usize, bool)>>>;
	thread_local! {pub(super) static CURRENT:std::cell::RefCell<Option<Audit>>=const{std::cell::RefCell::new(None)};}
	pub(crate) fn start() -> Audit {
		let audit = Audit::default();
		CURRENT.with(|a| *a.borrow_mut() = Some(audit.clone()));
		audit
	}
	#[cfg(fuzzing)]
	pub(crate) fn stop() {
		CURRENT.with(|a| *a.borrow_mut() = None);
	}
}

struct Grammar;
impl<'de> DeserializeSeed<'de> for Grammar {
	type Value = ();
	fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
		d.deserialize_any(self)
	}
}
impl<'de> Visitor<'de> for Grammar {
	type Value = ();
	fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("JSON value")
	}
	fn visit_unit<E: de::Error>(self) -> Result<(), E> {
		Ok(())
	}
	fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
		Ok(())
	}
	fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
		Ok(())
	}
	fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
		Ok(())
	}
	fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
		Ok(())
	}
	fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
		Ok(())
	}
	fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<(), A::Error> {
		while a.next_element_seed(Grammar)?.is_some() {}
		Ok(())
	}
	fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<(), A::Error> {
		while a.next_key_seed(Grammar)?.is_some() {
			a.next_value_seed(Grammar)?;
		}
		Ok(())
	}
}
pub(super) fn admit(bytes: &[u8]) -> Result<(), Failure> {
	let mut d = serde_json::Deserializer::from_slice(bytes);
	Grammar.deserialize(&mut d).map_err(|_| Failure::Json)?;
	d.end().map_err(|_| Failure::Json)
}

struct Key(Secret<String>);
impl PartialEq for Key {
	fn eq(&self, r: &Self) -> bool {
		self.0.expose() == r.0.expose()
	}
}
impl Eq for Key {}
impl PartialOrd for Key {
	fn partial_cmp(&self, r: &Self) -> Option<std::cmp::Ordering> {
		Some(self.cmp(r))
	}
}
impl Ord for Key {
	fn cmp(&self, r: &Self) -> std::cmp::Ordering {
		self.0.expose().cmp(r.0.expose())
	}
}
impl<'de> Deserialize<'de> for Key {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct K;
		impl Visitor<'_> for K {
			type Value = Key;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				f.write_str("JSON member name")
			}
			fn visit_str<E: de::Error>(self, s: &str) -> Result<Key, E> {
				Ok(Key(Secret::new(s.to_owned())))
			}
			fn visit_string<E: de::Error>(self, s: String) -> Result<Key, E> {
				Ok(Key(Secret::new(s)))
			}
		}
		d.deserialize_str(K)
	}
}
struct Object<'a>(BTreeMap<Key, &'a RawValue>);
impl<'de> Deserialize<'de> for Object<'de> {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct O;
		impl<'de> Visitor<'de> for O {
			type Value = Object<'de>;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				f.write_str("JSON object")
			}
			fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
				let mut fields = BTreeMap::new();
				while let Some((key, value)) = a.next_entry::<Key, &RawValue>()? {
					fields.insert(key, value);
				}
				Ok(Object(fields))
			}
		}
		d.deserialize_map(O)
	}
}
struct Writer<'a> {
	count: usize,
	buffer: Option<&'a mut Buffer>,
}
impl io::Write for Writer<'_> {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.count = self
			.count
			.checked_add(bytes.len())
			.ok_or_else(|| io::Error::other("forward output too large"))?;
		if let Some(buffer) = self.buffer.as_mut() {
			buffer.append(bytes).map_err(|_| io::Error::other("forward output length mismatch"))?;
		}
		Ok(bytes.len())
	}
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}
impl Writer<'_> {
	fn bytes(&mut self, bytes: &[u8]) -> Result<(), Failure> {
		use io::Write;
		self.write_all(bytes).map_err(|_| Failure::Json)
	}
}
fn emit(raw: &str, stamp: bool, w: &mut Writer<'_>) -> Result<(), Failure> {
	let raw = raw.trim();
	match raw.as_bytes().first() {
		Some(b'{') => {
			let object: Object<'_> = serde_json::from_str(raw).map_err(|_| Failure::Json)?;
			w.bytes(b"{")?;
			let mut first = true;
			for (key, value) in object.0 {
				if stamp && key.0.expose() == "protocol_version" {
					continue;
				}
				if !first {
					w.bytes(b",")?;
				}
				first = false;
				serde_json::to_writer(&mut *w, key.0.expose()).map_err(|_| Failure::Json)?;
				w.bytes(b":")?;
				emit(value.get(), false, w)?;
			}
			if stamp {
				if !first {
					w.bytes(b",")?;
				}
				w.bytes(b"\"protocol_version\":")?;
				serde_json::to_writer(&mut *w, &loupe_proto::PROTOCOL_VERSION)
					.map_err(|_| Failure::Json)?;
			}
			w.bytes(b"}")
		},
		Some(b'[') => {
			let array: Vec<&RawValue> = serde_json::from_str(raw).map_err(|_| Failure::Json)?;
			w.bytes(b"[")?;
			for (index, value) in array.into_iter().enumerate() {
				if index > 0 {
					w.bytes(b",")?;
				}
				emit(value.get(), false, w)?;
			}
			w.bytes(b"]")
		},
		Some(b'"' | b't' | b'f' | b'n') => w.bytes(raw.as_bytes()),
		Some(_) => {
			let number: serde_json::Number =
				serde_json::from_str(raw).map_err(|_| Failure::Json)?;
			serde_json::to_writer(w, &number).map_err(|_| Failure::Json)
		},
		None => Err(Failure::Json),
	}
}
/// Private concrete Browser wire encoder; no arbitrary Serialize callback.
pub(super) fn encode_browser(raw: &[u8]) -> Result<bytes::Bytes, Failure> {
	encode(raw, true)
}
pub(super) fn encode_server(raw: &[u8]) -> Result<bytes::Bytes, Failure> {
	encode(raw, false)
}
fn encode(raw: &[u8], stamp: bool) -> Result<bytes::Bytes, Failure> {
	let raw = std::str::from_utf8(raw).map_err(|_| Failure::Json)?;
	let mut count = Writer { count: 0, buffer: None };
	emit(raw, stamp, &mut count)?;
	let mut buffer = Buffer::new(count.count);
	let mut write = Writer { count: 0, buffer: Some(&mut buffer) };
	emit(raw, stamp, &mut write)?;
	if write.count != count.count {
		return Err(Failure::Json);
	}
	Ok(bytes::Bytes::from_owner(buffer))
}

/// Fixed diagnostic envelope. Text remains data in the guarded encoded output.
pub(super) fn encode_diagnostic(text: &str) -> Result<bytes::Bytes, Failure> {
	fn emit(text: &str, w: &mut Writer<'_>) -> Result<(), Failure> {
		w.bytes(b"{\"error\":")?;
		serde_json::to_writer(&mut *w, text).map_err(|_| Failure::Json)?;
		w.bytes(b"}")
	}
	let mut count = Writer { count: 0, buffer: None };
	emit(text, &mut count)?;
	let mut buffer = Buffer::new(count.count);
	let mut write = Writer { count: 0, buffer: Some(&mut buffer) };
	emit(text, &mut write)?;
	if write.count != count.count {
		return Err(Failure::Json);
	}
	Ok(bytes::Bytes::from_owner(buffer))
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn grammar_and_forward_semantics_match_independent_value_oracle() {
		let mut cases=vec!["null".to_owned(),"-0".into(),"-0.0".into(),"1e0".into(),"1e-100".into(),"18446744073709551616".into(),"1e400".into(),r#""\uD800""#.into(),r#"{"a":1,"a":2,"nested":{"github_pat":"old","github_\u0070at":"new"},"protocol_version":8,"protocol_\u0076ersion":9}"#.into(),r#"{"a":[{"b":1,"b":2}],"x":"\"\\\r\n\uD83D\uDE00"}"#.into()];
		for depth in 124..=130 {
			cases.push(format!("{}0{}", "[".repeat(depth), "]".repeat(depth)));
		}
		for raw in cases {
			let expected = serde_json::from_str::<serde_json::Value>(&raw);
			assert_eq!(admit(raw.as_bytes()).is_ok(), expected.is_ok(), "{raw}");
			if let Ok(mut expected) = expected {
				if let Some(map) = expected.as_object_mut() {
					map.insert("protocol_version".into(), loupe_proto::PROTOCOL_VERSION.into());
				}
				let bytes = encode_browser(raw.as_bytes()).unwrap();
				assert_eq!(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(), expected);
			}
		}
	}
	#[test]
	fn final_transport_clone_retains_and_then_wipes_the_exact_allocation() {
		let audit = audit::start();
		let bytes = encode_browser(br#"{"github_pat":"FAKE_PAT"}"#).unwrap();
		let second = bytes.clone();
		assert_eq!(bytes.as_ptr(), second.as_ptr());
		drop(bytes);
		assert!(audit.lock().unwrap().is_empty());
		drop(second);
		let records = audit.lock().unwrap();
		assert_eq!(records.len(), 1);
		assert!(records[0].2);
		assert_eq!(records[0].0, records[0].1);
	}
}
