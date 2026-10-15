//! Selector 0: PID JSON, 1: LE uid + uid_map, 2: route lines, 3: address lines.
//! Only the production pure parsers run; no process, namespace or network I/O.

use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv4Addr;

use loupe_worker::sandbox::fuzzing;
use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserializer;

use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	let Some((&selector, raw)) = data.split_first() else { return };
	if raw.len() > 64 * 1024 {
		return;
	}
	match selector % 4 {
		0 => {
			assert_eq!(
				fuzzing::bwrap_pid(raw).ok(),
				expected_pid(raw).ok(),
				"PID parser differs from required-field/sequence oracle"
			);
		},
		1 => {
			let Some(bytes) = raw.get(..4) else { return };
			let uid = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
			let Ok(map) = std::str::from_utf8(&raw[4..]) else { return };
			let expected = map.lines().any(|line| {
				let fields: Vec<_> = line.split_whitespace().take(2).collect();
				fields.len() == 2 && fields.iter().all(|field| field.parse::<u32>() == Ok(uid))
			});
			assert_eq!(fuzzing::uid_map(map, uid), expected, "uid_map identity pair differs");
		},
		2 => {
			let Ok(text) = std::str::from_utf8(raw) else { return };
			let expected: BTreeSet<_> = text
				.lines()
				.filter_map(|line| line.split_whitespace().next())
				.filter(|value| network_allowed(value))
				.map(str::to_owned)
				.collect();
			let actual = fuzzing::connected_routes(text);
			assert_eq!(actual, expected, "route parse disagrees with network oracle");
			for route in actual {
				assert!(fuzzing::valid_network(&route));
			}
		},
		3 => {
			let Ok(text) = std::str::from_utf8(raw) else { return };
			let expected: BTreeSet<Ipv4Addr> = text
				.lines()
				.filter_map(|line| {
					let mut fields = line.split_whitespace();
					fields.find(|field| *field == "inet")?;
					fields.next()?.split('/').next()?.parse().ok()
				})
				.collect();
			assert_eq!(fuzzing::host_addresses(text), expected, "address parse differs");
		},
		_ => unreachable!(),
	}
}

// Model the document contract without deriving the production struct again.
// Serde structs accept a single-field sequence as well as an object. Unknown
// values are skipped, including string bytes that Value would reject as UTF-8.
// The PID itself must still be an integer in u32 range, exactly once.
fn expected_pid(raw: &[u8]) -> serde_json::Result<u32> {
	struct PidDocument;
	impl<'de> Visitor<'de> for PidDocument {
		type Value = u32;

		fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
			formatter.write_str("one child-pid field or one PID sequence entry")
		}

		fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<u32, M::Error> {
			let mut pid = None;
			while let Some(key) = map.next_key::<String>()? {
				if key == "child-pid" {
					if pid.is_some() {
						return Err(de::Error::duplicate_field("child-pid"));
					}
					pid = Some(pid_in_range(map.next_value::<u64>()?)?);
				} else {
					map.next_value::<IgnoredAny>()?;
				}
			}
			pid.ok_or_else(|| de::Error::missing_field("child-pid"))
		}

		fn visit_seq<S: SeqAccess<'de>>(self, mut sequence: S) -> Result<u32, S::Error> {
			let value = sequence
				.next_element::<u64>()?
				.ok_or_else(|| de::Error::invalid_length(0, &self))?;
			if sequence.next_element::<IgnoredAny>()?.is_some() {
				return Err(de::Error::invalid_length(2, &self));
			}
			pid_in_range(value)
		}
	}

	fn pid_in_range<E: de::Error>(value: u64) -> Result<u32, E> {
		u32::try_from(value).map_err(|_| E::custom("PID exceeds u32 range"))
	}

	let mut decoder = serde_json::Deserializer::from_slice(raw);
	let pid = decoder.deserialize_any(PidDocument)?;
	decoder.end()?;
	Ok(pid)
}

fn network_allowed(value: &str) -> bool {
	let mut fields = value.split('/');
	let Some(address) = fields.next() else { return false };
	if address.parse::<Ipv4Addr>().is_err() {
		return false;
	}
	match fields.next() {
		None => true,
		Some(prefix) => {
			prefix.parse::<u32>().is_ok_and(|bits| bits <= 32) && fields.next().is_none()
		},
	}
}

pub fn worker_network_parsers_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_network_parsers_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn pid_oracle_accepts_typed_struct_representations() {
		for (raw, pid) in [
			(br#"{"child-pid":0}"#.as_slice(), 0),
			(br#"{"child-pid":4294967295}"#.as_slice(), u32::MAX),
			(b"[42]".as_slice(), 42),
			(b"[4294967295]".as_slice(), u32::MAX),
			(b"{\"child-pid\":42,\"unused\":\"\xff\"}".as_slice(), 42),
			(b"{\"unused\":{\"nested\":\"\xff\"},\"child-pid\":42}".as_slice(), 42),
			(br#"{"child\u002dpid":42,"unused":null,"unused":[false]}"#.as_slice(), 42),
		] {
			assert_eq!(expected_pid(raw).ok(), Some(pid), "PID oracle rejected {raw:?}");
			let data = [b"\0".as_slice(), raw].concat();
			do_test(&data);
		}
	}

	#[test]
	fn pid_oracle_rejects_missing_duplicate_and_wrong_required_fields() {
		for raw in [
			"{}",
			"{\"unused\":42}",
			"{\"child-pid\":42,\"child-pid\":42}",
			r#"{"child-pid":42,"child\u002dpid":43}"#,
			"{\"child-pid\":null}",
			"{\"child-pid\":\"42\"}",
			"{\"child-pid\":true}",
			"{\"child-pid\":[]}",
			"{\"child-pid\":{}}",
			"{\"child-pid\":-1}",
			"{\"child-pid\":-0}",
			"{\"child-pid\":42.0}",
			"{\"child-pid\":42e0}",
			"{\"child-pid\":4294967296}",
			"[]",
			"[42,43]",
			"[null]",
			"[4294967296]",
			"42",
			"null",
			"{\"child-pid\":42} true",
			"{\"child-pid\":42,\"unused\":[}",
		] {
			assert!(expected_pid(raw.as_bytes()).is_err(), "PID oracle accepted {raw}");
			let data = [b"\0".as_slice(), raw.as_bytes()].concat();
			do_test(&data);
		}
	}
}
