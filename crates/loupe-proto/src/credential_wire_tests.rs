use std::cell::Cell;
use std::io::Write;

use serde::ser::{Serialize, SerializeSeq, Serializer};

use super::*;

#[test]
fn count_overflow_and_second_pass_growth_fail_closed() {
	let mut count = Count(usize::MAX);
	assert!(count.write_all(b"x").is_err());
	let mut buffer = JsonBuffer::new(4);
	let pointer = buffer.bytes.as_ptr();
	buffer.write_all(b"key").unwrap();
	assert!(buffer.write_all(b"!!").is_err());
	assert_eq!(buffer.bytes.as_ptr(), pointer);
	assert_eq!(&buffer.bytes[..buffer.used], b"key");
	assert!(buffer.finish().is_err());
}

struct Changing {
	pass: Cell<usize>,
	second: Option<&'static str>,
}

impl Serialize for Changing {
	fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		let pass = self.pass.replace(self.pass.get() + 1);
		let mut seq = serializer.serialize_seq(Some(2))?;
		seq.serialize_element("FAKE_SECRET_PREFIX")?;
		if pass == 0 {
			seq.serialize_element("12345")?;
		} else if let Some(second) = self.second {
			seq.serialize_element(second)?;
		} else {
			return Err(serde::ser::Error::custom("synthetic serializer failure"));
		}
		seq.end()
	}
}

#[test]
fn partial_errors_and_both_length_mismatches_wipe_live_storage() {
	for second in [None, Some("123456"), Some("1")] {
		CLEANUPS.with(|seen| seen.borrow_mut().clear());
		assert!(encode(&Changing { pass: Cell::new(0), second }, false).is_err());
		CLEANUPS.with(|seen| {
			let seen = seen.borrow();
			assert_eq!(seen.len(), 1);
			assert!(seen[0].0 > b"FAKE_SECRET_PREFIX".len());
			assert!(seen[0].1, "partial serialized buffer was not erased");
		});
	}
}

#[test]
fn finishing_transfers_the_original_allocation() {
	CLEANUPS.with(|seen| seen.borrow_mut().clear());
	let mut buffer = JsonBuffer::new(6);
	let pointer = buffer.bytes.as_ptr();
	buffer.write_all(b"secret").unwrap();
	let value = buffer.finish().unwrap();
	assert_eq!(value.expose().as_ptr(), pointer);
	assert_eq!(value.expose(), b"secret");
	assert_eq!(format!("{value:?}"), "[redacted]");
	CLEANUPS.with(|seen| assert!(seen.borrow().iter().all(|(len, _)| *len == 0)));
}
#[test]
fn server_certificate_export_preserves_pretty_schema_and_escaped_bytes() {
	let certificate = "FAKE_CERT\n\"\\λ";
	let key = loupe_provenance::Secret::new("FAKE_KEY\n\"\\λ".to_owned());
	let actual = super::server_certificate_json_pretty(certificate, &key).unwrap();
	let expected = serde_json::to_vec_pretty(&serde_json::json!({
		"server_cert_pem": certificate,
		"server_key_pem": key.expose(),
	}))
	.unwrap();
	assert_eq!(actual.expose(), &expected);
	assert_eq!(format!("{actual:?}"), "[redacted]");
}
