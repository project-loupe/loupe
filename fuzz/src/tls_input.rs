//! Guarded PEM file, argument and base64 boundaries, with exact byte oracles.
//! Fixture bytes are arbitrary public data; this does not prove memory erasure.

use base64::Engine as _;
use loupe_provenance::Secret;
use loupe_tls::{decode_pem_base64, encode_pem_base64, read_pem_file, PemInput};

use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	if data.len() > 64 * 1024 {
		return;
	}
	let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("PEM fixture: {error}"));
	let path = dir.path().join("input.pem");
	std::fs::write(&path, data).unwrap_or_else(|error| panic!("PEM fixture write: {error}"));
	let loaded = read_pem_file(&path);
	let Ok(raw) = std::str::from_utf8(data) else {
		let error = loaded.err().unwrap_or_else(|| panic!("invalid UTF-8 file accepted"));
		let expected = "PEM input is not valid UTF-8";
		assert_eq!(format!("{error:#}"), expected);
		assert_eq!(error.chain().count(), 1);
		// Alternate Debug inspects the wrapped error without anyhow's backtrace.
		assert_eq!(format!("{error:#?}"), format!("{expected:?}"));
		return;
	};
	let loaded = loaded.unwrap_or_else(|error| panic!("valid UTF-8 file refused: {error}"));
	assert_eq!(loaded.expose().as_bytes(), data, "file loading changed PEM bytes");
	redacted(&loaded);

	let input = PemInput::from(raw);
	assert_eq!(format!("{input:?}"), "[redacted]");
	assert_eq!(format!("{input:#?}"), "[redacted]");
	assert_eq!(format!("{input}"), "[redacted]");
	assert_eq!(format!("{input:#}"), "[redacted]");
	let shared = input.clone();
	let retired = input.into_pem();
	assert_eq!(retired.expose(), raw);
	assert_eq!(shared.expose(), raw);
	redacted(&retired);
	let retired = shared.into_pem();
	assert_eq!(retired.expose(), raw);
	redacted(&retired);

	let encoded = encode_pem_base64(raw).unwrap_or_else(|error| panic!("PEM export: {error}"));
	assert_eq!(encoded.expose(), &base64::engine::general_purpose::STANDARD.encode(data));
	redacted(&encoded);
	let back = decode_pem_base64(encoded.expose())
		.unwrap_or_else(|error| panic!("exported base64 refused: {error}"));
	assert_eq!(back.expose(), raw);
	redacted(&back);

	// The library's allocating reference decoder checks our guarded wrapper's
	// admission and transfer. It is not an independent base64 algorithm proof.
	let expected = base64::engine::general_purpose::STANDARD
		.decode(data)
		.map_err(|_| "invalid base64 PEM input")
		.and_then(|bytes| String::from_utf8(bytes).map_err(|_| "PEM input is not valid UTF-8"));
	let actual = decode_pem_base64(raw);
	assert_eq!(actual.is_ok(), expected.is_ok(), "base64 input admission changed");
	match (actual, expected) {
		(Ok(value), Ok(expected)) => {
			assert_eq!(value.expose(), &expected, "base64 decode changed PEM bytes");
			redacted(&value);
		},
		(Err(error), Err(expected)) => {
			assert_eq!(format!("{error:#}"), expected);
			assert_eq!(error.chain().count(), 1);
			// Alternate Debug inspects the wrapped error without anyhow's backtrace.
			assert_eq!(format!("{error:#?}"), format!("{expected:?}"));
		},
		_ => panic!("base64 input admission changed"),
	}
}

fn redacted(value: &Secret<String>) {
	for rendered in
		[format!("{value:?}"), format!("{value:#?}"), format!("{value}"), format!("{value:#}")]
	{
		assert_eq!(rendered, "[redacted]");
	}
}

pub fn tls_input_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tls_input_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller supplies readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn file_growth_and_base64_error_classes_reach_the_oracle() {
		for raw in [b"".as_slice(), b"QUJD", b" QUJD ", b"/w==", b"!!!!", b"invalid\xff"] {
			do_test(raw);
		}
		for size in [8191, 8192, 8193, 16384, 32769, 65536] {
			do_test(&vec![b'x'; size]);
		}
	}
}
