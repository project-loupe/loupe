//! Six little-endian bytes select client/min/max u16 protocol versions.

use loupe_proto::{check_protocol_version, ProtocolMismatch};

use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	let Some(bytes) = data.get(..6) else { return };
	let client = u16::from_le_bytes([bytes[0], bytes[1]]);
	let min = u16::from_le_bytes([bytes[2], bytes[3]]);
	let max = u16::from_le_bytes([bytes[4], bytes[5]]);
	let result = check_protocol_version(client, min, max);
	// Widen before subtracting: this specification cannot wrap at either end.
	let offset = i32::from(client) - i32::from(min);
	let width = i32::from(max) - i32::from(min);
	let expected = offset >= 0 && offset <= width;
	assert_eq!(result.is_ok(), expected, "protocol window disagrees with interval oracle");
	if let Err(error) = result {
		assert_eq!(error, ProtocolMismatch { client, server_min: min, server_max: max });
		assert_eq!(
			error.to_string(),
			format!(
			"loupe protocol version mismatch: client sent {client}, server supports [{min}, {max}]"
		)
		);
		assert_eq!(
			format!("{error:?}"),
			format!(
				"ProtocolMismatch {{ client: {client}, server_min: {min}, server_max: {max} }}"
			)
		);
	}
}

pub fn proto_version_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proto_version_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
