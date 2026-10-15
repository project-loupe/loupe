//! Header admission follows `HeaderValue::to_str`, including HTAB. It is
//! deliberately broader than base64url; the lease lookup authorizes the hash.
use http::{HeaderMap, HeaderValue, StatusCode};
use loupe_proto::JOB_CAPABILITY_HEADER;

use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	assert!(loupe_server::job_capability::parse_hash(&HeaderMap::new()).is_err());
	let Ok(value) = HeaderValue::from_bytes(data) else { return };
	let mut headers = HeaderMap::new();
	headers.insert(JOB_CAPABILITY_HEADER, value);
	let result = loupe_server::job_capability::parse_hash(&headers);
	let admitted =
		data.len() == 43 && data.iter().all(|byte| (b' '..=b'~').contains(byte) || *byte == b'\t');
	assert_eq!(result.is_ok(), admitted, "capability admission differs from header contract");
	match result {
		Ok(hash) => assert_eq!(hash, *blake3::hash(data).as_bytes()),
		Err((status, message)) => {
			assert_eq!(status, StatusCode::FORBIDDEN);
			assert_eq!(message, "invalid or expired job capability");
		},
	}
}

pub fn server_capability_header_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn server_capability_header_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller guarantees a valid readable input buffer.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
