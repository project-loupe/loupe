//! Raw bytes exercise the persisted cursor and actual Git credential matcher.
//! Legacy origins are replaced without reading them; credential contexts must
//! match the current HTTPS host, effective port and decoded repository path.

use loupe_worker::repo_cache::fuzz_support;

use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	let decoded = fuzz_support::decode_cursor(data);
	let expected = data
		.strip_prefix(b"LOUPE\x01\n")
		.and_then(|body| std::str::from_utf8(body).ok())
		.map(str::trim)
		.filter(|sha| !sha.is_empty());
	assert_eq!(decoded.as_deref(), expected, "cursor magic/version/body contract changed");
	if let Some(sha) = decoded {
		let encoded = fuzz_support::encode_cursor(&sha);
		assert_eq!(fuzz_support::decode_cursor(&encoded).as_deref(), Some(sha.as_str()));
	}

	let url = "https://example.invalid/acme/repo.git";
	let matched = fuzz_support::matches_credential_context(url, data);
	assert_eq!(
		matched,
		fuzz_support::matches_credential_context(
			"https://example.invalid:443/acme/repo%2Egit/",
			data
		)
	);
	if matched {
		for other in [
			"http://example.invalid/acme/repo.git",
			"https://other.invalid/acme/repo.git",
			"https://example.invalid:444/acme/repo.git",
			"https://example.invalid/acme/repo.git/child",
		] {
			assert!(!fuzz_support::matches_credential_context(other, data));
		}
	}
	if let Ok(path) = std::str::from_utf8(data)
		&& !path.bytes().any(|byte| byte.is_ascii_control())
	{
		let frame = format!("protocol=https\nhost=example.invalid\npath={path}\n\n");
		let expected = frame.len() <= 16 * 1024 && path.trim_matches('/') == "acme/repo.git";
		assert_eq!(fuzz_support::matches_credential_context(url, frame.as_bytes()), expected);
	}
}

pub fn worker_repo_cache_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_repo_cache_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
