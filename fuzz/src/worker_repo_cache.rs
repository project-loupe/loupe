//! Raw bytes exercise the persisted cursor and actual Git credential matcher.
//! Legacy origins are replaced without reading them; credential contexts must
//! match the current HTTPS host, effective port and decoded repository path.

use loupe_worker::repo_cache::fuzz_support;

use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	if data.len() > 65_536 {
		return;
	}
	let recipe = data.strip_prefix(b"\xffCURSOR").map(|control| {
		let len = [0, 1, 2 * 1024 * 1024 - 1, 2 * 1024 * 1024, 2 * 1024 * 1024 + 1]
			[usize::from(control.first().copied().unwrap_or(0) % 5)];
		let mut bytes = b"LOUPE\x01\n".to_vec();
		bytes.resize(bytes.len() + len, b'a');
		bytes
	});
	let data = recipe.as_deref().unwrap_or(data);
	let decoded = fuzz_support::decode_cursor(data);
	let expected = data
		.strip_prefix(b"LOUPE\x01\n")
		.and_then(|body| std::str::from_utf8(body).ok())
		.map(str::trim)
		.filter(|sha| !sha.is_empty() && crate::worker_client_ingress::oracle::text(sha, false));
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

#[cfg(test)]
mod tests {
	#[test]
	fn original_cursor_file_policy_and_exact_limits() {
		for raw in [
			b"LOUPE\x01\n base ".as_slice(),
			b"LOUPE\x01\nbad\x01revision",
			b"LOUPE\x01\n",
			b"LOUPE\x02\nbase",
			b"LOUPE\x01\n\xff",
		] {
			super::do_test(raw);
		}
		for choice in 0..5 {
			let mut raw = b"\xffCURSOR".to_vec();
			raw.push(choice);
			super::do_test(&raw);
		}
		let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("cursor fixture: {error}"));
		let cache = loupe_worker::RepoCache::new(dir.path().to_owned(), u64::MAX, None)
			.unwrap_or_else(|error| panic!("cursor cache: {error}"));
		let key = loupe_worker::RepoKey::new("local", "owner", "repo");
		std::fs::create_dir_all(cache.repo_path(&key))
			.unwrap_or_else(|error| panic!("cursor parent: {error}"));
		for (raw, expected) in [(" base ", Some("base")), ("bad\u{1}revision", None), ("", None)] {
			cache.write_cursor(&key, raw).unwrap_or_else(|error| panic!("write cursor: {error}"));
			assert_eq!(
				cache.read_cursor(&key).as_deref(),
				expected,
				"actual persisted cursor differs from admitted Repo decoder"
			);
		}
	}
}
