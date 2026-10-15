//! Strict source-owned paths plus lexical predicates. The lexical
//! observation is not an unlabelled full submission construction entry point.

use crate::utils::test_logger;

pub fn legacy_acceptance(path: &str) -> (bool, bool) {
	(
		loupe_proto::fuzz_llm_path_is_normalized(path),
		loupe_worker::mcp::normalize_path_component_rules(path).is_ok(),
	)
}

pub fn do_test(data: &[u8]) {
	let Ok(path) = std::str::from_utf8(data) else { return };
	if let Ok(strict) = crate::fixtures::path(path) {
		assert_eq!(strict.expose(), path);
		assert!(path.len() <= 512);
		assert!(!path.contains(['\\', '\0']));
		assert!(path.split('/').all(|part| !matches!(part, "" | "." | "..")));
	}
	let proto_expected = !path.trim().is_empty()
		&& !path.starts_with('/')
		&& path != "."
		&& !path.starts_with("./")
		&& !path.split('/').any(|part| part == "..");
	let stripped = path.strip_prefix("/workdir/").unwrap_or(path);
	let parts: Vec<_> =
		stripped.split('/').filter(|part| !part.is_empty() && *part != ".").collect();
	let mcp_expected = !stripped.trim().is_empty()
		&& !stripped.starts_with('/')
		&& !parts.is_empty()
		&& !parts.contains(&"..");
	assert_eq!(legacy_acceptance(path), (proto_expected, mcp_expected));
}

pub fn core_text_repo_path_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes during the call.
#[allow(unsafe_code)] // C fuzz entry point.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn core_text_repo_path_run(data: *const u8, datalen: usize) {
	// SAFETY: supplied by the caller as documented above.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn recorded_legacy_disagreements_stay_explicit() {
		for path in ["a//b", "a/./b", "a/", "a\\b", "a\0b", "a\nb"] {
			assert!(crate::fixtures::path(path).is_err());
			assert_eq!(legacy_acceptance(path), (true, true), "{path:?}");
		}
		for path in ["./a", "/workdir/a"] {
			assert!(crate::fixtures::path(path).is_err());
			assert_eq!(legacy_acceptance(path), (false, true), "{path:?}");
		}
		let long = "a".repeat(513);
		assert!(crate::fixtures::path(&long).is_err());
		assert_eq!(legacy_acceptance(&long), (true, true));
	}
}
