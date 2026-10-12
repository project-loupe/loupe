//! Independent lexical, containment, symlink, and line-range oracles.

use std::path::{Component, Path};

use loupe_worker::mcp::{fuzz_support, normalize_path_component_rules};

use crate::utils::input::ByteSource;
use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	let mut input = ByteSource::new(data);
	let start = input.u32().unwrap_or_default();
	let end = input.u32().unwrap_or_default();
	let Some(path_bytes) = input.len_prefixed(2048) else { return };
	let Ok(path) = std::str::from_utf8(path_bytes) else { return };
	let workdir = tempfile::tempdir().unwrap_or_else(|e| panic!("worktree: {e}"));
	let outside = tempfile::tempdir().unwrap_or_else(|e| panic!("outside: {e}"));
	std::fs::create_dir(workdir.path().join("src")).unwrap_or_else(|e| panic!("source dir: {e}"));
	let contents = input.rest();
	std::fs::write(workdir.path().join("src/lib.rs"), contents)
		.unwrap_or_else(|e| panic!("source: {e}"));
	std::fs::write(outside.path().join("file"), "outside\n")
		.unwrap_or_else(|e| panic!("outside source: {e}"));
	#[cfg(unix)]
	{
		std::os::unix::fs::symlink(outside.path(), workdir.path().join("escape"))
			.unwrap_or_else(|e| panic!("escape: {e}"));
		std::os::unix::fs::symlink("src", workdir.path().join("inside"))
			.unwrap_or_else(|e| panic!("inside: {e}"));
	}
	let stripped = path.strip_prefix("/workdir/").unwrap_or(path);
	let parts: Vec<_> =
		stripped.split('/').filter(|part| !part.is_empty() && *part != ".").collect();
	let expected = !stripped.trim().is_empty()
		&& !stripped.starts_with('/')
		&& !parts.is_empty()
		&& !parts.contains(&"..");
	let lexical = normalize_path_component_rules(path);
	assert_eq!(lexical.is_ok(), expected);
	if let Ok(relative) = lexical {
		assert_eq!(relative, parts.join("/"));
		assert!(Path::new(&relative).components().all(|part| matches!(part, Component::Normal(_))));
		let candidate = workdir.path().join(&relative);
		// Materialize fuzzed names only below the fresh worktree and
		// outside the deliberately external symlink's subtree.
		if !relative.starts_with("escape/") && relative != "escape" && !candidate.exists() {
			if let Some(parent) = candidate.parent() {
				let _ = std::fs::create_dir_all(parent);
			}
			let _ = std::fs::write(&candidate, contents);
		}
		let normalized = fuzz_support::normalize(workdir.path(), path);
		let first_admitted = crate::worker_mcp_ingress::oracle::normalized_path(path).is_ok();
		if candidate.exists() {
			let canonical = candidate.canonicalize().unwrap_or_else(|e| panic!("candidate: {e}"));
			let root = workdir.path().canonicalize().unwrap_or_else(|e| panic!("root: {e}"));
			assert_eq!(normalized.is_ok(), first_admitted && canonical.starts_with(root));
		} else {
			assert_eq!(normalized.is_ok(), first_admitted);
		}
		if let Ok(relative) = normalized {
			let fingerprint = fuzz_support::fingerprint(workdir.path(), &relative, start, end);
			assert_eq!(fingerprint.len(), 64);
			if let Ok(source) = std::fs::read_to_string(&candidate) {
				let window = source
					.lines()
					.enumerate()
					.filter_map(|(index, line)| {
						let number = index as u64 + 1;
						(number + 2 >= u64::from(start)
							&& number <= u64::from(end.saturating_add(2)))
						.then_some(line)
					})
					.collect::<Vec<_>>()
					.join("\n");
				assert_eq!(fingerprint, independent_fingerprint(&relative, &window));
			} else {
				assert_eq!(
					fingerprint,
					independent_fingerprint(&relative, &format!("L{start}-L{end}")),
					"unreadable or invalid UTF-8 source changed fallback hash"
				);
			}
			let args = serde_json::json!({"severity":"high","title":"title","file":path,
				"line_start":start,"line_end":end,"description":"description","poc_unified":"diff"});
			let finding = fuzz_support::finding(workdir.path(), &args);
			// The first owner retains its normalized path. Strict protocol refusal
			// is a separate boundary, without repeating path normalization.
			assert_eq!(
				finding.is_ok(),
				first_admitted,
				"actual original MCP finding admission differs"
			);
			if let Ok(finding) = finding {
				assert_eq!(finding.file_path, relative);
				assert_eq!(finding.line_start, start);
				assert_eq!(finding.line_end, end);
				assert_eq!(finding.fingerprint, fingerprint);
			}
			let strict = fuzz_support::validate_finding(workdir.path(), &strict_args(path));
			assert_eq!(
				strict.is_ok(),
				!relative.trim().is_empty(),
				"final strict path refusal differs"
			);
		}
	}
	#[cfg(unix)]
	assert!(fuzz_support::normalize(workdir.path(), "escape/file").is_err());
}

fn strict_args(path: &str) -> serde_json::Value {
	serde_json::json!({"severity":"high","title":"A valid example title","file":path,
		"line_start":1,"line_end":1,"description":"description ".repeat(10),
		"poc_unified":"--- a/src.rs\n+++ b/src.rs\n@@ -1 +1 @@\n-old\n+new\n"})
}

fn independent_fingerprint(file: &str, window: &str) -> String {
	let normalized = window
		.lines()
		.filter_map(|line| {
			let words = line.split_whitespace().collect::<Vec<_>>();
			(!words.is_empty()).then(|| words.join(" ").to_lowercase())
		})
		.collect::<Vec<_>>()
		.join("\n");
	let mut digest = blake3::Hasher::new();
	digest.update(b"llm-code-review\0");
	digest.update(file.as_bytes());
	digest.update(b"\0");
	digest.update(normalized.as_bytes());
	digest.finalize().to_hex().to_string()
}

pub fn worker_mcp_submission_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes during the call.
#[allow(unsafe_code)] // C fuzz entry point.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_mcp_submission_run(data: *const u8, datalen: usize) {
	// SAFETY: supplied by the caller as documented above.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	fn path_input(path: &str) -> Vec<u8> {
		let mut input = Vec::new();
		input.extend(1u32.to_le_bytes());
		input.extend(1u32.to_le_bytes());
		input.extend(
			u16::try_from(path.len()).unwrap_or_else(|e| panic!("path length: {e}")).to_le_bytes(),
		);
		input.extend(path.as_bytes());
		input.extend(b"fn source() {}\n");
		input
	}

	fn check_path(path: &str, expected_first: Option<&str>, strict_admitted: bool) {
		let first = crate::worker_mcp_ingress::oracle::normalized_path(path);
		assert_eq!(first.as_deref().ok(), expected_first, "first path owner changed");
		let workdir = tempfile::tempdir().unwrap_or_else(|e| panic!("worktree: {e}"));
		let args = serde_json::json!({"severity":"high","title":"title","file":path,
			"line_start":1,"line_end":1,"description":"description","poc_unified":"diff"});
		let finding = fuzz_support::finding(workdir.path(), &args);
		assert_eq!(finding.is_ok(), expected_first.is_some(), "actual first owner changed");
		if let Ok(finding) = finding {
			assert_eq!(Some(finding.file_path.as_str()), expected_first);
		}
		let strict = fuzz_support::validate_finding(workdir.path(), &strict_args(path));
		assert_eq!(strict.is_ok(), strict_admitted, "actual final strict view changed");
		if expected_first.is_some_and(|path| path.trim().is_empty()) {
			let Err(error) = strict else {
				panic!("whitespace path unexpectedly passed strict validation")
			};
			assert!(
				error.to_string().contains("file_path"),
				"whitespace refusal must come from the final strict path predicate"
			);
		}
		do_test(&path_input(path));
	}

	#[test]
	fn captured_whitespace_path_reaches_final_strict_refusal() {
		do_test(include_bytes!(
			"../test_cases/worker_mcp_submission/whitespace-projection-captured"
		));
	}

	#[test]
	fn space_slash_reaches_final_strict_refusal() {
		check_path(" /", Some(" "), false);
	}

	#[test]
	fn space_curdir_reaches_final_strict_refusal() {
		check_path(" /./", Some(" "), false);
	}

	#[test]
	fn raw_space_refusal_and_significant_space_controls() {
		check_path(" ", None, false);
		check_path(" /a", Some(" /a"), true);
		check_path(" a/", Some(" a"), true);
		check_path("src/lib.rs", Some("src/lib.rs"), true);
	}
}
