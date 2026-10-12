//! Raw file bytes reach the scanner's actual synchronous walk. Byte zero
//! selects cancellation (bit 0), cap+1 (bit 1), or exact cap (bit 2). A byte
//! recognizer independent of regex computes every match and source line.
//! The input cap is 64 KiB; boundary modes pad with non-matching bytes.

use std::fs;
use std::sync::OnceLock;

use loupe_core::Severity;
use loupe_worker::scanners::RegexSecretsScanner;

use crate::utils::redact::{assert_redacted, Redaction};
use crate::utils::test_logger;

const FILE_CAP: usize = 1_048_576;

pub fn do_test(data: &[u8]) {
	if data.len() > 65_536 {
		return;
	}
	let (&mode, body) = data.split_first().unwrap_or((&0, &[]));
	let mut content =
		if mode & 16 != 0 { body.get(1..).unwrap_or_default() } else { body }.to_vec();
	if mode & 2 != 0 {
		content.resize(FILE_CAP + 1, b'x');
	} else if mode & 4 != 0 {
		content.resize(FILE_CAP, b'x');
	}
	// Hostile file names matter too: Finding's description and file_path carry
	// them. Keep the fixture name a bounded single safe filesystem component.
	let name: String =
		body.iter().copied().filter(u8::is_ascii_alphanumeric).take(80).map(char::from).collect();
	let leaf: std::path::PathBuf = if mode & 16 != 0 {
		native_fixture(body.first().copied().unwrap_or(0))
	} else {
		format!("source-{name}.rs").into()
	};
	let temp = tempfile::tempdir().unwrap_or_else(|_| panic!("create regex fixture"));
	let root = temp.path().join("repo");
	fs::create_dir_all(root.join(".git"))
		.unwrap_or_else(|_| panic!("create regex fixture directories"));
	let candidate = root.join(&leaf);
	fs::create_dir_all(candidate.parent().unwrap_or(&root))
		.unwrap_or_else(|_| panic!("create native path parents"));
	fs::write(&candidate, &content).unwrap_or_else(|_| panic!("write regex source"));
	let sibling = b"AKIAIOSFODNN7EXAMPLE";
	fs::write(root.join("legitimate.rs"), sibling)
		.unwrap_or_else(|_| panic!("write legitimate sibling"));
	fs::write(root.join(".git/ignored.rs"), b"AKIAIOSFODNN7EXAMPLE")
		.unwrap_or_else(|_| panic!("write metadata fixture"));
	fs::write(temp.path().join("outside.rs"), b"AKIAIOSFODNN7EXAMPLE")
		.unwrap_or_else(|_| panic!("write outside fixture"));
	#[cfg(unix)]
	std::os::unix::fs::symlink(temp.path().join("outside.rs"), root.join("linked.rs"))
		.unwrap_or_else(|_| panic!("create regex symlink"));
	static SCANNER: OnceLock<RegexSecretsScanner> = OnceLock::new();
	let (findings, typed) = SCANNER
		.get_or_init(RegexSecretsScanner::new)
		.fuzz_walk_observed(&root, mode & 1 != 0)
		.unwrap_or_else(|_| panic!("scan regex fixture"));
	let mut expected = Vec::new();
	if mode & 1 == 0 {
		for (path, bytes) in [
			(leaf.as_path(), content.as_slice()),
			(std::path::Path::new("legitimate.rs"), sibling.as_slice()),
		] {
			if let Some(path) =
				path.to_str().filter(|path| crate::worker_client_ingress::oracle::path(path))
			{
				for (line, range) in matches(bytes) {
					expected.push((path.to_owned(), line, fingerprint(path, &bytes[range])));
				}
			}
		}
	}
	let mut actual = Vec::new();
	assert_eq!(findings.len(), typed.len(), "typed Repo findings were lost at projection");
	for (finding, typed) in findings.iter().zip(typed) {
		let line = finding.line_start.unwrap_or_else(|| panic!("finding without source line"));
		let path = finding
			.file_path
			.as_ref()
			.map(|path| path.expose())
			.unwrap_or_else(|| panic!("finding without source path"));
		actual.push((path.to_owned(), line, finding.fingerprint.expose().to_owned()));
		assert_eq!(finding.scanner_id.expose(), "regex-secrets");
		assert_eq!(finding.severity, Severity::High);
		assert_eq!(finding.line_end, Some(line), "finding ends at wrong source line");
		assert_eq!(finding.title.expose(), "Possible AWS access key id");
		assert_eq!(finding.cwe.as_ref().map(|cwe| cwe.expose()), Some("CWE-798"));
		assert_eq!(finding.description.expose(), format!("Found a string matching the AWS access key id pattern (`AKIA…`) at {path}:{line}. Treat as a potential secret leak — confirm against the AWS account before reporting."));
		assert_eq!(
			(
				typed.scanner,
				typed.title,
				typed.description,
				typed.path,
				typed.start,
				typed.end,
				typed.cwe,
				typed.fingerprint
			),
			(
				finding.scanner_id.expose().to_owned(),
				finding.title.expose().to_owned(),
				finding.description.expose().to_owned(),
				finding.file_path.as_ref().map(|path| path.expose().to_owned()),
				finding.line_start,
				finding.line_end,
				finding.cwe.as_ref().map(|cwe| cwe.expose().to_owned()),
				finding.fingerprint.expose().to_owned()
			),
			"actual typed Repo output differs from its field observations"
		);
		let baseline = Redaction::baseline(format!(
			"Finding {{ source: \"repo\", severity: High, line_start: Some({line}), line_end: Some({line}), content: \"[redacted]\", .. }}"
		));
		assert_redacted(&format!("{finding:?}"), &content, &baseline);
	}
	actual.sort();
	expected.sort();
	assert_eq!(
		actual, expected,
		"native path admission, legitimate sibling or match/hash output differs"
	);
}

pub(crate) fn native_fixture(choice: u8) -> std::path::PathBuf {
	match choice % 8 {
		0 => {
			#[cfg(unix)]
			{
				use std::os::unix::ffi::OsStringExt;
				std::ffi::OsString::from_vec(b"invalid-\xff.rs".to_vec()).into()
			}
			#[cfg(not(unix))]
			{
				"ordinary.rs".into()
			}
		},
		1 => "é.rs".into(),
		2 => "e\u{301}.rs".into(),
		3 => "control-\u{1}.rs".into(),
		4 => "back\\slash.rs".into(),
		index => {
			let length = 511 + usize::from(index - 5);
			std::path::PathBuf::from("a".repeat(200))
				.join("b".repeat(200))
				.join(format!("{}.rs", "c".repeat(length - 405)))
		},
	}
}
fn fingerprint(path: &str, secret: &[u8]) -> String {
	let mut bytes = b"regex-secrets\0".to_vec();
	bytes.extend_from_slice(path.as_bytes());
	bytes.push(0);
	bytes.extend(secret.iter().map(u8::to_ascii_lowercase));
	blake3::hash(&bytes).to_hex().to_string()
}

#[cfg(test)]
fn match_lines(bytes: &[u8]) -> Vec<u32> {
	matches(bytes).into_iter().map(|(line, _)| line).collect()
}
fn matches(bytes: &[u8]) -> Vec<(u32, std::ops::Range<usize>)> {
	if bytes.is_empty()
		|| bytes.len() > FILE_CAP
		|| bytes.iter().take(8192).any(|byte| *byte == 0)
		|| std::str::from_utf8(bytes).is_err()
	{
		return Vec::new();
	}
	let mut out = Vec::new();
	let mut offset = 0;
	let mut line = 1;
	while offset < bytes.len() {
		let matched = bytes.get(offset..offset + 20).is_some_and(|window| {
			window.starts_with(b"AKIA")
				&& window[4..].iter().all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'Z'))
		});
		if matched {
			out.push((line, offset..offset + 20));
			offset += 20;
		} else {
			line += u32::from(bytes[offset] == b'\n');
			offset += 1;
		}
	}
	out
}

pub fn worker_regex_secrets_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_regex_secrets_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::match_lines;

	#[test]
	fn byte_oracle_distinguishes_matches_lines_and_rejections() {
		assert_eq!(match_lines(b"\nAKIAIOSFODNN7EXAMPLE AKIA0000000000000000\r\n"), [2, 2]);
		assert!(match_lines(b"AKIAshort").is_empty());
		assert!(match_lines(b"AKIA000000000000000x").is_empty());
		assert!(match_lines(b"\0AKIAIOSFODNN7EXAMPLE").is_empty());
		assert!(match_lines(b"\xffAKIAIOSFODNN7EXAMPLE").is_empty());
	}
	#[test]
	fn native_paths_and_repo_typed_results_retain_legitimate_siblings() {
		for choice in 0..8 {
			for mode in [16, 17, 18, 20] {
				let mut input = vec![mode, choice];
				input.extend_from_slice(b"\nAKIAIOSFODNN7EXAMPLE AKIA0000000000000000");
				super::do_test(&input);
			}
		}
	}
}
