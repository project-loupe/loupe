//! Fixed Repo operation observations; these are synthetic operation outputs,
//! while filesystem/libgit2/process collectors remain separate runtime tests.
use std::path::Path;

use loupe_worker::mcp::fuzz_support::{observe_repo, RepoCase, RepoObservation};
use loupe_worker::runner::fuzz_repo;

use crate::utils::test_logger;
use crate::worker_client_ingress::oracle;

pub(crate) fn fingerprint(file: &str, source: &str, start: u32, end: u32) -> String {
	let selected: Vec<_> = source
		.lines()
		.enumerate()
		.filter_map(|(index, line)| {
			let number = index as u128 + 1;
			(number + 2 >= u128::from(start) && number <= u128::from(end.saturating_add(2)))
				.then_some(line)
		})
		.collect();
	let normalized = selected
		.into_iter()
		.filter_map(|line| {
			let words: Vec<_> = line.split_whitespace().collect();
			(!words.is_empty()).then(|| words.join(" ").to_lowercase())
		})
		.collect::<Vec<_>>()
		.join("\n");
	let mut bytes = b"llm-code-review\0".to_vec();
	bytes.extend_from_slice(file.as_bytes());
	bytes.push(0);
	bytes.extend_from_slice(normalized.as_bytes());
	blake3::hash(&bytes).to_hex().to_string()
}
pub fn do_test(data: &[u8]) {
	oracle::without_logs(|| exercise(data));
}
fn exercise(data: &[u8]) {
	if data.len() > 65_536 {
		return;
	}
	let kind = data.first().copied().unwrap_or(0) % 6;
	let mode = data.get(1).copied().unwrap_or(0);
	let body = data.get(2..).unwrap_or_default();
	match kind {
		0 => {
			let expected = std::str::from_utf8(body)
				.map(|text| RepoObservation::Lines(text.lines().count().max(1) as u64))
				.unwrap_or(RepoObservation::InvalidUtf8);
			assert_eq!(
				observe_repo(RepoCase::LocalFile(body)),
				expected,
				"Repo line interpretation differs"
			);
		},
		1 => {
			let number = |offset| {
				body.get(offset..offset + 4)
					.and_then(|raw| raw.try_into().ok())
					.map(u32::from_le_bytes)
					.unwrap_or(0)
			};
			let start = number(0);
			let end = number(4);
			let source = body.get(8..).unwrap_or_default();
			let expected = std::str::from_utf8(source)
				.map(|source| {
					RepoObservation::Fingerprint(fingerprint("src/file.rs", source, start, end))
				})
				.unwrap_or(RepoObservation::InvalidUtf8);
			assert_eq!(
				observe_repo(RepoCase::Fingerprint {
					bytes: source,
					file: "src/file.rs",
					start,
					end
				}),
				expected,
				"Repo fingerprint byte framing/window differs"
			);
		},
		2 => check_git(mode, body),
		3 => {
			let expected = if body.len() == 20 {
				Ok(body.iter().map(|byte| format!("{byte:02x}")).collect::<String>())
			} else {
				Err("invalid repository object id".to_owned())
			};
			assert_eq!(
				fuzz_repo::revision(body),
				expected,
				"Repo original binary OID interpretation differs"
			);
		},
		4 => {
			let split = usize::from(mode).min(body.len());
			let expected = std::str::from_utf8(body)
				.ok()
				.filter(|text| oracle::path(text))
				.map(|text| fuzz_repo::Gitlink::Relative(text.to_owned()))
				.unwrap_or_else(|| fuzz_repo::Gitlink::Unrepresentable(body.to_vec()));
			assert_eq!(
				fuzz_repo::gitlink(&body[..split], &body[split..]),
				expected,
				"raw gitlink parts changed or acquired lossy path alias"
			);
		},
		_ => check_native(mode, body),
	}
}
#[cfg(unix)]
fn check_git(mode: u8, stderr: &[u8]) {
	use std::os::unix::process::ExitStatusExt;
	let status = std::process::ExitStatus::from_raw(i32::from(mode) << 8);
	let expected = if mode == 0 {
		RepoObservation::Applies
	} else {
		let decoded = String::from_utf8_lossy(stderr);
		let mut text = if decoded.len() > 4096 {
			let limit = decoded
				.char_indices()
				.map(|(offset, _)| offset)
				.take_while(|offset| *offset <= 4096)
				.last()
				.unwrap_or(0);
			format!("{}\n…(truncated)", decoded.get(..limit).unwrap_or_default())
		} else {
			decoded.into_owned()
		};
		if text.trim().is_empty() {
			text = format!("git apply exited exit status: {mode}");
		}
		RepoObservation::Rejects(text)
	};
	let actual = observe_repo(RepoCase::GitOutput(std::process::Output {
		status,
		stdout: b"ignored stdout".to_vec(),
		stderr: stderr.to_vec(),
	}));
	assert_eq!(actual, expected, "Git diagnostic status/UTF-8 boundary/fallback differs");
}
#[cfg(not(unix))]
fn check_git(_: u8, _: &[u8]) {}
#[cfg(unix)]
fn check_native(mode: u8, body: &[u8]) {
	use std::os::unix::ffi::OsStringExt;
	let leaf: Vec<_> = body.iter().copied().filter(|b| *b != 0 && *b != b'/').take(200).collect();
	let leaf = if leaf.is_empty() || leaf == b"." || leaf == b".." {
		b"ordinary.rs".to_vec()
	} else {
		leaf
	};
	let root = Path::new("/fixture/root");
	let parent = if mode.is_multiple_of(2) { root } else { Path::new("/fixture/outside") };
	let native = parent.join(std::ffi::OsString::from_vec(leaf.clone()));
	let expected = if mode.is_multiple_of(2) {
		RepoObservation::Membership {
			native: native.clone(),
			relative: std::str::from_utf8(&leaf)
				.ok()
				.filter(|s| oracle::path(s))
				.map(str::to_owned),
		}
	} else {
		RepoObservation::Outside
	};
	assert_eq!(
		observe_repo(RepoCase::Canonical { root, native }),
		expected,
		"native Repo membership acquired a lossy alias"
	);
}
#[cfg(not(unix))]
fn check_native(_: u8, _: &[u8]) {}

pub fn worker_repo_observations_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}
/// # Safety
/// The caller supplies `len` readable bytes at `data` for this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_repo_observations_run(data: *const u8, len: usize) {
	// SAFETY: the C runner guarantees the readable input buffer.
	do_test(unsafe { std::slice::from_raw_parts(data, len) });
}
#[cfg(test)]
mod tests {
	#[test]
	fn each_repo_owner_has_positive_and_negative_controls() {
		for kind in 0..6 {
			for body in
				[b"same".as_slice(), b"\xff", b"a\n\r\nb\n", b"abcdefghijklmnopqrst", b"../unsafe"]
			{
				let mut input = vec![kind, 1];
				input.extend_from_slice(body);
				super::do_test(&input);
			}
		}
		let mut boundary = vec![2, 1];
		boundary.extend_from_slice("x".repeat(4095).as_bytes());
		boundary.extend_from_slice("€tail".as_bytes());
		super::do_test(&boundary);
		for len in [511, 512, 513] {
			let mut input = vec![4, 0];
			input.resize(len + 2, b'a');
			super::do_test(&input);
		}
	}
}
