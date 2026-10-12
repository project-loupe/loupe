//! Byte zero selects ordinary/outside/inside symlinks. The remaining bytes
//! are NUL-separated root Cargo.toml, member Cargo.toml and exclusion pattern;
//! bit 3 instead sends every remaining byte verbatim to the root manifest.
//! Every selection uses the production manifest parser, glob rules and walker.
//! A 64 KiB input cap bounds filesystem churn, not the product parser's policy.

use std::fs;
use std::path::Path;

use loupe_worker::scanners::fuzz_source_discovery;

use crate::utils::test_logger;

const PACKAGE: &[u8] = b"[package]\nname=\"fixture\"\nversion=\"0.1.0\"\n";

pub fn do_test(data: &[u8]) {
	if data.len() > 65_536 {
		return;
	}
	let (&mode, bytes) = data.split_first().unwrap_or((&0, &[]));
	if mode & 16 != 0 {
		native_names();
	}
	let mut fields = bytes.splitn(3, |byte| *byte == 0);
	let (manifest, member, pattern) = if mode & 8 != 0 {
		(bytes, PACKAGE, &[][..])
	} else {
		(
			fields.next().unwrap_or_default(),
			fields.next().unwrap_or(PACKAGE),
			fields.next().unwrap_or_default(),
		)
	};
	let exclude = String::from_utf8_lossy(pattern);
	let temp = tempfile::tempdir().unwrap_or_else(|_| panic!("create discovery fixture"));
	let root = temp.path().join("repo");
	for directory in ["repo/src", "repo/internal", "repo/modules/member/src", "outside"] {
		fs::create_dir_all(temp.path().join(directory))
			.unwrap_or_else(|_| panic!("create discovery directories"));
	}
	write(&root.join("Cargo.toml"), manifest);
	write(&root.join("modules/member/Cargo.toml"), member);
	write(&root.join("modules/member/src/lib.rs"), b"pub fn member() {}\n");
	write(&root.join("src/lib.rs"), b"pub fn local() {}\n");
	write(&root.join("internal/inside.rs"), b"pub fn inside() {}\n");
	write(&root.join("internal/build.rs"), b"fn main() {}\n");
	write(&temp.path().join("outside/secret.rs"), b"private outside source\n");
	write(&temp.path().join("outside/build.rs"), b"private outside build\n");
	#[cfg(unix)]
	{
		use std::os::unix::fs::symlink;
		let destination =
			if mode & 4 == 0 { temp.path().join("outside") } else { root.join("internal") };
		if mode & 1 != 0 {
			fs::remove_dir_all(root.join("src"))
				.unwrap_or_else(|_| panic!("replace source directory"));
			symlink(&destination, root.join("src"))
				.unwrap_or_else(|_| panic!("create source symlink"));
		}
		if mode & 2 != 0 {
			symlink(destination.join("build.rs"), root.join("build.rs"))
				.unwrap_or_else(|_| panic!("create build symlink"));
		}
	}
	#[cfg(not(unix))]
	let _ = mode;

	for path in [root.join("Cargo.toml"), root.join("modules/member/Cargo.toml")] {
		let parsed = fuzz_source_discovery::parse_manifest(&path);
		let workspace = fuzz_source_discovery::workspace_excludes(&path);
		let expected = fs::read_to_string(&path)
			.ok()
			.and_then(|raw| toml::from_str::<toml::Value>(&raw).ok())
			.filter(|value| {
				value
					.get("workspace")
					.and_then(|v| v.get("exclude"))
					.and_then(toml::Value::as_array)
					.into_iter()
					.flatten()
					.filter_map(toml::Value::as_str)
					.all(|value| crate::worker_client_ingress::oracle::text(value, false))
			});
		assert!(
			match (&parsed, &expected) {
				(Some(parsed), Some(expected)) => toml_values_equal(parsed, expected),
				(None, None) => true,
				_ => false,
			},
			"Cargo decoder differs from independent TOML and exclude policy\n\
			parsed: {parsed:?}\nexpected: {expected:?}"
		);
		assert_eq!(
			workspace.is_some(),
			expected.as_ref().and_then(|value| value.get("workspace")).is_some(),
			"workspace presence disagrees with actual manifest"
		);
		if let Some(excludes) = workspace {
			let values = expected
				.as_ref()
				.and_then(|value| value.get("workspace"))
				.and_then(|value| value.get("exclude"))
				.and_then(|value| value.as_array());
			let expected: Vec<_> =
				values.into_iter().flatten().filter_map(|value| value.as_str()).collect();
			assert_eq!(excludes, expected, "workspace excludes must preserve only string entries");
		}
	}
	let excludes: Vec<_> =
		(!exclude.is_empty()).then(|| exclude.into_owned()).into_iter().collect();
	let selected = fuzz_source_discovery::walk(&root, &excludes);
	#[cfg(unix)]
	if manifest == PACKAGE && member == PACKAGE && excludes.is_empty() {
		let mut expected = vec![root.join("modules/member/src/lib.rs")];
		if mode & 1 == 0 {
			expected.push(root.join("src/lib.rs"));
		} else if mode & 4 != 0 {
			expected.push(root.join("src/inside.rs"));
			expected.push(root.join("src/build.rs"));
		}
		if mode & 2 != 0 && mode & 4 != 0 {
			expected.push(root.join("build.rs"));
		}
		expected.sort();
		assert_eq!(selected, expected, "fixture must retain every legitimate source");
	}
	let canonical_root = root.canonicalize().unwrap_or_else(|_| panic!("canonicalize fixture"));
	for path in &selected {
		assert!(path.starts_with(&root), "selected path has escaped spelling");
		let resolved = path.canonicalize().unwrap_or_else(|_| panic!("resolve selected source"));
		assert!(resolved.starts_with(&canonical_root), "selected source escapes repository");
		assert!(resolved.is_file(), "selected source is not a file");
		assert_eq!(path.extension().and_then(|ext| ext.to_str()), Some("rs"));
	}
	assert!(selected.windows(2).all(|pair| pair[0] < pair[1]), "sources must be sorted and unique");
	assert_eq!(
		selected,
		fuzz_source_discovery::walk(&root, &excludes),
		"discovery must be deterministic"
	);
}

fn toml_values_equal(left: &toml::Value, right: &toml::Value) -> bool {
	match (left, right) {
		// TOML permits NaN, whose ordinary float equality is not reflexive.
		// All other floats retain their existing equality semantics.
		(toml::Value::Float(left), toml::Value::Float(right)) => {
			left == right || (left.is_nan() && right.is_nan())
		},
		(toml::Value::Array(left), toml::Value::Array(right)) => {
			left.len() == right.len()
				&& left.iter().zip(right).all(|(left, right)| toml_values_equal(left, right))
		},
		(toml::Value::Table(left), toml::Value::Table(right)) => {
			left.len() == right.len()
				&& left.iter().all(|(key, left)| {
					right.get(key).is_some_and(|right| toml_values_equal(left, right))
				})
		},
		_ => left == right,
	}
}

fn native_names() {
	let temp = tempfile::tempdir().unwrap_or_else(|_| panic!("native discovery fixture"));
	let root = temp.path();
	write(&root.join("Cargo.toml"), PACKAGE);
	fs::create_dir(root.join("src")).unwrap_or_else(|_| panic!("native source dir"));
	let mut expected = vec![root.join("src/legitimate.rs")];
	write(&expected[0], b"fn ordinary() {}\n");
	for choice in 0..8 {
		let mut relative = crate::worker_regex_secrets::native_fixture(choice);
		if choice >= 5 {
			let name = relative.file_name().and_then(|v| v.to_str()).unwrap_or_default();
			let name = name.get(4..).unwrap_or_default().to_owned();
			relative.set_file_name(name);
		}
		let path = root.join("src").join(relative);
		fs::create_dir_all(path.parent().unwrap_or(root))
			.unwrap_or_else(|_| panic!("native parent"));
		write(&path, b"fn selected() {}\n");
		// Existing extension selection requires a UTF-8 leaf. A non-UTF-8
		// directory with a representable leaf remains a native selected path.
		if path.file_name().and_then(|name| name.to_str()).is_some() {
			expected.push(path);
		}
	}
	#[cfg(unix)]
	{
		use std::os::unix::ffi::OsStringExt;
		let path = root
			.join("src")
			.join(std::ffi::OsString::from_vec(b"native-\xff".to_vec()))
			.join("selected.rs");
		fs::create_dir_all(path.parent().unwrap_or(root))
			.unwrap_or_else(|_| panic!("native directory"));
		write(&path, b"fn selected() {}\n");
		expected.push(path);
	}
	expected.sort();
	assert_eq!(
		fuzz_source_discovery::walk(root, &[]),
		expected,
		"native source names acquired lossy aliases, cap or spelling changes"
	);
}

fn write(path: &Path, bytes: &[u8]) {
	fs::write(path, bytes).unwrap_or_else(|_| panic!("write discovery fixture"));
}

pub fn worker_source_discovery_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_source_discovery_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	#[test]
	fn discovery_accepts_member_nan_manifest() {
		super::do_test(include_bytes!("../test_cases/worker_source_discovery/member-nan"));
	}

	#[test]
	fn discovery_accepts_nested_nan_manifest() {
		super::do_test(
			b"\x08[package.metadata]\nvalues = [nan, +nan, -nan, { nested = [nan, 1.5] }]\n\
			[workspace]\nexclude = [\"excluded\", nan, { nested = [nan] }]\n",
		);
	}

	#[test]
	fn toml_comparison_accepts_nested_nan_values() {
		for literal in ["nan", "+nan", "-nan"] {
			let left =
				parse_toml(&format!("values = [{literal}, {{ nested = [{literal}, 1.5] }}]"));
			let right = parse_toml("values = [nan, { nested = [nan, 1.5] }]");
			assert!(super::toml_values_equal(&left, &right), "NaN spelling {literal}");
			assert!(super::toml_values_equal(&right, &left), "NaN spelling {literal}");
		}
	}

	#[test]
	fn toml_comparison_preserves_values_beside_nan() {
		let expected = parse_toml("values = [nan, { finite = 1.5, tag = 'kept' }]");
		for different in [
			"values = [nan, { finite = 2.5, tag = 'kept' }]",
			"values = [nan, { finite = '1.5', tag = 'kept' }]",
			"values = [nan, { finite = 1.5, tag = 'changed' }]",
			"values = [nan, { renamed = 1.5, tag = 'kept' }]",
			"values = [nan, { finite = 1.5 }]",
			"values = [nan, { finite = 1.5, tag = 'kept', extra = true }]",
			"values = [nan]",
			"values = [nan, { finite = 1.5, tag = 'kept' }, nan]",
			"values = [{ finite = 1.5, tag = 'kept' }, nan]",
			"values = [1.5, { finite = 1.5, tag = 'kept' }]",
			"values = ['nan', { finite = 1.5, tag = 'kept' }]",
			"other = [nan, { finite = 1.5, tag = 'kept' }]",
			"values = [nan, { finite = 1.5, tag = 'kept' }]\nextra = nan",
		] {
			let different = parse_toml(different);
			assert!(
				!super::toml_values_equal(&expected, &different),
				"oracle ignored a value or shape difference: {different:?}"
			);
			assert!(
				!super::toml_values_equal(&different, &expected),
				"oracle ignored a value or shape difference: {different:?}"
			);
		}
	}

	#[test]
	fn toml_comparison_preserves_non_nan_equality() {
		let values: Vec<_> = [
			"1.5",
			"2.5",
			"1",
			"1.0",
			"inf",
			"-inf",
			"0.0",
			"-0.0",
			"true",
			"false",
			"'text'",
			"'changed'",
			"1979-05-27T07:32:00Z",
			"1979-05-28T07:32:00Z",
			"[1, 2]",
			"[2, 1]",
			"[1]",
			"{ a = 1 }",
			"{ b = 1 }",
			"{ a = 1, b = 2 }",
		]
		.into_iter()
		.map(|literal| parse_toml(&format!("value = {literal}")))
		.collect();
		for left in &values {
			for right in &values {
				assert_eq!(
					super::toml_values_equal(left, right),
					left == right,
					"non-NaN equality changed: {left:?} versus {right:?}"
				);
			}
		}
	}

	fn parse_toml(raw: &str) -> toml::Value {
		toml::from_str(raw).unwrap_or_else(|error| panic!("invalid TOML fixture: {error}"))
	}

	#[test]
	fn discovery_preserves_native_names_without_losing_valid_siblings() {
		super::native_names();
	}
}
