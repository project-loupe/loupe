//! Run environment-sensitive unit tests in child processes. Setting a child's
//! environment through `Command` is safe even when the parent test runner has
//! other threads; mutating the parent's environment is not.

use std::ffi::OsStr;
use std::process::Command;

/// In the parent, run exactly this test with the requested environment and
/// return false. In the child, return true only for the selected case, so a
/// test can exercise multiple environments without changing process globals.
pub(crate) fn in_env(test_name: &str, case: &str, env: &[(&str, Option<&OsStr>)]) -> bool {
	const CHILD_CASE: &str = "LOUPE_TEST_PROCESS_CASE";
	let selected = format!("{test_name}:{case}");
	if let Some(child_case) = std::env::var_os(CHILD_CASE) {
		return child_case == OsStr::new(&selected);
	}

	let mut command = Command::new(std::env::current_exe().expect("unit test executable"));
	command.args(["--exact", test_name, "--nocapture", "--test-threads=1"]);
	command.env(CHILD_CASE, selected);
	for (name, value) in env {
		match value {
			Some(value) => command.env(name, value),
			None => command.env_remove(name),
		};
	}
	let output = command.output().expect("run test with an isolated environment");
	let stdout = String::from_utf8_lossy(&output.stdout);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		output.status.success() && stdout.contains("running 1 test"),
		"{test_name} ({case}) failed: {}\n{stdout}\n{stderr}",
		output.status,
	);
	false
}
