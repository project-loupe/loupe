//! Keep worker image builds on current agent CLIs without invalidating
//! the server or Rust build cache. No container engine is required.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
	Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn worker_image_defaults_to_latest_agent_clis() {
	let dockerfile = std::fs::read_to_string(repo_root().join("contrib/docker/Dockerfile"))
		.expect("read worker Dockerfile");
	for argument in ["CLAUDE_CODE_VERSION", "CODEX_VERSION"] {
		assert!(
			dockerfile.lines().any(|line| line == format!("ARG {argument}=latest")),
			"{argument} must default to latest so a fresh worker build picks up CLI releases"
		);
	}
}

fn build_with_fake_engine(engine: &Path, log: &Path) -> Vec<Vec<String>> {
	let output = Command::new("bash")
		.arg(repo_root().join("contrib/docker/build-images.sh"))
		.current_dir(log.parent().unwrap())
		.env_clear()
		.env("PATH", std::env::var_os("PATH").expect("PATH is set"))
		.env("CONTAINER_ENGINE", engine)
		.env("LOUPE_IMAGE_TAG", "cli-refresh-test")
		.env("LOUPE_TEST_BUILD_LOG", log)
		.output()
		.expect("run image build helper with a fake engine");
	assert!(output.status.success(), "build helper failed: {:?}", output);
	let stdout = String::from_utf8(output.stdout).unwrap();
	assert!(stdout.contains("export LOUPE_SERVER_IMAGE=localhost/loupe-server:cli-refresh-test"));
	assert!(stdout.contains("export LOUPE_WORKER_IMAGE=localhost/loupe-worker:cli-refresh-test"));
	std::fs::read_to_string(log)
		.unwrap()
		.trim_end()
		.split("\n\n")
		.map(|command| command.lines().map(str::to_owned).collect())
		.collect()
}

fn cli_refresh_argument(args: &[String]) -> Option<&str> {
	args.windows(2)
		.filter(|pair| pair[0] == "--build-arg")
		.find_map(|pair| pair[1].strip_prefix("AGENT_CLI_REFRESH="))
}

#[test]
fn successive_worker_builds_refresh_only_the_cli_install_layer() {
	use std::os::unix::fs::PermissionsExt;

	let scratch = tempfile::tempdir().unwrap();
	let engine = scratch.path().join("fake container engine");
	std::fs::write(
		&engine,
		"#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$LOUPE_TEST_BUILD_LOG\"\nprintf '\\n' >> \"$LOUPE_TEST_BUILD_LOG\"\n",
	)
	.unwrap();
	std::fs::set_permissions(&engine, std::fs::Permissions::from_mode(0o755)).unwrap();

	let first = build_with_fake_engine(&engine, &scratch.path().join("first.log"));
	let second = build_with_fake_engine(&engine, &scratch.path().join("second.log"));
	for builds in [&first, &second] {
		assert_eq!(builds.len(), 2, "build both the server and worker images");
		assert!(builds[0].windows(2).any(|pair| pair == ["--target", "loupe-server"]));
		assert!(builds[1].windows(2).any(|pair| pair == ["--target", "loupe-worker"]));
		assert!(cli_refresh_argument(&builds[0]).is_none(), "server builds should stay cached");
		assert!(
			cli_refresh_argument(&builds[1]).is_some_and(|value| !value.is_empty()),
			"worker builds must refresh the CLI install layer, even at the same Git revision"
		);
		assert!(
			builds.iter().flatten().all(|arg| !arg.starts_with("--no-cache")),
			"refreshing CLIs must not discard the Rust or system-package caches"
		);
	}
	assert_ne!(cli_refresh_argument(&first[1]), cli_refresh_argument(&second[1]));

	let dockerfile = std::fs::read_to_string(repo_root().join("contrib/docker/Dockerfile"))
		.expect("read worker Dockerfile");
	let worker = dockerfile.split(" AS loupe-worker\n").nth(1).unwrap();
	let refresh = worker.find("ARG AGENT_CLI_REFRESH").expect("declare the CLI cache argument");
	assert!(worker.find("apt-get install").unwrap() < refresh);
	assert!(refresh < worker.find("npm install").unwrap());
}
