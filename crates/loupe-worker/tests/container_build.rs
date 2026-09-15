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
	run_image_build(
		&repo_root().join("contrib/docker/build-images.sh"),
		engine,
		log,
		Some("cli-refresh-test"),
		None,
		"cli-refresh-test",
	)
}

/// Run the build helper with a fake engine. `tag` is `LOUPE_IMAGE_TAG` (None
/// leaves it unset so the script's own default is exercised); `expected_tag`
/// is what both image references must end with.
fn run_image_build(
	script: &Path, engine: &Path, log: &Path, tag: Option<&str>, revision: Option<&str>,
	expected_tag: &str,
) -> Vec<Vec<String>> {
	let mut command = Command::new("bash");
	command
		.arg(script)
		.current_dir(log.parent().unwrap())
		.env_clear()
		.env("PATH", std::env::var_os("PATH").expect("PATH is set"))
		.env("CONTAINER_ENGINE", engine)
		.env("LOUPE_TEST_BUILD_LOG", log);
	// The script's git calls must see the same global git configuration the
	// test's own git calls see (safe.directory in CI containers, for one), or
	// the two `describe` results legitimately differ.
	for name in ["HOME", "XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM"] {
		if let Some(value) = std::env::var_os(name) {
			command.env(name, value);
		}
	}
	if let Some(tag) = tag {
		command.env("LOUPE_IMAGE_TAG", tag);
	}
	if let Some(revision) = revision {
		command.env("LOUPE_BUILD_REVISION", revision);
	}
	let output = command.output().expect("run image build helper with a fake engine");
	assert!(output.status.success(), "build helper failed: {:?}", output);
	let stdout = String::from_utf8(output.stdout).unwrap();
	assert!(
		stdout
			.contains(&format!("export LOUPE_SERVER_IMAGE=localhost/loupe-server:{expected_tag}")),
		"unexpected server image reference: {stdout}"
	);
	assert!(
		stdout
			.contains(&format!("export LOUPE_WORKER_IMAGE=localhost/loupe-worker:{expected_tag}")),
		"unexpected worker image reference: {stdout}"
	);
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
fn both_images_receive_the_source_revision() {
	use std::os::unix::fs::PermissionsExt;

	let scratch = tempfile::tempdir().unwrap();
	let engine = scratch.path().join("fake container engine");
	std::fs::write(
		&engine,
		"#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$LOUPE_TEST_BUILD_LOG\"\nprintf '\\n' >> \"$LOUPE_TEST_BUILD_LOG\"\n",
	)
	.unwrap();
	std::fs::set_permissions(&engine, std::fs::Permissions::from_mode(0o755)).unwrap();
	let revision = Command::new("git")
		.args(["describe", "--always", "--dirty"])
		.current_dir(repo_root())
		.output()
		.unwrap();
	assert!(revision.status.success());
	let argument =
		format!("LOUPE_BUILD_REVISION={}", String::from_utf8(revision.stdout).unwrap().trim());
	let builds = build_with_fake_engine(&engine, &scratch.path().join("revision.log"));
	assert_eq!(builds.len(), 2);
	for build in builds {
		assert!(
			build.windows(2).any(|pair| pair[0] == "--build-arg" && pair[1] == argument),
			"each image must receive the source revision, even when invoked outside the checkout"
		);
	}
}

#[test]
fn image_revision_reaches_the_binary_and_both_labels() {
	let dockerfile = std::fs::read_to_string(repo_root().join("contrib/docker/Dockerfile"))
		.expect("read Dockerfile");
	let builder =
		dockerfile.split(" AS app-builder\n").nth(1).unwrap().split("\nFROM ").next().unwrap();
	assert!(
		!builder.contains("LOUPE_BUILD_REVISION"),
		"revision metadata must not invalidate the Rust build layer"
	);
	for target in ["loupe-server", "loupe-worker"] {
		let stage = dockerfile
			.split(&format!(" AS {target}\n"))
			.nth(1)
			.unwrap()
			.split("\nFROM ")
			.next()
			.unwrap();
		assert!(
			stage.contains("ARG LOUPE_BUILD_REVISION=unknown"),
			"each final stage must declare its argument"
		);
		assert!(
			stage.contains("LABEL org.opencontainers.image.revision=$LOUPE_BUILD_REVISION"),
			"each image must expose its revision"
		);
		assert!(
			stage.contains("ENV LOUPE_BUILD_REVISION=$LOUPE_BUILD_REVISION"),
			"each process must receive its runtime revision"
		);
	}
}

#[test]
fn source_exports_build_with_a_fallback_or_explicit_revision() {
	use std::os::unix::fs::PermissionsExt;
	let scratch = tempfile::tempdir().unwrap();
	let script = scratch.path().join("export/contrib/docker/build-images.sh");
	std::fs::create_dir_all(script.parent().unwrap()).unwrap();
	std::fs::copy(repo_root().join("contrib/docker/build-images.sh"), &script).unwrap();
	let engine = scratch.path().join("engine");
	std::fs::write(&engine, "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$LOUPE_TEST_BUILD_LOG\"\nprintf '\\n' >> \"$LOUPE_TEST_BUILD_LOG\"\n").unwrap();
	std::fs::set_permissions(&engine, std::fs::Permissions::from_mode(0o755)).unwrap();
	for revision in [None, Some("source-release")] {
		let expected = revision.unwrap_or("unknown");
		let commands = run_image_build(
			&script,
			&engine,
			&scratch.path().join(expected),
			Some("cli-refresh-test"),
			revision,
			"cli-refresh-test",
		);
		assert_eq!(commands.len(), 2);
		for args in commands {
			assert!(
				args.windows(2).any(|pair| pair[0] == "--build-arg"
					&& pair[1] == format!("LOUPE_BUILD_REVISION={expected}")),
				"source exports need reproducible fallback metadata"
			);
		}
	}
}

fn fake_engine(dir: &Path) -> PathBuf {
	use std::os::unix::fs::PermissionsExt;
	let engine = dir.join("engine");
	std::fs::write(
		&engine,
		"#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$LOUPE_TEST_BUILD_LOG\"\nprintf '\\n' >> \"$LOUPE_TEST_BUILD_LOG\"\n",
	)
	.unwrap();
	std::fs::set_permissions(&engine, std::fs::Permissions::from_mode(0o755)).unwrap();
	engine
}

fn exported_script(dir: &Path) -> PathBuf {
	let script = dir.join("export/contrib/docker/build-images.sh");
	std::fs::create_dir_all(script.parent().unwrap()).unwrap();
	std::fs::copy(repo_root().join("contrib/docker/build-images.sh"), &script).unwrap();
	script
}

#[test]
fn source_exports_default_their_image_tag_without_git() {
	// Without LOUPE_IMAGE_TAG the script used to call git for the tag before
	// the revision fallback could run, aborting every source-export build.
	let scratch = tempfile::tempdir().unwrap();
	let script = exported_script(scratch.path());
	let engine = fake_engine(scratch.path());
	let commands =
		run_image_build(&script, &engine, &scratch.path().join("notag.log"), None, None, "unknown");
	assert_eq!(commands.len(), 2, "both images must still build from a plain export");
}

#[test]
fn nested_source_exports_do_not_inherit_the_enclosing_repository() {
	// `git -C` walks up to any enclosing checkout; an export unpacked inside an
	// unrelated repository must not be stamped with that repository's revision.
	let scratch = tempfile::tempdir().unwrap();
	let git = |args: &[&str]| {
		let output = Command::new("git")
			.args(args)
			.current_dir(scratch.path())
			.env("GIT_AUTHOR_NAME", "t")
			.env("GIT_AUTHOR_EMAIL", "t@example.invalid")
			.env("GIT_COMMITTER_NAME", "t")
			.env("GIT_COMMITTER_EMAIL", "t@example.invalid")
			.output()
			.unwrap();
		assert!(output.status.success(), "git {args:?}: {output:?}");
	};
	// `--no-verify`: a developer's global commit hooks must not decide this test.
	git(&["init", "-q", "."]);
	git(&["commit", "-q", "--no-verify", "--allow-empty", "-m", "Enclosing repository"]);
	let script = exported_script(scratch.path());
	let engine = fake_engine(scratch.path());
	let commands = run_image_build(
		&script,
		&engine,
		&scratch.path().join("nested.log"),
		None,
		None,
		"unknown",
	);
	for args in commands {
		assert!(
			args.windows(2)
				.any(|pair| pair[0] == "--build-arg" && pair[1] == "LOUPE_BUILD_REVISION=unknown"),
			"an export inside a foreign checkout must not borrow its revision: {args:?}"
		);
	}
}

#[test]
fn revision_metadata_follows_the_package_layers() {
	// The revision changes on every commit; placing it before apt-get or npm
	// would invalidate exactly the layers the build is trying to keep cached.
	let dockerfile = std::fs::read_to_string(repo_root().join("contrib/docker/Dockerfile"))
		.expect("read Dockerfile");
	for target in ["loupe-server", "loupe-worker"] {
		let stage = dockerfile
			.split(&format!(" AS {target}\n"))
			.nth(1)
			.unwrap()
			.split("\nFROM ")
			.next()
			.unwrap();
		let revision = stage.find("ARG LOUPE_BUILD_REVISION").expect("declare the revision");
		let last_install = ["apt-get install", "npm install"]
			.iter()
			.filter_map(|needle| stage.rfind(needle))
			.max()
			.expect("each final stage installs packages");
		assert!(
			last_install < revision,
			"{target}: revision metadata must come after the last package install layer"
		);
		assert!(
			revision < stage.find("COPY --from=app-builder").unwrap(),
			"{target}: revision metadata still precedes the binaries it describes"
		);
	}
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
