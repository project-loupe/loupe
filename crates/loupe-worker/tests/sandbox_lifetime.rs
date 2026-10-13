//! Real checkout owners must follow finalized commands and their children.
#![cfg(unix)]

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use loupe_worker::config::SandboxLaunchConfig;
use loupe_worker::runner::{checkout_revision, CheckedOutWorktree};
use loupe_worker::sandbox::{PreparedChild, SandboxBuilder, SandboxValue};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

async fn checkout() -> CheckedOutWorktree {
	let source = tempfile::tempdir().unwrap();
	let repo = git2::Repository::init_bare(source.path()).unwrap();
	let blob = repo.blob(b"retained checkout\n").unwrap();
	let mut tree = repo.treebuilder(None).unwrap();
	tree.insert("README.md", blob, 0o100644).unwrap();
	let tree = repo.find_tree(tree.write().unwrap()).unwrap();
	let signature = git2::Signature::now("Lifetime fixture", "fixture@example.test").unwrap();
	let commit = repo.commit(Some("HEAD"), &signature, &signature, "Fixture", &tree, &[]).unwrap();
	checkout_revision(source.path(), &commit.to_string()).await.unwrap().0
}

#[tokio::test]
async fn finalized_command_retains_environment_path_owner() {
	let primary = checkout().await;
	let secondary = checkout().await;
	let secondary_file = secondary.path().join("README.md");
	let builder = SandboxBuilder::new(primary.sandbox_path(), &SandboxLaunchConfig::default())
		.set_env("SECOND_WORKTREE", SandboxValue::path(secondary.sandbox_path()));
	let command = builder.build(SandboxValue::r#static("/bin/true"), &[]);
	drop(secondary);
	assert!(secondary_file.is_file(), "the builder retains the environment path owner");
	drop(builder);
	let retained = secondary_file.is_file();
	drop(command);
	assert!(retained, "the finalized command must retain its environment path owner");
	assert!(!secondary_file.exists(), "dropping the last command releases the checkout");
}

async fn child(worktree: CheckedOutWorktree, environment: CheckedOutWorktree) -> PreparedChild {
	let builder = SandboxBuilder::new(worktree.sandbox_path(), &SandboxLaunchConfig::default())
		.set_env("SECOND_WORKTREE", SandboxValue::path(environment.sandbox_path()));
	let mut command = builder.build(
		SandboxValue::r#static("/bin/sh"),
		&[
			SandboxValue::r#static("-c"),
			SandboxValue::r#static(
				"printf 'READY\\n'; while read -r request; do if test -f /workdir/README.md; then printf 'PRESENT\\n'; else printf 'MISSING\\n'; fi; done",
			),
		],
	);
	command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true);
	command.spawn().unwrap()
}

async fn read_line(reader: &mut BufReader<tokio::process::ChildStdout>) -> String {
	let mut line = String::new();
	tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut line))
		.await
		.expect("child response deadline")
		.unwrap();
	line
}

#[tokio::test]
async fn spawned_child_retains_environment_path_owner() {
	let primary = checkout().await;
	let secondary = checkout().await;
	let secondary_file = secondary.path().join("README.md");
	let mut child = child(primary, secondary).await;
	let mut output = BufReader::new(child.take_stdout().unwrap());
	assert_eq!(read_line(&mut output).await, "READY\n");
	let retained = secondary_file.is_file();
	child.kill().await.unwrap();
	child.wait().await.unwrap();
	drop(child);
	assert!(retained, "a spawned child must retain its environment path owner");
	assert!(!secondary_file.exists(), "the last child owner releases the checkout");
}

#[tokio::test]
async fn swapping_complete_children_preserves_their_live_mounts_and_lifecycle() {
	let first = checkout().await;
	let first_file = first.path().join("README.md");
	let mut first = child(first, checkout().await).await;
	let second = checkout().await;
	let second_file = second.path().join("README.md");
	let mut second = child(second, checkout().await).await;
	let mut output = BufReader::new(first.take_stdout().unwrap());
	let mut other_output = BufReader::new(second.take_stdout().unwrap());
	assert_eq!(read_line(&mut output).await, "READY\n");
	assert_eq!(read_line(&mut other_output).await, "READY\n");
	let first_pid = first.id().unwrap();
	let second_pid = second.id().unwrap();
	std::mem::swap(&mut first, &mut second);
	assert_eq!(second.id(), Some(first_pid));
	first.kill().await.unwrap();
	first.wait().await.unwrap();
	drop(first);
	assert!(!second_file.exists());
	assert!(first_file.is_file(), "the surviving wrapper retains its own mount");
	assert!(second.try_wait().unwrap().is_none());
	second.take_stdin().unwrap().write_all(b"check\n").await.unwrap();
	let observed = read_line(&mut output).await;
	second.kill().await.unwrap();
	second.wait().await.unwrap();
	drop(second);
	assert_eq!(observed, "PRESENT\n", "the live child must still see its checkout");
	assert!(!first_file.exists());
	for pid in [first_pid, second_pid] {
		assert!(!Path::new(&format!("/proc/{pid}")).exists(), "the child must be reaped");
	}
}
