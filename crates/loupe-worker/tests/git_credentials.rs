//! Real Git cache tests run in isolated child environments.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use loupe_provenance::Secret;
use loupe_worker::{RepoCache, RepoKey};

const PAT: &str = "ghp_cache_origin_sentinel_917a";
const OLD_PAT: &str = "ghp_legacy_origin_sentinel_631b";
const CLEAN_URL: &str = "https://git.example.invalid/acme/repo.git";

#[path = "git_credentials/tls.rs"]
mod tls;

fn isolated(name: &str, run: impl FnOnce(&Path)) {
	if let Some(root) = std::env::var_os("LOUPE_GIT_TEST_ROOT") {
		run(Path::new(&root));
		return;
	}
	// Each case launches real Git and worker processes. Keep their runtimes
	// from competing with deadline assertions in other isolated cases.
	static ISOLATED: std::sync::Mutex<()> = std::sync::Mutex::new(());
	let _guard = ISOLATED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
	let root = tempfile::tempdir().unwrap();
	std::fs::create_dir(root.path().join("bin")).unwrap();
	let output = Command::new(std::env::current_exe().unwrap())
		.args(["--exact", name, "--nocapture", "--test-threads=1"])
		.env_clear()
		.env("PATH", format!("{}:/usr/bin:/bin", root.path().join("bin").display()))
		.env("HOME", root.path())
		.env("XDG_CONFIG_HOME", root.path())
		.env("GIT_CONFIG_GLOBAL", root.path().join("gitconfig"))
		.env("GIT_CONFIG_NOSYSTEM", "1")
		.env("GIT_TERMINAL_PROMPT", "0")
		.env("GIT_TRACE", root.path().join("git-trace"))
		.env("GIT_TRACE_CURL", root.path().join("curl-trace"))
		.env("GIT_TRACE_REDACT", "0")
		.env("GIT_TRACE2_EVENT", root.path().join("git-events"))
		.env("LOUPE_GIT_TEST_ROOT", root.path())
		.output()
		.unwrap();
	assert!(
		output.status.success(),
		"isolated {name} failed:\n{}\n{}",
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr)
	);
}

fn git(dir: &Path, args: &[&str]) -> String {
	let output = Command::new("/usr/bin/git").current_dir(dir).args(args).output().unwrap();
	assert!(
		output.status.success(),
		"test Git failed: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	String::from_utf8(output.stdout).unwrap().trim().into()
}

fn upstream(root: &Path) -> PathBuf {
	let path = root.join("upstream");
	std::fs::create_dir(&path).unwrap();
	git(&path, &["init", "-q", "-b", "main"]);
	git(&path, &["config", "user.name", "Loupe test"]);
	git(&path, &["config", "user.email", "test@example.invalid"]);
	commit(&path, "first");
	path
}

fn commit(path: &Path, contents: &str) -> String {
	std::fs::write(path.join("file"), contents).unwrap();
	git(path, &["add", "file"]);
	git(path, &["commit", "-qm", contents]);
	git(path, &["rev-parse", "HEAD"])
}

fn rewrite(root: &Path, source: &str, target: &Path) {
	git(
		root,
		&[
			"config",
			"--global",
			"--add",
			&format!("url.file://{}.insteadOf", target.display()),
			source,
		],
	);
}

fn cache(root: &Path) -> Arc<RepoCache> {
	let helper = root.join("worker's helper");
	if !helper.exists() {
		std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_loupe-worker"), &helper).unwrap();
	}
	Arc::new(RepoCache::new(root.join("cache"), u64::MAX, Some(helper)).unwrap())
}

fn runtime() -> tokio::runtime::Runtime {
	tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap()
}

#[test]
fn clone_never_persists_pat_in_origin() {
	isolated("clone_never_persists_pat_in_origin", |root| {
		let source = upstream(root);
		rewrite(root, CLEAN_URL, &source);
		rewrite(
			root,
			&format!("https://x-access-token:{PAT}@git.example.invalid/acme/repo.git"),
			&source,
		);
		let cache = cache(root);
		let token = Arc::new(Secret::new(PAT.to_owned()));
		let key = RepoKey::new("git.example.invalid", "acme", "repo");
		let repo = runtime().block_on(cache.ensure_repo(&key, CLEAN_URL, Some(&token))).unwrap();
		let stored = git(&repo.path, &["config", "--local", "--get-all", "remote.origin.url"]);
		assert!(!stored.contains(PAT), "real Git clone persisted the PAT in origin");
		assert_eq!(stored, CLEAN_URL);
	});
}

#[test]
fn refresh_without_pat_replaces_all_legacy_origins_and_preserves_refs() {
	isolated("refresh_without_pat_replaces_all_legacy_origins_and_preserves_refs", |root| {
		let source = upstream(root);
		let old = format!("https://x-access-token:{OLD_PAT}@git.example.invalid/acme/repo.git");
		rewrite(root, CLEAN_URL, &source);
		rewrite(root, &old, &source);
		let cache = cache(root);
		let key = RepoKey::new("git.example.invalid", "acme", "repo");
		let rt = runtime();
		let initial = rt.block_on(cache.ensure_repo(&key, CLEAN_URL, None)).unwrap();
		git(&initial.path, &["config", "--local", "--replace-all", "remote.origin.url", &old]);
		git(&initial.path, &["config", "--local", "--add", "remote.origin.url", &old]);
		drop(initial);
		let second = commit(&source, "second");
		git(&source, &["tag", "v2"]);
		let repo = rt.block_on(cache.ensure_repo(&key, CLEAN_URL, None)).unwrap();
		let stored = git(&repo.path, &["config", "--local", "--get-all", "remote.origin.url"]);
		assert_eq!(stored, CLEAN_URL, "refresh retained a legacy secret origin");
		for name in [
			"refs/heads/main",
			"refs/remotes/origin/main",
			"refs/remotes/origin/HEAD",
			"refs/tags/v2",
		] {
			assert_eq!(git(&repo.path, &["rev-parse", name]), second);
		}
	});
}

#[test]
fn refresh_uses_current_authorized_url() {
	isolated("refresh_uses_current_authorized_url", |root| {
		let source = upstream(root);
		let cache = cache(root);
		let key = RepoKey::new("local", "acme", "repo");
		let rt = runtime();
		let old_url = format!("file://{}", source.display());
		drop(rt.block_on(cache.ensure_repo(&key, &old_url, None)).unwrap());
		let moved = root.join("moved");
		std::fs::rename(&source, &moved).unwrap();
		let second = commit(&moved, "authorized-new-remote");
		// Keep the old URL working but with stale content. Refresh must use
		// the current lease's source, not infer one from the stored origin.
		git(root, &["clone", "-q", moved.to_str().unwrap(), source.to_str().unwrap()]);
		git(&source, &["reset", "--hard", "HEAD~1"]);
		let new_url = format!("file://{}", moved.display());
		let repo = rt.block_on(cache.ensure_repo(&key, &new_url, None)).unwrap();
		assert_eq!(
			git(&repo.path, &["rev-parse", "refs/heads/main"]),
			second,
			"refresh ignored the currently authorized URL"
		);
	});
}

#[test]
fn cancellation_keeps_repo_lock_until_git_finishes() {
	isolated("cancellation_keeps_repo_lock_until_git_finishes", |root| {
		use std::os::unix::fs::PermissionsExt;
		let source = upstream(root);
		rewrite(root, CLEAN_URL, &source);
		let script = root.join("bin/git");
		std::fs::write(&script, format!(
			"#!/bin/sh\ncase \" $* \" in *' clone '*)\nif mkdir '{0}/first' 2>/dev/null; then touch '{0}/entered'; else touch '{0}/second'; fi\nwhile [ ! -f '{0}/release' ]; do sleep 0.02; done\n;; esac\nexec /usr/bin/git \"$@\"\n", root.display()
		)).unwrap();
		std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
		let cache = cache(root);
		let key = RepoKey::new("local", "acme", "repo");
		let url = CLEAN_URL.to_owned();
		let token = Arc::new(Secret::new(PAT.to_owned()));
		let weak = Arc::downgrade(&token);
		runtime().block_on(async {
			let first_cache = cache.clone();
			let first_key = key.clone();
			let first_url = url.clone();
			let first = tokio::spawn(async move {
				first_cache.ensure_repo(&first_key, &first_url, Some(&token)).await
			});
			wait_file(&root.join("entered")).await;
			first.abort();
			assert!(matches!(first.await, Err(error) if error.is_cancelled()));
			assert!(weak.upgrade().is_some(), "cancellation dropped the live Git credential owner");
			let second = tokio::spawn(async move { cache.ensure_repo(&key, &url, None).await });
			tokio::time::sleep(Duration::from_millis(200)).await;
			let concurrent = root.join("second").exists();
			std::fs::write(root.join("release"), b"release").unwrap();
			let _ = second.await.unwrap();
			assert!(weak.upgrade().is_none(), "completed Git retained its credential owner");
			// Runtime teardown joins the first spawn_blocking operation too.
			assert!(
				!concurrent,
				"cancellation released the repository lock while Git was still running"
			);
		});
	});
}

async fn wait_file(path: &Path) {
	tokio::time::timeout(Duration::from_secs(10), async {
		while !path.exists() {
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
	})
	.await
	.unwrap();
}

#[test]
fn helper_accepts_git_eof_terminated_request() {
	use std::io::{Read, Write};
	use std::os::unix::net::UnixListener;
	use std::process::Stdio;
	let root = tempfile::tempdir().unwrap();
	let socket = root.path().join("helper.sock");
	let listener = UnixListener::bind(&socket).unwrap();
	listener.set_nonblocking(true).unwrap();
	let server = std::thread::spawn(move || {
		let until = std::time::Instant::now() + Duration::from_secs(5);
		let mut stream = loop {
			match listener.accept() {
				Ok((stream, _)) => break stream,
				Err(error)
					if error.kind() == std::io::ErrorKind::WouldBlock
						&& std::time::Instant::now() < until =>
				{
					std::thread::sleep(Duration::from_millis(10))
				},
				_ => return false,
			}
		};
		stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
		let mut request = Vec::new();
		loop {
			let mut byte = [0];
			if stream.read_exact(&mut byte).is_err() {
				return false;
			}
			request.push(byte[0]);
			if request.ends_with(b"\n\n") {
				break;
			}
		}
		assert_eq!(request, b"protocol=https\nhost=example.invalid\npath=repo.git\n\n");
		stream
			.write_all(format!("username=x-access-token\npassword={PAT}\n\n").as_bytes())
			.unwrap();
		true
	});
	let mut helper = Command::new(env!("CARGO_BIN_EXE_loupe-worker"))
		.args(["git-credential", "--socket"])
		.arg(&socket)
		.arg("get")
		.env_clear()
		.env("LOUPE_SERVER_URL", "invalid worker config must be ignored")
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.unwrap();
	helper
		.stdin
		.take()
		.unwrap()
		.write_all(b"protocol=https\nhost=example.invalid\npath=repo.git\n")
		.unwrap();
	let output = helper.wait_with_output().unwrap();
	let connected = server.join().unwrap();
	assert!(output.status.success());
	assert!(output.stderr.is_empty());
	assert_eq!(
		output.stdout,
		format!("username=x-access-token\npassword={PAT}\n\n").as_bytes(),
		"helper rejected Git's actual EOF framing"
	);
	assert!(connected);
}

#[test]
fn helper_store_and_erase_discard_input_without_connecting() {
	use std::io::Write;
	use std::os::unix::net::UnixListener;
	use std::process::Stdio;
	let root = tempfile::tempdir().unwrap();
	let socket = root.path().join("helper.sock");
	let listener = UnixListener::bind(&socket).unwrap();
	listener.set_nonblocking(true).unwrap();
	for operation in ["store", "erase"] {
		let mut child = Command::new(env!("CARGO_BIN_EXE_loupe-worker"))
			.args(["git-credential", "--socket"])
			.arg(&socket)
			.arg(operation)
			.current_dir(root.path())
			.env_clear()
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::piped())
			.spawn()
			.unwrap();
		child
			.stdin
			.take()
			.unwrap()
			.write_all(
				format!("protocol=https\nhost=example.invalid\npath=repo.git\npassword={PAT}\n")
					.as_bytes(),
			)
			.unwrap();
		let output = child.wait_with_output().unwrap();
		assert!(output.status.success());
		assert!(output.stdout.is_empty());
		assert!(output.stderr.is_empty());
		assert!(
			matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
		);
		assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1, "helper persisted input");
	}
}

#[test]
fn helper_limits_stalled_and_oversized_input() {
	use std::io::Write;
	use std::process::Stdio;
	for stalled in [false, true] {
		let mut child = Command::new(env!("CARGO_BIN_EXE_loupe-worker"))
			.args(["git-credential", "--socket", "/nonexistent-loupe-git-test", "get"])
			.env_clear()
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::piped())
			.spawn()
			.unwrap();
		let mut input = child.stdin.take().unwrap();
		if !stalled {
			let _ = input.write_all(&vec![b'x'; 20 * 1024]);
		}
		let started = std::time::Instant::now();
		// Keep stdin open: the deadline must stop an incomplete sender.
		let output = child.wait_with_output().unwrap();
		drop(input);
		assert!(started.elapsed() < Duration::from_secs(5));
		assert!(output.status.success());
		assert_eq!(output.stdout, b"quit=true\n\n");
		assert!(output.stderr.is_empty());
	}
}

#[test]
fn failed_origin_remediation_recovers_without_fetching_legacy_url() {
	isolated("failed_origin_remediation_recovers_without_fetching_legacy_url", |root| {
		let source = upstream(root);
		let cache = cache(root);
		let key = RepoKey::new("local", "acme", "repo");
		let url = format!("file://{}", source.display());
		let rt = runtime();
		let repo = rt.block_on(cache.ensure_repo(&key, &url, None)).unwrap();
		git(
			&repo.path,
			&["config", "--local", "remote.origin.url", "ext::unsafe-legacy-transport"],
		);
		// An existing lock makes --replace-all fail before any fetch.
		std::fs::write(repo.path.join("config.lock"), b"occupied").unwrap();
		drop(repo);
		let head = commit(&source, "recovered");
		let repo = rt.block_on(cache.ensure_repo(&key, &url, None)).unwrap();
		assert_eq!(git(&repo.path, &["rev-parse", "HEAD"]), head);
		assert_eq!(git(&repo.path, &["config", "--get-all", "remote.origin.url"]), url);
		assert!(!repo.path.join("config.lock").exists());
	});
}

#[test]
fn helper_connection_cannot_block_on_full_socket_backlog() {
	use std::io::Write;
	use std::os::unix::net::UnixStream;
	use std::process::Stdio;

	use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
	let root = tempfile::tempdir().unwrap();
	let socket = root.path().join("full.sock");
	let listener = rustix::net::socket_with(
		AddressFamily::UNIX,
		SocketType::STREAM,
		SocketFlags::CLOEXEC,
		None,
	)
	.unwrap();
	rustix::net::bind(&listener, &SocketAddrUnix::new(&socket).unwrap()).unwrap();
	rustix::net::listen(&listener, 0).unwrap();
	let _occupied = UnixStream::connect(&socket).unwrap();
	let mut child = Command::new(env!("CARGO_BIN_EXE_loupe-worker"))
		.args(["git-credential", "--socket"])
		.arg(&socket)
		.arg("get")
		.env_clear()
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.unwrap();
	child
		.stdin
		.take()
		.unwrap()
		.write_all(b"protocol=https\nhost=example.invalid\npath=repo.git\n")
		.unwrap();
	let deadline = std::time::Instant::now() + Duration::from_secs(4);
	let timely = loop {
		if child.try_wait().unwrap().is_some() {
			break true;
		}
		if std::time::Instant::now() >= deadline {
			child.kill().unwrap();
			break false;
		}
		std::thread::sleep(Duration::from_millis(10));
	};
	let output = child.wait_with_output().unwrap();
	assert!(timely, "credential helper blocked indefinitely connecting to a full socket");
	assert_eq!(output.stdout, b"quit=true\n\n");
	assert!(output.stderr.is_empty());
}

#[test]
fn refresh_prunes_deleted_branches_and_fetches_tags() {
	isolated("refresh_prunes_deleted_branches_and_fetches_tags", |root| {
		let source = upstream(root);
		git(&source, &["branch", "obsolete"]);
		let cache = cache(root);
		let key = RepoKey::new("local", "acme", "repo");
		let url = format!("file://{}", source.display());
		let rt = runtime();
		drop(rt.block_on(cache.ensure_repo(&key, &url, None)).unwrap());
		let repo = rt.block_on(cache.ensure_repo(&key, &url, None)).unwrap();
		for name in ["refs/heads/obsolete", "refs/remotes/origin/obsolete"] {
			assert!(!git(&repo.path, &["rev-parse", name]).is_empty());
		}
		drop(repo);
		git(&source, &["branch", "-D", "obsolete"]);
		let latest = commit(&source, "latest");
		git(&source, &["tag", "new-tag"]);
		let repo = rt.block_on(cache.ensure_repo(&key, &url, None)).unwrap();
		let refs = git(&repo.path, &["for-each-ref", "--format=%(refname)"]);
		assert!(!refs.contains("obsolete"), "fetch lost pruning semantics");
		for name in [
			"refs/heads/main",
			"refs/remotes/origin/main",
			"refs/remotes/origin/HEAD",
			"refs/tags/new-tag",
		] {
			assert_eq!(git(&repo.path, &["rev-parse", name]), latest);
		}
	});
}

#[test]
fn url_projection_rejects_userinfo_without_exposing_it() {
	isolated("url_projection_rejects_userinfo_without_exposing_it", |root| {
		let leaked = format!("https://x-access-token:{PAT}@other.invalid/repo.git");
		git(root, &["config", "--global", &format!("url.{leaked}.insteadOf"), CLEAN_URL]);
		let token = Arc::new(Secret::new(PAT.to_owned()));
		let result = runtime().block_on(cache(root).ensure_repo(
			&RepoKey::new("example.invalid", "acme", "repo"),
			CLEAN_URL,
			Some(&token),
		));
		let error = result.err().expect("userinfo rewrite was accepted");
		assert!(error.to_string().contains("projection contains userinfo"));
		assert!(!format!("{error:#}").contains(PAT));
	});
}

#[test]
fn scp_projection_rejects_userinfo_before_transport() {
	isolated("scp_projection_rejects_userinfo_before_transport", |root| {
		use std::os::unix::fs::PermissionsExt;
		let script = root.join("bin/git");
		std::fs::write(&script, format!("#!/bin/sh\ncase \" $* \" in *' clone '*) /usr/bin/env > '{}/transport-env'; exit 128;; esac\nexec /usr/bin/git \"$@\"\n", root.display())).unwrap();
		std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
		let token = Arc::new(Secret::new(PAT.to_owned()));
		for host in ["example.invalid", "[::1]"] {
			let projected = format!("{PAT}@{host}:repo.git");
			let rewrite_key = format!("url.{projected}.insteadOf");
			git(root, &["config", "--global", &rewrite_key, CLEAN_URL]);
			let result = runtime().block_on(cache(root).ensure_repo(
				&RepoKey::new("example.invalid", "acme", "repo"),
				CLEAN_URL,
				Some(&token),
			));
			let captured = std::fs::read_to_string(root.join("transport-env")).unwrap_or_default();
			assert!(!captured.contains(PAT), "scp-like projected userinfo entered Git environment");
			let error = result.err().expect("userinfo rewrite was accepted");
			assert!(error.to_string().contains("projection contains userinfo"));
			assert!(!format!("{error:#}").contains(PAT));
			git(root, &["config", "--global", "--unset-all", &rewrite_key]);
		}
	});
}

#[test]
fn uri_projection_rejects_encoded_userinfo_before_transport() {
	isolated("uri_projection_rejects_encoded_userinfo_before_transport", |root| {
		use std::os::unix::fs::PermissionsExt;
		let script = root.join("bin/git");
		std::fs::write(&script, format!("#!/bin/sh\ncase \" $* \" in *' clone '*) /usr/bin/env > '{}/transport-env'; exit 128;; esac\nexec /usr/bin/git \"$@\"\n", root.display())).unwrap();
		std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
		let projected = format!("ssh://{PAT}%40example.invalid/repo.git");
		git(root, &["config", "--global", &format!("url.{projected}.insteadOf"), CLEAN_URL]);
		let token = Arc::new(Secret::new(PAT.to_owned()));
		let result = runtime().block_on(cache(root).ensure_repo(
			&RepoKey::new("example.invalid", "acme", "repo"),
			CLEAN_URL,
			Some(&token),
		));
		let captured = std::fs::read_to_string(root.join("transport-env")).unwrap_or_default();
		assert!(!captured.contains(PAT), "URI-decoded projected userinfo entered Git environment");
		let error = result.err().expect("userinfo rewrite was accepted");
		assert!(error.to_string().contains("projection contains userinfo"));
		assert!(!format!("{error:#}").contains(PAT));
	});
}

#[test]
fn uri_projection_rejects_ambiguous_authority_before_transport() {
	isolated("uri_projection_rejects_ambiguous_authority_before_transport", |root| {
		use std::os::unix::fs::PermissionsExt;
		let script = root.join("bin/git");
		let capture = root.join("transport-env");
		std::fs::write(&script, format!("#!/bin/sh\ncase \" $* \" in *' clone '*) /usr/bin/env > '{}'; exit 128;; esac\nexec /usr/bin/git \"$@\"\n", capture.display())).unwrap();
		std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
		let token = Arc::new(Secret::new(PAT.to_owned()));
		let mut accepted = Vec::new();
		for suffix in
			["%2felse", "%5celse", "%3fquery", "%23fragment", "%00", "%0A", "%7f", "%", "%4", "%gg"]
		{
			let projected = format!("ssh://example.invalid{suffix}/repo.git");
			let key = format!("url.{projected}.insteadOf");
			git(root, &["config", "--global", &key, CLEAN_URL]);
			let result = runtime().block_on(cache(root).ensure_repo(
				&RepoKey::new("example.invalid", "acme", "repo"),
				CLEAN_URL,
				Some(&token),
			));
			assert!(result.is_err());
			if capture.exists() {
				accepted.push(suffix);
				std::fs::remove_file(&capture).unwrap();
			}
			git(root, &["config", "--global", "--unset-all", &key]);
		}
		assert!(accepted.is_empty(), "ambiguous URI authority reached Git transport: {accepted:?}");
	});
}

#[test]
fn projection_rejects_ssh_cross_path_userinfo_before_transport() {
	isolated("projection_rejects_ssh_cross_path_userinfo_before_transport", |root| {
		use std::os::unix::fs::PermissionsExt;
		let script = root.join("bin/git");
		let capture = root.join("transport-env");
		std::fs::write(&script, format!("#!/bin/sh\ncase \" $* \" in *' clone '*) /usr/bin/env > '{}'; exit 128;; esac\nexec /usr/bin/git \"$@\"\n", capture.display())).unwrap();
		std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
		let token = Arc::new(Secret::new(PAT.to_owned()));
		let mut accepted = Vec::new();
		for spelling in [
			format!("ssh://host/path/{PAT}@[::1]/repo"),
			format!("ssh://host/path/{PAT}%40%5b::1]/repo"),
			format!("git+ssh://host/path/{PAT}%40[::1]/repo"),
			format!("ssh+git://host/path/{PAT}@%5B::1]/repo"),
			format!("host:path/{PAT}@[::1]:repo"),
			format!("[::1]{PAT}@host:repo"),
			format!("ssh://%5Bhost/path/{PAT}%40evil%5D/repo"),
			format!("ssh://[host/path/{PAT}@evil]/repo"),
		] {
			let key = format!("url.{spelling}.insteadOf");
			git(root, &["config", "--global", &key, CLEAN_URL]);
			let result = runtime().block_on(cache(root).ensure_repo(
				&RepoKey::new("example.invalid", "acme", "repo"),
				CLEAN_URL,
				Some(&token),
			));
			assert!(result.is_err());
			if capture.exists() {
				accepted.push(spelling);
				std::fs::remove_file(&capture).unwrap();
			}
			git(root, &["config", "--global", "--unset-all", &key]);
		}
		assert!(accepted.is_empty(), "SSH cross-path userinfo reached Git transport: {accepted:?}");
	});
}

#[test]
fn projection_preserves_one_pass_uri_and_local_interpretation() {
	isolated("projection_preserves_one_pass_uri_and_local_interpretation", |root| {
		use std::os::unix::fs::PermissionsExt;
		let script = root.join("bin/git");
		let capture = root.join("transport-env");
		std::fs::write(&script, format!("#!/bin/sh\ncase \" $* \" in *' clone '*) /usr/bin/env > '{}'; exit 128;; esac\nexec /usr/bin/git \"$@\"\n", capture.display())).unwrap();
		std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
		let token = Arc::new(Secret::new(PAT.to_owned()));
		for spelling in [
			"ssh://%65xample.invalid/repo",
			"ssh://[::1]:2222/repo",
			"ssh://%5B::1%5D:2222/repo",
			"ssh://example.invalid%3A2222/repo",
			"ssh://%C3%A9xample.invalid/repo",
			"ssh://literal%2540host/repo",
			"ssh://host/repo@name",
			"ssh://host/repo%40name",
			"ssh://host/repo%2540%5Bname",
			"host:repo@name",
			"host:repo%40%5Bname",
			"[::1]:repo@name",
			"./user@[::1]:repo",
			"/tmp/user@[::1]:repo",
			"/tmp/dir://user@host",
		] {
			let key = format!("url.{spelling}.insteadOf");
			git(root, &["config", "--global", &key, CLEAN_URL]);
			let result = runtime().block_on(cache(root).ensure_repo(
				&RepoKey::new("example.invalid", "acme", "repo"),
				CLEAN_URL,
				Some(&token),
			));
			assert!(result.is_err()); // The transport-intercept fixture exits 128.
			let captured = std::fs::read_to_string(&capture)
				.unwrap_or_else(|_| panic!("valid projection was refused: {spelling}"));
			assert!(captured.contains(spelling), "projection spelling changed: {spelling}");
			std::fs::remove_file(&capture).unwrap();
			git(root, &["config", "--global", "--unset-all", &key]);
		}
	});
}

#[test]
fn url_projection_preserves_local_path_with_at_and_colon() {
	isolated("url_projection_preserves_local_path_with_at_and_colon", |root| {
		let source = upstream(root);
		let path = root.join("user@host:repo");
		std::fs::rename(source, &path).unwrap();
		git(root, &["config", "--global", &format!("url.{}.insteadOf", path.display()), CLEAN_URL]);
		let token = Arc::new(Secret::new(PAT.to_owned()));
		let repo = runtime()
			.block_on(cache(root).ensure_repo(
				&RepoKey::new("example.invalid", "acme", "repo"),
				CLEAN_URL,
				Some(&token),
			))
			.unwrap();
		assert_eq!(git(&repo.path, &["rev-parse", "HEAD"]), git(&path, &["rev-parse", "HEAD"]));
		assert_eq!(
			git(&repo.path, &["config", "--local", "--get-all", "remote.origin.url"]),
			CLEAN_URL
		);
	});
}

#[test]
fn url_projection_deadline_kills_and_reaps_the_child() {
	isolated("url_projection_deadline_kills_and_reaps_the_child", |root| {
		use std::os::unix::fs::PermissionsExt;
		let script = root.join("bin/git");
		std::fs::write(&script, format!("#!/bin/sh\ncase \" $* \" in *' ls-remote '*) echo $$ > '{}/probe-pid'; exec /bin/sleep 30;; esac\nexec /usr/bin/git \"$@\"\n", root.display())).unwrap();
		std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
		let token = Arc::new(Secret::new(PAT.to_owned()));
		let start = std::time::Instant::now();
		let result = runtime().block_on(cache(root).ensure_repo(
			&RepoKey::new("example.invalid", "acme", "repo"),
			CLEAN_URL,
			Some(&token),
		));
		assert!(result.is_err());
		assert!(start.elapsed() < Duration::from_secs(5));
		let pid = std::fs::read_to_string(root.join("probe-pid")).unwrap();
		assert!(
			!Path::new("/proc").join(pid.trim()).exists(),
			"projection child survived its deadline"
		);
	});
}
