//! Bubblewrap sandbox helper for scanner subprocesses.
//!
//! Every scanner runs inside `bwrap` so a malicious or buggy invocation
//! can't poison follow-up jobs. Each invocation gets a fresh `/tmp`,
//! its own `$HOME`, and the worktree mounted read-only at `/workdir`.
//! Network is unshared by default; LLM backends opt in via
//! [`SandboxBuilder::allow_network`].
//!
//! `LOUPE_DISABLE_SANDBOX=1` exists as a development escape hatch on
//! hosts without `bwrap`; the worker logs a loud warning if it's set,
//! and the helper produces a plain `Command` instead of a wrapped one.

use std::path::{Component, Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result};
use tokio::process::Command;

/// Path to the bwrap binary. Resolved once and cached.
const BWRAP_BIN: &str = "bwrap";

/// Env var that disables the sandbox entirely. Dev-only; production
/// deployments should leave this unset and install bubblewrap.
pub const DISABLE_SANDBOX_ENV: &str = "LOUPE_DISABLE_SANDBOX";

/// Probe for `bwrap` once at startup. Returns `Ok(true)` if `bwrap` is
/// available, `Ok(false)` if `LOUPE_DISABLE_SANDBOX` is set (caller
/// should warn loudly). Errors if `bwrap` is missing AND the disable
/// env var is unset — that's a hard fatal for the worker.
pub fn probe_at_startup() -> Result<bool> {
	if sandbox_disabled() {
		return Ok(false);
	}
	let status = std::process::Command::new(BWRAP_BIN)
		.arg("--version")
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.status();
	match status {
		Ok(s) if s.success() => Ok(true),
		Ok(s) => Err(anyhow::anyhow!("bwrap probe exited with {s}")),
		Err(e) => Err(anyhow::Error::from(e).context(format!(
			"`{BWRAP_BIN}` not found on PATH; install bubblewrap or set {DISABLE_SANDBOX_ENV}=1 \
			 to opt out (dev only)"
		))),
	}
}

/// Builder for a sandboxed `tokio::process::Command`. Default posture:
/// worktree mounted read-only at `/workdir`, fresh tmpfs `/tmp` and
/// `$HOME`, `--unshare-all`, `--die-with-parent`, working directory set
/// to `/workdir`.
pub struct SandboxBuilder {
	workdir: PathBuf,
	allow_network: bool,
	disabled: bool,
	/// Caller-supplied read-only bind mounts (host path, sandbox
	/// path). Populated by [`bind_ro`] and [`allow_binary`].
	extra_ro_binds: Vec<(PathBuf, PathBuf)>,
	/// Env vars to forward into the sandbox by name (the value is
	/// looked up from the worker's own env at `build()` time).
	forward_env: Vec<&'static str>,
}

impl SandboxBuilder {
	/// New builder targeting a worktree on disk. The `workdir` is bind-
	/// mounted read-only into the sandbox at `/workdir`.
	pub fn new(workdir: impl Into<PathBuf>) -> Self {
		let disabled = sandbox_disabled();
		Self {
			workdir: workdir.into(),
			allow_network: false,
			disabled,
			extra_ro_binds: Vec::new(),
			forward_env: Vec::new(),
		}
	}

	/// Permit outbound network. Used by LLM backends that need to reach
	/// their provider over HTTPS. Off by default — most scanners
	/// shouldn't need network access at all.
	pub fn allow_network(mut self) -> Self {
		self.allow_network = true;
		self
	}

	/// Bind-mount `src` (a path on the host) read-only at `dst` (a path
	/// inside the sandbox). The two can be equal — that's the common
	/// case when surfacing a host install directly.
	pub fn bind_ro(mut self, src: impl Into<PathBuf>, dst: impl Into<PathBuf>) -> Self {
		self.extra_ro_binds.push((src.into(), dst.into()));
		self
	}

	/// Forward an env var into the sandbox. The value is looked up
	/// from the worker's own environment at `build()` time. Use for
	/// things like `ANTHROPIC_API_KEY` that the agent reads to
	/// authenticate.
	pub fn forward_env(mut self, name: &'static str) -> Self {
		self.forward_env.push(name);
		self
	}

	/// Locate `name` on the host PATH and bind-mount the install tree
	/// into the sandbox so the wrapped subprocess can `exec` it. The
	/// default sandbox only mounts `/usr`, `/etc`, `/lib`, `/lib64`,
	/// `/bin`, `/sbin` — anything installed in `~/.local/bin` (per-
	/// user installs, npm-global with non-root prefix, etc.) is
	/// invisible to the wrapped subprocess unless this method is
	/// called.
	///
	/// Resolves the entry point on PATH, follows the symlink chain
	/// to its canonical real path, and bind-mounts both the entry
	/// point and the canonical install directory read-only. Symlinked
	/// entry points are preserved by mounting their parent directory:
	/// binding the symlink path itself turns it into a regular file in
	/// the sandbox, which can break runtimes that resolve modules from
	/// the real package path.
	///
	/// Special-cases npm package layouts: when canonical lives inside
	/// a `node_modules/<scope>?/<pkg>/` tree, the outer `node_modules`
	/// root is mounted instead of just the entry point's parent dir.
	/// This is load-bearing for wrappers that load platform-specific
	/// optional deps via `require.resolve('@scope/pkg-platform')`.
	/// Depending on the package manager, those deps can be nested under
	/// the wrapper package or installed as siblings under the global
	/// `node_modules` root. Codex is the canonical example.
	pub fn allow_binary(self, name: &str) -> Result<Self> {
		let original =
			locate_on_path(name).ok_or_else(|| anyhow::anyhow!("`{name}` not found on PATH"))?;
		let canonical = std::fs::canonicalize(&original)
			.with_context(|| format!("canonicalizing {}", original.display()))?;

		let entrypoint_bind = entrypoint_bind_source(&original)?;
		let mut this = self.bind_ro(entrypoint_bind.clone(), entrypoint_bind);
		// Decide what to mount alongside the entry point.
		// Priority: directory canonical → that dir; npm package
		// detected → the node_modules root; else canonical's parent.
		let install_dir = if canonical.is_dir() {
			canonical
		} else if let Some(node_modules_root) = npm_node_modules_root(&canonical) {
			node_modules_root
		} else {
			canonical
				.parent()
				.ok_or_else(|| anyhow::anyhow!("canonical path has no parent"))?
				.to_path_buf()
		};
		this = this.bind_ro(install_dir.clone(), install_dir);
		Ok(this)
	}

	/// Build a `Command` for `program`. The command runs inside the
	/// sandbox; its `args()` should be appended by the caller as
	/// normal. When the sandbox is disabled (`LOUPE_DISABLE_SANDBOX=1`)
	/// returns a bare `Command::new(program)` with `current_dir` set to
	/// the worktree.
	pub fn build(&self, program: &str) -> Command {
		if self.disabled {
			let mut cmd = Command::new(program);
			cmd.current_dir(&self.workdir);
			return cmd;
		}

		let mut cmd = Command::new(BWRAP_BIN);
		cmd.arg("--die-with-parent");
		cmd.arg("--clearenv");

		if self.allow_network {
			cmd.arg("--share-net");
		} else {
			cmd.arg("--unshare-net");
		}
		cmd.args(["--unshare-pid", "--unshare-ipc", "--unshare-uts"]);

		// Read-only system directories. /lib and /lib64 are platform-
		// dependent: glibc systems have /lib64, musl typically does not.
		// We bind whichever exists.
		for ro in ["/usr", "/etc", "/lib", "/lib64", "/bin", "/sbin"] {
			if Path::new(ro).exists() {
				cmd.args(["--ro-bind-try", ro, ro]);
			}
		}

		// On systemd-resolved hosts, /etc/resolv.conf often points
		// outside /etc. Keep the /etc symlink usable without exposing
		// the whole resolver runtime directory.
		if self.allow_network {
			add_resolver_binds(&mut cmd);
		}

		cmd.args(["--proc", "/proc", "--dev", "/dev"]);

		// Fresh tmpfs for /tmp and a new $HOME. *Must* come before
		// any extra_ro_binds that target paths inside /home/scanner —
		// bwrap processes args in order and a tmpfs mounted on top of
		// a prior bind hides it. Putting the tmpfs first lets caller
		// binds (e.g. ~/.claude.json → /home/scanner/.claude.json)
		// overlay the tmpfs and stay visible.
		cmd.args(["--tmpfs", "/tmp", "--tmpfs", "/home/scanner"]);
		cmd.args(["--setenv", "HOME", "/home/scanner"]);
		cmd.args(["--setenv", "TMPDIR", "/tmp"]);
		cmd.args(["--setenv", "PATH"]).arg(sandbox_path());

		// Caller-supplied read-only binds (binary install dirs, agent
		// config dirs, etc.). Use `--ro-bind-try` so a missing src
		// path is a no-op rather than a fatal — handy when binding an
		// optional auth dir that may or may not exist on every host.
		for (src, dst) in &self.extra_ro_binds {
			cmd.arg("--ro-bind-try").arg(src).arg(dst);
		}

		// Worktree: read-only.
		cmd.arg("--ro-bind").arg(&self.workdir).arg("/workdir");
		cmd.args(["--chdir", "/workdir"]);

		// Forwarded env vars. Skip those that aren't set on the host.
		for name in &self.forward_env {
			if let Some(value) = std::env::var_os(name) {
				cmd.arg("--setenv").arg(name).arg(value);
			}
		}

		cmd.arg("--").arg(program);
		cmd
	}

	/// Convenience: build with full args + stdio piped, returning the
	/// fully prepared command for the caller to spawn.
	pub fn build_with_args<'a>(
		&self, program: &str, args: impl IntoIterator<Item = &'a str>,
	) -> Command {
		let mut cmd = self.build(program);
		for a in args {
			cmd.arg(a);
		}
		cmd
	}
}

fn sandbox_disabled() -> bool {
	std::env::var_os(DISABLE_SANDBOX_ENV).is_some_and(|v| {
		let value = v.to_string_lossy();
		if value.is_empty() {
			return false;
		}
		!matches!(value.to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off")
	})
}

fn sandbox_path() -> String {
	std::env::var("PATH")
		.unwrap_or_else(|_| "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into())
}

fn add_resolver_binds(cmd: &mut Command) {
	let resolv_conf = Path::new("/etc/resolv.conf");
	let Ok(link_target) = std::fs::read_link(resolv_conf) else {
		return;
	};
	let Ok(real) = std::fs::canonicalize(resolv_conf) else {
		return;
	};

	for dst in resolver_bind_destinations(resolv_conf, &link_target, &real) {
		cmd.arg("--ro-bind-try").arg(&real).arg(dst);
	}
}

fn resolver_bind_destinations(symlink: &Path, link_target: &Path, real: &Path) -> Vec<PathBuf> {
	let visible = normalize_path(&if link_target.is_absolute() {
		link_target.to_path_buf()
	} else {
		symlink.parent().unwrap_or_else(|| Path::new("/")).join(link_target)
	});

	let mut destinations = vec![visible.clone()];
	if visible != real {
		destinations.push(real.to_path_buf());
	}
	destinations
}

fn normalize_path(path: &Path) -> PathBuf {
	let mut out = PathBuf::new();
	for component in path.components() {
		match component {
			Component::Prefix(prefix) => out.push(prefix.as_os_str()),
			Component::RootDir => out.push(Path::new("/")),
			Component::CurDir => {},
			Component::ParentDir => {
				out.pop();
			},
			Component::Normal(part) => out.push(part),
		}
	}
	out
}

/// If `path` lives inside a `node_modules/` tree, return the outer
/// `node_modules` directory.
/// Handles both unscoped (`node_modules/<pkg>/`) and scoped
/// (`node_modules/@scope/<pkg>/`) layouts. Returns `None` if `path`
/// isn't inside a `node_modules/`, or if the components after it
/// don't match an npm package shape.
///
/// Used by [`SandboxBuilder::allow_binary`] to make a global npm CLI
/// see both its own package and platform-specific optional deps. Some
/// npm installs keep those deps nested under the package; others hoist
/// them as siblings under the global `node_modules` root.
fn npm_node_modules_root(path: &Path) -> Option<PathBuf> {
	let components: Vec<_> = path.components().collect();
	// First (outermost) `node_modules` in the path. Outermost is
	// what we want: it covers both the wrapper package and any sibling
	// optional packages the wrapper resolves at runtime.
	let nm_idx = components.iter().position(|c| c.as_os_str() == "node_modules")?;
	let pkg_start = components.get(nm_idx + 1)?;
	let is_scoped = pkg_start.as_os_str().to_str().is_some_and(|s| s.starts_with('@'));
	let take = if is_scoped { nm_idx + 3 } else { nm_idx + 2 };
	if components.len() < take {
		return None;
	}
	let mut p = PathBuf::new();
	for c in &components[..=nm_idx] {
		p.push(c);
	}
	Some(p)
}

fn entrypoint_bind_source(original: &Path) -> Result<PathBuf> {
	if std::fs::symlink_metadata(original).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
		original
			.parent()
			.ok_or_else(|| anyhow::anyhow!("PATH entry has no parent"))
			.map(Path::to_path_buf)
	} else {
		Ok(original.to_path_buf())
	}
}

/// PATH walk: return the first existing executable file matching
/// `name`. Mirrors what `execvp` would do — used by
/// [`SandboxBuilder::allow_binary`] to discover the host install of
/// an agent CLI without pulling in a `which`-style dep.
fn locate_on_path(name: &str) -> Option<PathBuf> {
	let path = std::env::var_os("PATH")?;
	for dir in std::env::split_paths(&path) {
		let candidate = dir.join(name);
		if candidate.is_file() {
			return Some(candidate);
		}
	}
	None
}

/// Validate that the host can run `bwrap` *with its full mount layout*,
/// not just `--version`. Useful in tests and as a smoke check before
/// the worker runs its first scan. Many container hosts have `bwrap`
/// installed but disable user namespaces, which makes any real
/// invocation fail; calling this once at startup surfaces that early
/// rather than mid-job.
pub fn smoketest(workdir: &Path) -> Result<()> {
	let builder = SandboxBuilder::new(workdir);
	let mut cmd = builder.build("/bin/true");
	cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
	let output = std::process::Command::new(cmd.as_std().get_program())
		.args(cmd.as_std().get_args())
		.output()
		.context("running bwrap smoketest")?;
	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		anyhow::bail!("bwrap smoketest failed: {} ({stderr})", output.status);
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use std::io::Write;
	use std::sync::Mutex;

	use super::*;

	static ENV_LOCK: Mutex<()> = Mutex::new(());

	fn bwrap_present() -> bool {
		std::process::Command::new(BWRAP_BIN)
			.arg("--version")
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.status()
			.map(|s| s.success())
			.unwrap_or(false)
	}

	#[test]
	fn resolver_bind_destinations_preserve_symlink_visible_alias() {
		let destinations = resolver_bind_destinations(
			Path::new("/etc/resolv.conf"),
			Path::new("/var/run/systemd/resolve/stub-resolv.conf"),
			Path::new("/run/systemd/resolve/stub-resolv.conf"),
		);

		assert_eq!(
			destinations,
			vec![
				PathBuf::from("/var/run/systemd/resolve/stub-resolv.conf"),
				PathBuf::from("/run/systemd/resolve/stub-resolv.conf"),
			],
		);
	}

	#[test]
	fn resolver_bind_destinations_resolve_relative_symlink_target() {
		let destinations = resolver_bind_destinations(
			Path::new("/etc/resolv.conf"),
			Path::new("../run/systemd/resolve/stub-resolv.conf"),
			Path::new("/run/systemd/resolve/stub-resolv.conf"),
		);

		assert_eq!(destinations, vec![PathBuf::from("/run/systemd/resolve/stub-resolv.conf")],);
	}

	#[test]
	fn npm_node_modules_root_picks_unscoped_package_dir() {
		let p = Path::new("/home/u/.local/lib/node_modules/foo/bin/foo.js");
		let root = npm_node_modules_root(p).unwrap();
		assert_eq!(root, Path::new("/home/u/.local/lib/node_modules"));
	}

	#[test]
	fn npm_node_modules_root_picks_scoped_package_dir() {
		// Scoped packages (`@openai/codex`) have one extra path
		// component vs. unscoped. Mount the outer node_modules dir so
		// optional native-binary deps work whether npm nests or hoists
		// them.
		let p = Path::new("/h/u/.local/lib/node_modules/@openai/codex/bin/codex.js");
		let root = npm_node_modules_root(p).unwrap();
		assert_eq!(root, Path::new("/h/u/.local/lib/node_modules"));
	}

	#[test]
	fn npm_node_modules_root_returns_none_outside_node_modules() {
		assert!(npm_node_modules_root(Path::new("/usr/local/bin/foo")).is_none());
		assert!(npm_node_modules_root(Path::new("/home/u/.local/share/claude/versions/1/claude"))
			.is_none());
	}

	#[test]
	fn npm_node_modules_root_handles_outermost_when_nested() {
		// A nested install (the wrapper itself nests its native-bin
		// dep under its own node_modules) — the *outermost*
		// node_modules is what we want, so the mount covers the
		// wrapper package and the nested tree.
		let p = Path::new(
			"/h/u/.local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/.../bin",
		);
		let root = npm_node_modules_root(p).unwrap();
		assert_eq!(root, Path::new("/h/u/.local/lib/node_modules"));
	}

	#[cfg(unix)]
	#[test]
	fn entrypoint_bind_source_preserves_symlinked_entrypoint_parent() {
		use std::os::unix::fs::symlink;

		let tmp = tempfile::tempdir().unwrap();
		let bin_dir = tmp.path().join("bin");
		let pkg_dir = tmp.path().join("lib/node_modules/@openai/codex/bin");
		std::fs::create_dir_all(&bin_dir).unwrap();
		std::fs::create_dir_all(&pkg_dir).unwrap();
		let target = pkg_dir.join("codex.js");
		std::fs::write(&target, "#!/usr/bin/env node\n").unwrap();
		symlink("../lib/node_modules/@openai/codex/bin/codex.js", bin_dir.join("codex")).unwrap();

		assert_eq!(entrypoint_bind_source(&bin_dir.join("codex")).unwrap(), bin_dir);
	}

	#[tokio::test]
	async fn build_runs_a_command_inside_the_sandbox() {
		if !bwrap_present() {
			eprintln!("skipping: bwrap not installed");
			return;
		}
		let tmp = tempfile::tempdir().unwrap();
		let mut cmd = SandboxBuilder::new(tmp.path()).build("/bin/sh");
		let out =
			cmd.arg("-c").arg("echo hello && pwd").output().await.expect("bwrap smoketest spawned");
		assert!(
			out.status.success(),
			"exit: {}, stderr: {}",
			out.status,
			String::from_utf8_lossy(&out.stderr)
		);
		let stdout = String::from_utf8_lossy(&out.stdout);
		assert!(stdout.contains("hello"), "stdout: {stdout}");
		assert!(stdout.contains("/workdir"), "should be in /workdir, got: {stdout}");
	}

	#[tokio::test]
	async fn worktree_mount_is_read_only() {
		if !bwrap_present() {
			eprintln!("skipping: bwrap not installed");
			return;
		}
		let tmp = tempfile::tempdir().unwrap();
		// Plant a file the test can try to overwrite.
		let mut f = std::fs::File::create(tmp.path().join("readme")).unwrap();
		f.write_all(b"original").unwrap();

		let out = SandboxBuilder::new(tmp.path())
			.build("/bin/sh")
			.arg("-c")
			.arg("echo overwrite > /workdir/readme && echo OK || echo DENIED")
			.output()
			.await
			.expect("spawn");
		let stdout = String::from_utf8_lossy(&out.stdout);
		// The command itself must report DENIED — read-only mount.
		assert!(stdout.contains("DENIED"), "stdout: {stdout}");
		// And the original file on disk is unchanged.
		let after = std::fs::read_to_string(tmp.path().join("readme")).unwrap();
		assert_eq!(after, "original");
	}

	#[tokio::test]
	async fn tmp_is_fresh_per_invocation() {
		if !bwrap_present() {
			eprintln!("skipping: bwrap not installed");
			return;
		}
		let tmp = tempfile::tempdir().unwrap();
		// First run: drop a marker into /tmp.
		let out = SandboxBuilder::new(tmp.path())
			.build("/bin/sh")
			.arg("-c")
			.arg("echo marker > /tmp/m && cat /tmp/m")
			.output()
			.await
			.unwrap();
		assert!(out.status.success());
		assert!(String::from_utf8_lossy(&out.stdout).contains("marker"));

		// Second run: marker must be gone — /tmp is a fresh tmpfs.
		let out = SandboxBuilder::new(tmp.path())
			.build("/bin/sh")
			.arg("-c")
			.arg("test -f /tmp/m && echo LEAK || echo CLEAN")
			.output()
			.await
			.unwrap();
		let stdout = String::from_utf8_lossy(&out.stdout);
		assert!(stdout.contains("CLEAN"), "/tmp must be fresh between runs; got: {stdout}");
	}

	#[tokio::test]
	async fn unshare_net_blocks_outbound_connections() {
		if !bwrap_present() {
			eprintln!("skipping: bwrap not installed");
			return;
		}
		let tmp = tempfile::tempdir().unwrap();
		// `getent hosts` should fail without --share-net (no DNS).
		let out = SandboxBuilder::new(tmp.path())
			.build("/bin/sh")
			.arg("-c")
			.arg("getent hosts example.com >/dev/null 2>&1 && echo ALLOWED || echo BLOCKED")
			.output()
			.await
			.unwrap();
		let stdout = String::from_utf8_lossy(&out.stdout);
		assert!(stdout.contains("BLOCKED"), "net should be unshared; got: {stdout}");
	}

	#[test]
	fn disabled_sandbox_returns_bare_command() {
		// Use a builder that thinks the env var is set.
		let mut b = SandboxBuilder::new("/tmp");
		b.disabled = true;
		let cmd = b.build("/bin/echo");
		assert_eq!(cmd.as_std().get_program(), "/bin/echo");
	}

	#[test]
	fn disable_sandbox_env_accepts_false_values() {
		let _guard = ENV_LOCK.lock().unwrap();
		let old = std::env::var_os(DISABLE_SANDBOX_ENV);
		std::env::set_var(DISABLE_SANDBOX_ENV, "false");
		assert!(!sandbox_disabled());
		std::env::set_var(DISABLE_SANDBOX_ENV, "1");
		assert!(sandbox_disabled());
		if let Some(old) = old {
			std::env::set_var(DISABLE_SANDBOX_ENV, old);
		} else {
			std::env::remove_var(DISABLE_SANDBOX_ENV);
		}
	}

	#[tokio::test]
	async fn bind_ro_under_tmpfs_home_remains_visible() {
		// Regression: bwrap processes args in order, so a tmpfs
		// emitted *after* a bind on a path inside that tmpfs will
		// hide the bind. We emit tmpfs first; this test pins that
		// ordering by binding a marker file into /home/scanner and
		// reading it back from inside the sandbox.
		if !bwrap_present() {
			eprintln!("skipping: bwrap not installed");
			return;
		}
		let workdir = tempfile::tempdir().unwrap();
		let marker_dir = tempfile::tempdir().unwrap();
		let marker_path = marker_dir.path().join("creds");
		std::fs::write(&marker_path, b"hello-from-host").unwrap();

		let out = SandboxBuilder::new(workdir.path())
			.bind_ro(marker_path, "/home/scanner/creds")
			.build("/bin/sh")
			.arg("-c")
			.arg("cat /home/scanner/creds")
			.output()
			.await
			.unwrap();
		assert!(
			out.status.success(),
			"exit: {}, stderr: {}",
			out.status,
			String::from_utf8_lossy(&out.stderr),
		);
		let stdout = String::from_utf8_lossy(&out.stdout);
		assert_eq!(stdout.trim(), "hello-from-host");
	}

	#[test]
	fn allow_network_flag_emits_share_net() {
		let mut b = SandboxBuilder::new("/tmp");
		b.disabled = false; // even if env says disabled, force the wrapped path
		let cmd = b.allow_network().build("/bin/true");
		// Inspect the args of the bwrap invocation (program is bwrap).
		assert_eq!(cmd.as_std().get_program(), "bwrap");
		let args: Vec<String> =
			cmd.as_std().get_args().map(|s| s.to_string_lossy().into_owned()).collect();
		assert!(args.iter().any(|a| a == "--share-net"), "args: {args:?}");
		assert!(!args.iter().any(|a| a == "--unshare-net"), "args: {args:?}");
	}

	#[test]
	fn wrapped_command_starts_from_clear_environment() {
		let _guard = ENV_LOCK.lock().unwrap();
		std::env::set_var("LOUPE_SANDBOX_TEST_SECRET", "do-not-leak");

		let cmd = SandboxBuilder::new("/tmp").build("/bin/true");
		let args: Vec<String> =
			cmd.as_std().get_args().map(|s| s.to_string_lossy().into_owned()).collect();

		assert!(args.iter().any(|a| a == "--clearenv"), "args: {args:?}");
		assert!(args.windows(2).any(|w| w[0] == "--setenv" && w[1] == "PATH"), "args: {args:?}");
		assert!(!args.iter().any(|a| a == "LOUPE_SANDBOX_TEST_SECRET"), "args: {args:?}");
		assert!(!args.iter().any(|a| a == "do-not-leak"), "args: {args:?}");

		std::env::remove_var("LOUPE_SANDBOX_TEST_SECRET");
	}

	#[test]
	fn forward_env_explicitly_passes_allowlisted_values() {
		let _guard = ENV_LOCK.lock().unwrap();
		std::env::set_var("LOUPE_SANDBOX_TEST_SECRET", "forwarded-value");

		let cmd =
			SandboxBuilder::new("/tmp").forward_env("LOUPE_SANDBOX_TEST_SECRET").build("/bin/true");
		let args: Vec<String> =
			cmd.as_std().get_args().map(|s| s.to_string_lossy().into_owned()).collect();

		assert!(
			args.windows(3).any(|w| {
				w[0] == "--setenv"
					&& w[1] == "LOUPE_SANDBOX_TEST_SECRET"
					&& w[2] == "forwarded-value"
			}),
			"args: {args:?}"
		);

		std::env::remove_var("LOUPE_SANDBOX_TEST_SECRET");
	}
}
