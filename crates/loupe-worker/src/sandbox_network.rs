use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rustix::io::{fcntl_setfd, read, write, Errno, FdFlags};
use rustix::pipe::{pipe_with, PipeFlags};
use serde::Deserialize;

use crate::sandbox::{validate_network_host, SandboxNetworkMode, SANDBOX_RESOLV_CONF_PLACEHOLDER};

const BWRAP_BIN: &str = "bwrap";
const SLIRP4NETNS_BIN: &str = "slirp4netns";
const NSENTER_BIN: &str = "nsenter";
const NFT_BIN: &str = "nft";
const IP_BIN: &str = "ip";
const TUN_DEVICE: &str = "/dev/net/tun";
const SLIRP_DNS: &str = "10.0.2.3";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

const PUBLIC_DENYLIST: &[&str] = &[
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"224.0.0.0/4",
	"240.0.0.0/4",
];

#[derive(Debug, Deserialize)]
struct BwrapInfo {
	#[serde(rename = "child-pid")]
	child_pid: u32,
}

#[derive(Debug)]
struct NetworkTools {
	slirp4netns: PathBuf,
	nsenter: PathBuf,
	nft: PathBuf,
	ip: PathBuf,
}

impl NetworkTools {
	fn discover() -> Result<Self> {
		Ok(Self {
			slirp4netns: find_program(SLIRP4NETNS_BIN, &[])?,
			nsenter: find_program(NSENTER_BIN, &[])?,
			nft: find_program(NFT_BIN, &["/sbin/nft", "/usr/sbin/nft"])?,
			ip: find_program(IP_BIN, &["/sbin/ip", "/usr/sbin/ip"])?,
		})
	}
}

pub(crate) fn probe_network_helpers() -> Result<()> {
	let tools = NetworkTools::discover()?;
	probe_command(&tools.slirp4netns, &["--version"])?;
	let nsenter_help = Command::new(&tools.nsenter)
		.arg("--help")
		.output()
		.with_context(|| format!("probing {}", tools.nsenter.display()))?;
	let mut nsenter_output = nsenter_help.stdout;
	nsenter_output.extend(nsenter_help.stderr);
	if !nsenter_help.status.success()
		|| !String::from_utf8_lossy(&nsenter_output).contains("--user-parent")
	{
		anyhow::bail!(
			"`{}` lacks --user-parent; install util-linux 2.41 or newer",
			tools.nsenter.display()
		);
	}
	probe_command(&tools.nft, &["--version"])?;
	probe_command(&tools.ip, &["-Version"])?;
	if !std::fs::metadata(TUN_DEVICE)
		.map(|metadata| metadata.file_type().is_char_device())
		.unwrap_or(false)
	{
		anyhow::bail!("TUN device not found at {TUN_DEVICE}; load the host `tun` module");
	}
	Ok(())
}

fn probe_command(program: &Path, args: &[&str]) -> Result<()> {
	let status = Command::new(program)
		.args(args)
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.status()
		.with_context(|| format!("probing {}", program.display()))?;
	if !status.success() {
		anyhow::bail!("{} probe exited with {status}", program.display());
	}
	Ok(())
}

pub(crate) fn run_networked_sandbox(
	mode: SandboxNetworkMode, required_hosts: Vec<String>, allow_hosts: Vec<String>,
	command: Vec<OsString>,
) -> Result<ExitStatus> {
	let tools = NetworkTools::discover()?;
	run_networked_sandbox_with_tools(
		mode,
		required_hosts,
		allow_hosts,
		command,
		&tools,
		Path::new("/proc"),
	)
}

fn run_networked_sandbox_with_tools(
	mode: SandboxNetworkMode, required_hosts: Vec<String>, allow_hosts: Vec<String>,
	command: Vec<OsString>, tools: &NetworkTools, proc_root: &Path,
) -> Result<ExitStatus> {
	if mode == SandboxNetworkMode::Public && !allow_hosts.is_empty() {
		anyhow::bail!("--allow-host requires --network allowlist");
	}
	let (program, bwrap_args) = command
		.split_first()
		.ok_or_else(|| anyhow::anyhow!("sandbox-exec requires a Bubblewrap command"))?;
	if Path::new(program).file_name() != Some(OsStr::new(BWRAP_BIN)) {
		anyhow::bail!("sandbox-exec expected `{BWRAP_BIN}`, got `{}`", program.to_string_lossy());
	}

	let tmp = tempfile::Builder::new().prefix("loupe-network-").tempdir()?;
	let resolv_path = tmp.path().join("resolv.conf");
	std::fs::write(&resolv_path, format!("nameserver {SLIRP_DNS}\n"))?;
	let policy_path = tmp.path().join("policy.nft");
	let slirp_log_path = tmp.path().join("slirp4netns.log");

	let required_ipv4 = resolve_hosts(&required_hosts)?;
	let allowed_ipv4 = if mode == SandboxNetworkMode::Allowlist {
		let mut addresses = required_ipv4.clone();
		addresses.extend(resolve_hosts(&allow_hosts)?);
		addresses
	} else {
		required_ipv4
	};
	let policy = build_network_policy(mode, &allowed_ipv4, tools)?;
	std::fs::write(&policy_path, policy)?;

	let resolv_os = resolv_path.as_os_str();
	let resolved_args: Vec<OsString> = bwrap_args
		.iter()
		.map(|arg| {
			if arg == SANDBOX_RESOLV_CONF_PLACEHOLDER {
				resolv_os.to_owned()
			} else {
				arg.to_owned()
			}
		})
		.collect();

	let (info_read, info_write) = inheritable_pipe(true, InheritedEnd::Write)?;
	let (block_read, block_write) = inheritable_pipe(false, InheritedEnd::Read)?;
	let mut sandbox = Command::new(program);
	sandbox
		.args(["--info-fd", &info_write.as_raw_fd().to_string()])
		.args(["--block-fd", &block_read.as_raw_fd().to_string()])
		.args(resolved_args)
		.stdin(Stdio::inherit())
		.stdout(Stdio::inherit())
		.stderr(Stdio::inherit());
	let mut sandbox_child = sandbox.spawn().context("starting Bubblewrap network sandbox")?;
	drop(info_write);
	drop(block_read);

	let setup = (|| -> Result<(Child, OwnedFd)> {
		let child_pid = read_bwrap_pid(&info_read, &mut sandbox_child)?;
		wait_for_userns_mapping(child_pid, &mut sandbox_child, proc_root)?;

		let (ready_read, ready_write) = inheritable_pipe(true, InheritedEnd::Write)?;
		let (exit_read, exit_write) = inheritable_pipe(false, InheritedEnd::Read)?;
		let slirp_log =
			OpenOptions::new().create(true).truncate(true).write(true).open(&slirp_log_path)?;
		let mut slirp = Command::new(&tools.nsenter);
		slirp
			.args(["--target", &child_pid.to_string()])
			.args(["--user", "--user-parent", "--preserve-credentials", "--keep-caps", "--"])
			.arg(&tools.slirp4netns)
			.args([
				"--configure",
				"--mtu=65520",
				"--disable-host-loopback",
				"--enable-sandbox",
				"--enable-seccomp",
			])
			.arg(format!("--ready-fd={}", ready_write.as_raw_fd()))
			.arg(format!("--exit-fd={}", exit_read.as_raw_fd()))
			.arg("--userns-path=/proc/self/ns/user")
			.arg(child_pid.to_string())
			.arg("tap0")
			.stdout(Stdio::from(slirp_log.try_clone()?))
			.stderr(Stdio::from(slirp_log));
		let mut slirp_child = slirp.spawn().context("starting slirp4netns")?;
		drop(ready_write);
		drop(exit_read);

		if let Err(error) = wait_for_ready(&ready_read, &mut slirp_child) {
			terminate(&mut slirp_child);
			return Err(error.context(slirp_diagnostic(&slirp_log_path)));
		}
		drop(ready_read);

		let policy_status = Command::new(&tools.nsenter)
			.args(["--target", &child_pid.to_string()])
			.args(["--user", "--user-parent", "--preserve-credentials", "--keep-caps", "--"])
			.arg(&tools.nsenter)
			.args(["--target", &child_pid.to_string(), "--net", "--"])
			.arg(&tools.nft)
			.arg("-f")
			.arg(&policy_path)
			.status();
		let status = match policy_status {
			Ok(status) => status,
			Err(error) => {
				terminate(&mut slirp_child);
				return Err(anyhow::Error::from(error).context("applying sandbox nftables policy"));
			},
		};
		if !status.success() {
			terminate(&mut slirp_child);
			anyhow::bail!("applying sandbox nftables policy exited with {status}");
		}

		if let Err(error) = write(&block_write, b"x") {
			terminate(&mut slirp_child);
			return Err(anyhow::Error::from(error).context("releasing Bubblewrap network sandbox"));
		}
		Ok((slirp_child, exit_write))
	})();

	let (mut slirp_child, exit_write) = match setup {
		Ok(value) => value,
		Err(error) => {
			terminate(&mut sandbox_child);
			return Err(error);
		},
	};
	drop(block_write);
	let status = sandbox_child.wait().context("waiting for Bubblewrap network sandbox");
	drop(exit_write);
	terminate(&mut slirp_child);
	status
}

#[derive(Clone, Copy)]
enum InheritedEnd {
	Read,
	Write,
}

fn inheritable_pipe(nonblocking: bool, inherited: InheritedEnd) -> Result<(OwnedFd, OwnedFd)> {
	let mut flags = PipeFlags::CLOEXEC;
	if nonblocking {
		flags |= PipeFlags::NONBLOCK;
	}
	let (read_end, write_end) = pipe_with(flags)?;
	match inherited {
		InheritedEnd::Read => fcntl_setfd(&read_end, FdFlags::empty())?,
		InheritedEnd::Write => fcntl_setfd(&write_end, FdFlags::empty())?,
	}
	Ok((read_end, write_end))
}

fn read_bwrap_pid(info: &OwnedFd, child: &mut Child) -> Result<u32> {
	let deadline = Instant::now() + STARTUP_TIMEOUT;
	let mut bytes = Vec::new();
	let mut chunk = [0_u8; 1024];
	loop {
		match read(info, &mut chunk) {
			Ok(0) => {},
			Ok(count) => {
				bytes.extend_from_slice(&chunk[..count]);
				if let Ok(info) = serde_json::from_slice::<BwrapInfo>(&bytes) {
					return Ok(info.child_pid);
				}
			},
			Err(Errno::AGAIN) => {},
			Err(error) => return Err(error.into()),
		}
		if let Some(status) = child.try_wait()? {
			anyhow::bail!("Bubblewrap exited before reporting its child PID: {status}");
		}
		if Instant::now() >= deadline {
			anyhow::bail!("Bubblewrap did not report a child PID within {STARTUP_TIMEOUT:?}");
		}
		thread::sleep(POLL_INTERVAL);
	}
}

fn wait_for_userns_mapping(child_pid: u32, child: &mut Child, proc_root: &Path) -> Result<()> {
	let deadline = Instant::now() + STARTUP_TIMEOUT;
	let uid = rustix::process::geteuid().as_raw();
	let path = proc_root.join(child_pid.to_string()).join("uid_map");
	loop {
		if std::fs::read_to_string(&path).ok().is_some_and(|map| {
			map.lines().any(|line| {
				let mut fields = line.split_whitespace();
				let inside = fields.next().and_then(|value| value.parse::<u32>().ok());
				let outside = fields.next().and_then(|value| value.parse::<u32>().ok());
				inside == Some(uid) && outside == Some(uid)
			})
		}) {
			return Ok(());
		}
		if let Some(status) = child.try_wait()? {
			anyhow::bail!("Bubblewrap exited before its user namespace was ready: {status}");
		}
		if Instant::now() >= deadline {
			anyhow::bail!("Bubblewrap user namespace mapping did not become ready");
		}
		thread::sleep(POLL_INTERVAL);
	}
}

fn wait_for_ready(ready: &OwnedFd, child: &mut Child) -> Result<()> {
	let deadline = Instant::now() + STARTUP_TIMEOUT;
	let mut byte = [0_u8; 1];
	loop {
		match read(ready, &mut byte) {
			Ok(1) => return Ok(()),
			Ok(_) | Err(Errno::AGAIN) => {},
			Err(error) => return Err(error.into()),
		}
		if let Some(status) = child.try_wait()? {
			anyhow::bail!("slirp4netns exited before becoming ready: {status}");
		}
		if Instant::now() >= deadline {
			anyhow::bail!("slirp4netns did not become ready within {STARTUP_TIMEOUT:?}");
		}
		thread::sleep(POLL_INTERVAL);
	}
}

fn terminate(child: &mut Child) {
	let _ = child.kill();
	let _ = child.wait();
}

fn slirp_diagnostic(path: &Path) -> String {
	let text = std::fs::read_to_string(path).unwrap_or_default();
	let excerpt = text.lines().take(20).collect::<Vec<_>>().join("\n");
	if excerpt.is_empty() {
		return "slirp4netns produced no diagnostics".to_owned();
	}
	let mut diagnostic = format!("slirp4netns diagnostics:\n{excerpt}");
	if excerpt.contains("reassociate to namespace") {
		diagnostic.push_str(
			"\nhint: `nsenter --user-parent` needs Bubblewrap to have nested a second user \
			 namespace, which it only does when sandbox setup took privileges it then dropped; \
			 keep `--dev` in the Bubblewrap command",
		);
	}
	diagnostic
}

fn resolve_hosts(hosts: &[String]) -> Result<BTreeSet<Ipv4Addr>> {
	let mut addresses = BTreeSet::new();
	for host in hosts {
		let host = host.trim();
		validate_network_host(host)?;
		if let Ok(address) = host.parse::<Ipv4Addr>() {
			addresses.insert(address);
			continue;
		}
		let resolved: Vec<Ipv4Addr> = (host, 0)
			.to_socket_addrs()
			.with_context(|| format!("resolving sandbox network host `{host}`"))?
			.filter_map(|address| match address {
				SocketAddr::V4(address) => Some(*address.ip()),
				SocketAddr::V6(_) => None,
			})
			.collect();
		if resolved.is_empty() {
			anyhow::bail!("sandbox network host has no IPv4 address: `{host}`");
		}
		addresses.extend(resolved);
	}
	Ok(addresses)
}

fn build_network_policy(
	mode: SandboxNetworkMode, allowed: &BTreeSet<Ipv4Addr>, tools: &NetworkTools,
) -> Result<String> {
	let mut policy = String::new();
	let default_policy = if mode == SandboxNetworkMode::Public { "accept" } else { "drop" };
	policy.push_str("table inet loupe_sandbox {\n\tchain output {\n");
	policy.push_str(&format!(
		"\t\ttype filter hook output priority filter; policy {default_policy};\n"
	));
	policy.push_str("\t\toifname \"lo\" accept\n");
	policy.push_str(&format!("\t\tip daddr {SLIRP_DNS} udp dport 53 accept\n"));
	policy.push_str(&format!("\t\tip daddr {SLIRP_DNS} tcp dport 53 accept\n"));
	policy.push_str("\t\tct state established,related accept\n");
	for address in allowed {
		policy.push_str(&format!("\t\tip daddr {address} accept\n"));
	}
	if mode == SandboxNetworkMode::Public {
		for route in PUBLIC_DENYLIST {
			policy.push_str(&format!("\t\tip daddr {route} reject\n"));
		}
		for route in connected_ipv4_routes(&tools.ip)? {
			policy.push_str(&format!("\t\tip daddr {route} reject\n"));
		}
		for address in host_ipv4_addresses(&tools.ip)? {
			policy.push_str(&format!("\t\tip daddr {address} reject\n"));
		}
		policy.push_str("\t\tip6 daddr ::/0 reject\n");
	} else {
		// `policy drop` on its own blackholes blocked egress, so the agent's
		// connect() hangs until the TCP stack gives up instead of failing.
		// Reject explicitly; the `ct state ... related` rule above is what
		// lets the resulting ICMP error back out to the socket.
		policy.push_str("\t\treject\n");
	}
	policy.push_str("\t}\n}\n");
	Ok(policy)
}

fn connected_ipv4_routes(ip: &Path) -> Result<BTreeSet<String>> {
	let output = command_stdout(ip, &["-o", "-4", "route", "show", "scope", "link"])?;
	Ok(output
		.lines()
		.filter_map(|line| line.split_whitespace().next())
		.filter(|route| valid_ipv4_network(route))
		.map(str::to_owned)
		.collect())
}

fn host_ipv4_addresses(ip: &Path) -> Result<BTreeSet<Ipv4Addr>> {
	let output = command_stdout(ip, &["-o", "-4", "address", "show", "scope", "global"])?;
	Ok(output
		.lines()
		.filter_map(|line| {
			let fields: Vec<&str> = line.split_whitespace().collect();
			let inet = fields.iter().position(|field| *field == "inet")?;
			fields.get(inet + 1)?.split('/').next()?.parse().ok()
		})
		.collect())
}

fn valid_ipv4_network(value: &str) -> bool {
	let Some((address, prefix)) = value.split_once('/') else {
		return value.parse::<Ipv4Addr>().is_ok();
	};
	address.parse::<Ipv4Addr>().is_ok() && prefix.parse::<u8>().is_ok_and(|prefix| prefix <= 32)
}

fn command_stdout(program: &Path, args: &[&str]) -> Result<String> {
	let output = Command::new(program)
		.args(args)
		.output()
		.with_context(|| format!("running {}", program.display()))?;
	if !output.status.success() {
		anyhow::bail!("{} exited with {}", program.display(), output.status);
	}
	String::from_utf8(output.stdout)
		.with_context(|| format!("{} output was not UTF-8", program.display()))
}

fn find_program(name: &str, fallbacks: &[&str]) -> Result<PathBuf> {
	if let Some(path) = std::env::var_os("PATH").and_then(|path| {
		std::env::split_paths(&path).map(|dir| dir.join(name)).find(|path| path.is_file())
	}) {
		return Ok(path);
	}
	for fallback in fallbacks {
		let path = PathBuf::from(fallback);
		if path.is_file() {
			return Ok(path);
		}
	}
	anyhow::bail!("required sandbox network helper not found: {name}")
}

#[cfg(test)]
mod tests {
	use std::fs;
	use std::os::unix::fs::PermissionsExt;
	use std::sync::{Mutex, MutexGuard};

	use rustix::io::fcntl_getfd;

	use super::*;

	fn no_host_routes() -> NetworkTools {
		NetworkTools {
			slirp4netns: PathBuf::from("/bin/true"),
			nsenter: PathBuf::from("/bin/true"),
			nft: PathBuf::from("/bin/true"),
			ip: PathBuf::from("/bin/true"),
		}
	}

	fn write_script(path: &Path, contents: &str) {
		fs::write(path, contents).unwrap();
		let mut permissions = fs::metadata(path).unwrap().permissions();
		permissions.set_mode(0o755);
		fs::set_permissions(path, permissions).unwrap();
	}

	#[test]
	fn host_validation_accepts_ipv4_and_rejects_non_host_syntax() {
		assert_eq!(resolve_hosts(&["203.0.113.9".to_owned()]).unwrap().len(), 1);
		for invalid in ["", "https://example.com", "example.com:443", "*.example.com", "::1"] {
			let error = resolve_hosts(&[invalid.to_owned()]).unwrap_err();
			assert!(error.to_string().contains("sandbox network"), "got: {error:#}");
		}
	}

	#[test]
	fn ipv4_network_validation_is_strict() {
		assert!(valid_ipv4_network("192.0.2.0/24"));
		assert!(valid_ipv4_network("192.0.2.1"));
		assert!(!valid_ipv4_network("default"));
		assert!(!valid_ipv4_network("192.0.2.0/99"));
		assert!(!valid_ipv4_network("2001:db8::/32"));
	}

	#[test]
	fn allowlist_policy_defaults_to_drop_and_keeps_required_addresses() {
		let allowed = ["203.0.113.9".parse().unwrap()].into_iter().collect();
		let policy =
			build_network_policy(SandboxNetworkMode::Allowlist, &allowed, &no_host_routes())
				.unwrap();

		assert!(policy.contains("policy drop"));
		assert!(policy.contains("ip daddr 203.0.113.9 accept"));
		assert!(policy.contains("ip daddr 10.0.2.3 udp dport 53 accept"));
		assert!(!policy.contains("ip daddr 192.168.0.0/16 reject"));
	}

	#[test]
	fn allowlist_policy_rejects_blocked_egress_rather_than_blackholing_it() {
		let allowed = ["203.0.113.9".parse().unwrap()].into_iter().collect();
		let policy =
			build_network_policy(SandboxNetworkMode::Allowlist, &allowed, &no_host_routes())
				.unwrap();

		let terminal_reject = policy
			.find("\n\t\treject\n")
			.unwrap_or_else(|| panic!("allowlist policy needs a terminal reject:\n{policy}"));
		let related = policy.find("ct state established,related accept").unwrap();
		let last_accept = policy.rfind("accept\n").unwrap();
		// The reject has to come last, and the `related` rule has to come
		// before it: that rule is what lets the locally generated ICMP
		// error back out to the socket.
		assert!(related < terminal_reject, "policy: {policy}");
		assert!(last_accept < terminal_reject, "policy: {policy}");
	}

	#[test]
	fn public_policy_has_no_terminal_reject() {
		let policy =
			build_network_policy(SandboxNetworkMode::Public, &BTreeSet::new(), &no_host_routes())
				.unwrap();

		// Public mode's chain policy is `accept`, so an unconditional
		// terminal reject would blackhole every allowed destination.
		assert!(!policy.contains("\n\t\treject\n"), "policy: {policy}");
	}

	#[test]
	fn public_policy_blocks_non_public_ranges_and_ipv6() {
		let required = ["203.0.113.9".parse().unwrap()].into_iter().collect();
		let policy =
			build_network_policy(SandboxNetworkMode::Public, &required, &no_host_routes()).unwrap();

		assert!(policy.contains("policy accept"));
		assert!(policy.contains("ip daddr 203.0.113.9 accept"));
		assert!(policy.contains("ip daddr 192.168.0.0/16 reject"));
		assert!(policy.contains("ip daddr 100.64.0.0/10 reject"));
		assert!(policy.contains("ip6 daddr ::/0 reject"));
	}

	#[test]
	fn only_the_selected_pipe_end_is_inherited() {
		for inherited in [InheritedEnd::Read, InheritedEnd::Write] {
			let (read_end, write_end) = inheritable_pipe(false, inherited).unwrap();
			let read_flags = fcntl_getfd(&read_end).unwrap();
			let write_flags = fcntl_getfd(&write_end).unwrap();
			match inherited {
				InheritedEnd::Read => {
					assert!(!read_flags.contains(FdFlags::CLOEXEC));
					assert!(write_flags.contains(FdFlags::CLOEXEC));
				},
				InheritedEnd::Write => {
					assert!(read_flags.contains(FdFlags::CLOEXEC));
					assert!(!write_flags.contains(FdFlags::CLOEXEC));
				},
			}
		}
	}

	/// Serializes the fake-tool tests. Each one writes helper scripts and
	/// then execs them, and a concurrent `fork` elsewhere in the test
	/// binary can inherit the still-open write descriptor long enough to
	/// make that exec fail with `ETXTBSY`.
	static FAKE_SANDBOX_LOCK: Mutex<()> = Mutex::new(());

	fn fake_sandbox_guard() -> MutexGuard<'static, ()> {
		FAKE_SANDBOX_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
	}

	/// Stand-in for the real helper tools. The scripts record what the
	/// supervisor asked them to do so tests can assert on ordering, the
	/// generated policy, and the arguments handed to Bubblewrap without
	/// needing a TUN device or nested namespace support.
	struct FakeSandbox {
		_tmp: tempfile::TempDir,
		tools: NetworkTools,
		bwrap: PathBuf,
		proc_root: PathBuf,
		log: PathBuf,
		captured_policy: PathBuf,
		captured_args: PathBuf,
		captured_resolv: PathBuf,
	}

	impl FakeSandbox {
		fn new() -> Self {
			Self::build(None)
		}

		/// Harness whose slirp4netns dies with `message` on stderr instead of
		/// signalling readiness.
		fn with_failing_slirp(message: &str) -> Self {
			Self::build(Some(message))
		}

		fn build(slirp_failure: Option<&str>) -> Self {
			let tmp = tempfile::tempdir().unwrap();
			let bin = tmp.path().join("bin");
			let proc_root = tmp.path().join("proc");
			let log = tmp.path().join("events");
			let captured_policy = tmp.path().join("policy.nft");
			let captured_args = tmp.path().join("bwrap-args");
			let captured_resolv = tmp.path().join("resolv.captured");
			fs::create_dir_all(&bin).unwrap();
			fs::create_dir_all(&proc_root).unwrap();

			let uid = rustix::process::geteuid().as_raw();
			let bwrap = bin.join("bwrap");
			write_script(
				&bwrap,
				&format!(
					r#"#!/bin/bash
set -euo pipefail
printf '%s\n' "$@" > "{captured_args}"
while (($#)); do
	case "$1" in
		--info-fd) info_fd="$2"; shift 2 ;;
		--block-fd) block_fd="$2"; shift 2 ;;
		--ro-bind)
			if [[ "$3" == /etc/resolv.conf ]]; then cp "$2" "{captured_resolv}"; fi
			shift 3 ;;
		*) shift ;;
	esac
done
mkdir -p "{proc_root}/$$"
printf '{uid} {uid} 1\n' > "{proc_root}/$$/uid_map"
printf '{{"child-pid":%s}}\n' "$$" >&"$info_fd"
IFS= read -r -N 1 -u "$block_fd"
printf 'released\n' >> "{log}"
"#,
					captured_args = captured_args.display(),
					captured_resolv = captured_resolv.display(),
					proc_root = proc_root.display(),
					log = log.display(),
				),
			);

			let slirp = bin.join("slirp4netns");
			let slirp_body = match slirp_failure {
				Some(message) => format!("printf '%s\\n' {message:?} >&2\nexit 1\n"),
				None => format!(
					"printf x >&\"$ready_fd\"\nprintf 'slirp-ready\\n' >> \"{log}\"\n\
					 cat <&\"$exit_fd\" >/dev/null\n",
					log = log.display(),
				),
			};
			write_script(
				&slirp,
				&format!(
					r#"#!/bin/bash
set -euo pipefail
for arg in "$@"; do
	case "$arg" in
		--ready-fd=*) ready_fd="${{arg#*=}}" ;;
		--exit-fd=*) exit_fd="${{arg#*=}}" ;;
	esac
done
{slirp_body}"#,
				),
			);

			let nsenter = bin.join("nsenter");
			write_script(
				&nsenter,
				r#"#!/bin/bash
set -euo pipefail
while [[ "$1" != "--" ]]; do shift; done
shift
exec "$@"
"#,
			);

			let nft = bin.join("nft");
			write_script(
				&nft,
				&format!(
					r#"#!/bin/bash
set -euo pipefail
cp "$2" "{captured_policy}"
printf 'nft\n' >> "{log}"
"#,
					captured_policy = captured_policy.display(),
					log = log.display(),
				),
			);

			let ip = bin.join("ip");
			write_script(&ip, "#!/bin/sh\nexit 0\n");

			Self {
				tools: NetworkTools { slirp4netns: slirp, nsenter, nft, ip },
				bwrap,
				proc_root,
				log,
				captured_policy,
				captured_args,
				captured_resolv,
				_tmp: tmp,
			}
		}

		/// Run the supervisor over a Bubblewrap command shaped like the one
		/// [`crate::sandbox::SandboxBuilder`] emits, resolver placeholder
		/// included.
		fn run(
			&self, mode: SandboxNetworkMode, required_hosts: Vec<String>, allow_hosts: Vec<String>,
		) -> Result<ExitStatus> {
			let command = vec![
				self.bwrap.clone().into_os_string(),
				OsString::from("--fake-sandbox"),
				OsString::from("--ro-bind"),
				OsString::from(SANDBOX_RESOLV_CONF_PLACEHOLDER),
				OsString::from("/etc/resolv.conf"),
			];
			run_networked_sandbox_with_tools(
				mode,
				required_hosts,
				allow_hosts,
				command,
				&self.tools,
				&self.proc_root,
			)
		}

		fn bwrap_args(&self) -> Vec<String> {
			fs::read_to_string(&self.captured_args).unwrap().lines().map(str::to_owned).collect()
		}
	}

	#[test]
	fn supervisor_starts_networking_before_releasing_bwrap() {
		let _guard = fake_sandbox_guard();
		let fake = FakeSandbox::new();

		let status = fake.run(SandboxNetworkMode::Public, Vec::new(), Vec::new()).unwrap();

		assert!(status.success());
		assert_eq!(fs::read_to_string(&fake.log).unwrap(), "slirp-ready\nnft\nreleased\n");
		assert!(fs::read_to_string(&fake.captured_policy).unwrap().contains("policy accept"));
	}

	#[test]
	fn supervisor_replaces_the_resolver_placeholder_with_the_slirp_forwarder() {
		let _guard = fake_sandbox_guard();
		let fake = FakeSandbox::new();

		let status = fake.run(SandboxNetworkMode::Public, Vec::new(), Vec::new()).unwrap();

		assert!(status.success());
		let args = fake.bwrap_args();
		assert!(
			!args.iter().any(|arg| arg == SANDBOX_RESOLV_CONF_PLACEHOLDER),
			"the placeholder must never reach Bubblewrap: {args:?}",
		);
		// The sandbox only ever sees the generated resolver, so the DNS
		// forwarder address has to survive the substitution intact.
		assert_eq!(
			fs::read_to_string(&fake.captured_resolv).unwrap(),
			format!("nameserver {SLIRP_DNS}\n"),
		);
	}

	#[test]
	fn a_missing_parent_user_namespace_is_explained() {
		let _guard = fake_sandbox_guard();
		// What the real nsenter prints when Bubblewrap did not nest a second
		// user namespace, so `--user-parent` resolves to the supervisor's own
		// namespace and the kernel refuses the re-entry.
		let fake = FakeSandbox::with_failing_slirp(
			"nsenter: reassociate to namespace 'ns/user' failed: Invalid argument",
		);

		let error = fake.run(SandboxNetworkMode::Public, Vec::new(), Vec::new()).unwrap_err();

		let rendered = format!("{error:#}");
		assert!(rendered.contains("--dev"), "the hint must name the flag: {rendered}");
	}
}
