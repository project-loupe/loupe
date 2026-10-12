//! Raw JSON config projects a SandboxBuilder into argv without spawning it.
//! Values resembling flags are compared in their operand positions, not counted
//! as option tokens. Both the supervisor and bwrap `--` are part of the oracle.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use clap::builder::TypedValueParser;
use loupe_worker::sandbox::{SandboxBuilder, SandboxNetworkConfig, SandboxNetworkMode};
use serde::Deserialize;

use crate::utils::test_logger;

#[derive(Default, Deserialize)]
#[serde(default)]
struct Input {
	workdir: String,
	program: String,
	args: Vec<String>,
	env: Vec<(u8, String)>,
	binds: Vec<(String, String)>,
	network: u8,
	required: Vec<String>,
	hosts: Vec<String>,
	binary_name: String,
	symlink: bool,
}

pub fn do_test(data: &[u8]) {
	if data.len() > 64 * 1024 {
		return;
	}
	let Ok(input) = serde_json::from_slice::<Input>(data) else { return };
	let mut builder = SandboxBuilder::new(&input.workdir);
	let mut expected: Vec<OsString> = Vec::new();
	let network = input.network % 3;
	if network != 0 {
		let mode =
			if network == 1 { SandboxNetworkMode::Allowlist } else { SandboxNetworkMode::Public };
		let allowlist =
			input
				.hosts
				.iter()
				.take(16)
				.map(|host| {
					let admitted = loupe_worker::config_value_parsers::ConfiguredTextParser
						.parse_ref(&clap::Command::new("sandbox-fixture"), None, host.as_ref());
					assert_eq!(
						admitted.is_ok(),
						crate::worker_client_ingress::oracle::text(host, false),
						"actual Config host argument admission differs"
					);
					admitted.ok()
				})
				.collect::<Option<Vec<_>>>();
		let Some(allowlist) = allowlist else { return };
		builder = builder
			.with_network(
				SandboxNetworkConfig { mode, allowlist },
				input.required.iter().take(16).cloned().collect(),
			)
			.with_network_supervisor("/trusted/worker");
		add(&mut expected, &["/trusted/worker", "sandbox-exec", "--network", mode.as_str()]);
		for host in input.required.iter().take(16) {
			add(&mut expected, &["--required-host", host]);
		}
		for host in input.hosts.iter().take(16) {
			add(&mut expected, &["--allow-host", host]);
		}
		add(&mut expected, &["--", "bwrap"]);
	} else {
		add(&mut expected, &["bwrap"]);
	}
	add(
		&mut expected,
		&[
			"--die-with-parent",
			"--new-session",
			"--clearenv",
			"--unshare-user",
			"--unshare-net",
			"--unshare-pid",
			"--unshare-ipc",
			"--unshare-uts",
		],
	);
	for path in ["/usr", "/lib", "/lib64", "/bin", "/sbin"] {
		if Path::new(path).exists() {
			add(&mut expected, &["--ro-bind-try", path, path]);
		}
	}
	add(&mut expected, &["--dir", "/etc"]);
	for path in ["/etc/ld.so.cache", "/etc/passwd", "/etc/group", "/etc/nsswitch.conf"] {
		system_bind(&mut expected, path);
	}
	if network != 0 {
		for path in [
			"/etc/hosts",
			"/etc/ssl/certs",
			"/etc/ssl/cert.pem",
			"/etc/ca-certificates/extracted",
			"/etc/pki/ca-trust/extracted",
			"/etc/pki/tls/certs",
			"/etc/pki/tls/cert.pem",
		] {
			system_bind(&mut expected, path);
		}
		add(&mut expected, &["--ro-bind", "@LOUPE_RESOLV_CONF@", "/etc/resolv.conf"]);
	}
	let path = std::env::var("PATH")
		.unwrap_or_else(|_| "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
	add(
		&mut expected,
		&[
			"--proc",
			"/proc",
			"--dev",
			"/dev",
			"--tmpfs",
			"/tmp",
			"--tmpfs",
			"/home/scanner",
			"--setenv",
			"HOME",
			"/home/scanner",
			"--setenv",
			"TMPDIR",
			"/tmp",
			"--setenv",
			"PATH",
			&path,
		],
	);
	for (source, destination) in input.binds.iter().take(16) {
		builder = builder.bind_ro(source, destination);
		add(&mut expected, &["--ro-bind-try", source, destination]);
	}
	let fixture = tempfile::tempdir().unwrap_or_else(|_| panic!("create sandbox argv fixture"));
	if !input.binary_name.is_empty()
		&& input.binary_name.len() <= 32
		&& input
			.binary_name
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
	{
		// Keep the fuzz-named entrypoint separate from the package installation:
		// even a binary named node_modules must have an unoccupied entry path.
		let bin_dir = fixture.path().join("bin");
		std::fs::create_dir(&bin_dir)
			.unwrap_or_else(|_| panic!("create binary entrypoint directory"));
		let entry = bin_dir.join(&input.binary_name);
		let (entry_bind, install) = if input.symlink {
			let node_modules = fixture.path().join("node_modules");
			let binary = node_modules.join("package/bin/tool.js");
			std::fs::create_dir_all(binary.parent().unwrap_or(fixture.path()))
				.unwrap_or_else(|_| panic!("create binary fixture directory"));
			std::fs::write(&binary, b"fixture").unwrap_or_else(|_| panic!("write binary fixture"));
			std::os::unix::fs::symlink(binary, &entry)
				.unwrap_or_else(|_| panic!("create binary symlink"));
			(bin_dir, node_modules)
		} else {
			std::fs::write(&entry, b"fixture").unwrap_or_else(|_| panic!("write binary fixture"));
			(entry.clone(), bin_dir)
		};
		builder = builder
			.allow_binary(&entry.to_string_lossy())
			.unwrap_or_else(|_| panic!("allow fixture binary"));
		for bind in [entry_bind, install] {
			expected.extend([
				OsString::from("--ro-bind-try"),
				bind.as_os_str().to_owned(),
				bind.into_os_string(),
			]);
		}
	}
	add(&mut expected, &["--ro-bind", &input.workdir, "/workdir", "--chdir", "/home/scanner"]);
	const NAMES: [&str; 4] = ["FUZZ_VALUE", "HOME", "TMPDIR", "PATH"];
	for (index, value) in input.env.iter().take(16) {
		let name = NAMES[usize::from(*index) % NAMES.len()];
		builder = builder.set_env(name, value);
		add(&mut expected, &["--setenv", name, value]);
	}
	add(&mut expected, &["--", &input.program]);
	expected.extend(input.args.iter().take(16).map(OsString::from));
	let command =
		builder.build_with_args(&input.program, input.args.iter().take(16).map(String::as_str));
	let actual: Vec<_> = std::iter::once(command.as_std().get_program())
		.chain(command.as_std().get_args())
		.map(OsString::from)
		.collect();
	// std::process::Command marks a NUL-containing operand as invalid and
	// exposes this placeholder via get_args(); it would refuse to spawn.
	// Compare the projected representation without starting the command.
	for value in &mut expected {
		if value.as_encoded_bytes().contains(&0) {
			*value = "<string-with-nul>".into();
		}
	}
	assert_eq!(actual, expected, "sandbox argv differs from golden option/operand sequence");
	assert_eq!(
		command.as_std().get_envs().collect::<Vec<_>>(),
		vec![(std::ffi::OsStr::new("PATH"), Some(std::ffi::OsStr::new(&path)))]
	);
}

fn add(output: &mut Vec<OsString>, values: &[&str]) {
	output.extend(values.iter().map(OsString::from));
}
fn system_bind(output: &mut Vec<OsString>, destination: &str) {
	if let Ok(source) = std::fs::canonicalize(destination) {
		output.extend([
			OsString::from("--ro-bind"),
			source.into_os_string(),
			PathBuf::from(destination).into_os_string(),
		]);
	}
}

pub fn worker_sandbox_args_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_sandbox_args_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
