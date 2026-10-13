#![cfg(unix)]

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;
use std::time::Duration;

use loupe_worker::config::SandboxLaunchConfig;
use loupe_worker::sandbox::{SandboxBuilder, SandboxPath, SandboxValue};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn configured_supervisor_preserves_native_operands_stdin_and_eof() {
	// Exercise the real supervisor CLI and bwrap without a host TUN device.
	// Only network helper readiness/setup is scripted; this control makes no
	// claim about applying an actual network firewall or making an external call.
	if std::env::var_os("LOUPE_SUPERVISOR_OPERAND_FIXTURE").is_none() {
		let tools = tempfile::tempdir().unwrap();
		for (name, body) in [
			("slirp4netns", "#!/bin/bash\nset -eu\nfor arg in \"$@\"; do case \"$arg\" in --ready-fd=*) ready_fd=\"${arg#*=}\";; --exit-fd=*) exit_fd=\"${arg#*=}\";; esac; done\nprintf x >&\"$ready_fd\"\ncat <&\"$exit_fd\" >/dev/null\n"),
			("nsenter", "#!/bin/bash\nset -eu\nwhile [[ \"$1\" != -- ]]; do shift; done\nshift\nexec \"$@\"\n"),
			("nft", "#!/bin/sh\nexit 0\n"),
			("ip", "#!/bin/sh\nexit 0\n"),
		] {
			let path = tools.path().join(name);
			std::fs::write(&path, body).unwrap();
			std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
		}
		let path = std::env::join_paths([
			tools.path(),
			std::path::Path::new("/usr/bin"),
			std::path::Path::new("/bin"),
		])
		.unwrap();
		let output = tokio::process::Command::new(std::env::current_exe().unwrap())
			.args([
				"--exact",
				"configured_supervisor_preserves_native_operands_stdin_and_eof",
				"--nocapture",
			])
			.env("LOUPE_SUPERVISOR_OPERAND_FIXTURE", "1")
			.env("PATH", path)
			.output()
			.await
			.unwrap();
		assert!(
			output.status.success(),
			"supervisor fixture failed:\n{}\n{}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr)
		);
		return;
	}
	let directory = tempfile::tempdir().unwrap();
	let config = SandboxLaunchConfig::default();
	let builder = SandboxBuilder::new(SandboxPath::fixture(directory.path().to_owned()), &config)
		.with_network(config.network().clone(), Default::default())
		.with_network_supervisor(SandboxPath::fixture(env!("CARGO_BIN_EXE_loupe-worker").into()));
	let native = OsString::from_vec(b"--native-\xff-operand".to_vec());
	let mut command = builder.build(
		SandboxValue::r#static("/bin/sh"),
		&[
			SandboxValue::r#static("-c"),
			SandboxValue::r#static("cat; printf '%s' \"$1\""),
			SandboxValue::r#static("supervisor-fixture"),
			SandboxValue::path(SandboxPath::fixture(native.into())),
		],
	);
	command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
	let mut child = command.spawn().unwrap();
	let mut input = child.take_stdin().unwrap();
	let output = child.take_stdout().unwrap();
	let errors = child.take_stderr().unwrap();
	let mut stdout = Vec::new();
	let mut stderr = Vec::new();
	let run = tokio::time::timeout(Duration::from_secs(15), async {
		let mut output = output.take(4096);
		let mut errors = errors.take(4096);
		let write = async {
			input.write_all(b"stdin reaches the nested child\n").await?;
			input.shutdown().await?;
			drop(input);
			Ok::<_, std::io::Error>(())
		};
		let (_, _, _, status) = tokio::try_join!(
			write,
			output.read_to_end(&mut stdout),
			errors.read_to_end(&mut stderr),
			child.wait(),
		)?;
		Ok::<_, std::io::Error>(status)
	})
	.await;
	if run.is_err() {
		let _ = child.kill().await;
		let _ = child.wait().await;
	}
	let status = run.expect("network supervisor completion deadline").unwrap();
	assert!(status.success(), "supervisor failed: {}", String::from_utf8_lossy(&stderr));
	assert_eq!(stdout, b"stdin reaches the nested child\n--native-\xff-operand");
}
