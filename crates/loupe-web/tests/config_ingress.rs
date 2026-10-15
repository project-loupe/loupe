//! Actual configuration compatibility and fixed-error boundaries.
use clap::Parser;
use loupe_web::Cli;

#[test]
fn missing_native_file_diagnostic_does_not_retain_path() {
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("FAKE_CONFIG_PATH_SENTINEL");
	let cli = Cli::try_parse_from([
		std::ffi::OsStr::new("loupe-web"),
		std::ffi::OsStr::new("--admin-key"),
		path.as_os_str(),
	])
	.unwrap();
	let error = cli.conn.admin_key_pem().unwrap_err();
	let mut rendered =
		vec![format!("{error}"), format!("{error:#}"), format!("{error:?}"), format!("{error:#?}")];
	for cause in error.chain() {
		rendered.push(cause.to_string());
	}
	assert!(
		rendered.iter().all(|s| !s.contains("FAKE_CONFIG_PATH_SENTINEL")),
		"Config file error retains original path: {rendered:?}"
	);
}
#[test]
fn actual_process_refuses_routable_bind_before_selected_invalid_credentials() {
	let output = std::process::Command::new(env!("CARGO_BIN_EXE_loupe-web"))
		.env_clear()
		.args([
			"--bind",
			"0.0.0.0:8455",
			"--server-url",
			"http://127.0.0.1:1/",
			"--admin-key-pem-b64",
			"INVALID_B64_SENTINEL%%%",
		])
		.output()
		.unwrap();
	assert!(!output.status.success());
	let error = String::from_utf8(output.stderr).unwrap();
	assert!(error.contains("refusing to bind"));
	assert!(!error.contains("INVALID_B64_SENTINEL"));
	assert!(!error.contains("decoding") && !error.contains("upstream"));
}
