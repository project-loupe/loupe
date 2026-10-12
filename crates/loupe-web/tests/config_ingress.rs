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
fn supplied_values_keep_defaults_zero_poll_and_native_paths() {
	use std::os::unix::ffi::OsStringExt;
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join(std::ffi::OsString::from_vec(b"native-\xff".to_vec()));
	std::fs::write(&path, "FILE_TLS").unwrap();
	let cli = Cli::try_parse_from([
		std::ffi::OsStr::new("loupe-web"),
		std::ffi::OsStr::new("--ca-cert"),
		path.as_os_str(),
		std::ffi::OsStr::new("--poll-seconds"),
		std::ffi::OsStr::new("0"),
		std::ffi::OsStr::new("--server-url"),
		std::ffi::OsStr::new("http://localhost:8443/path"),
	])
	.unwrap();
	assert_eq!(cli.bind, "127.0.0.1:8455".parse().unwrap());
	assert_eq!(cli.poll_seconds, 0);
	assert_eq!(cli.conn.ca_cert.as_ref(), Some(&path));
	assert_eq!(cli.conn.ca_pem().unwrap().expose(), "FILE_TLS");
	assert_eq!(cli.conn.server_url().unwrap().as_str(), "http://localhost:8443/path");
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
#[test]
fn actual_clap_child_environment_precedence() {
	const CHILD: &str = "LOUPE_WEB_INGRESS_TEST_CHILD";
	if std::env::var_os(CHILD).is_some() {
		let cli = Cli::try_parse_from([
			"loupe-web",
			"--server-url",
			"http://flag.invalid/",
			"--ca-cert-pem",
			"FLAG_RAW",
			"--poll-seconds",
			"0",
		])
		.unwrap();
		assert_eq!(cli.conn.server_url().unwrap().as_str(), "http://flag.invalid/");
		assert_eq!(cli.conn.ca_pem().unwrap().expose(), "FLAG_RAW");
		assert_eq!(cli.conn.admin_cert_pem().unwrap().expose(), "ENV_CERT");
		assert_eq!(cli.poll_seconds, 0);
		return;
	}
	let output = std::process::Command::new(std::env::current_exe().unwrap())
		.env_clear()
		.env(CHILD, "1")
		.env("LOUPE_SERVER_URL", "http://env.invalid/")
		.env("LOUPE_CA_CERT_PEM", "ENV_RAW")
		.env("LOUPE_ADMIN_CERT_PEM", "ENV_CERT")
		.env("LOUPE_WEB_POLL_SECONDS", "17")
		.args(["--exact", "actual_clap_child_environment_precedence", "--nocapture"])
		.output()
		.unwrap();
	assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}
