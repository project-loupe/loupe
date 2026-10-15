use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use loupe_storage::secrets::MasterKey;
use rusqlite::Connection;

fn server(key: &MasterKey) -> Command {
	let mut command = Command::new(env!("CARGO_BIN_EXE_loupe-server"));
	command
		.env_clear()
		.env("LOUPE_MASTER_KEY", key.to_hex().expose())
		.env("LOUPE_LOG_JSON", "1")
		.env("RUST_LOG", "info");
	command
}

fn output_text(output: &Output) -> String {
	format!(
		"{}\n{}",
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr)
	)
}

fn run(command: &mut Command) -> Output {
	let mut child = command.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
	let deadline = Instant::now() + Duration::from_secs(30);
	while child.try_wait().unwrap().is_none() {
		if Instant::now() >= deadline {
			child.kill().unwrap();
			let output = child.wait_with_output().unwrap();
			panic!("server command did not exit within 30 seconds: {}", output_text(&output));
		}
		std::thread::sleep(Duration::from_millis(10));
	}
	child.wait_with_output().unwrap()
}

#[test]
fn migration_failure_is_logged_with_safe_actionable_context() {
	let canary = "PRIVATE_UNKNOWN_JOB_KIND_7ac5";
	for newer_schema in [false, true] {
		let directory = tempfile::tempdir().unwrap();
		let key = MasterKey::for_tests();
		let output = run(server(&key).args(["init", "--data-dir"]).arg(directory.path()));
		assert!(output.status.success(), "{}", output_text(&output));

		let db_path = directory.path().join("loupe.sqlite");
		let connection = Connection::open(&db_path).unwrap();
		let raw_key = loupe_provenance::Secret::new(format!("x'{}'", key.to_hex().expose()));
		connection.pragma_update(None, "key", raw_key.expose()).unwrap();
		if newer_schema {
			connection.execute("UPDATE schema_meta SET version=999", []).unwrap();
		} else {
			connection.pragma_update(None, "foreign_keys", false).unwrap();
			connection
				.execute_batch(
					"INSERT INTO registered_repos
					 (id, clone_url, host, owner, repo, reporting, created_at)
					 VALUES (1, 'https://github.com/a/b', 'github.com', 'a', 'b',
					         '{\"kind\":\"manual\"}', 1);",
				)
				.unwrap();
			connection
				.execute(
					"INSERT INTO jobs (id, repo_id, kind, state, enqueued_at)
					 VALUES (17, 1, ?1, 'failed', 1)",
					[canary],
				)
				.unwrap();
		}
		drop(connection);

		let mut command = server(&key);
		command.args(["serve", "--bind", "127.0.0.1:0", "--db"]).arg(&db_path);
		for (flag, file) in [
			("--server-cert", "server.pem"),
			("--server-key", "server.key"),
			("--ca-cert", "ca.pem"),
			("--ca-key", "ca.key"),
		] {
			command.arg(flag).arg(directory.path().join(file));
		}
		let output = run(&mut command);
		assert!(!output.status.success(), "invalid database must refuse startup");
		let text = output_text(&output);
		assert!(!text.contains(canary), "startup diagnostics must omit stored content");
		assert!(!text.contains(key.to_hex().expose()), "startup diagnostics must omit keys");
		let event = text
			.lines()
			.filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
			.find(|event| event["fields"]["message"] == "loupe-server: database upgrade failed")
			.expect("migration failure must emit a structured startup error log");
		assert_eq!(event["level"], "ERROR");
		let diagnostic = event["fields"]["error"].as_str().unwrap();
		if newer_schema {
			assert!(diagnostic.contains("schema 999"));
			assert!(diagnostic.contains("NewerSchema"));
			assert!(diagnostic.contains("use a newer binary"));
		} else {
			for expected in ["UnknownJobKind", "table=jobs", "column=kind", "rowid=17"] {
				assert!(diagnostic.contains(expected), "missing {expected}: {diagnostic}");
			}
		}
	}
}
