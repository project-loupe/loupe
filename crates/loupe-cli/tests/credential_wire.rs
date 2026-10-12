//! Real loupectl requests preserve credential JSON and content type.

use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn capture(args: &[&str], credential: Option<&str>, response: &str) -> (String, Value) {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let response = response.to_owned();
	let server = tokio::spawn(async move {
		let (mut socket, _) = listener.accept().await.unwrap();
		let mut request = Vec::new();
		let (end, len) = loop {
			let mut chunk = [0; 1024];
			let count = socket.read(&mut chunk).await.unwrap();
			assert!(count > 0);
			request.extend_from_slice(&chunk[..count]);
			if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
				let headers = std::str::from_utf8(&request[..end]).unwrap().to_lowercase();
				let len = headers
					.lines()
					.find_map(|line| line.strip_prefix("content-length: "))
					.unwrap()
					.parse::<usize>()
					.unwrap();
				break (end + 4, len);
			}
		};
		while request.len() < end + len {
			let mut chunk = [0; 1024];
			let count = socket.read(&mut chunk).await.unwrap();
			assert!(count > 0);
			request.extend_from_slice(&chunk[..count]);
		}
		socket.write_all(response.as_bytes()).await.unwrap();
		(
			String::from_utf8(request[..end].to_vec()).unwrap(),
			serde_json::from_slice(&request[end..end + len]).unwrap(),
		)
	});
	let ca = loupe_tls::Ca::new("credential-wire-test").unwrap();
	let admin = ca.mint_client("admin").unwrap();
	let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_loupectl"));
	command
		.kill_on_drop(true)
		.env_clear()
		.args(args)
		.env("LOUPE_SERVER_URL", format!("http://{addr}"))
		.env("LOUPE_CA_CERT_PEM", ca.cert_pem())
		.env("LOUPE_ADMIN_CERT_PEM", admin.cert_pem)
		.env("LOUPE_ADMIN_KEY_PEM", admin.key_pem.expose());
	if let Some(credential) = credential {
		command.env("LOUPE_TRACKER_PAT", credential).env("LOUPE_GITHUB_APP_KEY_PEM", credential);
	}
	let output =
		tokio::time::timeout(Duration::from_secs(10), command.output()).await.unwrap().unwrap();
	if !output.status.success() {
		server.abort();
		panic!("loupectl failed: {}", String::from_utf8_lossy(&output.stderr));
	}
	tokio::time::timeout(Duration::from_secs(10), server).await.unwrap().unwrap()
}

#[tokio::test]
async fn actual_credential_commands_preserve_wire_contracts() {
	const SECRET: &str = "FAKE_CLI_WIRE_\"\\\n\r\té秘密";
	const EMPTY: &str = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
	let repo_body = r#"{"protocol_version":2,"repo_id":42}"#;
	let repo_response = format!(
		"HTTP/1.1 201 Created\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
		repo_body.len(),
		repo_body
	);
	for (args, method_path, response, expected) in [
		(
			vec!["github-app", "set", "--app-id", "42"],
			"PUT /v1/github-app",
			EMPTY,
			json!({"protocol_version":2,"app_id":42,"private_key_pem":SECRET}),
		),
		(
			vec!["repo", "rotate-pat", "7"],
			"POST /v1/repos/7/reporting/github-pat",
			EMPTY,
			json!({"protocol_version":2,"github_pat":SECRET}),
		),
		(
			vec![
				"repo",
				"set-github-reporting",
				"7",
				"--target-owner",
				"acme",
				"--target-repo",
				"issues",
			],
			"PUT /v1/repos/7/reporting/github",
			EMPTY,
			json!({"protocol_version":2,"target_owner":"acme","target_repo":"issues","github_pat":SECRET}),
		),
		(
			vec![
				"repo",
				"add",
				"--clone-url",
				"local",
				"--target-owner",
				"acme",
				"--target-repo",
				"issues",
			],
			"POST /v1/repos",
			repo_response.as_str(),
			json!({"protocol_version":2,"clone_url":"local","reporting":{"kind":"github_issue","target_owner":"acme","target_repo":"issues","github_pat":SECRET}}),
		),
	] {
		let (headers, body) = capture(&args, Some(SECRET), response).await;
		assert!(headers.starts_with(&format!("{method_path} HTTP/1.1\r\n")));
		let headers = headers.to_lowercase();
		assert!(headers.contains("\r\ncontent-type: application/json\r\n"));
		// loupectl currently carries the version in its DTO body, without
		// a separate header. Preserve that behavior at this ownership boundary.
		assert_eq!(body, expected);
	}
	let (_, body) = capture(
		&["repo", "set-github-reporting", "7", "--target-owner", "acme", "--target-repo", "issues"],
		None,
		EMPTY,
	)
	.await;
	assert_eq!(body, json!({"protocol_version":2,"target_owner":"acme","target_repo":"issues"}));
}
