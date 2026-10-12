//! Exercise the executable's human output, including sinks outside detail view.

use std::process::Output;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PAYLOAD: &str = "visible-é\u{1b}[2J\r\u{85}\t\nforged-row";

async fn command(args: &[&str], status: &str, body: String) -> Output {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let address = listener.local_addr().unwrap();
	let response = format!(
		"HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
		body.len()
	);
	let server = tokio::spawn(async move {
		let (mut socket, _) = listener.accept().await.unwrap();
		let mut request = [0; 4096];
		let count = socket.read(&mut request).await.unwrap();
		assert!(count > 0, "CLI closed the socket without a request");
		socket.write_all(response.as_bytes()).await.unwrap();
	});
	let ca = loupe_tls::Ca::new("terminal-test").unwrap();
	let client = ca.mint_client("admin").unwrap();
	let output = tokio::time::timeout(
		Duration::from_secs(10),
		tokio::process::Command::new(env!("CARGO_BIN_EXE_loupectl"))
			.kill_on_drop(true)
			.env_clear()
			.env("LOUPE_SERVER_URL", format!("http://{address}"))
			.env("LOUPE_CA_CERT_PEM", ca.cert_pem())
			.env("LOUPE_ADMIN_CERT_PEM", client.cert_pem)
			.env("LOUPE_ADMIN_KEY_PEM", client.key_pem.expose())
			.env("NO_COLOR", "1")
			.args(args)
			.output(),
	)
	.await
	.expect("CLI timed out")
	.unwrap();
	server.await.unwrap();
	output
}

fn assert_rejected(output: &Output) {
	assert!(
		!output.status.success(),
		"new single-line ingress policy must reject the original terminal payload"
	);
	assert!(output.stdout.is_empty());
	let error = String::from_utf8_lossy(&output.stderr);
	assert!(error.contains("server response violates schema or field policy"));
	assert!(!error.contains("visible-é"));
}

fn findings() -> String {
	json!({"protocol_version": 2, "findings": [{
		"id": 1, "repo_id": 2, "job_id": 3, "scanner_id": PAYLOAD,
		"severity": "high", "title": PAYLOAD, "file_path": PAYLOAD,
		"line_start": 1, "fingerprint": "fixture", "state": "confirmed",
		"verification_required": false, "created_at": 0
	}]})
	.to_string()
}

#[tokio::test]
async fn finding_list_rejects_forbidden_typed_fields() {
	let output = command(&["finding", "list", "2"], "200 OK", findings()).await;
	assert_rejected(&output);
}

#[tokio::test]
async fn finding_search_rejects_forbidden_typed_fields() {
	let output = command(&["finding", "search", "2", "query"], "200 OK", findings()).await;
	assert_rejected(&output);
}

#[tokio::test]
async fn repository_listing_rejects_forbidden_typed_fields() {
	let body = json!({"protocol_version": 2, "repos": [{
		"id": 1, "clone_url": "https://example.test/repo", "host": PAYLOAD,
		"owner": PAYLOAD, "repo": PAYLOAD, "verification_enabled": false,
		"created_at": 0, "reporting": {"kind": "email", "to": [PAYLOAD]}
	}]})
	.to_string();
	let output = command(&["repo", "list"], "200 OK", body).await;
	assert_rejected(&output);
}

#[tokio::test]
async fn github_app_slug_rejects_forbidden_typed_fields() {
	let body = json!({"protocol_version": 2, "app": {"app_id": 1, "slug": PAYLOAD}}).to_string();
	let output = command(&["github-app", "show"], "200 OK", body).await;
	assert_rejected(&output);
}
