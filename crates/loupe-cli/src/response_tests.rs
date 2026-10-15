use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

const BUDGET: usize = 16 * 1024 * 1024;

async fn response(status: &str, body: &str, padding: usize) -> reqwest::Url {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let headers =
		format!("HTTP/1.1 {status}\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n");
	let body = body.to_owned();
	tokio::spawn(async move {
		let (mut socket, _) = listener.accept().await.unwrap();
		let mut request = [0; 4096];
		let _ = socket.read(&mut request).await.unwrap();
		let first = format!("{headers}{:x}\r\n{body}\r\n", body.len());
		if socket.write_all(first.as_bytes()).await.is_err() {
			return;
		}
		let spaces = [b' '; 8192];
		let mut remaining = padding;
		while remaining > 0 {
			let count = remaining.min(spaces.len());
			if socket.write_all(format!("{count:x}\r\n").as_bytes()).await.is_err()
				|| socket.write_all(&spaces[..count]).await.is_err()
				|| socket.write_all(b"\r\n").await.is_err()
			{
				return;
			}
			remaining -= count;
		}
		let _ = socket.write_all(b"0\r\n\r\n").await;
	});
	reqwest::Url::parse(&format!("http://{addr}/")).unwrap()
}

#[tokio::test]
async fn cli_rejects_chunked_json_one_byte_over_budget() {
	let base = response("200 OK", "[]", BUDGET - 1).await;
	let result = job_list(&reqwest::Client::new(), &base, None).await;
	assert!(result.is_err(), "CLI accepted valid chunked JSON exceeding response budget");
	assert!(format!("{:#}", result.unwrap_err()).contains("response body exceeds"));
}

#[tokio::test]
async fn cli_accepts_chunked_json_exactly_at_budget() {
	let base = response("200 OK", "[]", BUDGET - 2).await;
	job_list(&reqwest::Client::new(), &base, None).await.unwrap();
}

#[tokio::test]
async fn cli_error_body_is_bounded() {
	let base = response("409 Conflict", "diagnostic", BUDGET).await;
	let error = finding_approve(&reqwest::Client::new(), &base, 1).await.unwrap_err();
	let message = format!("{error:#}");
	assert!(message.contains("409 Conflict"));
	assert!(message.contains("response body exceeds"));
	assert!(message.len() < 512);
	assert!(!message.contains("diagnostic"));
}

#[tokio::test]
async fn cli_error_retains_short_diagnostic() {
	let base = response("409 Conflict", "diagnostic", 0).await;
	let error = finding_approve(&reqwest::Client::new(), &base, 1).await.unwrap_err();
	let message = format!("{error:#}");
	assert!(message.contains("409 Conflict"));
	assert!(message.contains("diagnostic"));
}

#[tokio::test]
async fn cli_no_content_is_empty_success() {
	let base = response("204 No Content", "", 0).await;
	finding_approve(&reqwest::Client::new(), &base, 1).await.unwrap();
}
