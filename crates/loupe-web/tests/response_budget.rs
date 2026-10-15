mod support;
use loupe_proto::{PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use reqwest::StatusCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BUDGET: usize = 16 * 1024 * 1024;

async fn response(status: &str, body: &str, padding: usize) -> reqwest::Url {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let headers = format!("HTTP/1.1 {status}\r\n{PROTOCOL_VERSION_HEADER}: {PROTOCOL_VERSION}\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n");
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
async fn web_rejects_chunked_json_one_byte_over_budget() {
	let base = response("200 OK", "{}", BUDGET - 1).await;
	let client = support::client(reqwest::Client::new(), base);
	let (status, body) = support::health(client).await;
	assert_eq!(
		status,
		StatusCode::BAD_GATEWAY,
		"web accepted valid chunked JSON exceeding response budget"
	);
	assert!(body.unwrap()["error"].as_str().unwrap().contains("response body exceeds"));
}

#[tokio::test]
async fn web_accepts_chunked_json_exactly_at_budget() {
	let base = response("200 OK", "{}", BUDGET - 2).await;
	let client = support::client(reqwest::Client::new(), base);
	assert_eq!(support::health(client).await, (StatusCode::OK, Some(serde_json::json!({}))));
}

#[tokio::test]
async fn web_error_body_is_bounded_and_keeps_status() {
	let base = response("409 Conflict", "diagnostic", BUDGET).await;
	let client = support::client(reqwest::Client::new(), base);
	let (status, body) = support::health(client).await;
	assert_eq!(status, StatusCode::CONFLICT);
	let body = body.unwrap();
	let error = body["error"].as_str().unwrap();
	assert!(error.contains("response body exceeds"));
	assert!(error.len() < 512);
	assert!(!error.contains("diagnostic"));
}

#[tokio::test]
async fn web_error_retains_short_diagnostic() {
	let base = response("409 Conflict", "diagnostic", 0).await;
	let client = support::client(reqwest::Client::new(), base);
	let (status, body) = support::health(client).await;
	assert_eq!(status, StatusCode::CONFLICT);
	assert_eq!(body.unwrap()["error"], "diagnostic");
}

#[tokio::test]
async fn web_no_content_is_empty_success() {
	let base = response("204 No Content", "", 0).await;
	let client = support::client(reqwest::Client::new(), base);
	assert_eq!(support::health(client).await, (StatusCode::NO_CONTENT, None));
}
