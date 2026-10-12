//! Transport budget regressions exercise the public client against real HTTP.

use loupe_proto::{JobCapability, PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use loupe_worker::ServerClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Kept literal so this regression also compiles against the pre-budget client.
const BUDGET: usize = 16 * 1024 * 1024;

async fn chunked_response(status: &str, prefix: &[u8], length: usize) -> reqwest::Url {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let headers = format!(
		"HTTP/1.1 {status}\r\n{PROTOCOL_VERSION_HEADER}: {PROTOCOL_VERSION}\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n"
	);
	let prefix = prefix.to_vec();
	tokio::spawn(async move {
		let (mut socket, _) = listener.accept().await.unwrap();
		let mut request = [0; 4096];
		let _ = socket.read(&mut request).await.unwrap();
		if socket.write_all(headers.as_bytes()).await.is_err() {
			return;
		}
		let mut sent = 0;
		while sent < length {
			let size = (length - sent).min(8192);
			let mut chunk = vec![b' '; size];
			let prefix_end = prefix.len().min(sent + size);
			if sent < prefix_end {
				chunk[..prefix_end - sent].copy_from_slice(&prefix[sent..prefix_end]);
			}
			if socket.write_all(format!("{size:x}\r\n").as_bytes()).await.is_err()
				|| socket.write_all(&chunk).await.is_err()
				|| socket.write_all(b"\r\n").await.is_err()
			{
				return;
			}
			sent += size;
		}
		let _ = socket.write_all(b"0\r\n\r\n").await;
	});
	reqwest::Url::parse(&format!("http://{addr}/")).unwrap()
}

#[tokio::test]
async fn worker_rejects_chunked_json_one_byte_over_budget() {
	let body = format!(r#"{{"protocol_version":{PROTOCOL_VERSION},"lease_expires_at":42}}"#);
	let base = chunked_response("200 OK", body.as_bytes(), BUDGET + 1).await;
	let client = ServerClient::from_parts(reqwest::Client::new(), base);
	let result = client.heartbeat(1, &JobCapability::from_secret("test")).await;
	assert!(result.is_err(), "worker accepted valid chunked JSON exceeding response budget");
	let error = format!("{:#}", result.unwrap_err());
	assert!(error.contains("response body exceeds"), "unexpected error: {error}");
}

#[tokio::test]
async fn worker_accepts_chunked_json_exactly_at_budget() {
	let body = format!(r#"{{"protocol_version":{PROTOCOL_VERSION},"lease_expires_at":42}}"#);
	let base = chunked_response("200 OK", body.as_bytes(), BUDGET).await;
	let client = ServerClient::from_parts(reqwest::Client::new(), base);
	assert_eq!(
		client.heartbeat(1, &JobCapability::from_secret("test")).await.unwrap().lease_expires_at,
		42
	);
}

#[tokio::test]
async fn worker_error_body_is_bounded() {
	let base = chunked_response("409 Conflict", b"private server diagnostic", BUDGET + 1).await;
	let client = ServerClient::from_parts(reqwest::Client::new(), base);
	let error = client.heartbeat(1, &JobCapability::from_secret("test")).await.unwrap_err();
	let message = format!("{error:#}");
	assert!(message.len() < 512, "oversized server error was retained");
	assert!(message.contains("409 Conflict"));
	assert!(message.contains("response body exceeds"));
	assert!(!message.contains("private server diagnostic"));
}

#[tokio::test]
async fn worker_no_content_is_empty_success() {
	let base = chunked_response("204 No Content", b"", 0).await;
	let client = ServerClient::from_parts(reqwest::Client::new(), base);
	client
		.complete(
			1,
			&JobCapability::from_secret("test"),
			&loupe_proto::CompleteRequest {
				protocol_version: PROTOCOL_VERSION,
				outcome: loupe_proto::CompleteOutcome::Succeeded,
				head_sha: None,
				error: None,
			},
		)
		.await
		.unwrap();
}

#[tokio::test]
async fn conservative_escaped_finding_fixture_fits_budget() {
	let description = "a".repeat(16_384);
	let diff = "a".repeat(262_144);
	let mut body = serde_json::to_string(&serde_json::json!({
		"protocol_version": PROTOCOL_VERSION,
		"id": 1, "repo_id": 1, "job_id": 1,
		"scanner_id": "scanner", "severity": "high", "title": "example",
		"description": description, "poc_unified": diff, "patch_unified": diff,
		"fingerprint": "abc", "state": "validating",
		"verification_required": true, "created_at": 42,
	}))
	.unwrap();
	// Preserve the original six-byte escaping stress while using admitted text.
	// serde_json would otherwise serialize these letters as one byte each.
	body = body.replace(&format!("\"{diff}\""), &format!("\"{}\"", "\\u0061".repeat(diff.len())));
	body = body.replace(
		&format!("\"{description}\""),
		&format!("\"{}\"", "\\u0061".repeat(description.len())),
	);
	assert!(body.len() > 3_244_032, "fixture includes escaped fields and metadata");
	assert!(body.len() < BUDGET);
	let base = chunked_response("200 OK", body.as_bytes(), body.len()).await;
	let client = ServerClient::from_parts(reqwest::Client::new(), base);
	let finding = client.get_finding(1, &JobCapability::from_secret("test")).await.unwrap();
	assert_eq!(finding.description, description);
	assert_eq!(finding.poc_unified.as_deref(), Some(diff.as_str()));
	assert_eq!(finding.patch_unified.as_deref(), Some(diff.as_str()));
}

#[tokio::test]
async fn all_worker_response_paths_reject_malformed_dtos() {
	let capability = JobCapability::from_secret("test");
	for route in 0..4 {
		let base = chunked_response("200 OK", b"{}", 2).await;
		let client = ServerClient::from_parts(reqwest::Client::new(), base);
		let result = match route {
			0 => client.lease(Vec::new(), 0).await.map(|_| ()),
			1 => client.heartbeat(1, &capability).await.map(|_| ()),
			2 => client.search_findings(1, &capability, "", 100).await.map(|_| ()),
			_ => client.get_finding(1, &capability).await.map(|_| ()),
		};
		let error = result.unwrap_err();
		assert!(format!("{error:#}").contains("missing field"));
	}
}
