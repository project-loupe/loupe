use std::time::Duration;

use loupe_http::{read_response_bytes, ResponseBodyError, MAX_RESPONSE_BYTES};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn collected_body_clones_share_the_original_allocation() {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let server = tokio::spawn(async move {
		let (mut socket, _) = listener.accept().await.unwrap();
		let mut request = [0; 1024];
		let _ = socket.read(&mut request).await.unwrap();
		socket.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 8192\r\n\r\n").await.unwrap();
		socket.write_all(&[b'x'; 8192]).await.unwrap();
	});
	let response = reqwest::get(format!("http://{addr}/")).await.unwrap();
	let body = read_response_bytes(response).await.unwrap();
	let shared = body.clone();
	assert_eq!(body.len(), 8192);
	assert_eq!(
		body.as_ptr(),
		shared.as_ptr(),
		"cloning a collected credential body must share its guarded allocation"
	);
	drop(body);
	assert!(shared.iter().all(|byte| *byte == b'x'));
	server.await.unwrap();
}

/// The server remains open after sending headers; refusing a declared
/// oversized body must not wait for payload bytes or EOF.
#[tokio::test]
async fn oversized_content_length_is_rejected_before_reading_body() {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let (release, held) = tokio::sync::oneshot::channel::<()>();
	let server = tokio::spawn(async move {
		let (mut socket, _) = listener.accept().await.unwrap();
		let mut request = [0; 1024];
		let _ = socket.read(&mut request).await.unwrap();
		let headers =
			format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", MAX_RESPONSE_BYTES + 1);
		socket.write_all(headers.as_bytes()).await.unwrap();
		let _ = held.await;
	});
	let response = reqwest::get(format!("http://{addr}/")).await.unwrap();
	let result = tokio::time::timeout(Duration::from_secs(2), read_response_bytes(response))
		.await
		.expect("declared over-budget response must fail without polling body");
	assert!(matches!(result, Err(ResponseBodyError::TooLarge)));
	let _ = release.send(());
	server.await.unwrap();
}

#[tokio::test]
async fn irregular_chunked_response_fills_the_exact_budget() {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let server = tokio::spawn(async move {
		let (mut socket, _) = listener.accept().await.unwrap();
		let mut request = [0; 1024];
		let _ = socket.read(&mut request).await.unwrap();
		socket.write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n").await.unwrap();
		// Irregular chunk sizes cross allocation boundaries independently
		// of the final size; the last fragment fills the budget exactly.
		let chunk = [b'x'; 31_337];
		let mut remaining = MAX_RESPONSE_BYTES;
		while remaining > 0 {
			let size = remaining.min(chunk.len());
			socket.write_all(format!("{size:x}\r\n").as_bytes()).await.unwrap();
			socket.write_all(&chunk[..size]).await.unwrap();
			socket.write_all(b"\r\n").await.unwrap();
			remaining -= size;
		}
		socket.write_all(b"0\r\n\r\n").await.unwrap();
	});
	let response = reqwest::get(format!("http://{addr}/")).await.unwrap();
	let body = read_response_bytes(response).await.unwrap();
	assert_eq!(body.len(), MAX_RESPONSE_BYTES);
	// The private collector test checks every intermediate allocation's cap;
	// Bytes deliberately exposes only the collected payload here.
	assert!(body.iter().all(|byte| *byte == b'x'));
	server.await.unwrap();
}

#[tokio::test]
async fn truncated_response_remains_a_transport_error() {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let server = tokio::spawn(async move {
		let (mut socket, _) = listener.accept().await.unwrap();
		let mut request = [0; 1024];
		let _ = socket.read(&mut request).await.unwrap();
		socket.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 99\r\n\r\nshort").await.unwrap();
	});
	let response = reqwest::get(format!("http://{addr}/")).await.unwrap();
	assert!(matches!(read_response_bytes(response).await, Err(ResponseBodyError::Transport(_))));
	server.await.unwrap();
}
