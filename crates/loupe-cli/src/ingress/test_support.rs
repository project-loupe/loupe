//! Shared real HTTP fixture for binary and cfg-fuzz-library unit tests.
use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub(crate) async fn respond(body: Vec<u8>) -> (reqwest::Url, tokio::task::JoinHandle<()>) {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let task = tokio::spawn(async move {
		let (mut socket, _) = listener.accept().await.unwrap();
		let mut request = [0; 4096];
		assert!(socket.read(&mut request).await.unwrap() > 0);
		let headers = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nX-Loupe-Protocol: deliberately-invalid\r\nConnection: close\r\n\r\n", body.len());
		socket.write_all(headers.as_bytes()).await.unwrap();
		socket.write_all(&body).await.unwrap();
	});
	(reqwest::Url::parse(&format!("http://{addr}/")).unwrap(), task)
}

/// Test traffic enters through the production collector and its sole Server mint.
pub(crate) async fn received(
	raw: &[u8],
) -> loupe_provenance::Untrusted<bytes::Bytes, loupe_provenance::Server> {
	let (base, task) = respond(raw.to_vec()).await;
	let response = reqwest::Client::new().get(base).send().await.unwrap();
	let body = super::receive(response, "fixture").await.unwrap();
	task.await.unwrap();
	body
}
