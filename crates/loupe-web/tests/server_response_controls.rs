//! Successful/error response contracts, exercised on a real socket.
mod support;
use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
async fn upstream(
	status: &str, header: Option<&str>, body: &[u8],
) -> (loupe_web::AdminClient, tokio::task::JoinHandle<()>) {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let mut response=format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n",body.len()).into_bytes();
	if let Some(header) = header {
		response.extend_from_slice(format!("X-Loupe-Protocol: {header}\r\n").as_bytes());
	}
	response.extend_from_slice(b"\r\n");
	response.extend_from_slice(body);
	let task = tokio::spawn(async move {
		let (mut stream, _) = listener.accept().await.unwrap();
		let mut request = [0; 4096];
		assert!(stream.read(&mut request).await.unwrap() > 0);
		let _ = stream.write_all(&response).await;
	});
	let client =
		support::client(reqwest::Client::new(), format!("http://{addr}/").parse().unwrap());
	(client, task)
}
async fn call(status: &str, header: Option<&str>, body: &[u8]) -> (StatusCode, Option<Value>) {
	let (client, task) = upstream(status, header, body).await;
	let result = support::health(client).await;
	task.await.unwrap();
	result
}
#[tokio::test]
async fn successful_response_shapes_header_spellings_and_lossy_utf8_controls() {
	for (body, expected) in [
		(b"\"invalid\xff\"".as_slice(), Some(json!("invalid�"))),
		(b" \t\r\n", None),
		(b"null", Some(Value::Null)),
		(br#"{"x":1,"x":2}"#, Some(json!({"x":2}))),
		(b"[1,true]", Some(json!([1, true]))),
	] {
		let (status, value) = call("201 Created", Some("+2"), body).await;
		assert_eq!(status, StatusCode::CREATED);
		assert_eq!(value, expected);
	}
	for header in [None, Some("wrong"), Some("3"), Some("65536")] {
		let (status, body) = call("200 OK", header, b"{}").await;
		assert_eq!(status, StatusCode::BAD_GATEWAY);
		let expected = match header {
			None => format!("server response missing {}", loupe_proto::PROTOCOL_VERSION_HEADER),
			Some("3") => format!("server speaks protocol 3, this loupe-web build speaks {} — rebuild loupe-web against the running server", loupe_proto::PROTOCOL_VERSION),
			_ => "server protocol header is not a u16".to_owned(),
		};
		assert_eq!(body.unwrap()["error"], expected);
	}
	let (status, body) = call("200 OK", Some("2"), b"[").await;
	assert_eq!(status, StatusCode::BAD_GATEWAY);
	assert_eq!(body.unwrap()["error"], "upstream sent invalid JSON");
}
#[tokio::test]
async fn intentional_server_diagnostic_keeps_quotes_markup_trim_and_status() {
	let (status, body) =
		call("409 Conflict", Some("wrong"), b"  FAKE_SERVER_DIAGNOSTIC \"<script>\"\n ").await;
	assert_eq!(status, StatusCode::CONFLICT);
	assert_eq!(body.unwrap()["error"], "FAKE_SERVER_DIAGNOSTIC \"<script>\"");
	let (status, body) = call("404 Not Found", None, b" \n\t").await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(body.unwrap()["error"], "server returned 404 Not Found");
}

#[tokio::test]
async fn health_error_retains_terminal_diagnostic_but_redacts_debug() {
	let (client, task) =
		upstream("409 Conflict", Some("wrong"), b" \nFAKE_SERVER_DIAGNOSTIC \"<script>\" ").await;
	let error = client.health().await.unwrap_err();
	assert_eq!(error.to_string(), "409 Conflict: FAKE_SERVER_DIAGNOSTIC \"<script>\"");
	for debug in [format!("{error:?}"), format!("{error:#?}")] {
		assert!(
			!debug.contains("FAKE_SERVER_DIAGNOSTIC"),
			"owned Server diagnostic leaked through Debug: {debug}"
		);
	}
	task.await.unwrap();
	let (client, task) = upstream("404 Not Found", None, b" \n\t").await;
	assert_eq!(
		client.health().await.unwrap_err().to_string(),
		"404 Not Found: server returned 404 Not Found"
	);
	task.await.unwrap();
}

#[tokio::test]
async fn transport_error_renders_without_a_status() {
	let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
	let addr = reserved.local_addr().unwrap();
	drop(reserved);
	let client =
		support::client(reqwest::Client::new(), format!("http://{addr}/").parse().unwrap());
	assert_eq!(client.health().await.unwrap_err().to_string(), "upstream request failed");
}
