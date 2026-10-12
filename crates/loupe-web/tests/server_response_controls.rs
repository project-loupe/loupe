//! Original successful/error response contracts, exercised on a real socket.
use loupe_web::AdminClient;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
async fn call(
	status: &str, header: Option<&str>, body: &[u8],
) -> loupe_web::client::UpstreamResult<(StatusCode, Option<Value>)> {
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
		AdminClient::from_parts(reqwest::Client::new(), format!("http://{addr}/").parse().unwrap());
	let result = client.call(Method::GET, "/v1/health", &[], None).await;
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
		let (status, value) = call("201 Created", Some("+2"), body).await.unwrap();
		assert_eq!(status, StatusCode::CREATED);
		assert_eq!(value, expected);
	}
	for header in [None, Some("wrong"), Some("3"), Some("65536")] {
		let error = call("200 OK", header, b"{}").await.unwrap_err();
		assert!(error.status.is_none());
	}
	assert!(call("200 OK", Some("2"), b"[").await.is_err());
}
#[tokio::test]
async fn intentional_server_diagnostic_keeps_quotes_markup_trim_and_status() {
	let error = call("409 Conflict", Some("wrong"), b"  FAKE_SERVER_DIAGNOSTIC \"<script>\"\n ")
		.await
		.unwrap_err();
	assert_eq!(error.status, Some(StatusCode::CONFLICT));
	assert_eq!(error.message, "FAKE_SERVER_DIAGNOSTIC \"<script>\"");
	let error = call("404 Not Found", None, b" \n\t").await.unwrap_err();
	assert_eq!(error.message, "server returned 404 Not Found");
}
