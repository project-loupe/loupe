//! Broker forwarding and cancellation under job quarantine.
use super::*;

async fn credential_refusal(codex: bool, escaped: bool) {
	const CREDENTIAL: &str = "host-secret-s3-sandbox-72dc4e";
	let upstream = FakeUpstream::start("{}").await;
	let (backend, credential, endpoint, auth) = if codex {
		(
			codex_backend(),
			ModelCredential::openai_api_key(CREDENTIAL),
			"/v1/responses",
			"authorization",
		)
	} else {
		(
			claude_backend(),
			ModelCredential::anthropic_api_key(CREDENTIAL),
			"/v1/messages",
			"x-api-key",
		)
	};
	let session = ModelBrokerSession::start(backend, upstream.url.clone(), credential, limits())
		.await
		.unwrap();
	let mut client = connect(&session).await;
	let response = client
		.send_request(request(endpoint, r#"{"input":"ordinary public input"}"#))
		.await
		.unwrap();
	assert_eq!(response.status(), StatusCode::OK);
	response.into_body().collect().await.unwrap();
	let positive = upstream.captured().await;
	assert_eq!(positive.len(), 1, "positive request must reach the actual upstream");
	assert_eq!(
		positive[0].headers[auth].to_str().unwrap(),
		if codex { format!("Bearer {CREDENTIAL}") } else { CREDENTIAL.to_owned() }
	);
	let observed = if escaped {
		CREDENTIAL.bytes().map(|byte| format!("\\u{byte:04x}")).collect::<String>()
	} else {
		CREDENTIAL.to_owned()
	};
	let body = format!(r#"{{"input":"public","unknown":"{observed}"}}"#);
	let response = client.send_request(request(endpoint, body)).await.unwrap();
	let status = response.status();
	let reply = response.into_body().collect().await.unwrap().to_bytes();
	session.finish().await.unwrap();
	assert_eq!(
		upstream.captured().await.len(),
		1,
		"watched host credential must be refused before any upstream forwarding"
	);
	assert_eq!(status, StatusCode::FORBIDDEN);
	let reply: serde_json::Value = serde_json::from_slice(&reply).unwrap();
	assert_eq!(reply["error"]["code"], "job_quarantined");
}

#[tokio::test]
async fn s3_sandbox_claude_refuses_raw_host_credential() {
	credential_refusal(false, false).await;
}
#[tokio::test]
async fn s3_sandbox_claude_refuses_escaped_host_credential() {
	credential_refusal(false, true).await;
}
#[tokio::test]
async fn s3_sandbox_codex_refuses_raw_host_credential() {
	credential_refusal(true, false).await;
}
#[tokio::test]
async fn s3_sandbox_codex_refuses_escaped_host_credential() {
	credential_refusal(true, true).await;
}

async fn watched_session(
	url: reqwest::Url,
) -> (ModelBrokerSession, Arc<crate::canary::JobSecurity>) {
	let credential = ModelCredential::anthropic_api_key("pending-fixture-secret");
	let security =
		crate::canary::JobSecurity::new(Default::default(), vec![credential.watch()]).unwrap();
	let session = ModelBrokerSession::start_for_job(
		claude_backend(),
		url,
		credential,
		limits(),
		security.clone(),
	)
	.await
	.unwrap();
	(session, security)
}
fn trip(security: &crate::canary::JobSecurity) {
	assert!(security.observe(b"pending-fixture-secret", loupe_core::security_event::Broker::Mcp));
}

#[tokio::test]
async fn quarantine_refuses_the_local_head_preflight() {
	let upstream = FakeUpstream::start("{}").await;
	let (session, security) = watched_session(upstream.url.clone()).await;
	let mut client = connect(&session).await;
	trip(&security);
	let response = client
		.send_request(
			HyperRequest::builder()
				.method(Method::HEAD)
				.uri("/api/hello")
				.body(Full::new(Bytes::new()))
				.unwrap(),
		)
		.await
		.unwrap();
	let status = response.status();
	response.into_body().collect().await.unwrap();
	session.finish().await.unwrap();
	assert_eq!(upstream.captured().await.len(), 0);
	assert_eq!(
		status,
		StatusCode::FORBIDDEN,
		"quarantine must precede the local preflight shortcut"
	);
}

#[tokio::test]
async fn quarantine_cancels_pending_upstream_headers() {
	let arrived = Arc::new(tokio::sync::Notify::new());
	let release = Arc::new(tokio::sync::Notify::new());
	let (handler_arrived, handler_release) = (arrived.clone(), release.clone());
	let app = Router::new().fallback(any(move || {
		let (arrived, release) = (handler_arrived.clone(), handler_release.clone());
		async move {
			arrived.notify_one();
			release.notified().await;
			"{}"
		}
	}));
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let url = format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
	let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	let (session, security) = watched_session(url).await;
	let mut client = connect(&session).await;
	let pending =
		tokio::spawn(async move { client.send_request(request("/v1/messages", "{}")).await });
	arrived.notified().await;
	trip(&security);
	let mut pending = pending;
	let result = tokio::time::timeout(Duration::from_millis(500), &mut pending).await;
	release.notify_one();
	if result.is_err() {
		let _ = pending.await;
	}
	session.finish().await.unwrap();
	server.abort();
	let response = result
		.expect("quarantine must cancel the pending header wait before the upstream is released")
		.unwrap()
		.unwrap();
	assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn quarantine_cancels_pending_original_body_collection() {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	let upstream = FakeUpstream::start("{}").await;
	let (session, security) = watched_session(upstream.url.clone()).await;
	let mut stream = UnixStream::connect(session.socket_path()).await.unwrap();
	stream
		.write_all(b"POST /v1/messages HTTP/1.1\r\nHost: local\r\nContent-Length: 20\r\n\r\n{")
		.await
		.unwrap();
	tokio::task::yield_now().await;
	trip(&security);
	let mut response = [0u8; 1024];
	let result = tokio::time::timeout(Duration::from_millis(500), stream.read(&mut response)).await;
	drop(stream);
	session.finish().await.unwrap();
	assert!(upstream.captured().await.is_empty());
	let length = result.expect("quarantine must cancel pending original-body collection").unwrap();
	assert!(response[..length].starts_with(b"HTTP/1.1 403"));
}
