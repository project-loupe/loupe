//! The same job flag prevents buffered and subsequent network egress.
use std::sync::atomic::{AtomicUsize, Ordering};

use loupe_core::security_event::Broker;

use super::*;

async fn session() -> (Arc<Session>, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
	let count = Arc::new(AtomicUsize::new(0));
	let calls = count.clone();
	let app = axum::Router::new().fallback(axum::routing::any(move || {
		let calls = calls.clone();
		async move {
			calls.fetch_add(1, Ordering::SeqCst);
			(
				[(loupe_proto::PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string())],
				axum::Json(json!({"protocol_version":PROTOCOL_VERSION})),
			)
		}
	}));
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let url = format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
	let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	let mut session = tests::fake_session_for_verify(7);
	let session_mut = Arc::get_mut(&mut session).unwrap();
	session_mut.client = Arc::new(ServerClient::from_parts(reqwest::Client::new(), url));
	session_mut.security = crate::canary::JobSecurity::new(
		Default::default(),
		vec![crate::llm::model_broker::ModelCredential::anthropic_api_key(
			"quarantine-fixture-secret",
		)
		.watch()],
	)
	.unwrap();
	(session, count, server)
}
fn trip(session: &Session) {
	assert!(session.security.observe(b"quarantine-fixture-secret", Broker::Model));
}

#[tokio::test]
async fn quarantined_buffer_never_flushes_to_actual_upstream() {
	let (session, calls, server) = session().await;
	tool_submit_verdict(&session, &json!({"verdict":"confirmed","notes":"valid verdict"}))
		.await
		.unwrap();
	trip(&session);
	let result = flush_verify_session(&session).await;
	server.abort();
	assert_eq!(
		calls.load(Ordering::SeqCst),
		0,
		"previously buffered verdict must not leave a quarantined job"
	);
	assert_eq!(result.unwrap_err().to_string(), "injection_suspected");
}

#[tokio::test]
async fn quarantine_while_waiting_for_buffer_lock_refuses_mutation() {
	let (session, calls, server) = session().await;
	let guard = session.verify.as_ref().unwrap().inner.lock().await;
	let task_session = session.clone();
	let task = tokio::spawn(async move {
		tool_submit_verdict(&task_session, &json!({"verdict":"confirmed","notes":"valid verdict"}))
			.await
	});
	tokio::task::yield_now().await;
	trip(&session);
	drop(guard);
	let result = task.await.unwrap();
	server.abort();
	assert!(
		session.verify.as_ref().unwrap().inner.lock().await.verdict.is_none(),
		"quarantine during the lock wait must refuse the buffered write"
	);
	assert_eq!(calls.load(Ordering::SeqCst), 0);
	assert_eq!(result.unwrap_err().to_string(), "injection_suspected");
}
