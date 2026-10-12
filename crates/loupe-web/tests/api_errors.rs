//! Reflected extractor diagnostics must remain data in the API's JSON envelope.

mod support;
use loupe_web::{Token, WebState};

#[tokio::test]
async fn invalid_path_values_have_fixed_json_diagnostics() {
	let client = support::client(reqwest::Client::new(), "http://127.0.0.1:9/".parse().unwrap());
	let token = Token::generate();
	let secret = token.reveal().to_owned();
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let address = listener.local_addr().unwrap();
	let app = loupe_web::router(WebState::new(client, token, address, 5));
	let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	let http = reqwest::Client::new();
	for kind in ["jobs", "findings"] {
		let response = http
			.get(format!("http://{address}/api/{kind}/hostile-%22-value"))
			.header(loupe_web::token::HEADER_NAME, &secret)
			.send()
			.await
			.unwrap();
		assert_eq!(response.status(), 400);
		let body = response.text().await.unwrap();
		let decoded: serde_json::Value =
			serde_json::from_str(&body).expect("API reflected path input outside a JSON string");
		assert_eq!(decoded["error"], "invalid request path identifier");
	}
	let response = http
		.get(format!("http://{address}/api/config"))
		.header(loupe_web::token::HEADER_NAME, secret)
		.send()
		.await
		.unwrap();
	assert_eq!(response.status(), 200);
	assert!(response.json::<serde_json::Value>().await.is_ok());
	server.abort();
	let _ = server.await;
}
