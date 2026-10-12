#![allow(dead_code)]
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use clap::Parser;
use loupe_web::{AdminClient, Cli, Token, WebState};
use tower::ServiceExt;

pub fn client(http: reqwest::Client, base: reqwest::Url) -> AdminClient {
	let cli = Cli::try_parse_from(["loupe-web", "--server-url", base.as_str()]).unwrap();
	AdminClient::from_parts(http, cli.conn.server_url().unwrap())
}
pub async fn forward(client: AdminClient, path: &str) -> (StatusCode, Option<serde_json::Value>) {
	let token = Token::generate();
	let request = Request::builder()
		.uri(path)
		.header("Host", "127.0.0.1:8455")
		.header(loupe_web::token::HEADER_NAME, token.reveal())
		.body(Body::empty())
		.unwrap();
	let app = loupe_web::router(WebState::new(client, token, "127.0.0.1:8455".parse().unwrap(), 5));
	let response = app.oneshot(request).await.unwrap();
	let status = response.status();
	let body = to_bytes(response.into_body(), 64 * 1024 * 1024).await.unwrap();
	(status, (!body.is_empty()).then(|| serde_json::from_slice(&body).unwrap()))
}
pub async fn health(client: AdminClient) -> (StatusCode, Option<serde_json::Value>) {
	forward(client, "/api/health").await
}
