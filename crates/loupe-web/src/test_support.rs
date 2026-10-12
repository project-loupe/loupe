//! Test fixtures exercise the real native Config callback and named dashboard
//! routes. They do not construct provenance tokens or decode labelled DTOs.
use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use clap::Parser;
use tower::ServiceExt;

pub(crate) fn client(http: reqwest::Client, url: &str) -> crate::AdminClient {
	let cli = crate::Cli::try_parse_from(["loupe-web", "--server-url", url]).unwrap();
	crate::AdminClient::from_parts(http, cli.conn.server_url().unwrap())
}
pub(crate) struct Echo {
	app: axum::Router,
	token: String,
	task: tokio::task::JoinHandle<()>,
}
impl Echo {
	pub(crate) async fn new() -> Self {
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let addr = listener.local_addr().unwrap();
		let upstream =
			axum::Router::new().fallback(axum::routing::any(|request: Request| async move {
				let bytes =
					axum::body::to_bytes(request.into_body(), 4 * 1024 * 1024).await.unwrap();
				(
					[(
						loupe_proto::PROTOCOL_VERSION_HEADER,
						loupe_proto::PROTOCOL_VERSION.to_string(),
					)],
					bytes,
				)
					.into_response()
			}));
		let task = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
		let client = client(reqwest::Client::new(), &format!("http://{addr}/"));
		let token = crate::Token::generate();
		let reveal = token.reveal().to_owned();
		let app = crate::router(crate::WebState::new(
			client,
			token,
			"127.0.0.1:8455".parse().unwrap(),
			5,
		));
		Self { app, token: reveal, task }
	}
	pub(crate) async fn oneshot(
		self, mut request: Request,
	) -> Result<Response, std::convert::Infallible> {
		let (method, path) = match request.uri().path() {
			"/create" => (axum::http::Method::POST, "/api/repos"),
			"/report" => (axum::http::Method::PUT, "/api/repos/1/reporting/github"),
			"/rotate" | "/" => (axum::http::Method::POST, "/api/repos/1/reporting/github-pat"),
			_ => panic!("unknown fixture route"),
		};
		*request.method_mut() = method;
		*request.uri_mut() = path.parse().unwrap();
		request.headers_mut().insert(crate::token::HEADER_NAME, self.token.parse().unwrap());
		self.app.clone().oneshot(request).await
	}
}
impl Drop for Echo {
	fn drop(&mut self) {
		self.task.abort();
	}
}
