//! Shared socket/runtime mechanics for the two concrete web fixtures.
use std::net::SocketAddr;
use std::sync::Mutex;

use axum::body::Body;
use axum::http::Request;
use loupe_web::{AdminClient, Token, WebState};

pub const BROWSER_CAP: usize = 2 * 1024 * 1024;
pub const SERVER_CAP: usize = 16 * 1024 * 1024;
pub const RAW_CAP: usize = 64 * 1024;
pub struct Fixture {
	pub runtime: tokio::runtime::Runtime,
	listener: std::net::TcpListener,
	pub address: SocketAddr,
}
impl Fixture {
	pub fn new() -> Mutex<Self> {
		let runtime = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.unwrap_or_else(|e| panic!("web fixture runtime: {e}"));
		let listener = std::net::TcpListener::bind("127.0.0.1:0")
			.unwrap_or_else(|e| panic!("web fixture listener: {e}"));
		listener.set_nonblocking(true).unwrap_or_else(|e| panic!("web nonblocking: {e}"));
		let address = listener.local_addr().unwrap_or_else(|e| panic!("web fixture address: {e}"));
		Mutex::new(Self { runtime, listener, address })
	}
	// One bound socket per process. Each iteration owns and reaps its acceptor.
	pub fn listener(&self) -> tokio::net::TcpListener {
		tokio::net::TcpListener::from_std(
			self.listener.try_clone().unwrap_or_else(|e| panic!("web listener clone: {e}")),
		)
		.unwrap_or_else(|e| panic!("web listener conversion: {e}"))
	}
	pub fn app(&self) -> (axum::Router, String) {
		let client = reqwest::Client::builder()
			.no_proxy()
			.redirect(reqwest::redirect::Policy::none())
			.pool_max_idle_per_host(0)
			.timeout(std::time::Duration::from_secs(5))
			.build()
			.unwrap_or_else(|e| panic!("web client: {e}"));
		let client = AdminClient::from_parts(
			client,
			format!("http://{}/", self.address).parse().unwrap_or_else(|e| panic!("web URL: {e}")),
		);
		let token = Token::generate();
		let secret = token.reveal().to_owned();
		for rendered in
			[format!("{token}"), format!("{token:#}"), format!("{token:?}"), format!("{token:#?}")]
		{
			assert_eq!(rendered, "[redacted]");
		}
		let app = loupe_web::router(WebState::new(
			client,
			token,
			"127.0.0.1:8455".parse().unwrap_or_else(|_| unreachable!()),
			5,
		));
		(app, secret)
	}
}
pub fn request(method: &str, path: &str, secret: &str, body: Body) -> Request<Body> {
	Request::builder()
		.method(method)
		.uri(path)
		.header("host", "127.0.0.1:8455")
		.header(loupe_web::token::HEADER_NAME, secret)
		.header(loupe_web::guard::REQUEST_HEADER, "")
		.header("sec-fetch-site", "same-origin")
		.header("content-type", "application/json")
		.body(body)
		.unwrap_or_else(|e| panic!("web request: {e}"))
}
pub fn encoded(raw: &[u8]) -> String {
	raw.iter().map(|byte| format!("%{byte:02X}")).collect()
}
pub fn assert_wiped(drops: &[(usize, usize, bool)]) {
	assert!(
		drops.iter().all(|(capacity, used, zero)| used <= capacity && *zero),
		"web live-owner cleanup failed: {drops:?}"
	);
}
