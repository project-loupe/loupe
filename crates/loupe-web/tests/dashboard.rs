//! End-to-end tests: a real `loupe-server` behind mTLS, a real
//! `loupe-web` in front of it, driven over plain HTTP the way a browser
//! would.
//!
//! The security behaviours are the point of most of these. A loopback
//! HTTP listener holding the admin certificate is only safe because of the
//! token and the CSRF/rebinding guards, so each of those gets a test that
//! fails if the guard is removed.

mod support;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::get;
use axum::{Json, Router};
use clap::builder::TypedValueParser;
use loupe_proto::PROTOCOL_VERSION;
use loupe_server::config::{HostnameParser, PathParser};
use loupe_server::init::run_init;
use loupe_server::reporters::github_app::testing::APP_PRIVATE_KEY_PEM;
use loupe_server::reporters::GithubReporter;
use loupe_server::{serve as serve_server, AppState, Config};
use loupe_storage::Db;
use loupe_web::guard::REQUEST_HEADER;
use loupe_web::token::HEADER_NAME as TOKEN_HEADER;
use loupe_web::{router, Token, WebState};

/// The GitHub App the stub below vouches for. `PUT /v1/github-app`
/// verifies a key by calling `GET /app` and compares the returned id with
/// the one the operator claims, so the stub has to agree with
/// `configure_github_app`.
const STUB_APP_ID: u64 = 42;
const STUB_APP_SLUG: &str = "loupe-reporter";

/// Stand-in for GitHub's `GET /app`, which is all the server calls while
/// storing an app credential. Same shape as the server's own
/// `tests/github_app.rs` stub, minus the call recording this file never
/// inspects.
async fn spawn_github_stub() -> SocketAddr {
	let app = Router::new().route(
		"/app",
		get(|| async { Json(serde_json::json!({"id": STUB_APP_ID, "slug": STUB_APP_SLUG})) }),
	);
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

struct Fixture {
	server: loupe_server::ServeHandle,
	web_addr: SocketAddr,
	web_join: tokio::task::JoinHandle<()>,
	token: String,
	http: reqwest::Client,
	/// Direct admin client against `loupe-server`, for setup the dashboard
	/// deliberately has no route for (storing the GitHub App credential is
	/// a `loupectl` job).
	admin: reqwest::Client,
}

impl Fixture {
	/// Store the stub-backed GitHub App credential on the server, as
	/// `loupectl github-app set` would.
	async fn configure_github_app(&self) {
		let resp = self
			.admin
			.put("https://loupe-server/v1/github-app")
			.json(&serde_json::json!({
				"protocol_version": PROTOCOL_VERSION,
				"app_id": STUB_APP_ID,
				"private_key_pem": APP_PRIVATE_KEY_PEM,
			}))
			.send()
			.await
			.unwrap();
		assert_eq!(resp.status(), 204, "{}", resp.text().await.unwrap_or_default());
	}

	fn url(&self, path: &str) -> String {
		format!("http://{}{path}", self.web_addr)
	}

	/// A GET carrying the origin-scoped capability, as the page sends it.
	fn get(&self, path: &str) -> reqwest::RequestBuilder {
		self.http.get(self.url(path)).header(TOKEN_HEADER, &self.token)
	}

	/// A mutating request with everything the guards require.
	fn post(&self, path: &str) -> reqwest::RequestBuilder {
		self.http
			.post(self.url(path))
			.header(TOKEN_HEADER, &self.token)
			.header("sec-fetch-site", "same-origin")
			.header(REQUEST_HEADER, "1")
	}

	fn delete(&self, path: &str) -> reqwest::RequestBuilder {
		self.http
			.delete(self.url(path))
			.header(TOKEN_HEADER, &self.token)
			.header("sec-fetch-site", "same-origin")
			.header(REQUEST_HEADER, "1")
	}

	async fn shutdown(self) {
		self.web_join.abort();
		let _ = self.web_join.await;
		self.server.shutdown().await;
	}
}

async fn bring_up() -> Fixture {
	let stub_addr = spawn_github_stub().await;
	let tmp = tempfile::tempdir().unwrap();
	let command = clap::Command::new("fixture");
	let data_dir = PathParser.parse_ref(&command, None, tmp.path().as_os_str()).unwrap();
	let hostname =
		HostnameParser.parse_ref(&command, None, std::ffi::OsStr::new("loupe-server")).unwrap();
	let init = run_init(&data_dir, &[hostname], None).unwrap();

	let ca_cert = init.layout.ca_cert.read_tls_pem().unwrap();
	let ca_key = init.layout.ca_key.read_tls_pem().unwrap();
	let ca = ca_cert.import_ca(&ca_key).unwrap();
	let ca_cert_pem = std::fs::read_to_string(init.layout.ca_cert.as_path()).unwrap();
	let cfg = Config {
		bind_addr: "127.0.0.1:0".parse().unwrap(),
		db_path: init.layout.db_path.clone(),
		server_cert_pem: init.layout.server_cert.read_tls_pem().unwrap(),
		server_key_pem: init.layout.server_key.read_tls_pem().unwrap(),
		ca_cert_pem: ca_cert,
		ca_key_pem: ca_key,
	};
	let db = Arc::new(Db::open(init.layout.db_path.as_path(), &init.master_key).unwrap());
	let reporter = Arc::new(GithubReporter::with_base(&format!("http://{stub_addr}")).unwrap());
	let state = AppState::new(db, Arc::new(ca), reporter);
	let server = serve_server(cfg, state).await.unwrap();
	let server_addr = server.local_addr;
	std::mem::forget(tmp);

	// The dashboard's upstream client. `.resolve()` maps the server cert's
	// SAN hostname onto the ephemeral port, the same trick the server's own
	// integration tests use.
	let upstream = reqwest::Client::builder()
		.add_root_certificate(reqwest::Certificate::from_pem(ca_cert_pem.as_bytes()).unwrap())
		.identity(
			reqwest::Identity::from_pem(
				format!("{}\n{}", init.admin_bundle.cert_pem, init.admin_bundle.key_pem.expose())
					.as_bytes(),
			)
			.unwrap(),
		)
		.resolve("loupe-server", server_addr)
		.use_rustls_tls()
		.build()
		.unwrap();
	let client =
		support::client(upstream.clone(), reqwest::Url::parse("https://loupe-server/").unwrap());

	let token = Token::generate();
	let token_plain = token.reveal().to_owned();
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let web_addr = listener.local_addr().unwrap();
	let web_state = WebState::new(client, token, web_addr, 5);
	let app = router(web_state);
	let web_join = tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});

	Fixture {
		server,
		web_addr,
		web_join,
		token: token_plain,
		http: reqwest::Client::builder()
			.redirect(reqwest::redirect::Policy::none())
			.build()
			.unwrap(),
		admin: upstream,
	}
}

// ------------------------------------------------------------------ security

#[tokio::test]
async fn api_requires_the_capability_token() {
	let f = bring_up().await;

	// No capability at all: this is what any other local process gets.
	let resp = f.http.get(f.url("/api/repos")).send().await.unwrap();
	assert_eq!(resp.status(), 401, "an untokened request must be refused");

	// Cookies are shared by every port on a host, so even the real token
	// must be ignored when presented as a cookie.
	let resp = f
		.http
		.get(f.url("/api/repos"))
		.header(reqwest::header::COOKIE, format!("loupe_dashboard={}", f.token))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 401, "a port-global cookie must not authenticate");

	// A wrong token must not work either.
	let resp = f
		.http
		.get(f.url("/api/repos"))
		.header(TOKEN_HEADER, Token::generate().reveal())
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 401, "a foreign token must be refused");

	// The real token works.
	let resp = f.get("/api/repos").send().await.unwrap();
	assert!(resp.status().is_success(), "the printed token must work: {}", resp.status());

	f.shutdown().await;
}

#[tokio::test]
async fn the_startup_url_keeps_the_token_out_of_http() {
	let f = bring_up().await;

	// Fragments are origin-local browser state and never enter the HTTP
	// request. The document bootstraps the token into sessionStorage.
	let resp = f.http.get(format!("{}#t={}", f.url("/"), f.token)).send().await.unwrap();
	assert_eq!(resp.status(), 200);
	assert!(resp.headers().get("set-cookie").is_none(), "capabilities must not use cookies");

	// Query-string tokens are deliberately ignored: query strings
	// are sent over HTTP and can be logged by intermediaries.
	let resp = f.http.get(f.url(&format!("/?t={}", f.token))).send().await.unwrap();
	assert_eq!(resp.status(), 200);
	assert!(resp.headers().get("set-cookie").is_none(), "query tokens must not set cookies");

	f.shutdown().await;
}

/// Any website the operator visits can POST to 127.0.0.1. The browser
/// blocks reading the response, but the request still executes — so a
/// mutating route must refuse it.
#[tokio::test]
async fn cross_origin_mutations_are_refused() {
	let f = bring_up().await;

	// Cross-site, as a browser would label a request from evil.com.
	let resp = f
		.http
		.post(f.url("/api/repos"))
		.header(TOKEN_HEADER, &f.token)
		.header("sec-fetch-site", "cross-site")
		.header(REQUEST_HEADER, "1")
		.json(&serde_json::json!({}))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 403, "a cross-site mutation must be refused");

	// A foreign Origin with no Sec-Fetch-Site.
	let resp = f
		.http
		.post(f.url("/api/repos"))
		.header(TOKEN_HEADER, &f.token)
		.header(reqwest::header::ORIGIN, "http://evil.example")
		.header(REQUEST_HEADER, "1")
		.json(&serde_json::json!({}))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 403, "a foreign Origin must be refused");

	// The form-POST shape: no Origin, no Sec-Fetch-Site, no custom header.
	// This is the request a plain <form> on another site can make.
	let resp = f
		.http
		.post(f.url("/api/repos"))
		.header(TOKEN_HEADER, &f.token)
		.body("clone_url=x")
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 403, "a simple cross-origin form POST must be refused");

	f.shutdown().await;
}

#[tokio::test]
async fn mutations_require_the_custom_header() {
	let f = bring_up().await;

	// Same-origin but missing the header a cross-origin caller could not
	// set without a preflight. Refused, so the header stays load-bearing.
	let resp = f
		.http
		.post(f.url("/api/repos"))
		.header(TOKEN_HEADER, &f.token)
		.header("sec-fetch-site", "same-origin")
		.json(&serde_json::json!({}))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 403);
	let body = resp.text().await.unwrap();
	assert!(body.contains(REQUEST_HEADER), "the error should name the header: {body}");

	f.shutdown().await;
}

/// DNS rebinding: `evil.com` resolving to 127.0.0.1 would be same-origin
/// as far as the browser is concerned. The Host header gives it away.
#[tokio::test]
async fn a_foreign_host_header_is_refused_even_on_reads() {
	let f = bring_up().await;

	for host in ["evil.example", "evil.example:80"] {
		let resp = f
			.http
			.get(f.url("/api/repos"))
			.header(TOKEN_HEADER, &f.token)
			.header(reqwest::header::HOST, host)
			.send()
			.await
			.unwrap();
		assert_eq!(resp.status(), 403, "Host {host} must be refused");
	}

	// The document is guarded too, so a rebound page cannot even load.
	let resp =
		f.http.get(f.url("/")).header(reqwest::header::HOST, "evil.example").send().await.unwrap();
	assert_eq!(resp.status(), 403, "the document must be guarded as well");

	f.shutdown().await;
}

#[tokio::test]
async fn the_document_carries_a_strict_csp() {
	let f = bring_up().await;

	let resp = f.http.get(f.url("/")).send().await.unwrap();
	assert!(resp.status().is_success());
	let csp = resp.headers().get("content-security-policy").expect("CSP header").to_str().unwrap();
	assert!(csp.starts_with("default-src 'none'"), "{csp}");
	assert!(!csp.contains("unsafe-inline"), "{csp}");
	assert_eq!(resp.headers().get("x-content-type-options").unwrap(), "nosniff");
	assert_eq!(resp.headers().get("referrer-policy").unwrap(), "no-referrer");

	// Assets are reachable and are not HTML.
	for (path, expected) in [("/app.css", "text/css"), ("/app.js", "text/javascript")] {
		let resp = f.http.get(f.url(path)).send().await.unwrap();
		assert!(resp.status().is_success(), "{path}");
		let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
		assert!(ct.starts_with(expected), "{path} content-type was {ct}");
	}

	f.shutdown().await;
}

/// Cheap static guards for the GitHub App affordances: the page needs the
/// hint element the script fills from `/api/github-app`, and the listing
/// has to say which credential a GitHub destination files issues with.
#[tokio::test]
async fn the_page_explains_github_app_reporting() {
	let f = bring_up().await;

	let html = f.http.get(f.url("/")).send().await.unwrap().text().await.unwrap();
	assert!(html.contains(r#"id="github-auth-hint""#), "no auth hint element in index.html");
	assert!(
		!html.contains(r#"name="github_pat" type="password" required"#),
		"the PAT must not be statically required: the script decides per server"
	);

	let js = f.http.get(f.url("/app.js")).send().await.unwrap().text().await.unwrap();
	assert!(js.contains("/api/github-app"), "app.js never asks for the GitHub App status");
	assert!(js.contains("(via app)"), "app.js must label app-mode destinations");
	assert!(js.contains("(via PAT)"), "app.js must label PAT-mode destinations");
	assert!(
		js.contains("GitHub App status unavailable"),
		"a failed app-status fetch must degrade instead of aborting the repos view"
	);

	f.shutdown().await;
}

// ---------------------------------------------------------------- functional

#[tokio::test]
async fn a_repo_registered_through_the_dashboard_round_trips() {
	let f = bring_up().await;

	let resp = f
		.post("/api/repos")
		.json(&serde_json::json!({
			"clone_url": "https://github.com/acme/widget.git",
			"reporting": {
				"kind": "github_issue",
				"target_owner": "acme",
				"target_repo": "tracker",
				"github_pat": "ghp_do_not_leak",
			},
		}))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
	let created: serde_json::Value = resp.json().await.unwrap();
	let repo_id = created["repo_id"].as_i64().unwrap();

	// The listing shows the reporter kind but never the PAT.
	let raw = f.get("/api/repos").send().await.unwrap().text().await.unwrap();
	assert!(!raw.contains("ghp_do_not_leak"), "PAT reached the browser: {raw}");
	assert!(!raw.contains("pat_secret_id"), "secret id reached the browser: {raw}");
	let listing: serde_json::Value = serde_json::from_str(&raw).unwrap();
	let repo = &listing["repos"][0];
	assert_eq!(repo["reporting"]["kind"], "github_issue");
	assert_eq!(repo["reporting"]["target_repo"], "tracker");

	// The dashboard fills in protocol_version, so a body without one works.
	let resp = f
		.post(&format!("/api/repos/{repo_id}/scan"))
		.json(&serde_json::json!({ "incremental": false }))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());

	// The scan shows up as a queued job, via the state filter.
	let queued: Vec<serde_json::Value> =
		f.get("/api/jobs?state=queued").send().await.unwrap().json().await.unwrap();
	assert_eq!(queued.len(), 1, "the triggered scan should be queued: {queued:?}");
	assert_eq!(queued[0]["repo_id"], repo_id);
	assert!(
		f.get("/api/jobs?state=succeeded,failed,cancelled")
			.send()
			.await
			.unwrap()
			.json::<Vec<serde_json::Value>>()
			.await
			.unwrap()
			.is_empty(),
		"nothing has finished yet"
	);

	let resp = f.delete(&format!("/api/repos/{repo_id}")).send().await.unwrap();
	assert_eq!(resp.status(), 204);

	f.shutdown().await;
}

/// The page decides whether a PAT is optional from this route, so it has
/// to reflect the server's credential store, not a build-time answer.
#[tokio::test]
async fn the_github_app_status_is_forwarded() {
	let f = bring_up().await;

	let resp = f.get("/api/github-app").send().await.unwrap();
	assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
	let body: serde_json::Value = resp.json().await.unwrap();
	assert_eq!(body["protocol_version"], PROTOCOL_VERSION);
	assert!(body["app"].is_null(), "a fresh server has no app: {body}");

	f.configure_github_app().await;

	let raw = f.get("/api/github-app").send().await.unwrap().text().await.unwrap();
	assert!(!raw.contains("PRIVATE KEY"), "the app key reached the browser: {raw}");
	let body: serde_json::Value = serde_json::from_str(&raw).unwrap();
	assert_eq!(body["app"]["app_id"], STUB_APP_ID);
	assert_eq!(body["app"]["slug"], STUB_APP_SLUG);

	f.shutdown().await;
}

/// The form omits `github_pat` entirely when the operator leaves it
/// empty; the server reads that as "report through the app".
#[tokio::test]
async fn a_repo_without_a_pat_reports_through_the_app() {
	let f = bring_up().await;
	f.configure_github_app().await;

	let resp = f
		.post("/api/repos")
		.json(&serde_json::json!({
			"clone_url": "https://github.com/acme/widget.git",
			"reporting": {
				"kind": "github_issue",
				"target_owner": "acme",
				"target_repo": "tracker",
			},
		}))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());

	let raw = f.get("/api/repos").send().await.unwrap().text().await.unwrap();
	assert!(!raw.contains("pat_secret_id"), "secret id reached the browser: {raw}");
	assert!(!raw.contains("github_pat"), "a PAT field reached the browser: {raw}");
	let listing: serde_json::Value = serde_json::from_str(&raw).unwrap();
	let reporting = &listing["repos"][0]["reporting"];
	assert_eq!(reporting["kind"], "github_issue");
	assert_eq!(reporting["auth"], "app", "listing must say the repo uses the app: {raw}");

	// A PAT-backed registration is labelled the other way, so the page can
	// offer the right per-repo actions.
	let resp = f
		.post("/api/repos")
		.json(&serde_json::json!({
			"clone_url": "https://github.com/acme/gadget.git",
			"reporting": {
				"kind": "github_issue",
				"target_owner": "acme",
				"target_repo": "tracker",
				"github_pat": "ghp_do_not_leak",
			},
		}))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
	let listing: serde_json::Value =
		f.get("/api/repos").send().await.unwrap().json().await.unwrap();
	let auths: Vec<&str> = listing["repos"]
		.as_array()
		.unwrap()
		.iter()
		.map(|r| r["reporting"]["auth"].as_str().unwrap())
		.collect();
	assert!(auths.contains(&"pat") && auths.contains(&"app"), "{auths:?}");

	f.shutdown().await;
}

/// Without a configured app the server refuses a PAT-less registration;
/// the page relies on that refusal reaching it as a JSON error carrying
/// the server's own explanation.
#[tokio::test]
async fn registering_without_a_pat_needs_a_configured_app() {
	let f = bring_up().await;

	let resp = f
		.post("/api/repos")
		.json(&serde_json::json!({
			"clone_url": "https://github.com/acme/widget.git",
			"reporting": {
				"kind": "github_issue",
				"target_owner": "acme",
				"target_repo": "tracker",
			},
		}))
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), 400);
	let body: serde_json::Value = resp.json().await.unwrap();
	assert!(
		body["error"].as_str().unwrap().contains("no GitHub App configured"),
		"the server's explanation should survive: {body}"
	);
	let listing: serde_json::Value =
		f.get("/api/repos").send().await.unwrap().json().await.unwrap();
	assert!(listing["repos"].as_array().unwrap().is_empty(), "nothing registered: {listing}");

	f.shutdown().await;
}

#[tokio::test]
async fn status_endpoints_report_identity_and_protocol() {
	let f = bring_up().await;

	let who: serde_json::Value = f.get("/api/whoami").send().await.unwrap().json().await.unwrap();
	assert_eq!(who["kind"], "admin", "the dashboard authenticates as admin");

	let health: serde_json::Value =
		f.get("/api/health").send().await.unwrap().json().await.unwrap();
	assert_eq!(health["status"], "ok");
	assert_eq!(health["protocol_version"], loupe_proto::PROTOCOL_VERSION);

	// The bootstrap config tells the page which headers to send.
	let config: serde_json::Value =
		f.get("/api/config").send().await.unwrap().json().await.unwrap();
	assert_eq!(config["request_header"], REQUEST_HEADER);
	assert_eq!(config["capability_header"], TOKEN_HEADER);
	assert_eq!(config["protocol_version"], loupe_proto::PROTOCOL_VERSION);
	assert_eq!(config["poll_seconds"], 5);

	f.shutdown().await;
}

/// Upstream errors are plain text; the dashboard has to turn them into
/// JSON the page can display, while keeping the status meaningful.
#[tokio::test]
async fn upstream_errors_reach_the_browser_as_json() {
	let f = bring_up().await;

	let resp = f.get("/api/jobs/9999").send().await.unwrap();
	assert_eq!(resp.status(), 404);
	let body: serde_json::Value = resp.json().await.unwrap();
	assert!(
		body["error"].as_str().unwrap().contains("no job with id 9999"),
		"the server's own message should survive: {body}"
	);

	// A bad filter must surface the server's explanation, not a bare 400.
	let resp = f.get("/api/jobs?state=bogus").send().await.unwrap();
	assert_eq!(resp.status(), 400);
	let body: serde_json::Value = resp.json().await.unwrap();
	assert!(
		body["error"].as_str().unwrap().contains("unknown job state"),
		"unexpected body: {body}"
	);

	f.shutdown().await;
}

#[tokio::test]
async fn the_dashboard_refuses_to_bind_off_loopback() {
	let state = {
		let client = support::client(
			reqwest::Client::new(),
			reqwest::Url::parse("https://127.0.0.1:8443").unwrap(),
		);
		WebState::new(client, Token::generate(), "127.0.0.1:0".parse().unwrap(), 5)
	};
	// Port 0 on a routable address: binding would succeed, so the refusal
	// has to come from our own check, not from the OS.
	let err = loupe_web::serve("0.0.0.0:0".parse().unwrap(), state).await.unwrap_err();
	let msg = err.to_string();
	assert!(msg.contains("refusing to bind"), "{msg}");
	assert!(msg.contains("loopback"), "{msg}");
}
