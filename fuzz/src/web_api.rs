//! Actual Browser router and concrete Config callbacks. Ordinary JSON values
//! occur only in this independent fake-input oracle, never in production owners.
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::Query;
use axum::http::{HeaderValue, Request, Uri};
use base64::Engine as _;
use futures_util::{stream, StreamExt};
use loupe_web::fuzz_support::{
	self as observe, BrowserField, ConfigParser, Entry, Observation, Session,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;
use unicode_general_category::{get_general_category, GeneralCategory as G};

use crate::utils::test_logger;
use crate::web_support::{self as support, Fixture, BROWSER_CAP, RAW_CAP};

const PAT: &str = "FAKE_WEB_DIRECT_PAT_SENTINEL";
// Independent expected schemas; production DTO edits cannot change this oracle.
#[derive(Deserialize)]
struct LimitOracle {
	#[serde(default)]
	limit: Option<i64>,
}
#[derive(Deserialize)]
struct JobsOracle {
	#[serde(default)]
	limit: Option<i64>,
	#[serde(default)]
	state: Option<String>,
	#[serde(default)]
	kind: Option<String>,
}
#[derive(Deserialize)]
struct SearchOracle {
	q: String,
	#[serde(default)]
	limit: Option<i64>,
}
const HOST_ERROR: &str =
	"unexpected Host header; loupe-web only answers on its own loopback address\n";
const ORIGIN_ERROR: &str = "cross-origin request refused\n";
const CUSTOM_ERROR: &str =
	"missing X-Loupe-Dashboard header; mutating requests must come from the dashboard itself\n";
const TOKEN_ERROR: &str =
	"missing or invalid dashboard capability; reopen the URL printed at startup\n";
const BODY_ROUTES: [(&str, &str, Entry, &str); 6] = [
	("POST", "/api/repos", Entry::CreateRepo, "BrowserCreateRepo"),
	("PATCH", "/api/repos/7", Entry::UpdateRepo, "BrowserUpdateRepo"),
	("POST", "/api/repos/7/reporting/github-pat", Entry::RotatePat, "BrowserRotatePat"),
	(
		"PUT",
		"/api/repos/7/reporting/github",
		Entry::SetGithubReporting,
		"BrowserSetGithubReporting",
	),
	("POST", "/api/repos/7/scan", Entry::EnqueueScan, "BrowserEnqueueScan"),
	("POST", "/api/findings/retry-verify", Entry::RetryVerify, "BrowserRetryVerify"),
];
const ID_ROUTES: [(&str, &str, &str); 11] = [
	("GET", "/api/jobs/", ""),
	("POST", "/api/jobs/", "/retry"),
	("POST", "/api/jobs/", "/cancel"),
	("DELETE", "/api/repos/", ""),
	("GET", "/api/findings/", ""),
	("POST", "/api/findings/", "/approve"),
	("POST", "/api/findings/", "/reject"),
	("POST", "/api/findings/", "/retry-report"),
	("GET", "/api/repos/", "/findings"),
	("POST", "/api/repos/", "/scan"),
	("GET", "/api/repos/", "/findings/search?q="),
];
#[derive(Debug, PartialEq)]
struct Forward {
	method: String,
	uri: String,
	body: Option<Value>,
}
#[derive(Debug)]
struct Captured {
	method: String,
	uri: String,
	body: Vec<u8>,
	protocol: Option<String>,
	capability: bool,
}
async fn upstream(
	listener: tokio::net::TcpListener, captured: Arc<Mutex<Vec<Captured>>>,
) -> std::io::Result<()> {
	let (mut socket, _) = listener.accept().await?;
	let mut head = Vec::new();
	while !head.ends_with(b"\r\n\r\n") {
		let mut byte = [0];
		socket.read_exact(&mut byte).await?;
		head.push(byte[0]);
		assert!(head.len() <= RAW_CAP + 8192, "upstream request header bound");
	}
	let head =
		String::from_utf8(head).unwrap_or_else(|_| panic!("invalid upstream request headers"));
	let mut lines = head.split("\r\n");
	let mut request = lines.next().unwrap_or_else(|| panic!("upstream request line")).split(' ');
	let method = request.next().unwrap_or_else(|| panic!("upstream method")).to_owned();
	let uri = request.next().unwrap_or_else(|| panic!("upstream URI")).to_owned();
	assert_eq!(request.next(), Some("HTTP/1.1"));
	let mut length = 0usize;
	let mut protocol = None;
	let mut capability = false;
	for line in lines.filter(|s| !s.is_empty()) {
		let (name, value) = line.split_once(':').unwrap_or_else(|| panic!("upstream header"));
		let value = value.trim();
		if name.eq_ignore_ascii_case("content-length") {
			length = value.parse().unwrap_or_else(|_| panic!("upstream content length"));
		}
		if name.eq_ignore_ascii_case(loupe_proto::PROTOCOL_VERSION_HEADER) {
			assert!(protocol.is_none());
			protocol = Some(value.to_owned());
		}
		capability |= name.eq_ignore_ascii_case(loupe_web::token::HEADER_NAME);
		assert!(
			!name.eq_ignore_ascii_case("transfer-encoding"),
			"actual Bytes request body must retain known length"
		);
	}
	assert!(length <= BROWSER_CAP + 1024, "upstream fixture body bound");
	let mut body = vec![0; length];
	socket.read_exact(&mut body).await?;
	captured.lock().unwrap_or_else(|_| panic!("upstream capture poisoned")).push(Captured {
		method,
		uri,
		body,
		protocol,
		capability,
	});
	let body = b"{\"forwarded\":true}";
	socket.write_all(format!("HTTP/1.1 201 Created\r\nX-Loupe-Protocol: 2\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await?;
	socket.write_all(body).await?;
	socket.shutdown().await
}
struct Case {
	method: String,
	path: String,
	raw: Vec<u8>,
	media: Option<HeaderValue>,
	forward: Result<Option<Forward>, (u16, &'static str)>,
	owner: Option<usize>,
	query_values: Vec<(BrowserField, String)>,
	entry: Option<Entry>,
	recipe: Option<u8>,
}
impl Case {
	fn new() -> Self {
		Self {
			method: "GET".into(),
			path: "/api/config".into(),
			raw: Vec::new(),
			media: Some(HeaderValue::from_static("application/json")),
			forward: Ok(None),
			owner: None,
			query_values: Vec::new(),
			entry: None,
			recipe: None,
		}
	}
	fn route(&mut self, method: &str, path: String) {
		self.method = method.into();
		self.path = path.clone();
		self.forward = Ok(Some(Forward {
			method: method.into(),
			uri: path.replacen("/api", "/v1", 1),
			body: None,
		}));
	}
	fn body(&mut self, owner: usize, raw: Vec<u8>, media: Option<HeaderValue>) {
		let (method, path, _, _) = BODY_ROUTES[owner];
		self.route(method, path.into());
		self.raw = raw;
		self.media = media;
		self.owner = Some(owner);
		let value = if self.media.is_none() {
			Ok(json!({}))
		} else if !json_media(self.media.as_ref()) {
			self.forward = Err((415, "expected JSON Content-Type"));
			return;
		} else {
			serde_json::from_slice::<Value>(&self.raw)
		};
		match value {
			Ok(mut value) => {
				if let Some(object) = value.as_object_mut() {
					object.insert("protocol_version".into(), 2.into());
				}
				if let Ok(Some(f)) = &mut self.forward {
					f.body = Some(value);
				}
			},
			Err(_) => self.forward = Err((400, "invalid JSON request")),
		}
	}
}
fn json_media(header: Option<&HeaderValue>) -> bool {
	// Independent MIME acceptance table exercised by fixed and arbitrary media.
	let Some(text) = header.and_then(|h| h.to_str().ok()) else {
		return false;
	};
	let Ok(media) = text.parse::<mime::Mime>() else {
		return false;
	};
	media.type_() == mime::APPLICATION
		&& (media.subtype() == mime::JSON || media.suffix() == Some(mime::JSON))
}
fn policy(text: &str, multiline: bool) -> bool {
	text.len() <= BROWSER_CAP
		&& text.chars().count() <= BROWSER_CAP
		&& text.chars().all(|c| {
			if multiline && matches!(c, '\r' | '\n' | '\t') {
				return true;
			}
			let cp = c as u32;
			!matches!(
				get_general_category(c),
				G::Control
					| G::Format
					| G::Unassigned
					| G::PrivateUse
					| G::LineSeparator
					| G::ParagraphSeparator
			) && !(0xfdd0..=0xfdef).contains(&cp)
				&& cp & 0xffff < 0xfffe
		})
}
fn query(case: &mut Case, path: &str, raw: &str, search: bool) {
	case.route("GET", format!("{path}?{raw}"));
	case.entry = Some(if search { Entry::Search } else { Entry::Jobs });
	let Ok(uri) = case.path.parse::<Uri>() else {
		return;
	};
	let mut pairs = Vec::new();
	if search {
		let Ok(q) = Query::<SearchOracle>::try_from_uri(&uri) else {
			case.forward = Err((400, "invalid request query"));
			return;
		};
		if !policy(&q.q, true) {
			case.forward = Err((400, "invalid request query"));
			return;
		}
		case.query_values.push((BrowserField::Search, q.q.clone()));
		pairs.push(("q", q.q.clone()));
		if let Some(limit) = q.limit {
			pairs.push(("limit", limit.to_string()));
		}
	} else {
		let Ok(q) = Query::<JobsOracle>::try_from_uri(&uri) else {
			case.forward = Err((400, "invalid request query"));
			return;
		};
		if let Some(limit) = q.limit {
			pairs.push(("limit", limit.to_string()));
		}
		for (field, name, text) in
			[(BrowserField::State, "state", &q.state), (BrowserField::Kind, "kind", &q.kind)]
		{
			if let Some(text) = text {
				if !policy(text, false) {
					case.forward = Err((400, "invalid request query"));
					return;
				}
				case.query_values.push((field, text.clone()));
				if !text.is_empty() {
					pairs.push((name, text.clone()));
				}
			}
		}
	}
	let mut url = url::Url::parse(&format!("http://fixture{}", path.replacen("/api", "/v1", 1)))
		.unwrap_or_else(|_| unreachable!());
	if !pairs.is_empty() {
		url.query_pairs_mut().extend_pairs(pairs);
	}
	if let Ok(Some(f)) = &mut case.forward {
		f.uri =
			format!("{}{}", url.path(), url.query().map(|q| format!("?{q}")).unwrap_or_default());
	}
}
fn guard(request: &Request<Body>) -> Option<&'static str> {
	let headers = request.headers();
	if !matches!(
		headers.get("host").and_then(|h| h.to_str().ok()),
		Some("127.0.0.1:8455" | "localhost:8455")
	) {
		return Some(HOST_ERROR);
	}
	if !matches!(request.method().as_str(), "GET" | "HEAD" | "OPTIONS") {
		let origin = match headers.get("sec-fetch-site").and_then(|h| h.to_str().ok()) {
			Some(site) => site == "same-origin",
			None => matches!(
				headers.get("origin").and_then(|h| h.to_str().ok()),
				Some("http://127.0.0.1:8455" | "http://localhost:8455")
			),
		};
		if !origin {
			return Some(ORIGIN_ERROR);
		}
		if !headers.contains_key(loupe_web::guard::REQUEST_HEADER) {
			return Some(CUSTOM_ERROR);
		}
	}
	None
}
fn set_header(request: &mut Request<Body>, name: &'static str, raw: &[u8]) {
	request.headers_mut().remove(name);
	if let Ok(value) = HeaderValue::from_bytes(raw) {
		request.headers_mut().insert(name, value);
	}
}

fn config(mode: u8, bytes: &[u8]) {
	let session = Session::start();
	if mode <= 14 {
		let (parser, entry) = match mode {
			12 => (ConfigParser::Url, Entry::ConfigUrl),
			13 => (ConfigParser::Path, Entry::ConfigPath),
			_ => (ConfigParser::Pem, Entry::ConfigPem),
		};
		let expected = match parser {
			ConfigParser::Path => Ok(bytes.to_vec()),
			ConfigParser::Pem => std::str::from_utf8(bytes)
				.map(|s| s.as_bytes().to_vec())
				.map_err(|_| "configuration value is not UTF-8"),
			ConfigParser::Url => std::str::from_utf8(bytes)
				.map_err(|_| "configuration value is not UTF-8")
				.and_then(|s| {
					url::Url::parse(s)
						.map(|u| u.as_str().as_bytes().to_vec())
						.map_err(|_| "invalid server URL")
				}),
		};
		let actual = observe::config_parse(parser, OsStr::from_bytes(bytes));
		match (&actual, &expected) {
			(Ok(a), Ok(e)) => assert_eq!(a, e),
			(Err(a), Err(e)) => assert_eq!(a, &format!("error: {e}")),
			_ => panic!("Config callback changed admission: {actual:?} {expected:?}"),
		}
		let (trace, drops) = session.finish();
		support::assert_wiped(&drops);
		assert_eq!(trace.entries, vec![entry]);
		let values: Vec<_> = trace
			.values
			.iter()
			.filter_map(|v| {
				if let Observation::ConfigValue { owner, bytes, debug, .. } = v {
					Some((*owner, bytes.clone(), debug.clone()))
				} else {
					None
				}
			})
			.collect();
		assert_eq!(values.len(), usize::from(actual.is_ok()));
		if let Ok(expected) = expected {
			assert_eq!(values[0].0, entry);
			assert_eq!(values[0].1, expected);
			if matches!(parser, ConfigParser::Pem) {
				assert_eq!(values[0].2.as_deref(), Some("[redacted]"));
			}
		}
		return;
	}
	let selector = bytes.first().copied().unwrap_or(0) % 10;
	let input = bytes.get(1..).unwrap_or_default();
	let encoded = base64::engine::general_purpose::STANDARD.encode(input);
	let text = String::from_utf8_lossy(input);
	let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("web Config fixture directory: {e}"));
	let path = dir.path().join(OsStr::from_bytes(b"native-\xff-FAKE_PEM"));
	std::fs::write(&path, input).unwrap_or_else(|e| panic!("web Config fixture file: {e}"));
	let padded = format!(" \r\n{encoded}\t ");
	let large = (selector == 9).then(|| "P".repeat(BROWSER_CAP + 1));
	let (raw, b64, file, expected, entry) = match selector {
		0 => (
			Some(PAT),
			Some("invalid%%%"),
			Some(path.as_path()),
			Ok(PAT.as_bytes().to_vec()),
			Some(Entry::ConfigRaw),
		),
		1 => (
			Some(""),
			Some(padded.as_str()),
			Some(path.as_path()),
			std::str::from_utf8(input)
				.map(|s| s.as_bytes().to_vec())
				.map_err(|_| "invalid base64 PEM input"),
			Some(Entry::ConfigBase64),
		),
		2 => (
			None,
			None,
			Some(path.as_path()),
			std::str::from_utf8(input)
				.map(|s| s.as_bytes().to_vec())
				.map_err(|_| "reading PEM input failed"),
			std::str::from_utf8(input).is_ok().then_some(Entry::ConfigFile),
		),
		3 => (
			None,
			Some("INVALID%%%"),
			Some(path.as_path()),
			Err("invalid base64 PEM input"),
			Some(Entry::ConfigBase64),
		),
		4 => (Some(" \n"), Some("invalid%%%"), None, Ok(b" \n".to_vec()), Some(Entry::ConfigRaw)),
		5 => (None, None, None, Err("missing fixture PEM source"), None),
		6 => (
			Some(text.as_ref()),
			None,
			None,
			if text.is_empty() {
				Err("missing fixture PEM source")
			} else {
				Ok(text.as_bytes().to_vec())
			},
			(!text.is_empty()).then_some(Entry::ConfigRaw),
		),
		7 => (
			None,
			Some(text.as_ref()),
			None,
			if text.is_empty() {
				Err("missing fixture PEM source")
			} else {
				base64::engine::general_purpose::STANDARD
					.decode(text.trim())
					.ok()
					.and_then(|v| String::from_utf8(v).ok())
					.map(String::into_bytes)
					.ok_or("invalid base64 PEM input")
			},
			(!text.is_empty()).then_some(Entry::ConfigBase64),
		),
		8 => (
			Some(""),
			Some(""),
			Some(path.as_path()),
			std::str::from_utf8(input)
				.map(|s| s.as_bytes().to_vec())
				.map_err(|_| "reading PEM input failed"),
			std::str::from_utf8(input).is_ok().then_some(Entry::ConfigFile),
		),
		_ => (
			large.as_deref(),
			Some("invalid%%%"),
			None,
			Ok(large.as_ref().unwrap_or_else(|| unreachable!()).as_bytes().to_vec()),
			Some(Entry::ConfigRaw),
		),
	};
	let actual = observe::config_selected(raw, b64, file);
	assert_eq!(actual, expected.map_err(str::to_owned), "selected Config priority/grammar changed");
	let (trace, drops) = session.finish();
	support::assert_wiped(&drops);
	assert_eq!(trace.entries, entry.into_iter().collect::<Vec<_>>());
	let values: Vec<_> = trace
		.values
		.iter()
		.filter_map(|v| {
			if let Observation::ConfigValue { bytes, pointer, debug, .. } = v {
				Some((bytes, pointer, debug))
			} else {
				None
			}
		})
		.collect();
	assert_eq!(values.len(), if actual.is_ok() { 2 } else { 0 });
	if let Ok(expected) = actual {
		assert_eq!(values[0].0, &expected);
		assert_eq!(values[1].0, &expected);
		assert_eq!(values[0].1, values[1].1, "selected PEM copied at legacy exit");
		for value in values {
			assert_eq!(value.2.as_deref(), Some("[redacted]"));
		}
	}
}

pub fn do_test(data: &[u8]) {
	if data.len() > RAW_CAP {
		return;
	}
	let Some((&mode, bytes)) = data.split_first() else {
		return;
	};
	let mode = mode % 26;
	if (12..=15).contains(&mode) {
		config(mode, bytes);
		return;
	}
	if mode == 16 {
		let selector = bytes.first().copied().unwrap_or(0);
		let tail = bytes.get(1..).unwrap_or_default();
		let encoded = String::from_utf8_lossy(tail);
		let decoded: Vec<_> = percent_encoding::percent_decode_str(&encoded).collect();
		let length = String::from_utf8_lossy(&decoded).len();
		let prefix = BROWSER_CAP.saturating_sub(length) + usize::from(selector % 3);
		let input = format!("{}{encoded}", "a".repeat(prefix));
		assert_eq!(
			observe::query_decoded_budget(&input),
			prefix + length <= BROWSER_CAP,
			"pre-allocation lossy query budget changed"
		);
		assert!(
			format!("/search?q={input}").parse::<Uri>().is_err(),
			"budget seam is distinct from actual URI size admission"
		);
		return;
	}
	let mut case = Case::new();
	match mode {
		1 => {
			case.route("GET", format!("/api/jobs/{}", support::encoded(bytes)));
			case.entry = Some(Entry::Path);
			case.forward = std::str::from_utf8(bytes)
				.ok()
				.and_then(|s| s.parse::<i64>().ok())
				.map(|n| {
					Some(Forward { method: "GET".into(), uri: format!("/v1/jobs/{n}"), body: None })
				})
				.ok_or((400, "invalid request path identifier"));
		},
		2 => {
			case.route("GET", format!("/api/repos?limit={}", support::encoded(bytes)));
			case.entry = Some(Entry::Limit);
			let Ok(uri) = case.path.parse::<Uri>() else {
				return;
			};
			case.forward = Query::<LimitOracle>::try_from_uri(&uri)
				.map(|q| {
					Some(Forward {
						method: "GET".into(),
						uri: q
							.limit
							.map(|n| format!("/v1/repos?limit={n}"))
							.unwrap_or_else(|| "/v1/repos".into()),
						body: None,
					})
				})
				.map_err(|_| (400, "invalid request query"));
		},
		3 => case.body(0, bytes.to_vec(), Some(HeaderValue::from_static("application/json"))),
		5 | 6 => case.body(0, b"{}".to_vec(), None),
		8 => {
			let owner = usize::from(bytes.first().copied().unwrap_or(0)) % 6;
			let media = match bytes.get(1).copied().unwrap_or(0) % 6 {
				0 => None,
				1 => Some(HeaderValue::from_static("text/plain")),
				2 => Some(HeaderValue::from_static("application/json")),
				3 => Some(HeaderValue::from_static("application/vnd.fixture+json; charset=utf-8")),
				4 => HeaderValue::from_bytes(b"\xff").ok(),
				_ => Some(HeaderValue::from_static("application/json; charset=utf-8")),
			};
			case.body(owner, bytes.get(2..).unwrap_or_default().to_vec(), media);
		},
		9 | 10 => {
			let Ok(raw) = std::str::from_utf8(bytes) else {
				return;
			};
			query(
				&mut case,
				if mode == 9 { "/api/jobs" } else { "/api/repos/7/findings/search" },
				raw,
				mode == 10,
			);
		},
		11 => {
			let which = usize::from(bytes.first().copied().unwrap_or(0)) % ID_ROUTES.len();
			let (method, prefix, suffix) = ID_ROUTES[which];
			let raw = bytes.get(1..).unwrap_or_default();
			case.route(method, format!("{prefix}{}{suffix}", support::encoded(raw)));
			case.entry = Some(Entry::Path);
			case.media = None;
			case.forward = std::str::from_utf8(raw)
				.ok()
				.and_then(|s| s.parse::<i64>().ok())
				.map(|id| {
					Some(Forward {
						method: method.into(),
						uri: format!("{}{id}{suffix}", prefix.replacen("/api", "/v1", 1)),
						body: (which == 9).then(|| json!({"protocol_version":2})),
					})
				})
				.ok_or((400, "invalid request path identifier"));
			if which == 9 {
				case.owner = Some(4);
			}
			if which == 10 {
				case.query_values.push((BrowserField::Search, String::new()));
			}
		},
		17 if bytes.first().copied().unwrap_or(0) & 32 == 0 => case.body(0, b"{}".to_vec(), None),
		18 => {
			let recipe = bytes.first().copied().unwrap_or(0) % 10;
			let mut raw = b"{}".to_vec();
			if recipe <= 2 {
				raw.resize(BROWSER_CAP - 1 + usize::from(recipe), b' ');
			}
			if recipe == 3 {
				raw = format!("{{\"x\":\"{}\"}}", "a".repeat(BROWSER_CAP - 8)).into_bytes();
			}
			if matches!(recipe, 4 | 5) {
				raw = b"FAKE_STREAM_PAT".to_vec();
			}
			case.body(
				2,
				raw,
				if recipe == 8 {
					None
				} else if recipe == 9 {
					Some(HeaderValue::from_static("text/plain"))
				} else {
					Some(HeaderValue::from_static("application/json"))
				},
			);
			case.recipe = Some(recipe);
			if recipe == 2 {
				case.forward = Err((413, "request body exceeds 2097152 bytes"));
			}
			if recipe == 4 {
				case.forward = Err((400, "reading request body failed"));
			}
		},
		19 => {
			let depth = 110 + usize::from(bytes.first().copied().unwrap_or(0) % 30);
			let raw =
				format!("{}{{\"github_pat\":\"{PAT}\"}}{}", "[".repeat(depth), "]".repeat(depth));
			case.body(
				usize::from(bytes.get(1).copied().unwrap_or(0)) % 6,
				raw.into_bytes(),
				Some(HeaderValue::from_static("application/json")),
			);
		},
		20 => query(
			&mut case,
			"/api/repos/7/findings/search",
			&format!("q={}", support::encoded(bytes)),
			true,
		),
		21 => query(&mut case, "/api/jobs", &format!("kind={}", support::encoded(bytes)), false),
		22 => {},
		23 => {
			let path = ["/api/health", "/api/whoami", "/api/github-app", "/api/repos", "/api/jobs"]
				[usize::from(bytes.first().copied().unwrap_or(0)) % 5];
			case.route("GET", path.into());
			if path == "/api/jobs" {
				case.entry = Some(Entry::Jobs);
			}
			if path == "/api/repos" {
				case.entry = Some(Entry::Limit);
			}
		},
		24 => {
			case.path = ["/", "/app.css", "/app.js"]
				[usize::from(bytes.first().copied().unwrap_or(0)) % 3]
				.into();
		},
		25 => {
			let owner = usize::from(bytes.first().copied().unwrap_or(0)) % 6;
			case.body(
				owner,
				format!("{{\"github_pat\":\"{PAT}\"}}").into_bytes(),
				HeaderValue::from_bytes(bytes.get(1..).unwrap_or_default()).ok(),
			);
		},
		_ => {},
	}
	if case.path.parse::<Uri>().is_err() {
		return;
	}
	static FIXTURE: OnceLock<Mutex<Fixture>> = OnceLock::new();
	let fixture = FIXTURE
		.get_or_init(Fixture::new)
		.lock()
		.unwrap_or_else(|_| panic!("web request fixture poisoned"));
	fixture.runtime.block_on(async {
		let session = Session::start();
		let seen = Arc::new(Mutex::new(Vec::<Captured>::new()));
		let listener = fixture.listener();
		let mut server = tokio::spawn(upstream(listener, seen.clone()));
		let (app, secret) = fixture.app();
		let polls = Arc::new(AtomicUsize::new(0));
		let observed = polls.clone();
		let chunks = case.raw.chunks(8192).map(Bytes::copy_from_slice).collect::<Vec<_>>();
		let recipe = case.recipe;
		let body = stream::iter(chunks.into_iter().map(Ok::<_, std::io::Error>))
			.chain(stream::once(async move {
				if recipe == Some(4) {
					Err(std::io::Error::other("FAKE_STREAM_ERROR_SENTINEL"))
				} else if recipe == Some(5) {
					std::future::pending().await
				} else {
					Ok(Bytes::new())
				}
			}))
			.inspect(move |_| {
				observed.fetch_add(1, Ordering::SeqCst);
			});
		let mut request =
			support::request(&case.method, &case.path, &secret, Body::from_stream(body));
		request.headers_mut().remove("content-type");
		if let Some(media) = &case.media {
			request.headers_mut().insert("content-type", media.clone());
		}
		match mode {
			0 => set_header(&mut request, loupe_web::token::HEADER_NAME, bytes),
			4 => set_header(&mut request, "host", bytes),
			5 => {
				request.headers_mut().remove("sec-fetch-site");
				set_header(&mut request, "origin", bytes);
			},
			6 => set_header(&mut request, "sec-fetch-site", bytes),
			17 => {
				let bits = bytes.first().copied().unwrap_or(0);
				if bits & 1 != 0 {
					set_header(&mut request, "sec-fetch-site", b"\xff");
				} else if bits & 2 != 0 {
					set_header(&mut request, "sec-fetch-site", b"cross-site");
				} else {
					request.headers_mut().remove("sec-fetch-site");
				}
				if bits & 4 != 0 {
					set_header(&mut request, "origin", b"http://127.0.0.1:8455");
				}
				if bits & 8 != 0 {
					request.headers_mut().remove(loupe_web::guard::REQUEST_HEADER);
				}
				if bits & 16 != 0 {
					set_header(&mut request, "host", b"evil.invalid");
				}
			},
			18 if recipe == Some(6) => set_header(&mut request, "host", b"evil.invalid"),
			18 if recipe == Some(7) => {
				request.headers_mut().remove(loupe_web::token::HEADER_NAME);
			},
			22 => {
				request.headers_mut().remove(loupe_web::token::HEADER_NAME);
				set_header(&mut request, "cookie", format!("loupe_dashboard={secret}").as_bytes());
			},
			24 => {
				set_header(&mut request, "host", bytes.get(1..).unwrap_or_default());
				request.headers_mut().remove(loupe_web::token::HEADER_NAME);
			},
			_ => {},
		}
		let guard_error = guard(&request);
		let token_ok =
			request.headers().get(loupe_web::token::HEADER_NAME).and_then(|h| h.to_str().ok())
				== Some(secret.as_str());
		let deadline =
			if recipe == Some(5) { Duration::from_millis(30) } else { Duration::from_secs(10) };
		let outcome = tokio::time::timeout(deadline, app.oneshot(request)).await;
		let response = if let Ok(Ok(response)) = outcome {
			let status = response.status();
			Some((
				status,
				to_bytes(response.into_body(), BROWSER_CAP + 1024)
					.await
					.unwrap_or_else(|e| panic!("browser response: {e}"))
					.to_vec(),
			))
		} else {
			None
		};
		if seen.lock().unwrap_or_else(|_| panic!("upstream capture poisoned")).is_empty() {
			server.abort();
			let join = server.await;
			assert!(
				join.is_ok() || join.is_err_and(|e| e.is_cancelled()),
				"upstream task panicked"
			);
		} else {
			match tokio::time::timeout(Duration::from_secs(2), &mut server).await {
				Ok(result) => result
					.unwrap_or_else(|e| panic!("upstream task: {e}"))
					.unwrap_or_else(|e| panic!("upstream socket: {e}")),
				Err(_) => {
					server.abort();
					let _ = server.await;
					panic!("upstream sender failed to finish");
				},
			}
		}
		let captured = seen.lock().unwrap_or_else(|_| panic!("upstream capture poisoned"));
		let (trace, drops) = session.finish();
		support::assert_wiped(&drops);
		assert_eq!(trace.entries.iter().filter(|e| **e == Entry::Guard).count(), 1);
		let empty_id = (mode == 1 && bytes.is_empty()) || (mode == 11 && bytes.len() <= 1);
		// A trailing empty capture has no route. An empty intermediate capture
		// matches its static suffix, then the actual path validator rejects it.
		let unmatched_empty_id = empty_id && case.path.ends_with('/');
		assert_eq!(
			trace.entries.contains(&Entry::Token),
			guard_error.is_none() && mode != 24 && !unmatched_empty_id
		);
		if recipe == Some(5) {
			assert!(response.is_none(), "cancelled Browser read completed");
			assert!(captured.is_empty());
			assert!(polls.load(Ordering::SeqCst) > 0);
			assert!(drops.iter().any(|(cap, used, _)| *cap == BROWSER_CAP && *used > 0));
			return;
		}
		let (status, body) = response.unwrap_or_else(|| panic!("Browser route timed out"));
		if let Some(message) = guard_error {
			assert_eq!(status, 403);
			assert_eq!(body.as_slice(), message.as_bytes());
			assert!(captured.is_empty());
			assert_eq!(polls.load(Ordering::SeqCst), 0);
			return;
		}
		if mode == 24 {
			assert_eq!(status, 200);
			assert!(!body.is_empty());
			assert!(captured.is_empty());
			assert_eq!(polls.load(Ordering::SeqCst), 0);
			return;
		}
		if !token_ok {
			assert_eq!(status, 401);
			assert_eq!(body.as_slice(), TOKEN_ERROR.as_bytes());
			assert!(captured.is_empty());
			assert_eq!(polls.load(Ordering::SeqCst), 0);
			return;
		}
		if unmatched_empty_id {
			assert_eq!(status, 404);
			assert!(body.is_empty());
			assert_eq!(trace.entries, [Entry::Guard]);
			assert!(captured.is_empty());
			assert_eq!(polls.load(Ordering::SeqCst), 0);
			return;
		}
		if empty_id {
			assert_eq!(trace.entries, [Entry::Guard, Entry::Token, Entry::Path]);
			assert_eq!(polls.load(Ordering::SeqCst), 0);
		}
		if let Some(entry) = case.entry {
			// Axum can reject invalid UTF-8 before the i64 validator. Empty
			// intermediate captures must reach it, as checked above.
			if entry != Entry::Path || case.forward.is_ok() {
				assert!(
					trace.entries.contains(&entry),
					"named query/path validator was bypassed: {trace:?}"
				);
			}
		}
		match &case.forward {
			Err((expected, message)) => {
				assert_eq!(status.as_u16(), *expected);
				assert_eq!(
					serde_json::from_slice::<Value>(&body)
						.unwrap_or_else(|_| panic!("Browser error outside JSON")),
					json!({"error":message})
				);
				assert!(captured.is_empty(), "rejected Browser input reached upstream");
			},
			Ok(None) => {
				assert_eq!(status, 200);
				let value: Value =
					serde_json::from_slice(&body).unwrap_or_else(|_| panic!("config JSON"));
				assert_eq!(value["protocol_version"], 2);
				assert_eq!(value["poll_seconds"], 5);
				assert!(captured.is_empty());
			},
			Ok(Some(expected)) => {
				assert_eq!(status, 201);
				assert_eq!(captured.len(), 1);
				let observed = &captured[0];
				assert_eq!(observed.method, expected.method);
				assert_eq!(observed.uri, expected.uri);
				assert_eq!(observed.protocol.as_deref(), Some("2"));
				assert!(!observed.capability);
				let actual = if observed.body.is_empty() {
					None
				} else {
					Some(
						serde_json::from_slice::<Value>(&observed.body)
							.unwrap_or_else(|_| panic!("upstream body JSON")),
					)
				};
				assert_eq!(
					actual, expected.body,
					"Browser unknown/last-wins/PAT/stamp semantics changed"
				);
				if recipe == Some(3) {
					assert!(
						observed.body.len() > BROWSER_CAP,
						"protocol stamp introduced an outbound input cap"
					);
				}
			},
		}
		if let Some(index) = case.owner {
			let (_, _, owner, name) = BODY_ROUTES[index];
			let admitted = case.forward.is_ok();
			assert_eq!(
				trace.entries.contains(&owner),
				json_media(case.media.as_ref()) && !matches!(recipe, Some(2 | 4 | 5)),
				"named Browser body validator was bypassed"
			);
			let values: Vec<_> = trace
				.values
				.iter()
				.filter_map(|v| {
					if let Observation::Body {
						owner,
						absent,
						original_len,
						shared_pointer,
						debug,
					} = v
					{
						Some((*owner, *absent, *original_len, *shared_pointer, debug))
					} else {
						None
					}
				})
				.collect();
			assert_eq!(values.len(), usize::from(admitted));
			if admitted {
				let value = &values[0];
				assert_eq!(value.0, owner);
				assert_eq!(value.1, case.media.is_none());
				assert_eq!(value.2, if case.media.is_none() { 0 } else { case.raw.len() });
				assert!(value.3);
				assert_eq!(value.4, &format!("{name}([redacted])"));
			}
			if case.media.is_none() || !json_media(case.media.as_ref()) {
				assert_eq!(polls.load(Ordering::SeqCst), 0);
			}
			if case.media.is_some() && json_media(case.media.as_ref()) {
				assert!(
					drops.iter().any(|(capacity, _, _)| *capacity == BROWSER_CAP),
					"Browser collection owner cleanup missing"
				);
			}
		}
		if case.forward.is_ok() {
			let values: Vec<_> = trace
				.values
				.iter()
				.filter_map(|v| {
					if let Observation::BrowserText(field, text) = v {
						Some((*field, text.clone()))
					} else {
						None
					}
				})
				.collect();
			assert_eq!(values, case.query_values, "typed Browser query changed before legacy exit");
		}
	});
}
pub fn web_api_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}
/// # Safety
/// `data` must point to `datalen` readable bytes throughout this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_api_run(data: *const u8, datalen: usize) {
	// SAFETY: the fuzzer supplies readable bytes throughout this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn empty_id_routes_keep_terminal_and_intermediate_controls() {
		do_test(&[7]);
		do_test(&[1]);
		do_test(&[11]);
		for route in 0..11 {
			do_test(&[11, route]);
		}
		do_test(&[0xf5, 0x2d]);
	}
	#[test]
	fn router_and_native_controls() {
		for input in [
			b"\x07".as_slice(),
			b"\0wrong",
			b"\x04evil.invalid",
			b"\x01+0007",
			b"\x01-9223372036854775808",
			b"\x01FAKE_PATH_SENTINEL",
			b"\x02-2",
			b"\x09limit=-2&state=&kind=++&unknown=x",
			b"\x0aq=++e%CC%81%0A%26%3D%2B%25++&limit=-3",
			b"\x0aq=%1bFAKE_QUERY",
			b"\x0chttp://example.invalid/path",
			b"\x0cFAKE_BAD_URL",
			b"\x0dnative-\xff",
			b"\x0eFAKE_PEM",
			b"\x0e\xff",
			b"\x11\x05",
			b"\x11\x06",
			b"\x11\x0d",
			b"\x16",
		] {
			do_test(input);
		}
		for selector in 0..10 {
			let mut input = vec![15, selector];
			input.extend_from_slice(b"FAKE_PEM");
			do_test(&input);
		}
		for route in 0..6 {
			for media in 0..6 {
				let mut input = vec![8, route, media];
				input.extend_from_slice(format!("{{\"github_pat\":\"old\",\"github_\\u0070at\":\"{PAT}\",\"extra\":{{\"same\":1,\"same\":2}}}}").as_bytes());
				do_test(&input);
			}
		}
		for route in 0..11 {
			let mut input = vec![11, route];
			input.extend_from_slice(b"+007");
			do_test(&input);
		}
	}
	#[test]
	fn collection_budget_cleanup_and_uri_preflight() {
		for recipe in 0..10 {
			do_test(&[18, recipe]);
		}
		for suffix in [b"%FF".as_slice(), b"%E2%82", b"%E2%28%A1", b"%F0%90%80%80", b"+%2B", b"%GG"]
		{
			for budget in 0..3 {
				let mut input = vec![16, budget];
				input.extend_from_slice(suffix);
				do_test(&input);
			}
		}
	}
}
