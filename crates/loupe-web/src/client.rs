//! Typed client for the `loupe-server` admin RPCs.
//!
//! Modelled on `loupe-worker`'s client rather than `loupectl`'s: it sends
//! `X-Loupe-Protocol` on every request *and* validates it on every
//! response, and folds the response body into its errors. Both matter for
//! a UI — server errors are plain text, not JSON, so the body is the only
//! useful message, and a protocol cutover should surface as one clear
//! banner instead of a wall of opaque 400s.

use anyhow::{Context, Result};
use loupe_proto::{PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use reqwest::{Method, StatusCode, Url};

/// An upstream call that failed. Keeps the status so the dashboard can
/// pass a meaningful code back to the browser rather than flattening
/// everything to 500.
#[derive(Debug)]
pub struct UpstreamError {
	pub status: Option<StatusCode>,
	pub message: String,
}

impl std::fmt::Display for UpstreamError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self.status {
			Some(status) => write!(f, "{status}: {}", self.message),
			None => f.write_str(&self.message),
		}
	}
}

impl std::error::Error for UpstreamError {}

impl UpstreamError {
	fn transport(message: String) -> Self {
		Self { status: None, message }
	}
}

pub type UpstreamResult<T> = std::result::Result<T, UpstreamError>;

/// Opaque startup response. Server text stays in its guarded source owner.
///
/// The production health owner cannot become an arbitrary JSON value:
///
/// ```compile_fail,E0308
/// async fn raw_response(client: &loupe_web::AdminClient) {
///     let _: serde_json::Value = client.health().await.unwrap();
/// }
/// ```
///
/// Its diagnostic form is available without exposing Server content:
///
/// ```
/// fn requires_debug<T: std::fmt::Debug>() {}
/// requires_debug::<loupe_web::client::HealthResponse>();
/// ```
pub struct HealthResponse(pub(crate) crate::ingress::server::ServerJson);
impl std::fmt::Debug for HealthResponse {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		self.0.fmt(f)
	}
}

/// Admin-authenticated client. Holds the mTLS identity; every method is a
/// thin pass-through so the dashboard never invents its own semantics.
#[derive(Clone)]
pub struct AdminClient {
	http: reqwest::Client,
	base: Url,
}

impl AdminClient {
	/// Build from PEM material. Pins the private loupe CA as an additional
	/// root and presents the admin cert; certificate verification stays on.
	pub fn new(base: Url, ca_pem: &str, cert_pem: &str, key_pem: &str) -> Result<Self> {
		let tls = loupe_tls::reqwest_client_config(cert_pem, key_pem, ca_pem)?;
		let http = reqwest::Client::builder()
			.use_preconfigured_tls(tls)
			.build()
			.context("building reqwest client")?;
		Ok(Self { http, base })
	}

	/// Test-only constructor for a pre-built client (lets integration
	/// tests use `.resolve()` to reach an ephemeral port).
	pub fn from_parts(http: reqwest::Client, base: Url) -> Self {
		Self { http, base }
	}

	/// Perform an admin request and return the raw JSON body.
	///
	/// Everything the dashboard exposes is a proxy, so one generic method
	/// beats a hand-written wrapper per route: there is no place for the
	/// two to drift, and the browser gets the server's own JSON shapes.
	/// Returns the upstream status alongside the body so the proxy can pass
	/// it through rather than flattening every success to 200 — `201` on
	/// create and `204` on the mutating routes are both meaningful.
	pub async fn call(
		&self, method: Method, path: &str, query: &[(&str, String)],
		body: Option<serde_json::Value>,
	) -> UpstreamResult<(StatusCode, Option<serde_json::Value>)> {
		let body = body
			.as_ref()
			.map(crate::ingress::json::legacy_value_bytes)
			.transpose()
			.map_err(|_| UpstreamError::transport("encoding upstream request failed".into()))?;
		self.call_forward(method, path, query, body)
			.await
			.map_err(crate::ingress::server::Failure::into_error_legacy)?
			.into_call_legacy()
	}

	pub(crate) async fn call_forward(
		&self, method: Method, path: &str, query: &[(&str, String)], body: Option<bytes::Bytes>,
	) -> Result<crate::ingress::server::Outcome, crate::ingress::server::Failure> {
		use crate::ingress::server::{self, Failure};
		let mut url = self.base.join(path).map_err(|_| Failure::Url)?;
		if !query.is_empty() {
			// Built through `query_pairs_mut` so values are percent-encoded:
			// the search term is free-form operator input.
			let mut pairs = url.query_pairs_mut();
			for (name, value) in query {
				pairs.append_pair(name, value);
			}
		}
		let mut req = self
			.http
			.request(method, url)
			.header(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string());
		if let Some(body) = body {
			req = req.header(reqwest::header::CONTENT_TYPE, "application/json").body(body);
		}
		let resp = req.send().await.map_err(|_| Failure::Transport)?;
		server::receive(resp).await
	}

	/// GET a path and deserialize into `T`. Used for the few places the
	/// dashboard itself needs to understand a response.
	pub async fn get_typed<T: serde::de::DeserializeOwned>(&self, path: &str) -> UpstreamResult<T> {
		let (_, value) = self.call(Method::GET, path, &[], None).await?;
		let value = value
			.ok_or_else(|| UpstreamError::transport("upstream returned an empty body".into()))?;
		serde_json::from_value(value)
			.map_err(|_| UpstreamError::transport("decoding upstream response failed".into()))
	}

	/// Stamp `protocol_version` into an outgoing body.
	///
	/// Every admin request DTO carries the field, and the server rejects a
	/// mismatch with a 400. Filling it in here means the browser never
	/// sends a version and cannot get it wrong.
	pub fn with_protocol_version(mut body: serde_json::Value) -> serde_json::Value {
		if let Some(map) = body.as_object_mut() {
			map.insert("protocol_version".to_owned(), serde_json::Value::from(PROTOCOL_VERSION));
		}
		body
	}

	/// Unauthenticated liveness probe. Returns the server's protocol
	/// version so the UI can diagnose a mismatch explicitly.
	pub async fn health(&self) -> UpstreamResult<HealthResponse> {
		self.call_forward(Method::GET, "/v1/health", &[], None)
			.await
			.map_err(crate::ingress::server::Failure::into_error_legacy)?
			.into_health_legacy()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn protocol_version_is_stamped_into_an_object() {
		let body = AdminClient::with_protocol_version(serde_json::json!({"incremental": true}));
		assert_eq!(body["protocol_version"], PROTOCOL_VERSION);
		assert_eq!(body["incremental"], true);
	}

	#[test]
	fn a_client_supplied_protocol_version_is_overwritten() {
		// The browser must not be able to talk a different protocol than
		// the build it is served from.
		let body =
			AdminClient::with_protocol_version(serde_json::json!({"protocol_version": 9999}));
		assert_eq!(body["protocol_version"], PROTOCOL_VERSION);
	}

	#[test]
	fn non_objects_pass_through_unchanged() {
		let body = AdminClient::with_protocol_version(serde_json::json!([1, 2, 3]));
		assert_eq!(body, serde_json::json!([1, 2, 3]));
	}

	#[test]
	fn upstream_error_renders_status_and_body() {
		let err = UpstreamError {
			status: Some(StatusCode::CONFLICT),
			message: "job 3 is Succeeded, not queued or leased".into(),
		};
		let rendered = err.to_string();
		assert!(rendered.contains("409"));
		assert!(rendered.contains("not queued or leased"));
	}

	#[test]
	fn transport_error_renders_without_a_status() {
		let err = UpstreamError::transport("upstream request failed: connection refused".into());
		assert_eq!(err.to_string(), "upstream request failed: connection refused");
	}
}

#[cfg(test)]
mod tls_constructor_controls {
	use std::sync::Arc;
	use std::time::Duration;

	use loupe_tls::Ca;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	use super::*;

	fn application_client(ca: &str, cert: &str, key: &str) -> anyhow::Result<reqwest::Client> {
		Ok(AdminClient::new("https://localhost/".parse().unwrap(), ca, cert, key)?.http)
	}

	async fn exchange(
		http: reqwest::Client, mut config: rustls::ServerConfig,
	) -> (bool, Option<(Vec<u8>, Vec<Vec<u8>>)>) {
		config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let port = listener.local_addr().unwrap().port();
		let mut task = tokio::spawn(async move {
			let (socket, _) = listener.accept().await.unwrap();
			let Ok(mut tls) =
				tokio_rustls::TlsAcceptor::from(Arc::new(config)).accept(socket).await
			else {
				return None;
			};
			let alpn = tls.get_ref().1.alpn_protocol().unwrap_or_default().to_vec();
			let chain = tls
				.get_ref()
				.1
				.peer_certificates()
				.unwrap_or_default()
				.iter()
				.map(|cert| cert.to_vec())
				.collect();
			let mut request = Vec::new();
			while !request.ends_with(b"\r\n\r\n") {
				let mut byte = [0u8; 1];
				if tls.read_exact(&mut byte).await.is_err() || request.len() == 16 * 1024 {
					return None;
				}
				request.push(byte[0]);
			}
			if tls
				.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
				.await
				.is_err()
			{
				return None;
			}
			let _ = tls.shutdown().await;
			Some((alpn, chain))
		});
		let success = tokio::time::timeout(Duration::from_secs(5), async {
			let response = http.get(format!("https://localhost:{port}/")).send().await?;
			let body = response.bytes().await?;
			Ok::<_, reqwest::Error>(body == b"ok".as_slice())
		})
		.await
		.is_ok_and(|result| result.unwrap_or(false));
		let peer = match tokio::time::timeout(Duration::from_secs(5), &mut task).await {
			Ok(result) => result.unwrap(),
			Err(_) => {
				task.abort();
				let _ = task.await;
				None
			},
		};
		(success, peer)
	}

	#[tokio::test]
	async fn actual_constructor_preserves_mtls_http11_chain_and_mixed_roots() {
		let ca = Ca::new("throwaway-application-ca").unwrap();
		let server = ca.mint_server("server", &["localhost".into()]).unwrap();
		let client = ca.mint_client("client").unwrap();
		let unused = ca.mint_client("unused").unwrap();
		let roots = format!("{}{}", unused.key_pem.expose(), ca.cert_pem());
		let chain = format!("{}{}", client.cert_pem, ca.cert_pem());
		let expected: Vec<_> = rustls_pemfile::certs(&mut chain.as_bytes())
			.map(|cert| cert.unwrap().to_vec())
			.collect();
		let http = application_client(&roots, &chain, client.key_pem.expose()).unwrap();
		let config =
			loupe_tls::server_config(&server.cert_pem, server.key_pem.expose(), ca.cert_pem())
				.unwrap();
		let (success, peer) = exchange(http, config).await;
		assert!(success, "actual application client must complete mutual TLS");
		let (alpn, observed) = peer.unwrap();
		assert_eq!(alpn, b"http/1.1");
		assert_eq!(observed, expected);
	}

	#[tokio::test]
	async fn actual_constructor_rejects_wrong_ca_hostname_and_mismatched_key() {
		let ca = Ca::new("throwaway-application-ca").unwrap();
		let foreign = Ca::new("throwaway-foreign-ca").unwrap();
		let client = ca.mint_client("client").unwrap();
		let wrong = ca.mint_client("wrong-key").unwrap();
		assert!(
			application_client(ca.cert_pem(), &client.cert_pem, wrong.key_pem.expose()).is_err()
		);
		for (host, roots) in [("localhost", foreign.cert_pem()), ("wrong-host", ca.cert_pem())] {
			let server = ca.mint_server("server", &[host.into()]).unwrap();
			let http =
				application_client(roots, &client.cert_pem, client.key_pem.expose()).unwrap();
			let config =
				loupe_tls::server_config(&server.cert_pem, server.key_pem.expose(), ca.cert_pem())
					.unwrap();
			assert!(
				!exchange(http, config).await.0,
				"verification must reject wrong trust or hostname"
			);
		}
	}
}
