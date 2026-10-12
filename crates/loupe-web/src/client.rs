//! Closed admin operations. Browser, Server and Config owners survive to their
//! selected HTTP/TLS sinks; the client has no arbitrary request or JSON exit.
use anyhow::Result;
use axum::response::{IntoResponse, Response};
use loupe_proto::{PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use reqwest::{Method, StatusCode};

use crate::config::{ConfigUrl, ConnArgs};
use crate::ingress::bodies::*;
use crate::ingress::queries::{BrowserJobs, BrowserSearch};
use crate::ingress::server::{self, Failure, ServerDiagnostic};
use crate::ingress::BrowserLimit;

/// An upstream failure retains the original Server diagnostic until Display.
/// Debug only renders the status and a redaction marker.
///
/// ```compile_fail,E0609
/// fn raw(error: loupe_web::client::UpstreamError) -> String { error.message }
/// ```
pub struct UpstreamError(ErrorSource);
enum ErrorSource {
	Host(Failure),
	Server(ServerDiagnostic),
}
impl UpstreamError {
	pub(crate) fn host(failure: Failure) -> Self {
		Self(ErrorSource::Host(failure))
	}
	pub(crate) fn diagnostic(diagnostic: ServerDiagnostic) -> Self {
		Self(ErrorSource::Server(diagnostic))
	}
	pub fn status(&self) -> Option<StatusCode> {
		match &self.0 {
			ErrorSource::Host(f) => f.status(),
			ErrorSource::Server(d) => Some(d.status()),
		}
	}
}
impl std::fmt::Debug for UpstreamError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("UpstreamError")
			.field("status", &self.status())
			.field("message", &"[redacted]")
			.finish()
	}
}
impl std::fmt::Display for UpstreamError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if let Some(status) = self.status() {
			write!(f, "{status}: ")?;
		}
		match &self.0 {
			ErrorSource::Host(failure) => f.write_str(&failure.message()),
			ErrorSource::Server(diagnostic) => diagnostic.fmt_message(f),
		}
	}
}
impl std::error::Error for UpstreamError {}
pub type UpstreamResult<T> = std::result::Result<T, UpstreamError>;

/// Opaque startup response. Server text stays in its guarded source owner.
///
/// ```compile_fail,E0308
/// async fn raw_response(client: &loupe_web::AdminClient) {
///     let _: serde_json::Value = client.health().await.unwrap();
/// }
/// ```
/// ```compile_fail,E0308
/// async fn agent_response(client: &loupe_web::AdminClient) {
///     let _: loupe_core::text::BoundedText<loupe_core::text::policy::FindingTitle, loupe_provenance::Agent> = client.health().await.unwrap();
/// }
/// ```
/// ```
/// fn requires_debug<T: std::fmt::Debug>() {}
/// requires_debug::<loupe_web::client::HealthResponse>();
/// ```
pub struct HealthResponse(pub(crate) server::ServerJson);
impl std::fmt::Debug for HealthResponse {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		self.0.fmt(f)
	}
}

/// The only operations the browser router can dispatch. Text-bearing variants
/// require the corresponding actual Browser extractor, never raw JSON/strings.
pub(crate) enum AdminRequest {
	Health,
	Whoami,
	GithubApp,
	ListRepos(BrowserLimit),
	CreateRepo(BrowserCreateRepo),
	UpdateRepo(i64, BrowserUpdateRepo),
	DeleteRepo(i64),
	RotatePat(i64, BrowserRotatePat),
	SetGithubReporting(i64, BrowserSetGithubReporting),
	EnqueueScan(i64, BrowserEnqueueScan),
	ListJobs(BrowserJobs),
	GetJob(i64),
	RetryJob(i64),
	CancelJob(i64),
	ListFindings(i64, BrowserLimit),
	SearchFindings(i64, BrowserSearch),
	GetFinding(i64),
	ApproveFinding(i64),
	RejectFinding(i64),
	RetryReportFinding(i64),
	RetryVerify(BrowserRetryVerify),
}
impl AdminRequest {
	fn endpoint(&self) -> (Method, std::borrow::Cow<'static, str>) {
		use AdminRequest::*;
		match self {
			Health => (Method::GET, "/v1/health".into()),
			Whoami => (Method::GET, "/v1/whoami".into()),
			GithubApp => (Method::GET, "/v1/github-app".into()),
			ListRepos(_) => (Method::GET, "/v1/repos".into()),
			CreateRepo(_) => (Method::POST, "/v1/repos".into()),
			UpdateRepo(id, _) => (Method::PATCH, format!("/v1/repos/{id}").into()),
			DeleteRepo(id) => (Method::DELETE, format!("/v1/repos/{id}").into()),
			RotatePat(id, _) => {
				(Method::POST, format!("/v1/repos/{id}/reporting/github-pat").into())
			},
			SetGithubReporting(id, _) => {
				(Method::PUT, format!("/v1/repos/{id}/reporting/github").into())
			},
			EnqueueScan(id, _) => (Method::POST, format!("/v1/repos/{id}/scan").into()),
			ListJobs(_) => (Method::GET, "/v1/jobs".into()),
			GetJob(id) => (Method::GET, format!("/v1/jobs/{id}").into()),
			RetryJob(id) => (Method::POST, format!("/v1/jobs/{id}/retry").into()),
			CancelJob(id) => (Method::POST, format!("/v1/jobs/{id}/cancel").into()),
			ListFindings(id, _) => (Method::GET, format!("/v1/repos/{id}/findings").into()),
			SearchFindings(id, _) => {
				(Method::GET, format!("/v1/repos/{id}/findings/search").into())
			},
			GetFinding(id) => (Method::GET, format!("/v1/findings/{id}").into()),
			ApproveFinding(id) => (Method::POST, format!("/v1/findings/{id}/approve").into()),
			RejectFinding(id) => (Method::POST, format!("/v1/findings/{id}/reject").into()),
			RetryReportFinding(id) => {
				(Method::POST, format!("/v1/findings/{id}/retry-report").into())
			},
			RetryVerify(_) => (Method::POST, "/v1/findings/retry-verify".into()),
		}
	}
}

/// Admin-authenticated client with a closed endpoint set.
///
/// ```compile_fail,E0599
/// async fn arbitrary(client: &loupe_web::AdminClient) {
///     client.call(reqwest::Method::GET, "/arbitrary", &[], None).await;
/// }
/// ```
/// ```compile_fail,E0599
/// async fn arbitrary(client: &loupe_web::AdminClient) {
///     client.get_typed::<serde_json::Value>("/arbitrary").await;
/// }
/// ```
#[derive(Clone)]
pub struct AdminClient {
	http: reqwest::Client,
	base: ConfigUrl,
}
impl AdminClient {
	/// Select the actual Config inputs and borrow PEM only at the TLS sink.
	pub fn new(config: &ConnArgs) -> Result<Self> {
		let base = config.server_url()?;
		let http = config.tls_client()?;
		Ok(Self { http, base })
	}
	/// Use an already configured transport with a URL admitted by actual Clap.
	/// Integration tests use this to resolve a test server's ephemeral address.
	/// ```compile_fail,E0308
	/// fn raw(http: reqwest::Client, url: reqwest::Url) {
	///     loupe_web::AdminClient::from_parts(http, url);
	/// }
	/// ```
	pub fn from_parts(http: reqwest::Client, base: ConfigUrl) -> Self {
		Self { http, base }
	}
	fn request(&self, operation: &AdminRequest) -> Result<reqwest::RequestBuilder, Failure> {
		let (method, path) = operation.endpoint();
		Ok(self
			.base
			.admin_request(&self.http, method, &path)?
			.header(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string()))
	}
	pub(crate) async fn forward(&self, operation: AdminRequest) -> Response {
		let request = match self.request(&operation) {
			Ok(request) => request,
			Err(error) => return error.into_response(),
		};
		use AdminRequest::*;
		let response = match operation {
			CreateRepo(body) => body.send(request).await.map_err(|response| *response),
			UpdateRepo(_, body) => body.send(request).await.map_err(|response| *response),
			RotatePat(_, body) => body.send(request).await.map_err(|response| *response),
			SetGithubReporting(_, body) => body.send(request).await.map_err(|response| *response),
			EnqueueScan(_, body) => body.send(request).await.map_err(|response| *response),
			RetryVerify(body) => body.send(request).await.map_err(|response| *response),
			ListJobs(query) => {
				query.send(request).await.map_err(|_| Failure::Transport.into_response())
			},
			SearchFindings(_, query) => {
				query.send(request).await.map_err(|_| Failure::Transport.into_response())
			},
			ListRepos(query) | ListFindings(_, query) => {
				query.send(request).await.map_err(|_| Failure::Transport.into_response())
			},
			_ => request.send().await.map_err(|_| Failure::Transport.into_response()),
		};
		match response {
			Ok(response) => match server::receive(response).await {
				Ok(outcome) => outcome.into_response(),
				Err(error) => error.into_response(),
			},
			Err(response) => response,
		}
	}
	/// Fixed startup liveness probe; no generic Server JSON projection exists.
	pub async fn health(&self) -> UpstreamResult<HealthResponse> {
		let response = self
			.request(&AdminRequest::Health)
			.map_err(Failure::into_error)?
			.send()
			.await
			.map_err(|_| Failure::Transport.into_error())?;
		server::receive(response).await.map_err(Failure::into_error)?.into_health()
	}
	/// Render the selected Config URL and opaque health only at startup's log or
	/// terminal diagnostic sink.
	pub async fn check_startup(&self) -> Result<()> {
		self.base.report_startup(self.health().await)
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
		use clap::Parser;
		let cli = crate::Cli::try_parse_from([
			"loupe-web".to_owned(),
			"--server-url=https://localhost/".to_owned(),
			format!("--ca-cert-pem={ca}"),
			format!("--admin-cert-pem={cert}"),
			format!("--admin-key-pem={key}"),
		])?;
		Ok(AdminClient::new(&cli.conn)?.http)
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
