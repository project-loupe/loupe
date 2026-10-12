//! Typed reqwest client for talking to loupe-server. Constructed once at
//! startup; methods on it serialise the proto DTOs and shuttle them
//! over mTLS.

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use loupe_http::read_response_bytes;
use loupe_proto::{
	CompleteRequest, FindingDetail, FindingsBatch, HeartbeatRequest, HeartbeatResponse,
	JobCapability, LeaseRequest, LeaseResponse, ListFindingsResponse, LlmFindingSubmission,
	VerdictSubmission, JOB_CAPABILITY_HEADER, PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER,
};
use reqwest::header::{HeaderValue, InvalidHeaderValue};
use reqwest::Url;

/// Named authentication handoff: Bytes keeps this shared secret owner alive
/// through header clones. HTTP/TLS encoding and kernel copies are not covered
/// by the original Secret allocation's wipe-on-drop guarantee.
struct CapabilityHeader(JobCapability);

impl AsRef<[u8]> for CapabilityHeader {
	fn as_ref(&self) -> &[u8] {
		self.0.expose_secret().as_bytes()
	}
}

impl TryFrom<CapabilityHeader> for HeaderValue {
	type Error = InvalidHeaderValue;

	fn try_from(value: CapabilityHeader) -> Result<Self, Self::Error> {
		let mut header = Self::from_maybe_shared(Bytes::from_owner(value))?;
		header.set_sensitive(true);
		Ok(header)
	}
}

pub struct ServerClient {
	http: reqwest::Client,
	base: Url,
}

impl ServerClient {
	pub fn new(
		server_cert_pem: &str, client_cert_pem: &str, client_key_pem: &str, base: Url,
	) -> Result<Self> {
		let identity = build_identity(client_cert_pem, client_key_pem)?;
		let root = reqwest::Certificate::from_pem(server_cert_pem.as_bytes())
			.context("parsing server CA PEM")?;
		let http = reqwest::Client::builder()
			.add_root_certificate(root)
			.identity(identity)
			.use_rustls_tls()
			.build()
			.context("building reqwest client")?;
		Ok(Self { http, base })
	}

	/// Construct from a pre-built `reqwest::Client`. Useful for tests
	/// (which want `Client::builder().resolve(...)`) and for callers
	/// that need to inject their own connector / proxy / DNS overrides.
	pub fn from_parts(http: reqwest::Client, base: Url) -> Self {
		Self { http, base }
	}

	pub async fn lease(
		&self, capabilities: Vec<String>, wait_seconds: u32,
	) -> Result<LeaseResponse> {
		let url = self.url("/v1/jobs/lease");
		let req = LeaseRequest { protocol_version: PROTOCOL_VERSION, capabilities, wait_seconds };
		let resp = self
			.with_protocol(self.http.post(url))
			.json(&req)
			.send()
			.await
			.context("lease request")?;
		let resp = ensure_ok(resp).await?;
		serde_json::from_slice(&resp).context("decoding lease response")
	}

	pub async fn heartbeat(
		&self, job_id: i64, job_capability: &JobCapability,
	) -> Result<HeartbeatResponse> {
		let url = self.url(&format!("/v1/jobs/{job_id}/heartbeat"));
		let req = HeartbeatRequest { protocol_version: PROTOCOL_VERSION };
		let resp = self
			.with_job_capability(self.http.post(url), job_capability)
			.json(&req)
			.send()
			.await
			.context("heartbeat request")?;
		let resp = ensure_ok(resp).await?;
		serde_json::from_slice(&resp).context("decoding heartbeat")
	}

	pub async fn submit_findings(
		&self, job_id: i64, job_capability: &JobCapability, batch: &FindingsBatch,
	) -> Result<()> {
		let url = self.url(&format!("/v1/jobs/{job_id}/findings"));
		let resp = self
			.with_job_capability(self.http.post(url), job_capability)
			.json(batch)
			.send()
			.await
			.context("findings request")?;
		ensure_ok(resp).await.map(|_| ())
	}

	pub async fn submit_llm_finding(
		&self, job_id: i64, job_capability: &JobCapability, finding: &LlmFindingSubmission,
	) -> Result<()> {
		let url = self.url(&format!("/v1/jobs/{job_id}/llm-findings"));
		let resp = self
			.with_job_capability(self.http.post(url), job_capability)
			.json(finding)
			.send()
			.await
			.context("LLM finding request")?;
		ensure_ok(resp).await.map(|_| ())
	}

	pub async fn complete(
		&self, job_id: i64, job_capability: &JobCapability, req: &CompleteRequest,
	) -> Result<()> {
		let url = self.url(&format!("/v1/jobs/{job_id}/complete"));
		let resp = self
			.with_job_capability(self.http.post(url), job_capability)
			.json(req)
			.send()
			.await
			.context("complete request")?;
		ensure_ok(resp).await.map(|_| ())
	}

	pub async fn submit_verdict(
		&self, job_id: i64, job_capability: &JobCapability, req: &VerdictSubmission,
	) -> Result<()> {
		let url = self.url(&format!("/v1/jobs/{job_id}/verdict"));
		let resp = self
			.with_job_capability(self.http.post(url), job_capability)
			.json(req)
			.send()
			.await
			.context("verdict request")?;
		ensure_ok(resp).await.map(|_| ())
	}

	/// FTS keyword search over a repo's accumulated findings. The
	/// MCP server's `query_prior_findings` tool calls this. `query`
	/// is free-form keywords; the server sanitises them.
	pub async fn search_findings(
		&self, repo_id: i64, job_capability: &JobCapability, query: &str, limit: i64,
	) -> Result<ListFindingsResponse> {
		let url = self.url(&format!("/v1/repos/{repo_id}/findings/search"));
		let resp = self
			.with_job_capability(
				self.http.get(url).query(&[("q", query), ("limit", &limit.to_string())]),
				job_capability,
			)
			.send()
			.await
			.context("search request")?;
		let resp = ensure_ok(resp).await?;
		serde_json::from_slice(&resp).context("decoding search response")
	}

	/// Fetch the full detail view for one finding by id. Used by the
	/// MCP `get_finding_by_id` tool when the agent wants the
	/// description / PoC body of a search hit beyond what
	/// `query_prior_findings` (a summary-only listing) returned.
	pub async fn get_finding(
		&self, id: i64, job_capability: &JobCapability,
	) -> Result<FindingDetail> {
		let url = self.url(&format!("/v1/findings/{id}"));
		let resp = self
			.with_job_capability(self.http.get(url), job_capability)
			.send()
			.await
			.context("get_finding request")?;
		let resp = ensure_ok(resp).await?;
		serde_json::from_slice(&resp).context("decoding finding detail")
	}

	fn url(&self, path: &str) -> Url {
		self.base.join(path).expect("path is always valid")
	}

	fn with_protocol(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
		req.header(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string())
	}

	fn with_job_capability(
		&self, req: reqwest::RequestBuilder, job_capability: &JobCapability,
	) -> reqwest::RequestBuilder {
		self.with_protocol(req)
			.header(JOB_CAPABILITY_HEADER, CapabilityHeader(job_capability.clone()))
	}
}

fn build_identity(cert_pem: &str, key_pem: &str) -> Result<reqwest::Identity> {
	let mut combined = String::with_capacity(cert_pem.len() + key_pem.len() + 1);
	combined.push_str(cert_pem);
	if !cert_pem.ends_with('\n') {
		combined.push('\n');
	}
	combined.push_str(key_pem);
	reqwest::Identity::from_pem(combined.as_bytes())
		.map_err(|e| anyhow!("building reqwest identity from PEM: {e}"))
}

async fn ensure_ok(resp: reqwest::Response) -> Result<Vec<u8>> {
	if !resp.status().is_success() {
		let status = resp.status();
		let bytes = read_response_bytes(resp)
			.await
			.map_err(|error| anyhow!("server returned {status}: {error}"))?;
		let body = String::from_utf8_lossy(&bytes);
		let body = body.trim();
		if body.is_empty() {
			return Err(anyhow!("server returned {status}"));
		}
		return Err(anyhow!("server returned {status}: {body}"));
	}
	let header = resp
		.headers()
		.get(PROTOCOL_VERSION_HEADER)
		.ok_or_else(|| anyhow!("server response missing {PROTOCOL_VERSION_HEADER}"))?;
	let server_version = header
		.to_str()
		.context("server protocol header is not valid ASCII")?
		.parse::<u16>()
		.context("server protocol header is not a u16")?;
	if server_version != PROTOCOL_VERSION {
		return Err(anyhow!(
			"server protocol mismatch: worker speaks {PROTOCOL_VERSION}, server sent {server_version}"
		));
	}
	read_response_bytes(resp).await.map_err(|error| anyhow!("reading server response: {error}"))
}

#[cfg(test)]
mod tests {
	use loupe_proto::CompleteOutcome;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::net::TcpListener;

	use super::*;

	const HEADER_CAPABILITY: &str = "worker-header-debug-sentinel-49f0b21";

	fn request_with_capability() -> reqwest::Request {
		let client =
			ServerClient::from_parts(reqwest::Client::new(), "http://127.0.0.1/".parse().unwrap());
		let capability = JobCapability::from_secret(HEADER_CAPABILITY);
		client
			.with_job_capability(client.http.post(client.url("/v1/jobs/17/heartbeat")), &capability)
			.build()
			.unwrap()
	}

	#[test]
	fn capability_header_is_sensitive_and_preserves_wire_value() {
		let request = request_with_capability();
		let header = &request.headers()[JOB_CAPABILITY_HEADER];
		assert_eq!(header.to_str().unwrap(), HEADER_CAPABILITY);
		assert!(header.is_sensitive(), "job capability header must be marked sensitive");
	}

	#[test]
	fn capability_header_debug_does_not_disclose_bearer() {
		let request = request_with_capability();
		assert!(
			!format!("{:?}", request.headers()).contains(HEADER_CAPABILITY),
			"worker request header Debug disclosed the job capability"
		);
		assert!(
			!format!("{request:?}").contains(HEADER_CAPABILITY),
			"worker request Debug disclosed the job capability"
		);
	}

	#[test]
	fn capability_header_retains_shared_storage_across_clones() {
		let client =
			ServerClient::from_parts(reqwest::Client::new(), "http://127.0.0.1/".parse().unwrap());
		let capability = JobCapability::from_secret(HEADER_CAPABILITY);
		let original_storage = capability.expose_secret().as_ptr();
		let request = client
			.with_job_capability(client.http.post(client.url("/v1/jobs/17/heartbeat")), &capability)
			.build()
			.unwrap();
		let header = request.headers()[JOB_CAPABILITY_HEADER].clone();
		assert_eq!(
			header.as_bytes().as_ptr(),
			original_storage,
			"capability header must retain the original secret allocation"
		);
		drop(request);
		drop(capability);
		assert_eq!(header.to_str().unwrap(), HEADER_CAPABILITY);
	}

	#[test]
	fn capability_header_rejects_invalid_bytes_without_disclosure() {
		let client =
			ServerClient::from_parts(reqwest::Client::new(), "http://127.0.0.1/".parse().unwrap());
		let capability = JobCapability::from_secret(format!("{HEADER_CAPABILITY}\r\ninvalid"));
		let error = client
			.with_job_capability(client.http.post(client.url("/v1/jobs/17/heartbeat")), &capability)
			.build()
			.unwrap_err();
		assert!(!format!("{error:?}").contains(HEADER_CAPABILITY));
		assert!(!error.to_string().contains(HEADER_CAPABILITY));
	}

	#[tokio::test]
	async fn server_error_includes_response_body() {
		let body = "successful verify completion requires a submitted verdict";
		let base = serve_once("HTTP/1.1 409 Conflict", body).await;
		let client = ServerClient::from_parts(reqwest::Client::new(), base);
		let job_capability = JobCapability::from_secret("test-capability");
		let err = client
			.complete(
				1513,
				&job_capability,
				&CompleteRequest {
					protocol_version: PROTOCOL_VERSION,
					outcome: CompleteOutcome::Succeeded,
					head_sha: None,
					error: None,
				},
			)
			.await
			.expect_err("complete should fail on server 409");

		let msg = err.to_string();
		assert!(msg.contains("409 Conflict"), "error should include status: {msg}");
		assert!(
			msg.contains(body),
			"error should include response body so worker logs show the failure reason: {msg}",
		);
	}

	async fn serve_once(status_line: &str, body: &str) -> Url {
		let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind test server");
		let addr = listener.local_addr().expect("test server addr");
		let status_line = status_line.to_owned();
		let body = body.to_owned();
		tokio::spawn(async move {
			let (mut stream, _) = listener.accept().await.expect("accept test request");
			let mut buf = [0_u8; 1024];
			let _ = stream.read(&mut buf).await.expect("read test request");
			let response = format!(
				"{status_line}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
				body.len(),
			);
			stream.write_all(response.as_bytes()).await.expect("write test response");
		});
		Url::parse(&format!("http://{addr}/")).expect("test server URL")
	}
}
