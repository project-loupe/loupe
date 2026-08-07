//! Typed reqwest client for talking to loupe-server. Constructed once at
//! startup; methods on it serialise the proto DTOs and shuttle them
//! over mTLS.

use anyhow::{anyhow, Context, Result};
use loupe_proto::{
	CompleteRequest, FindingDetail, FindingsBatch, HeartbeatRequest, HeartbeatResponse,
	LeaseRequest, LeaseResponse, ListFindingsResponse, VerdictSubmission, PROTOCOL_VERSION,
	PROTOCOL_VERSION_HEADER,
};
use reqwest::Url;

/// The server no longer considers this worker the holder of the job's
/// lease — the reaper reclaimed it after the lease TTL elapsed.
///
/// Typed because the correct response is different from every other
/// heartbeat error. A network blip is worth retrying; this is not.
/// Once the lease is gone, the findings the scan submits and the
/// completion call it ends with are all rejected, so continuing to
/// scan produces nothing but load and, with an LLM scanner, spend.
#[derive(Debug, thiserror::Error)]
#[error("lease for job {job_id} is no longer held by this worker")]
pub struct LeaseLost {
	pub job_id: i64,
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
		resp.json().await.context("decoding lease response")
	}

	pub async fn heartbeat(&self, job_id: i64) -> Result<HeartbeatResponse> {
		let url = self.url(&format!("/v1/jobs/{job_id}/heartbeat"));
		let req = HeartbeatRequest { protocol_version: PROTOCOL_VERSION };
		let resp = self
			.with_protocol(self.http.post(url))
			.json(&req)
			.send()
			.await
			.context("heartbeat request")?;
		if resp.status() == reqwest::StatusCode::FORBIDDEN {
			return Err(anyhow::Error::new(LeaseLost { job_id }));
		}
		let resp = ensure_ok(resp).await?;
		resp.json().await.context("decoding heartbeat")
	}

	pub async fn submit_findings(&self, job_id: i64, batch: &FindingsBatch) -> Result<()> {
		let url = self.url(&format!("/v1/jobs/{job_id}/findings"));
		let resp = self
			.with_protocol(self.http.post(url))
			.json(batch)
			.send()
			.await
			.context("findings request")?;
		ensure_ok(resp).await.map(|_| ())
	}

	pub async fn complete(&self, job_id: i64, req: &CompleteRequest) -> Result<()> {
		let url = self.url(&format!("/v1/jobs/{job_id}/complete"));
		let resp = self
			.with_protocol(self.http.post(url))
			.json(req)
			.send()
			.await
			.context("complete request")?;
		ensure_ok(resp).await.map(|_| ())
	}

	pub async fn submit_verdict(&self, job_id: i64, req: &VerdictSubmission) -> Result<()> {
		let url = self.url(&format!("/v1/jobs/{job_id}/verdict"));
		let resp = self
			.with_protocol(self.http.post(url))
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
		&self, repo_id: i64, query: &str, limit: i64,
	) -> Result<ListFindingsResponse> {
		let url = self.url(&format!("/v1/repos/{repo_id}/findings/search"));
		let resp = self
			.with_protocol(self.http.get(url).query(&[("q", query), ("limit", &limit.to_string())]))
			.send()
			.await
			.context("search request")?;
		let resp = ensure_ok(resp).await?;
		resp.json().await.context("decoding search response")
	}

	/// Fetch the full detail view for one finding by id. Used by the
	/// MCP `get_finding_by_id` tool when the agent wants the
	/// description / PoC body of a search hit beyond what
	/// `query_prior_findings` (a summary-only listing) returned.
	pub async fn get_finding(&self, id: i64) -> Result<FindingDetail> {
		let url = self.url(&format!("/v1/findings/{id}"));
		let resp =
			self.with_protocol(self.http.get(url)).send().await.context("get_finding request")?;
		let resp = ensure_ok(resp).await?;
		resp.json().await.context("decoding finding detail")
	}

	fn url(&self, path: &str) -> Url {
		self.base.join(path).expect("path is always valid")
	}

	fn with_protocol(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
		req.header(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string())
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

async fn ensure_ok(resp: reqwest::Response) -> Result<reqwest::Response> {
	if !resp.status().is_success() {
		let status = resp.status();
		let body =
			resp.text().await.unwrap_or_else(|e| format!("<failed to read response body: {e}>"));
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
	Ok(resp)
}

#[cfg(test)]
mod tests {
	use loupe_proto::CompleteOutcome;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::net::TcpListener;

	use super::*;

	#[tokio::test]
	async fn server_error_includes_response_body() {
		let body = "successful verify completion requires a submitted verdict";
		let base = serve_once("HTTP/1.1 409 Conflict", body).await;
		let client = ServerClient::from_parts(reqwest::Client::new(), base);
		let err = client
			.complete(
				1513,
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

	/// A reclaimed lease must be distinguishable from a transient
	/// heartbeat failure. The runner keys its abort decision on the
	/// type: everything else is retryable, this is not.
	#[tokio::test]
	async fn heartbeat_403_is_a_typed_lease_loss() {
		let base = serve_once("HTTP/1.1 403 Forbidden", "lease not held by this worker").await;
		let client = ServerClient::from_parts(reqwest::Client::new(), base);

		let err = client.heartbeat(4242).await.expect_err("403 must be an error");

		let lost = err
			.downcast_ref::<LeaseLost>()
			.expect("403 on heartbeat must surface as LeaseLost, not an opaque anyhow");
		assert_eq!(lost.job_id, 4242);
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
