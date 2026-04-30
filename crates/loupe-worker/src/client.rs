//! Typed reqwest client for talking to loupe-server. Constructed once at
//! startup; methods on it serialise the proto DTOs and shuttle them
//! over mTLS.

use anyhow::{anyhow, Context, Result};
use loupe_proto::{
	CompleteRequest, FindingsBatch, HeartbeatResponse, KnownFingerprintsRequest,
	KnownFingerprintsResponse, LeaseRequest, LeaseResponse, ListFindingsResponse,
	VerdictSubmission, PROTOCOL_VERSION,
};
use reqwest::Url;

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
		let resp = self.http.post(url).json(&req).send().await.context("lease request")?;
		ensure_ok(&resp)?;
		resp.json().await.context("decoding lease response")
	}

	pub async fn heartbeat(&self, job_id: i64) -> Result<HeartbeatResponse> {
		let url = self.url(&format!("/v1/jobs/{job_id}/heartbeat"));
		let resp = self.http.post(url).send().await.context("heartbeat request")?;
		ensure_ok(&resp)?;
		resp.json().await.context("decoding heartbeat")
	}

	pub async fn submit_findings(&self, job_id: i64, batch: &FindingsBatch) -> Result<()> {
		let url = self.url(&format!("/v1/jobs/{job_id}/findings"));
		let resp = self.http.post(url).json(batch).send().await.context("findings request")?;
		ensure_ok(&resp)
	}

	pub async fn complete(&self, job_id: i64, req: &CompleteRequest) -> Result<()> {
		let url = self.url(&format!("/v1/jobs/{job_id}/complete"));
		let resp = self.http.post(url).json(req).send().await.context("complete request")?;
		ensure_ok(&resp)
	}

	pub async fn submit_verdict(&self, job_id: i64, req: &VerdictSubmission) -> Result<()> {
		let url = self.url(&format!("/v1/jobs/{job_id}/verdict"));
		let resp = self.http.post(url).json(req).send().await.context("verdict request")?;
		ensure_ok(&resp)
	}

	/// FTS keyword search over a repo's accumulated findings. The
	/// MCP server's `query_prior_findings` tool calls this. `query`
	/// is free-form keywords; the server sanitises them.
	pub async fn search_findings(
		&self, repo_id: i64, query: &str, limit: i64,
	) -> Result<ListFindingsResponse> {
		let url = self.url(&format!("/v1/repos/{repo_id}/findings/search"));
		let resp = self
			.http
			.get(url)
			.query(&[("q", query), ("limit", &limit.to_string())])
			.send()
			.await
			.context("search request")?;
		ensure_ok(&resp)?;
		resp.json().await.context("decoding search response")
	}

	/// Worker-side dedup pass: of these candidate fingerprints, which
	/// already exist on the repo? Used between discovery and
	/// validation so the worker doesn't pay validation LLM cost on
	/// candidates that already hash-match a prior finding.
	pub async fn known_fingerprints(
		&self, repo_id: i64, fingerprints: Vec<String>,
	) -> Result<KnownFingerprintsResponse> {
		let url = self.url(&format!("/v1/repos/{repo_id}/findings/known-fingerprints"));
		let req = KnownFingerprintsRequest { protocol_version: PROTOCOL_VERSION, fingerprints };
		let resp =
			self.http.post(url).json(&req).send().await.context("known-fingerprints request")?;
		ensure_ok(&resp)?;
		resp.json().await.context("decoding known-fingerprints response")
	}

	fn url(&self, path: &str) -> Url {
		self.base.join(path).expect("path is always valid")
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

fn ensure_ok(resp: &reqwest::Response) -> Result<()> {
	if resp.status().is_success() {
		Ok(())
	} else {
		Err(anyhow!("server returned {}", resp.status()))
	}
}
