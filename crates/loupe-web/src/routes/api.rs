//! JSON endpoints that proxy the `loupe-server` admin RPCs.
//!
//! Every route here is an explicit entry rather than a catch-all
//! forwarder. A wildcard proxy would let the browser reach any upstream
//! path — which the admin cert would happily authenticate — so the set of
//! reachable operations would be defined by whatever the page happened to
//! request rather than by this file. Query parameters are likewise
//! rebuilt from typed structs, not passed through, so the browser cannot
//! smuggle a parameter the server would honour.
//!
//! Request bodies get `protocol_version` stamped in by the client, so the
//! page never sends a version and cannot get it wrong.

use axum::extract::State;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::ingress::bodies::{
	BrowserCreateRepo, BrowserEnqueueScan, BrowserRetryVerify, BrowserRotatePat,
	BrowserSetGithubReporting, BrowserUpdateRepo,
};
use crate::ingress::queries::{BrowserJobs, BrowserSearch};
use crate::ingress::{BrowserId, BrowserLimit};
use crate::state::WebState;

/// Axum's path/query rejections may repeat browser input. Keep these
/// diagnostics inside the same JSON envelope as upstream API errors.
pub(crate) async fn enclose_bad_request(response: Response) -> Response {
	if response.status() != StatusCode::BAD_REQUEST
		|| !response
			.headers()
			.get(axum::http::header::CONTENT_TYPE)
			.and_then(|value| value.to_str().ok())
			.is_some_and(|value| value.starts_with("text/plain"))
	{
		return response;
	}
	// Extractor errors are small; a pathological URI must not create an
	// unbounded second allocation merely to construct an error response.
	let error = match axum::body::to_bytes(response.into_body(), 16 * 1024).await {
		Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
		Err(_) => "invalid request".to_owned(),
	};
	(StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": error }))).into_response()
}

async fn forward(
	state: &WebState, method: Method, path: &str, query: &[(&str, String)],
	body: Option<bytes::Bytes>,
) -> Response {
	match state.client.call_forward(method, path, query, body).await {
		Ok(outcome) => outcome.into_response_legacy(),
		Err(err) => err.into_response(),
	}
}

macro_rules! forwarded_body {
	($payload:expr) => {
		match $payload.into_upstream_legacy() {
			Ok(bytes) => Some(bytes),
			Err(error) => return error.into_response(),
		}
	};
}

// ---------------------------------------------------------------- status

pub(crate) async fn health(State(state): State<WebState>) -> Response {
	forward(&state, Method::GET, "/v1/health", &[], None).await
}

pub(crate) async fn whoami(State(state): State<WebState>) -> Response {
	forward(&state, Method::GET, "/v1/whoami", &[], None).await
}

/// Read-only view of the server-wide GitHub App, so the page can tell
/// whether a PAT is optional. Setting or clearing the app stays a
/// `loupectl` job: the private key should never pass through a browser.
pub(crate) async fn github_app(State(state): State<WebState>) -> Response {
	forward(&state, Method::GET, "/v1/github-app", &[], None).await
}

// ----------------------------------------------------------------- repos

#[derive(Debug, Deserialize)]
pub struct LimitQuery {
	#[serde(default)]
	pub limit: Option<i64>,
}

impl LimitQuery {
	pub(crate) fn pairs(&self) -> Vec<(&'static str, String)> {
		self.limit.map(|n| vec![("limit", n.to_string())]).unwrap_or_default()
	}
}

pub(crate) async fn list_repos(State(state): State<WebState>, q: BrowserLimit) -> Response {
	forward(&state, Method::GET, "/v1/repos", &q.pairs(), None).await
}

pub(crate) async fn create_repo(
	State(state): State<WebState>, payload: BrowserCreateRepo,
) -> Response {
	forward(&state, Method::POST, "/v1/repos", &[], forwarded_body!(payload)).await
}

pub(crate) async fn update_repo(
	State(state): State<WebState>, BrowserId(id): BrowserId, payload: BrowserUpdateRepo,
) -> Response {
	forward(&state, Method::PATCH, &format!("/v1/repos/{id}"), &[], forwarded_body!(payload)).await
}

pub(crate) async fn delete_repo(
	State(state): State<WebState>, BrowserId(id): BrowserId,
) -> Response {
	forward(&state, Method::DELETE, &format!("/v1/repos/{id}"), &[], None).await
}

pub(crate) async fn rotate_repo_pat(
	State(state): State<WebState>, BrowserId(id): BrowserId, payload: BrowserRotatePat,
) -> Response {
	forward(
		&state,
		Method::POST,
		&format!("/v1/repos/{id}/reporting/github-pat"),
		&[],
		forwarded_body!(payload),
	)
	.await
}

pub(crate) async fn set_github_reporting(
	State(state): State<WebState>, BrowserId(id): BrowserId, payload: BrowserSetGithubReporting,
) -> Response {
	forward(
		&state,
		Method::PUT,
		&format!("/v1/repos/{id}/reporting/github"),
		&[],
		forwarded_body!(payload),
	)
	.await
}

pub(crate) async fn enqueue_scan(
	State(state): State<WebState>, BrowserId(id): BrowserId, payload: BrowserEnqueueScan,
) -> Response {
	forward(&state, Method::POST, &format!("/v1/repos/{id}/scan"), &[], forwarded_body!(payload))
		.await
}

// ------------------------------------------------------------------ jobs

#[derive(Debug, Deserialize)]
pub struct JobsQuery {
	#[serde(default)]
	pub limit: Option<i64>,
	#[serde(default)]
	pub state: Option<String>,
	#[serde(default)]
	pub kind: Option<String>,
}

pub(crate) async fn list_jobs(State(state): State<WebState>, q: BrowserJobs) -> Response {
	let mut pairs: Vec<(&'static str, String)> = Vec::new();
	// Values are forwarded verbatim; the server validates them and returns
	// a 400 naming the accepted set, which the page surfaces as-is.
	pairs.extend(q.into_pairs_legacy());
	forward(&state, Method::GET, "/v1/jobs", &pairs, None).await
}

pub(crate) async fn get_job(State(state): State<WebState>, BrowserId(id): BrowserId) -> Response {
	forward(&state, Method::GET, &format!("/v1/jobs/{id}"), &[], None).await
}

pub(crate) async fn retry_job(State(state): State<WebState>, BrowserId(id): BrowserId) -> Response {
	forward(&state, Method::POST, &format!("/v1/jobs/{id}/retry"), &[], None).await
}

pub(crate) async fn cancel_job(
	State(state): State<WebState>, BrowserId(id): BrowserId,
) -> Response {
	forward(&state, Method::POST, &format!("/v1/jobs/{id}/cancel"), &[], None).await
}

// -------------------------------------------------------------- findings

pub(crate) async fn list_findings(
	State(state): State<WebState>, BrowserId(repo_id): BrowserId, q: BrowserLimit,
) -> Response {
	forward(&state, Method::GET, &format!("/v1/repos/{repo_id}/findings"), &q.pairs(), None).await
}

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
	pub q: String,
	#[serde(default)]
	pub limit: Option<i64>,
}

pub(crate) async fn search_findings(
	State(state): State<WebState>, BrowserId(repo_id): BrowserId, q: BrowserSearch,
) -> Response {
	let pairs = q.into_pairs_legacy();
	forward(&state, Method::GET, &format!("/v1/repos/{repo_id}/findings/search"), &pairs, None)
		.await
}

pub(crate) async fn get_finding(
	State(state): State<WebState>, BrowserId(id): BrowserId,
) -> Response {
	forward(&state, Method::GET, &format!("/v1/findings/{id}"), &[], None).await
}

pub(crate) async fn approve_finding(
	State(state): State<WebState>, BrowserId(id): BrowserId,
) -> Response {
	forward(&state, Method::POST, &format!("/v1/findings/{id}/approve"), &[], None).await
}

pub(crate) async fn reject_finding(
	State(state): State<WebState>, BrowserId(id): BrowserId,
) -> Response {
	forward(&state, Method::POST, &format!("/v1/findings/{id}/reject"), &[], None).await
}

pub(crate) async fn retry_report_finding(
	State(state): State<WebState>, BrowserId(id): BrowserId,
) -> Response {
	forward(&state, Method::POST, &format!("/v1/findings/{id}/retry-report"), &[], None).await
}

pub(crate) async fn retry_verify(
	State(state): State<WebState>, payload: BrowserRetryVerify,
) -> Response {
	forward(&state, Method::POST, "/v1/findings/retry-verify", &[], forwarded_body!(payload)).await
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn limit_query_is_omitted_when_absent() {
		assert!(LimitQuery { limit: None }.pairs().is_empty());
		assert_eq!(LimitQuery { limit: Some(50) }.pairs(), vec![("limit", "50".to_owned())]);
	}
}
