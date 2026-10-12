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
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::client::AdminRequest;
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

pub(crate) async fn health(State(state): State<WebState>) -> Response {
	state.client.forward(AdminRequest::Health).await
}
pub(crate) async fn whoami(State(state): State<WebState>) -> Response {
	state.client.forward(AdminRequest::Whoami).await
}
pub(crate) async fn github_app(State(state): State<WebState>) -> Response {
	state.client.forward(AdminRequest::GithubApp).await
}
pub(crate) async fn list_repos(State(state): State<WebState>, query: BrowserLimit) -> Response {
	state.client.forward(AdminRequest::ListRepos(query)).await
}
pub(crate) async fn create_repo(
	State(state): State<WebState>, body: BrowserCreateRepo,
) -> Response {
	state.client.forward(AdminRequest::CreateRepo(body)).await
}
pub(crate) async fn update_repo(
	State(state): State<WebState>, BrowserId(id): BrowserId, body: BrowserUpdateRepo,
) -> Response {
	state.client.forward(AdminRequest::UpdateRepo(id, body)).await
}
pub(crate) async fn delete_repo(
	State(state): State<WebState>, BrowserId(id): BrowserId,
) -> Response {
	state.client.forward(AdminRequest::DeleteRepo(id)).await
}
pub(crate) async fn rotate_repo_pat(
	State(state): State<WebState>, BrowserId(id): BrowserId, body: BrowserRotatePat,
) -> Response {
	state.client.forward(AdminRequest::RotatePat(id, body)).await
}
pub(crate) async fn set_github_reporting(
	State(state): State<WebState>, BrowserId(id): BrowserId, body: BrowserSetGithubReporting,
) -> Response {
	state.client.forward(AdminRequest::SetGithubReporting(id, body)).await
}
pub(crate) async fn enqueue_scan(
	State(state): State<WebState>, BrowserId(id): BrowserId, body: BrowserEnqueueScan,
) -> Response {
	state.client.forward(AdminRequest::EnqueueScan(id, body)).await
}
pub(crate) async fn list_jobs(State(state): State<WebState>, query: BrowserJobs) -> Response {
	state.client.forward(AdminRequest::ListJobs(query)).await
}
pub(crate) async fn get_job(State(state): State<WebState>, BrowserId(id): BrowserId) -> Response {
	state.client.forward(AdminRequest::GetJob(id)).await
}
pub(crate) async fn retry_job(State(state): State<WebState>, BrowserId(id): BrowserId) -> Response {
	state.client.forward(AdminRequest::RetryJob(id)).await
}
pub(crate) async fn cancel_job(
	State(state): State<WebState>, BrowserId(id): BrowserId,
) -> Response {
	state.client.forward(AdminRequest::CancelJob(id)).await
}
pub(crate) async fn list_findings(
	State(state): State<WebState>, BrowserId(id): BrowserId, query: BrowserLimit,
) -> Response {
	state.client.forward(AdminRequest::ListFindings(id, query)).await
}
pub(crate) async fn search_findings(
	State(state): State<WebState>, BrowserId(id): BrowserId, query: BrowserSearch,
) -> Response {
	state.client.forward(AdminRequest::SearchFindings(id, query)).await
}
pub(crate) async fn get_finding(
	State(state): State<WebState>, BrowserId(id): BrowserId,
) -> Response {
	state.client.forward(AdminRequest::GetFinding(id)).await
}
pub(crate) async fn approve_finding(
	State(state): State<WebState>, BrowserId(id): BrowserId,
) -> Response {
	state.client.forward(AdminRequest::ApproveFinding(id)).await
}
pub(crate) async fn reject_finding(
	State(state): State<WebState>, BrowserId(id): BrowserId,
) -> Response {
	state.client.forward(AdminRequest::RejectFinding(id)).await
}
pub(crate) async fn retry_report_finding(
	State(state): State<WebState>, BrowserId(id): BrowserId,
) -> Response {
	state.client.forward(AdminRequest::RetryReportFinding(id)).await
}
pub(crate) async fn retry_verify(
	State(state): State<WebState>, body: BrowserRetryVerify,
) -> Response {
	state.client.forward(AdminRequest::RetryVerify(body)).await
}
