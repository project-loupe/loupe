//! Typed review phase calls. Each request body is serialized once and every
//! try sends those same bytes; failures are retried only as
//! `review::retry::classify` decides, and never past the caller's deadline.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use loupe_core::review_candidates::CandidateQuery;
use loupe_proto::review_api::{
	CandidatesResponse, CandidatesResponseDecoder, InventoryBatchRequest, ManifestProgress,
	ManifestProgressDecoder, PhaseLimitsResponse, PhaseLimitsResponseDecoder, PinTargetRequest,
	PinTargetResponse, PinTargetResponseDecoder, PublishProfileRequest, PublishedProfile,
	PublishedProfileDecoder, ReviewErrorCode, ReviewErrorResponseDecoder, ReviewProtocol,
	ReviewResponseDecodeError, SealInventoryRequest,
};
use loupe_proto::review_drilldown::{
	DrilldownTerminalResponse, DrilldownTerminalResponseDecoder, FinalizeDrilldownRequest,
};
use loupe_proto::review_evidence::{
	LeadCheckpointRequest, LeadCheckpointResponse, LeadCheckpointResponseDecoder,
	UnitResultCheckpointRequest, UnitResultCheckpointResponse, UnitResultCheckpointResponseDecoder,
};
use loupe_proto::review_inventory::{
	InventoryDispositionRequest, InventoryDispositionResponse, InventoryDispositionResponseDecoder,
};
use loupe_proto::review_lifecycle::{
	FailedOutcome, PhaseControlResponse, PhaseControlResponseDecoder, PhaseFailureRequest,
	PhaseHeartbeatRequest,
};
use loupe_proto::review_terminal::{
	FinalizeSurveyRequest, SurveyTerminalResponse, SurveyTerminalResponseDecoder,
};
use loupe_proto::review_units::{ReviewUnitRequest, ReviewUnitResponse, ReviewUnitResponseDecoder};
use loupe_proto::{HeartbeatResponse, JobCapability, PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use loupe_provenance::{Agent, Server, Source, Untrusted};
use reqwest::header::CONTENT_TYPE;
use reqwest::Method;

use super::{read_server_response, ServerClient, REQUEST_TIMEOUT};
use crate::review::retry::{classify, Decision, Failure};

/// The job a phase call acts for, and the time after which no try starts.
pub struct PhaseJob<'a> {
	pub job_id: i64,
	pub capability: &'a JobCapability,
	pub deadline: SystemTime,
}

/// A failed phase call after its retries. Carries no server text.
// debug-ok: numeric statuses, closed error codes and static classifications.
#[derive(Debug, thiserror::Error)]
pub enum PhaseError {
	#[error("phase request timed out")]
	Timeout,
	#[error("phase request connection failed")]
	Connection,
	#[error("server rejected phase request with {status} {code:?}")]
	Rejected { status: u16, code: ReviewErrorCode, current_revision: Option<i64> },
	#[error("server returned {status} without a phase error envelope")]
	Status { status: u16 },
	#[error("invalid phase response: {0}")]
	Response(&'static str),
	#[error(transparent)]
	Decode(#[from] ReviewResponseDecodeError),
}

impl ServerClient {
	pub async fn pin_target<S: Source>(
		&self, job: &PhaseJob<'_>, req: &PinTargetRequest<S>,
	) -> Result<PinTargetResponse<Agent, Server>, PhaseError> {
		let body = self.post_phase(job, "pin-target", req).await?;
		Ok(body.as_bytes().validate_carrying(PinTargetResponseDecoder)?)
	}

	pub async fn inventory_batch<S: Source>(
		&self, job: &PhaseJob<'_>, req: &InventoryBatchRequest<S>,
	) -> Result<ManifestProgress<Server>, PhaseError> {
		let body = self.post_phase(job, "inventory-batches", req).await?;
		Ok(body.as_bytes().validate(ManifestProgressDecoder)?)
	}

	pub async fn seal_inventory(
		&self, job: &PhaseJob<'_>,
	) -> Result<ManifestProgress<Server>, PhaseError> {
		let req = SealInventoryRequest { protocol_version: ReviewProtocol };
		let body = self.post_phase(job, "seal-inventory", &req).await?;
		Ok(body.as_bytes().validate(ManifestProgressDecoder)?)
	}

	pub async fn publish_profile<S: Source>(
		&self, job: &PhaseJob<'_>, req: &PublishProfileRequest<S>,
	) -> Result<PublishedProfile<Server>, PhaseError> {
		let body = self.post_phase(job, "publish-profile", req).await?;
		Ok(body.as_bytes().validate(PublishedProfileDecoder)?)
	}

	pub async fn review_unit<C: Source, K: Source>(
		&self, job: &PhaseJob<'_>, req: &ReviewUnitRequest<C, K>,
	) -> Result<ReviewUnitResponse, PhaseError> {
		let body = self.post_phase(job, "review-units", req).await?;
		Ok(body.as_bytes().validate(ReviewUnitResponseDecoder)?)
	}

	pub async fn lead<K: Source>(
		&self, job: &PhaseJob<'_>, req: &LeadCheckpointRequest<K>,
	) -> Result<LeadCheckpointResponse, PhaseError> {
		let body = self.post_phase(job, "leads", req).await?;
		Ok(body.as_bytes().validate(LeadCheckpointResponseDecoder)?)
	}

	/// Store a further lead found during a drilldown; it gets its own
	/// drilldown.
	pub async fn sibling_lead<K: Source>(
		&self, job: &PhaseJob<'_>, req: &LeadCheckpointRequest<K>,
	) -> Result<LeadCheckpointResponse, PhaseError> {
		let body = self.post_phase(job, "sibling-leads", req).await?;
		Ok(body.as_bytes().validate(LeadCheckpointResponseDecoder)?)
	}

	pub async fn unit_result<K: Source>(
		&self, job: &PhaseJob<'_>, req: &UnitResultCheckpointRequest<K>,
	) -> Result<UnitResultCheckpointResponse, PhaseError> {
		let body = self.post_phase(job, "review-unit-results", req).await?;
		Ok(body.as_bytes().validate(UnitResultCheckpointResponseDecoder)?)
	}

	pub async fn inventory_disposition<S: Source>(
		&self, job: &PhaseJob<'_>, req: &InventoryDispositionRequest<S>,
	) -> Result<InventoryDispositionResponse, PhaseError> {
		let body = self.post_phase(job, "inventory-dispositions", req).await?;
		Ok(body.as_bytes().validate(InventoryDispositionResponseDecoder)?)
	}

	pub async fn lead_candidates<S: Source>(
		&self, job: &PhaseJob<'_>, query: &CandidateQuery<S>,
	) -> Result<CandidatesResponse<Agent, Server>, PhaseError> {
		let mut url = self.url(&format!("/v1/jobs/{}/lead-candidates", job.job_id));
		url.query_pairs_mut()
			.append_pair("query", query.query.expose())
			.append_pair("limit", &query.limit.to_string());
		let body = self.send_phase(job, Method::GET, url, None).await?;
		Ok(body.as_bytes().validate_carrying(CandidatesResponseDecoder)?)
	}

	pub async fn limits(&self, job: &PhaseJob<'_>) -> Result<PhaseLimitsResponse, PhaseError> {
		let url = self.url(&format!("/v1/jobs/{}/limits", job.job_id));
		let body = self.send_phase(job, Method::GET, url, None).await?;
		Ok(body.as_bytes().validate(PhaseLimitsResponseDecoder)?)
	}

	pub async fn finalize_survey<S: Source>(
		&self, job: &PhaseJob<'_>, req: &FinalizeSurveyRequest<S>,
	) -> Result<SurveyTerminalResponse<Server>, PhaseError> {
		let body = self.post_phase(job, "finalize-survey", req).await?;
		Ok(body.as_bytes().validate(SurveyTerminalResponseDecoder)?)
	}

	pub async fn finalize_drilldown<S: Source>(
		&self, job: &PhaseJob<'_>, req: &FinalizeDrilldownRequest<S>,
	) -> Result<DrilldownTerminalResponse<Server>, PhaseError> {
		let body = self.post_phase(job, "finalize-drilldown", req).await?;
		Ok(body.as_bytes().validate(DrilldownTerminalResponseDecoder)?)
	}

	pub async fn phase_heartbeat(
		&self, job: &PhaseJob<'_>,
	) -> Result<HeartbeatResponse, PhaseError> {
		let req = PhaseHeartbeatRequest { protocol_version: ReviewProtocol };
		let body = self.post_phase(job, "heartbeat", &req).await?;
		super::ingress::heartbeat(&body).map_err(|_| PhaseError::Response("heartbeat"))
	}

	/// Report a failed phase attempt through `complete`.
	pub async fn phase_failure<S: Source>(
		&self, job: &PhaseJob<'_>, req: &PhaseFailureRequest<S>,
	) -> Result<PhaseControlResponse, PhaseError> {
		let body = self.post_phase(job, "complete", req).await?;
		Ok(body.as_bytes().validate(PhaseControlResponseDecoder)?)
	}

	/// Report a failed phase attempt with a reason from the host's closed
	/// vocabulary.
	pub(crate) async fn phase_failure_reason(
		&self, job: &PhaseJob<'_>, reason: crate::review::failure::FailureReason,
	) -> Result<PhaseControlResponse, PhaseError> {
		#[derive(serde::Serialize)]
		struct HostFailure {
			protocol_version: ReviewProtocol,
			outcome: FailedOutcome,
			error: &'static str,
		}
		let req = HostFailure {
			protocol_version: ReviewProtocol,
			outcome: FailedOutcome::Failed,
			error: reason.text(),
		};
		let body = self.post_phase(job, "complete", &req).await?;
		Ok(body.as_bytes().validate(PhaseControlResponseDecoder)?)
	}

	async fn post_phase(
		&self, job: &PhaseJob<'_>, route: &str, req: &impl serde::Serialize,
	) -> Result<Untrusted<Bytes, Server>, PhaseError> {
		let body = serde_json::to_vec(req).map_err(|_| PhaseError::Response("request encoding"))?;
		let url = self.url(&format!("/v1/jobs/{}/{route}", job.job_id));
		self.send_phase(job, Method::POST, url, Some(Bytes::from(body))).await
	}

	/// The one retry wrapper: re-sends `body` unchanged while `classify`
	/// allows it.
	async fn send_phase(
		&self, job: &PhaseJob<'_>, method: Method, url: reqwest::Url, body: Option<Bytes>,
	) -> Result<Untrusted<Bytes, Server>, PhaseError> {
		let deadline = since_epoch(job.deadline);
		let mut tries = 1;
		loop {
			let (failure, error) = match self
				.try_phase(job, method.clone(), url.clone(), body.clone(), deadline)
				.await
			{
				Ok(response) => return Ok(response),
				Err(failed) => failed,
			};
			match classify(failure, tries, since_epoch(SystemTime::now()), deadline) {
				Decision::Retry(pause) => {
					tokio::time::sleep(pause).await;
					tries += 1;
				},
				Decision::Final => return Err(error),
			}
		}
	}

	async fn try_phase(
		&self, job: &PhaseJob<'_>, method: Method, url: reqwest::Url, body: Option<Bytes>,
		deadline: Duration,
	) -> Result<Untrusted<Bytes, Server>, (Failure, PhaseError)> {
		let remaining = deadline.saturating_sub(since_epoch(SystemTime::now()));
		if remaining.is_zero() {
			return Err((Failure::Timeout, PhaseError::Timeout));
		}
		#[allow(
			clippy::disallowed_methods,
			reason = "Phase HTTP egress carries typed phase requests under the active job capability."
		)]
		let response = self
			.with_job_capability(
				match body {
					Some(body) => self
						.http
						.request(method, url)
						.header(CONTENT_TYPE, "application/json")
						.body(body),
					None => self.http.request(method, url),
				},
				job.capability,
			)
			.timeout(remaining.min(REQUEST_TIMEOUT))
			.send()
			.await
			.map_err(transport)?;
		let status = response.status();
		if !status.is_success() {
			let failure = Failure::Status(status.as_u16());
			let error = match read_server_response(response).await {
				Ok(bytes) => match bytes.as_bytes().validate(ReviewErrorResponseDecoder) {
					Ok(envelope) => PhaseError::Rejected {
						status: status.as_u16(),
						code: envelope.code,
						current_revision: envelope.current_revision,
					},
					Err(_) => PhaseError::Status { status: status.as_u16() },
				},
				Err(_) => PhaseError::Status { status: status.as_u16() },
			};
			return Err((failure, error));
		}
		let version = response
			.headers()
			.get(PROTOCOL_VERSION_HEADER)
			.and_then(|value| value.to_str().ok())
			.and_then(|value| value.parse::<u16>().ok());
		if version != Some(PROTOCOL_VERSION) {
			return Err((
				Failure::Status(status.as_u16()),
				PhaseError::Response("protocol header missing or mismatched"),
			));
		}
		// The server answered: a body that cannot be collected is final, as
		// a resend would meet the same answer.
		read_server_response(response).await.map_err(|error| {
			let error = match error {
				loupe_http::ResponseBodyError::TooLarge => "response too large",
				loupe_http::ResponseBodyError::Transport(_) => "response body unreadable",
			};
			(Failure::Status(status.as_u16()), PhaseError::Response(error))
		})
	}
}

fn transport(error: reqwest::Error) -> (Failure, PhaseError) {
	if error.is_timeout() {
		(Failure::Timeout, PhaseError::Timeout)
	} else if error.is_builder() {
		(Failure::Status(0), PhaseError::Response("request construction"))
	} else {
		(Failure::Connection, PhaseError::Connection)
	}
}

fn since_epoch(time: SystemTime) -> Duration {
	time.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO)
}

#[cfg(test)]
mod tests {
	use std::sync::{Arc, Mutex};

	use loupe_proto::review_lifecycle::FailedOutcome;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::net::TcpListener;

	use super::*;

	enum Reply {
		Drop,
		Status(u16, &'static str),
		/// A 200 whose body ends before its declared length.
		Truncated,
		/// A 200 whose body exceeds the response cap.
		Oversized,
	}

	const CONTROL: &str =
		r#"{"protocol_version":3,"job_id":7,"state":"queued","eligible_at":null}"#;
	const CONFLICT: &str =
		r#"{"protocol_version":3,"error":{"code":"checkpoint_conflict","detail":null}}"#;
	const INTERNAL: &str =
		r#"{"protocol_version":3,"error":{"code":"internal_error","detail":null}}"#;

	struct Seen {
		head: String,
		body: Vec<u8>,
	}

	/// Serves `replies` in order, one connection each, repeating the last.
	async fn fake_server(replies: Vec<Reply>) -> (reqwest::Url, Arc<Mutex<Vec<Seen>>>) {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let base = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
		let seen = Arc::new(Mutex::new(Vec::new()));
		let record = seen.clone();
		tokio::spawn(async move {
			for index in 0.. {
				let (mut stream, _) = listener.accept().await.unwrap();
				let mut request = Vec::new();
				let (head, body) = loop {
					let mut buf = [0; 4096];
					let read = stream.read(&mut buf).await.unwrap();
					assert_ne!(read, 0, "request ended early");
					request.extend_from_slice(&buf[..read]);
					let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
						continue;
					};
					let head = String::from_utf8(request[..end].to_vec()).unwrap();
					let length: usize = head
						.lines()
						.find_map(|line| {
							let (name, value) = line.split_once(':')?;
							name.eq_ignore_ascii_case("content-length")
								.then(|| value.trim().parse().unwrap())
						})
						.unwrap_or(0);
					if request.len() >= end + 4 + length {
						break (head, request[end + 4..end + 4 + length].to_vec());
					}
				};
				record.lock().unwrap().push(Seen { head, body });
				let reply = replies.get(index).or(replies.last()).unwrap();
				match reply {
					Reply::Drop => drop(stream),
					Reply::Status(status, body) => {
						let response = format!(
							"HTTP/1.1 {status} X\r\nX-Loupe-Protocol: 3\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
							body.len()
						);
						stream.write_all(response.as_bytes()).await.unwrap();
					},
					Reply::Truncated => {
						let response = "HTTP/1.1 200 OK\r\nX-Loupe-Protocol: 3\r\ncontent-type: application/json\r\ncontent-length: 100\r\nconnection: close\r\n\r\n{\"job";
						stream.write_all(response.as_bytes()).await.unwrap();
					},
					Reply::Oversized => {
						let length = loupe_http::MAX_RESPONSE_BYTES + 1;
						let head = format!(
							"HTTP/1.1 200 OK\r\nX-Loupe-Protocol: 3\r\ncontent-type: application/json\r\ncontent-length: {length}\r\nconnection: close\r\n\r\n"
						);
						stream.write_all(head.as_bytes()).await.unwrap();
						let _ = stream.write_all(&vec![b' '; length]).await;
					},
				}
			}
		});
		(base, seen)
	}

	async fn fail(
		replies: Vec<Reply>, deadline: Duration,
	) -> (Result<PhaseControlResponse, PhaseError>, Vec<Seen>) {
		let (base, seen) = fake_server(replies).await;
		let client = ServerClient::from_parts(reqwest::Client::new(), base);
		let capability = JobCapability::from_secret("phase-capability");
		let job =
			PhaseJob { job_id: 7, capability: &capability, deadline: SystemTime::now() + deadline };
		let req = PhaseFailureRequest::<loupe_provenance::Worker> {
			protocol_version: ReviewProtocol,
			outcome: FailedOutcome::Failed,
			error: None,
		};
		let result = client.phase_failure(&job, &req).await;
		let seen = std::mem::take(&mut *seen.lock().unwrap());
		(result, seen)
	}

	fn assert_identical_tries(seen: &[Seen], tries: usize) {
		assert_eq!(seen.len(), tries);
		for try_ in seen {
			assert_eq!(try_.body, br#"{"protocol_version":3,"outcome":"failed","error":null}"#);
			let head = try_.head.to_ascii_lowercase();
			assert!(head.starts_with("post /v1/jobs/7/complete "), "{head}");
			assert_eq!(head.matches("\r\nx-loupe-protocol: 3").count(), 1, "{head}");
			assert_eq!(head.matches("\r\ncontent-type: application/json").count(), 1);
			assert_eq!(head.matches("\r\nx-loupe-job-capability: phase-capability").count(), 1);
		}
	}

	#[tokio::test]
	async fn dropped_response_is_retried_with_identical_bytes() {
		let (result, seen) =
			fail(vec![Reply::Drop, Reply::Status(200, CONTROL)], Duration::from_secs(60)).await;
		assert_eq!(
			result.unwrap().job_id,
			loupe_proto::review_lease::ReviewId::try_from(7).unwrap()
		);
		assert_identical_tries(&seen, 2);
	}

	#[tokio::test]
	async fn server_error_is_retried_with_identical_bytes() {
		let (result, seen) = fail(
			vec![Reply::Status(500, INTERNAL), Reply::Status(200, CONTROL)],
			Duration::from_secs(60),
		)
		.await;
		result.unwrap();
		assert_identical_tries(&seen, 2);
	}

	#[tokio::test]
	async fn conflict_is_final_and_typed_without_server_text() {
		let (result, seen) = fail(
			vec![Reply::Status(409, CONFLICT), Reply::Status(200, CONTROL)],
			Duration::from_secs(60),
		)
		.await;
		assert!(matches!(
			result,
			Err(PhaseError::Rejected {
				status: 409,
				code: ReviewErrorCode::CheckpointConflict,
				current_revision: None
			})
		));
		assert_identical_tries(&seen, 1);
	}

	#[tokio::test]
	async fn unrecognised_error_body_keeps_only_the_status() {
		let (result, seen) =
			fail(vec![Reply::Status(400, "agent-visible-sentinel")], Duration::from_secs(60)).await;
		let error = result.unwrap_err();
		assert!(matches!(error, PhaseError::Status { status: 400 }));
		assert!(!format!("{error} {error:?}").contains("sentinel"));
		assert_identical_tries(&seen, 1);
	}

	#[tokio::test]
	async fn deadline_stops_retries() {
		// The second pause (4 s) would start the third try past the deadline.
		let (result, seen) = fail(vec![Reply::Status(500, INTERNAL)], Duration::from_secs(3)).await;
		assert!(matches!(
			result,
			Err(PhaseError::Rejected { status: 500, code: ReviewErrorCode::InternalError, .. })
		));
		assert_identical_tries(&seen, 2);
	}

	#[tokio::test]
	async fn unreadable_success_body_is_final() {
		let (result, seen) =
			fail(vec![Reply::Truncated, Reply::Status(200, CONTROL)], Duration::from_secs(60))
				.await;
		assert!(matches!(result, Err(PhaseError::Response("response body unreadable"))));
		assert_identical_tries(&seen, 1);
	}

	#[tokio::test]
	async fn oversized_success_body_is_final() {
		let (result, seen) =
			fail(vec![Reply::Oversized, Reply::Status(200, CONTROL)], Duration::from_secs(60))
				.await;
		assert!(matches!(result, Err(PhaseError::Response("response too large"))));
		assert_identical_tries(&seen, 1);
	}

	#[tokio::test]
	async fn retries_stop_after_three_tries() {
		let (result, seen) = fail(vec![Reply::Drop], Duration::from_secs(60)).await;
		assert!(matches!(result, Err(PhaseError::Connection)));
		assert_identical_tries(&seen, 3);
	}
}
