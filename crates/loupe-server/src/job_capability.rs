use axum::http::{HeaderMap, HeaderValue, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use loupe_core::security_event::{
	emit, CapabilityDenial, EventContext, Operation, RequestedTarget, SecurityEvent,
};
use loupe_core::{JobKind, JobState};
use loupe_proto::{JobCapability, JOB_CAPABILITY_HEADER, JOB_CAPABILITY_TOKEN_CHARS};
use loupe_provenance::Zeroise;
use loupe_storage::jobs::{self, JobRow};
use rand_core::{OsRng, RngCore};

use crate::auth::AuthedWorker;
use crate::state::AppState;

pub(crate) struct AuthorizedJob {
	pub row: JobRow,
	pub capability_hash: [u8; 32],
	operation: Operation,
	requested: RequestedTarget,
}

impl AuthorizedJob {
	pub(crate) fn deny(&self, worker: &AuthedWorker, reason: CapabilityDenial) {
		denied(worker, Some(&self.row), self.operation, self.requested, reason);
	}
	pub(crate) fn lease_invalidated(&self, worker: &AuthedWorker) -> (StatusCode, String) {
		self.deny(worker, CapabilityDenial::LeaseInvalidated);
		forbidden()
	}
	pub(crate) fn lease_identity(&self, worker_id: i64) -> jobs::LeaseIdentity<'_> {
		jobs::LeaseIdentity {
			job_id: self.row.id,
			worker_id,
			capability_hash: &self.capability_hash,
		}
	}

	pub(crate) fn active_lease(&self, worker_id: i64, now: i64) -> jobs::ActiveLease<'_> {
		jobs::ActiveLease { identity: self.lease_identity(worker_id), now }
	}
}

pub(crate) fn issue() -> (JobCapability, [u8; 32]) {
	let mut random = [0u8; 32];
	OsRng.fill_bytes(&mut random);
	let token = JobCapability::from_secret(URL_SAFE_NO_PAD.encode(random.as_slice()));
	random.zeroise();
	let hash = *blake3::hash(token.expose_secret().as_bytes()).as_bytes();
	(token, hash)
}

/// Parse the capability header without requiring a live lease.
pub fn parse_hash(headers: &HeaderMap) -> Result<[u8; 32], (StatusCode, String)> {
	parse_capability(headers).ok_or_else(forbidden)
}

pub(crate) fn parse_capability(headers: &HeaderMap) -> Option<[u8; 32]> {
	parse_capability_value(headers.get(JOB_CAPABILITY_HEADER))
}

pub(crate) fn parse_capability_value(value: Option<&HeaderValue>) -> Option<[u8; 32]> {
	let token = value
		.and_then(|value| value.to_str().ok())
		.filter(|value| value.len() == JOB_CAPABILITY_TOKEN_CHARS)?;
	Some(hash_capability(token.as_bytes()))
}

fn hash_capability(token: &[u8]) -> [u8; 32] {
	*blake3::hash(token).as_bytes()
}

pub(crate) struct LeaseFacts {
	pub worker_id: Option<i64>,
	pub capability_hash: [u8; 32],
	pub lease_expires_at: Option<i64>,
	pub state: JobState,
}

pub(crate) fn capability_admits(
	row: &LeaseFacts, caller_worker: i64, hash: &[u8; 32], now: i64,
) -> bool {
	row.worker_id == Some(caller_worker)
		&& row.capability_hash == *hash
		&& row.state == JobState::Leased
		&& row.lease_expires_at.is_some_and(|expiry| now <= expiry)
}

pub(crate) fn legacy_kind<S: loupe_provenance::Source>(kind: &JobKind<S>) -> bool {
	matches!(kind, JobKind::Scan | JobKind::Verify)
}

pub(crate) fn authorize(
	state: &AppState, worker: &AuthedWorker, headers: &HeaderMap, now: i64, operation: Operation,
	requested: RequestedTarget,
) -> Result<AuthorizedJob, (StatusCode, String)> {
	let capability_hash = parse_capability(headers).ok_or_else(|| {
		denied(
			worker,
			None,
			operation,
			requested,
			if headers.contains_key(JOB_CAPABILITY_HEADER) {
				CapabilityDenial::MalformedCapability
			} else {
				CapabilityDenial::MissingCapability
			},
		);
		forbidden()
	})?;
	let row = jobs::active_lease_facts(&state.db, worker.id(), &capability_hash, now)
		.map_err(|error| {
			(StatusCode::INTERNAL_SERVER_ERROR, format!("authorize job capability: {error}"))
		})?
		.ok_or_else(|| {
			denied(worker, None, operation, requested, CapabilityDenial::InactiveLease);
			forbidden()
		})?;
	// SQL established hash equality in the same lookup. JobRow does not
	// retain the secret hash; the remaining facts come from the returned row.
	let facts = LeaseFacts {
		worker_id: row.worker_id,
		capability_hash,
		lease_expires_at: row.lease_expires_at,
		state: row.state,
	};
	if !capability_admits(&facts, worker.id(), &capability_hash, now) {
		denied(worker, Some(&row), operation, requested, CapabilityDenial::InactiveLease);
		return Err(forbidden());
	}
	Ok(AuthorizedJob { row, capability_hash, operation, requested })
}

pub(crate) fn authorize_for_job(
	state: &AppState, worker: &AuthedWorker, headers: &HeaderMap, job_id: i64, now: i64,
	operation: Operation,
) -> Result<AuthorizedJob, (StatusCode, String)> {
	let requested = RequestedTarget::Job(job_id);
	let authorized = authorize(state, worker, headers, now, operation, requested)?;
	if authorized.row.id != job_id || !legacy_kind(&authorized.row.kind) {
		denied(
			worker,
			Some(&authorized.row),
			operation,
			requested,
			if authorized.row.id != job_id {
				CapabilityDenial::JobMismatch
			} else {
				CapabilityDenial::UnsupportedJobKind
			},
		);
		return Err(forbidden());
	}
	Ok(authorized)
}

pub(crate) fn denied(
	worker: &AuthedWorker, row: Option<&JobRow>, operation: Operation, requested: RequestedTarget,
	reason: CapabilityDenial,
) {
	emit(SecurityEvent::CapabilityDenied {
		context: EventContext {
			worker_id: Some(worker.id()),
			job_id: row.map(|row| row.id),
			repo_id: row.map(|row| row.repo_id),
			campaign_id: row.and_then(|row| row.campaign_id),
		},
		operation,
		requested,
		reason,
	});
}

pub(crate) fn forbidden() -> (StatusCode, String) {
	(StatusCode::FORBIDDEN, "invalid or expired job capability".into())
}

#[cfg(test)]
mod tests {
	use super::*;
	#[tokio::test]
	async fn actual_job_route_denials_emit_closed_context_and_preserve_rows() {
		use std::sync::Arc;

		use axum::body::Body;
		use tower::ServiceExt;
		for (kind, route, reason, body) in [
			(
				"scan",
				"findings",
				"strict_endpoint_required",
				serde_json::json!({"protocol_version":loupe_proto::PROTOCOL_VERSION,"findings":[{"scanner_id":loupe_proto::LLM_CODE_REVIEW_SCANNER_ID,"severity":"high","title":"AGENT_EVENT_SENTINEL","description":"description","fingerprint":"fingerprint"}]}),
			),
			(
				"verify",
				"verdict",
				"missing_assigned_target",
				serde_json::json!({"protocol_version":loupe_proto::PROTOCOL_VERSION,"verdict":{"outcome":"inconclusive","reason":"AGENT_EVENT_SENTINEL"}}),
			),
		] {
			let (_guard, events) = crate::test_support::capture_security_events();
			let mut fixture = crate::test_support::offline::OfflineDatabase::new();
			let cert = crate::PeerCert(vec![4, 5, 6].into());
			let (token, hash) = issue();
			fixture.edit(|conn| {
				conn.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(1,'https://github.com/example/repo','github.com','example','repo','{\"kind\":\"manual\"}',0)",[])?;
				conn.execute("INSERT INTO workers(id,name,kind,cert_fingerprint,created_at) VALUES(1,'worker','worker',?1,0)",[loupe_tls::cert_fingerprint(cert.0.as_ref())])?;
				// NULL verify target deliberately represents an old/corrupt persisted row.
				conn.execute("INSERT INTO jobs(id,repo_id,kind,state,worker_id,lease_expires_at,job_capability_hash,enqueued_at) VALUES(1,1,?1,'leased',1,9223372036854775807,?2,0)",rusqlite::params![kind,hash])?;
				Ok(())
			});
			let db = fixture.open();
			let state = AppState::new(
				db.clone(),
				Arc::new(loupe_tls::Ca::new("event-test").unwrap()),
				Arc::new(crate::reporters::GithubReporter::new().unwrap()),
			);
			let app = crate::router(state);
			let request = |body: serde_json::Value| {
				let mut request = axum::extract::Request::builder()
					.method("POST")
					.uri(format!("/v1/jobs/1/{route}"))
					.header("content-type", "application/json")
					.header(
						loupe_proto::PROTOCOL_VERSION_HEADER,
						loupe_proto::PROTOCOL_VERSION.to_string(),
					)
					.header(JOB_CAPABILITY_HEADER, token.expose_secret())
					.body(Body::from(body.to_string()))
					.unwrap();
				request.extensions_mut().insert(cert.clone());
				request
			};
			assert_eq!(
				app.clone().oneshot(request(body.clone())).await.unwrap().status(),
				StatusCode::BAD_REQUEST
			);
			loupe_storage::scope::with_operator_repository(
				&db,
				&crate::test_support::operator(),
				loupe_storage::scope::OperatorTarget::Repository(1),
				|scope| {
					assert!(loupe_storage::findings::list_for_repo(scope, 10)?.is_empty());
					assert_eq!(
						loupe_storage::jobs::get(scope, 1)?.unwrap().state,
						loupe_core::JobState::Leased
					);
					Ok(())
				},
			)
			.unwrap();
			let rows = std::mem::take(&mut *events.lock().unwrap());
			assert_eq!(rows.len(), 1, "actual {reason} route rejection needs one event");
			assert_eq!(rows[0]["reason"], reason);
			assert_eq!(rows[0]["job_id"], "1");
			assert_eq!(rows[0]["repo_id"], "1");
			assert!(!format!("{rows:?}").contains("AGENT_EVENT_SENTINEL"));
			if kind == "scan" {
				let mut accepted = body;
				accepted["findings"][0]["scanner_id"] = "semgrep".into();
				assert_eq!(
					app.oneshot(request(accepted)).await.unwrap().status(),
					StatusCode::NO_CONTENT
				);
				assert!(events.lock().unwrap().is_empty());
			}
		}
	}
	#[tokio::test]
	async fn actual_capability_admission_emits_closed_denial_without_token() {
		use std::sync::Arc;

		use axum::body::Body;
		use axum::extract::State;
		use axum::routing::get;
		use axum::{middleware, Extension, Router};
		use tower::ServiceExt;
		async fn guarded(
			State(state): State<AppState>, Extension(worker): Extension<AuthedWorker>,
			headers: HeaderMap,
		) -> StatusCode {
			match authorize_for_job(&state, &worker, &headers, 123, 0, Operation::Heartbeat) {
				Ok(_) => StatusCode::OK,
				Err((status, _)) => status,
			}
		}
		let (_guard, events) = crate::test_support::capture_security_events();
		let db = Arc::new(
			loupe_storage::Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests())
				.unwrap(),
		);
		let cert = crate::router::PeerCert(vec![9, 8, 7].into());
		let worker = loupe_storage::registry::register_worker(
			&db,
			&crate::test_support::operator(),
			&crate::test_support::text("FAKE_WORKER_NAME"),
			&loupe_tls::cert_fingerprint(cert.0.as_ref()),
			0,
		)
		.unwrap();
		let state = AppState::new(
			db,
			Arc::new(loupe_tls::Ca::new("event-test").unwrap()),
			Arc::new(crate::reporters::GithubReporter::new().unwrap()),
		);
		let app = Router::new()
			.route("/", get(guarded))
			.layer(middleware::from_fn_with_state(state.clone(), crate::auth::mtls_auth))
			.with_state(state);
		for (token, reason) in [
			(None, "missing_capability"),
			(Some("FAKE_TOKEN_SENTINEL".to_owned()), "malformed_capability"),
			(Some("A".repeat(JOB_CAPABILITY_TOKEN_CHARS)), "inactive_lease"),
		] {
			let mut request = axum::extract::Request::new(Body::empty());
			request.extensions_mut().insert(cert.clone());
			if let Some(token) = token {
				request
					.headers_mut()
					.insert(JOB_CAPABILITY_HEADER, HeaderValue::from_str(&token).unwrap());
			}
			assert_eq!(app.clone().oneshot(request).await.unwrap().status(), StatusCode::FORBIDDEN);
			let rows = std::mem::take(&mut *events.lock().unwrap());
			assert_eq!(rows.len(), 1, "actual capability rejection must emit exactly one event");
			assert_eq!(rows[0]["reason"], reason);
			assert_eq!(rows[0]["worker_id"], worker.to_string());
			assert_eq!(rows[0]["requested_id"], "123");
			assert!(
				!rows[0].contains_key("job_id"),
				"unresolved request IDs are not authority context"
			);
			assert!(!format!("{rows:?}").contains("FAKE_"));
		}
	}

	#[test]
	fn issued_tokens_match_the_length_authorize_filters_on() {
		// `authorize` rejects anything of a different length before it
		// hashes, so widening the random token without widening the
		// filter would reject every capability the server just issued.
		let (token, _) = issue();
		assert_eq!(token.expose_secret().len(), JOB_CAPABILITY_TOKEN_CHARS);
	}
}

#[cfg(test)]
mod decision_tests {
	use axum::http::HeaderValue;

	use super::*;

	#[test]
	fn capability_facts_require_every_lease_condition() {
		let mut facts = LeaseFacts {
			worker_id: Some(7),
			capability_hash: [9; 32],
			lease_expires_at: Some(10),
			state: JobState::Leased,
		};
		assert!(capability_admits(&facts, 7, &[9; 32], 10));
		assert!(capability_admits(&facts, 7, &[9; 32], 9));
		assert!(!capability_admits(&facts, 7, &[9; 32], 11));
		assert!(!capability_admits(&facts, 8, &[9; 32], 10));
		for index in 0..32 {
			let mut wrong = [9; 32];
			wrong[index] ^= 1;
			assert!(!capability_admits(&facts, 7, &wrong, 10));
		}
		facts.worker_id = None;
		assert!(!capability_admits(&facts, 7, &[9; 32], 10));
		facts.worker_id = Some(7);
		facts.lease_expires_at = None;
		assert!(!capability_admits(&facts, 7, &[9; 32], 10));
		facts.lease_expires_at = Some(10);
		for state in [JobState::Queued, JobState::Succeeded, JobState::Failed, JobState::Cancelled]
		{
			facts.state = state;
			assert!(!capability_admits(&facts, 7, &[9; 32], 10));
		}
	}

	#[test]
	fn capability_header_requires_text_of_exact_length_and_hashes_all_bytes() {
		assert!(parse_capability(&HeaderMap::new()).is_none());
		for len in [0, 42, 43, 44] {
			for byte in [b'a', b' ', b'\t', 0x80] {
				let bytes = vec![byte; len];
				let mut headers = HeaderMap::new();
				headers.insert(JOB_CAPABILITY_HEADER, HeaderValue::from_bytes(&bytes).unwrap());
				let expected = if len == 43 && byte != 0x80 {
					Some(*blake3::hash(&bytes).as_bytes())
				} else {
					None
				};
				assert_eq!(parse_capability(&headers), expected, "length {len}, byte {byte}");
			}
		}
	}

	#[test]
	fn legacy_authority_rejects_every_phase_or_unknown_kind() {
		for (kind, expected) in [
			(JobKind::Scan, true),
			(JobKind::Verify, true),
			(JobKind::Survey, false),
			(JobKind::Drilldown, false),
			(JobKind::Unknown(crate::test_support::text("scan")), false),
		] {
			assert_eq!(legacy_kind(&kind), expected);
		}
	}
}
