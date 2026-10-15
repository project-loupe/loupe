//! Byte zero selects one of 36 DTO contexts; the rest is raw JSON.
//! Inputs are capped at 512 KiB, allowing report-budget and PoC boundaries.
//! Credential equality uses subtle; explicit field comparisons avoid requiring
//! PartialEq on credential-bearing DTOs.
//! Source-bearing DTOs enter through their actual named consumer. Standalone
//! fragments are put in a fixed synthetic enclosing message before admission;
//! this is not a public generic Deserialize path or an HTTP coverage claim.

use std::fmt::Debug;

use loupe_proto::*;
use loupe_provenance::{Agent, Operator, Secret, Server, Worker};
use serde::Serialize;
use subtle::ConstantTimeEq;

use crate::utils::test_logger;

type LeaseRequest = loupe_proto::LeaseRequest<Worker>;
type LeaseResponse = loupe_proto::LeaseResponse<Agent, Server>;
type LeaseEnvelope = loupe_proto::LeaseEnvelope<Agent, Server>;
type LeasePayload = loupe_proto::LeasePayload<Agent, Server>;
type FindingsBatch = loupe_proto::FindingsBatch<Agent>;
type LlmFindingSubmission = loupe_proto::LlmFindingSubmission<Agent>;
type VerdictSubmission = loupe_proto::VerdictSubmission<Agent>;
type CompleteRequest = loupe_proto::CompleteRequest<Worker, Worker>;
type JobInfo = loupe_proto::JobInfo<Server>;
type ReportingSetup = loupe_proto::ReportingSetup<Operator>;
type RegisterRepoRequest = loupe_proto::RegisterRepoRequest<Operator>;
type SetRepoGithubReportingRequest = loupe_proto::SetRepoGithubReportingRequest<Operator>;
type GithubAppSummary = loupe_proto::GithubAppSummary<Server>;
type GithubAppResponse = loupe_proto::GithubAppResponse<Server>;
type ListReposResponse = loupe_proto::ListReposResponse<Server>;
type ReportingSummary = loupe_proto::ReportingSummary<Server>;
type RepoSummary = loupe_proto::RepoSummary<Server>;
type RegisterWorkerRequest = loupe_proto::RegisterWorkerRequest<Operator>;
type ListFindingsResponse = loupe_proto::ListFindingsResponse<Agent, Server>;
type FindingSummary = loupe_proto::FindingSummary<Agent, Server>;
type FindingDetail = loupe_proto::FindingDetail<Agent, Server>;

trait NamedDecode: Sized {
	fn decode(raw: &[u8]) -> Option<Self>;
}
macro_rules! scalar_decoder {
	($($ty:ty),+ $(,)?) => { $(impl NamedDecode for $ty {
		fn decode(raw: &[u8]) -> Option<Self> { serde_json::from_slice(raw).ok() }
	})+ };
}
scalar_decoder!(
	HeartbeatRequest,
	HeartbeatResponse,
	ScanRequest,
	ScanResponse,
	RegisterRepoResponse,
	RotateRepoPatRequest,
	SetGithubAppRequest,
	UpdateRepoRequest,
	GithubReportingAuth,
	RegisterWorkerResponse,
	RetryVerifyRequest,
	RetryVerifyResponse,
	CompleteOutcome,
	JobCapability,
	ProtocolMismatch
);
macro_rules! worker_decoder {
	($ty:ty, $case:ident, $variant:ident) => {
		impl NamedDecode for $ty {
			fn decode(raw: &[u8]) -> Option<Self> {
				use loupe_server::fuzz_support::{worker_value, WorkerRequest, WorkerValue};
				match worker_value(WorkerRequest::$case, raw)? {
					WorkerValue::$variant(value) => Some(value),
					_ => None,
				}
			}
		}
	};
}
worker_decoder!(LeaseRequest, Lease, Lease);
worker_decoder!(FindingsBatch, Findings, Findings);
worker_decoder!(LlmFindingSubmission, LlmFinding, Llm);
worker_decoder!(VerdictSubmission, Verdict, Verdict);
worker_decoder!(CompleteRequest, Complete, Complete);
macro_rules! operator_decoder {
	($ty:ty, $case:ident, $variant:ident) => {
		impl NamedDecode for $ty {
			fn decode(raw: &[u8]) -> Option<Self> {
				use loupe_server::fuzz_support::{operator_value, OperatorRequest, OperatorValue};
				match operator_value(OperatorRequest::$case, raw)? {
					OperatorValue::$variant(value) => Some(value),
					_ => None,
				}
			}
		}
	};
}
operator_decoder!(RegisterRepoRequest, RegisterRepo, Register);
operator_decoder!(SetRepoGithubReportingRequest, SetReporting, Reporting);
operator_decoder!(RegisterWorkerRequest, RegisterWorker, Worker);
macro_rules! cli_decoder {
	($ty:ty, $case:ident, $variant:ident) => {
		impl NamedDecode for $ty {
			fn decode(raw: &[u8]) -> Option<Self> {
				use loupe_cli::fuzz_support::{observe_response, ResponseCase, ResponseValue};
				match observe_response(ResponseCase::$case, raw).result.ok()? {
					ResponseValue::$variant(value) => Some(value),
					_ => None,
				}
			}
		}
	};
}
cli_decoder!(JobInfo, GetJob, Job);
cli_decoder!(GithubAppResponse, ShowApp, App);
cli_decoder!(ListReposResponse, ListRepos, Repos);
cli_decoder!(ListFindingsResponse, ListFindings, Findings);
cli_decoder!(FindingDetail, GetFinding, Finding);
impl NamedDecode for LeaseResponse {
	fn decode(raw: &[u8]) -> Option<Self> {
		loupe_worker::client::fuzz_support::lease_response(raw)
	}
}
fn enclosure(prefix: &str, raw: &[u8], suffix: &str) -> Option<Vec<u8>> {
	let raw = std::str::from_utf8(raw).ok()?;
	Some(format!("{prefix}{raw}{suffix}").into_bytes())
}
impl NamedDecode for LeaseEnvelope {
	fn decode(raw: &[u8]) -> Option<Self> {
		let raw = std::str::from_utf8(raw).ok()?.trim_start();
		let body = if let Some(tail) = raw.strip_prefix('{') {
			format!(r#"{{"kind":"lease",{tail}"#)
		} else {
			let tail = raw.strip_prefix('[')?;
			format!(r#"["lease",{tail}"#)
		};
		match LeaseResponse::decode(body.as_bytes())? {
			LeaseResponse::Lease(value) => Some(*value),
			_ => None,
		}
	}
}
impl NamedDecode for LeasePayload {
	fn decode(raw: &[u8]) -> Option<Self> {
		let body = enclosure(
			r#"{"protocol_version":2,"job_id":1,"repo_id":1,"job_capability":"fixture","repo":{"host":"example.org","owner":"org","repo":"repo","clone_url":"https://example.org/org/repo"},"scanner_config":null,"lease_expires_at":300,"payload":"#,
			raw,
			"}",
		)?;
		Some(LeaseEnvelope::decode(&body)?.payload)
	}
}
impl NamedDecode for ReportingSetup {
	fn decode(raw: &[u8]) -> Option<Self> {
		let body = enclosure(
			r#"{"protocol_version":2,"clone_url":"https://example.org/org/repo","reporting":"#,
			raw,
			"}",
		)?;
		Some(RegisterRepoRequest::decode(&body)?.reporting)
	}
}
impl NamedDecode for GithubAppSummary {
	fn decode(raw: &[u8]) -> Option<Self> {
		let body = enclosure(r#"{"protocol_version":2,"app":"#, raw, "}")?;
		GithubAppResponse::decode(&body)?.app
	}
}
impl NamedDecode for RepoSummary {
	fn decode(raw: &[u8]) -> Option<Self> {
		let body = enclosure(r#"{"protocol_version":2,"repos":["#, raw, "]}")?;
		ListReposResponse::decode(&body)?.repos.into_iter().next()
	}
}
impl NamedDecode for ReportingSummary {
	fn decode(raw: &[u8]) -> Option<Self> {
		let body = enclosure(
			r#"{"id":1,"clone_url":"https://example.org/org/repo","host":"example.org","owner":"org","repo":"repo","verification_enabled":false,"created_at":0,"reporting":"#,
			raw,
			"}",
		)?;
		RepoSummary::decode(&body)?.reporting
	}
}
impl NamedDecode for FindingSummary {
	fn decode(raw: &[u8]) -> Option<Self> {
		let body = enclosure(r#"{"protocol_version":2,"findings":["#, raw, "]}")?;
		ListFindingsResponse::decode(&body)?.findings.into_iter().next()
	}
}

fn decode<T: NamedDecode + Serialize>(raw: &[u8]) -> Option<(T, T)> {
	let value = T::decode(raw)?;
	let encoded = serde_json::to_vec(&value).unwrap_or_else(|_| panic!("DTO serialization failed"));
	let back = T::decode(&encoded).unwrap_or_else(|| panic!("serialized DTO could not be decoded"));
	Some((value, back))
}

fn roundtrip<T: NamedDecode + Serialize + PartialEq + Debug>(raw: &[u8]) {
	if let Some((value, back)) = decode::<T>(raw) {
		assert_eq!(value, back, "DTO round trip changed a field");
	}
}

fn capability(value: &JobCapability, back: &JobCapability) {
	assert!(
		bool::from(value.expose_secret().as_bytes().ct_eq(back.expose_secret().as_bytes())),
		"capability changed during wire round trip"
	);
	assert_eq!(format!("{value:?}"), "[redacted]");
	assert_eq!(format!("{back:?}"), "[redacted]");
	assert_eq!(format!("{value}"), "[redacted]");
	assert_eq!(format!("{back}"), "[redacted]");
}

fn secret(value: &Secret<String>, back: &Secret<String>) {
	assert!(
		bool::from(value.expose().as_bytes().ct_eq(back.expose().as_bytes())),
		"PAT changed during wire round trip"
	);
}

fn optional_secret(value: &Option<Secret<String>>, back: &Option<Secret<String>>) {
	match (value, back) {
		(Some(value), Some(back)) => secret(value, back),
		(None, None) => {},
		_ => panic!("PAT presence changed during wire round trip"),
	}
}

fn scrub_pat(value: &mut Option<Secret<String>>) {
	if value.is_some() {
		*value = Some(Secret::new("fixed PAT debug baseline".into()));
	}
}

fn scrub_envelope(value: &mut LeaseEnvelope) {
	let debug = format!("{value:?}");
	value.job_capability = JobCapability::from_secret("fixed debug baseline");
	// Only the capability changes. A coincidental secret match in another
	// public field cannot cause a false positive in this comparison.
	assert_eq!(debug, format!("{value:?}"), "envelope Debug exposes capability");
	let debug = format!("{value:?}");
	scrub_pat(&mut value.github_pat);
	assert_eq!(debug, format!("{value:?}"), "envelope Debug exposes PAT");
}

fn envelope(value: &mut LeaseEnvelope, back: &mut LeaseEnvelope) {
	capability(&value.job_capability, &back.job_capability);
	optional_secret(&value.github_pat, &back.github_pat);
	assert_eq!(value.protocol_version, back.protocol_version);
	assert_eq!(value.job_id, back.job_id);
	assert_eq!(value.repo_id, back.repo_id);
	assert_eq!(value.repo, back.repo);
	assert_eq!(value.head_branch, back.head_branch);
	assert_eq!(value.lease_expires_at, back.lease_expires_at);
	assert_eq!(value.scanner_config, back.scanner_config);
	assert_eq!(value.payload, back.payload);
	scrub_envelope(value);
	scrub_envelope(back);
}

fn reporting(value: &mut ReportingSetup, back: &mut ReportingSetup) {
	let before = (format!("{value:?}"), format!("{back:?}"));
	match (&mut *value, &mut *back) {
		(
			ReportingSetup::GithubIssue { target_owner, target_repo, github_pat },
			ReportingSetup::GithubIssue { target_owner: owner, target_repo: repo, github_pat: pat },
		) => {
			assert_eq!(target_owner, owner);
			assert_eq!(target_repo, repo);
			optional_secret(github_pat, pat);
			scrub_pat(github_pat);
			scrub_pat(pat);
		},
		(
			ReportingSetup::Email { to, from, subject_prefix },
			ReportingSetup::Email { to: back_to, from: back_from, subject_prefix: back_prefix },
		) => {
			assert_eq!(to, back_to);
			assert_eq!(from, back_from);
			assert_eq!(subject_prefix, back_prefix);
		},
		(ReportingSetup::Manual, ReportingSetup::Manual) => {},
		_ => panic!("reporting setup variant changed during wire round trip"),
	}
	assert_eq!(before, (format!("{value:?}"), format!("{back:?}")), "reporting Debug exposes PAT");
}

pub fn do_test(data: &[u8]) {
	let Some((&selector, raw)) = data.split_first() else { return };
	if raw.len() > 512 * 1024 {
		return;
	}
	match selector % 36 {
		0 => roundtrip::<LeaseRequest>(raw),
		1 => {
			if let Some((mut value, mut back)) = decode::<LeaseResponse>(raw) {
				match (&mut value, &mut back) {
					(LeaseResponse::Lease(a), LeaseResponse::Lease(b)) => envelope(a, b),
					(
						LeaseResponse::Empty { protocol_version: a },
						LeaseResponse::Empty { protocol_version: b },
					) => assert_eq!(a, b),
					_ => panic!("lease response variant changed during wire round trip"),
				}
			}
		},
		2 => {
			if let Some((mut value, mut back)) = decode::<LeaseEnvelope>(raw) {
				envelope(&mut value, &mut back);
			}
		},
		3 => roundtrip::<LeasePayload>(raw),
		4 => roundtrip::<HeartbeatRequest>(raw),
		5 => roundtrip::<HeartbeatResponse>(raw),
		6 => roundtrip::<FindingsBatch>(raw),
		7 => {
			if let Some((value, back)) = decode::<LlmFindingSubmission>(raw) {
				assert_eq!(value, back);
				assert_eq!(
					validate_llm_finding_submission(&value).is_ok(),
					submission_allowed(&value),
					"LLM submission acceptance disagrees with independent oracle"
				);
			}
		},
		8 => roundtrip::<VerdictSubmission>(raw),
		9 => roundtrip::<CompleteRequest>(raw),
		10 => roundtrip::<ScanRequest>(raw),
		11 => roundtrip::<ScanResponse>(raw),
		12 => roundtrip::<JobInfo>(raw),
		13 => {
			if let Some((mut value, mut back)) = decode::<ReportingSetup>(raw) {
				reporting(&mut value, &mut back);
			}
		},
		14 => {
			if let Some((mut value, mut back)) = decode::<RegisterRepoRequest>(raw) {
				assert_eq!(value.protocol_version, back.protocol_version);
				assert_eq!(value.clone_url, back.clone_url);
				assert_eq!(value.branch, back.branch);
				assert_eq!(value.scan_interval_seconds, back.scan_interval_seconds);
				assert_eq!(value.scanner_config, back.scanner_config);
				assert_eq!(value.verification_enabled, back.verification_enabled);
				assert_eq!(value.require_approval, back.require_approval);
				let before = (format!("{value:?}"), format!("{back:?}"));
				reporting(&mut value.reporting, &mut back.reporting);
				assert_eq!(
					before,
					(format!("{value:?}"), format!("{back:?}")),
					"registration Debug exposes PAT"
				);
			}
		},
		15 => roundtrip::<RegisterRepoResponse>(raw),
		16 => {
			if let Some((mut value, mut back)) = decode::<RotateRepoPatRequest>(raw) {
				assert_eq!(value.protocol_version, back.protocol_version);
				secret(&value.github_pat, &back.github_pat);
				let before = (format!("{value:?}"), format!("{back:?}"));
				value.github_pat = Secret::new("fixed PAT debug baseline".into());
				back.github_pat = Secret::new("fixed PAT debug baseline".into());
				assert_eq!(
					before,
					(format!("{value:?}"), format!("{back:?}")),
					"rotation Debug exposes PAT"
				);
			}
		},
		17 => {
			if let Some((mut value, mut back)) = decode::<SetRepoGithubReportingRequest>(raw) {
				assert_eq!(value.protocol_version, back.protocol_version);
				assert_eq!(value.target_owner, back.target_owner);
				assert_eq!(value.target_repo, back.target_repo);
				optional_secret(&value.github_pat, &back.github_pat);
				let before = (format!("{value:?}"), format!("{back:?}"));
				scrub_pat(&mut value.github_pat);
				scrub_pat(&mut back.github_pat);
				assert_eq!(
					before,
					(format!("{value:?}"), format!("{back:?}")),
					"reporting update Debug exposes PAT"
				);
			}
		},
		18 => {
			if let Some((value, back)) = decode::<SetGithubAppRequest>(raw) {
				assert_eq!(value.protocol_version, back.protocol_version);
				assert_eq!(value.app_id, back.app_id);
				assert!(
					bool::from(
						value
							.private_key_pem
							.expose()
							.as_bytes()
							.ct_eq(back.private_key_pem.expose().as_bytes())
					),
					"App private PEM changed during wire round trip"
				);
			}
		},
		19 => roundtrip::<GithubAppSummary>(raw),
		20 => roundtrip::<GithubAppResponse>(raw),
		21 => roundtrip::<UpdateRepoRequest>(raw),
		22 => roundtrip::<ListReposResponse>(raw),
		23 => roundtrip::<GithubReportingAuth>(raw),
		24 => roundtrip::<ReportingSummary>(raw),
		25 => roundtrip::<RepoSummary>(raw),
		26 => roundtrip::<RegisterWorkerRequest>(raw),
		27 => {
			if let Some((mut value, mut back)) = decode::<RegisterWorkerResponse>(raw) {
				assert_eq!(value.protocol_version, back.protocol_version);
				assert_eq!(value.worker_id, back.worker_id);
				assert_eq!(value.client_cert_pem, back.client_cert_pem);
				secret(&value.client_key_pem, &back.client_key_pem);
				secret(&value.ca_cert_pem, &back.ca_cert_pem);
				for response in [&mut value, &mut back] {
					let before = format!("{response:?}");
					response.client_key_pem =
						Secret::new("fixed private-key debug baseline".into());
					response.ca_cert_pem = Secret::new("fixed mixed-CA debug baseline".into());
					assert_eq!(before, format!("{response:?}"), "registration Debug exposes PEM");
				}
			}
		},
		28 => roundtrip::<ListFindingsResponse>(raw),
		29 => roundtrip::<RetryVerifyRequest>(raw),
		30 => roundtrip::<RetryVerifyResponse>(raw),
		31 => roundtrip::<FindingSummary>(raw),
		32 => roundtrip::<FindingDetail>(raw),
		33 => roundtrip::<CompleteOutcome>(raw),
		34 => {
			if let Some((value, back)) = decode::<JobCapability>(raw) {
				capability(&value, &back);
			}
		},
		35 => roundtrip::<ProtocolMismatch>(raw),
		_ => unreachable!(),
	}
}

fn submission_allowed(value: &LlmFindingSubmission) -> bool {
	let title_chars = value.title.expose().trim().chars().count();
	let description_chars = value.description.expose().trim().chars().count();
	let content_chars =
		value.description.expose().chars().count() + value.poc_unified.expose().chars().count();
	let cwe_valid = value.cwe.as_ref().is_none_or(|cwe| {
		let cwe = cwe.expose();
		cwe.as_bytes().starts_with(b"CWE-")
			&& cwe.len() > 4
			&& cwe.as_bytes().iter().skip(4).all(u8::is_ascii_digit)
	});
	let fingerprint_valid = value.fingerprint.expose().len() == 64
		&& value.fingerprint.expose().bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
	(8..=100).contains(&title_chars)
		&& (80..=16_384).contains(&description_chars)
		&& content_chars <= 60_000
		&& value.line_start > 0
		&& value.line_end >= value.line_start
		&& relative_path_allowed(value.file_path.expose())
		&& cwe_valid
		&& fingerprint_valid
		&& value.poc_unified.expose().len() <= 262_144
		&& diff_allowed(value.poc_unified.expose())
}

// Independent lexical recognizer for the Unix Path::components behavior the
// validator accepts: inner dots and repeated/trailing slashes fold,
// a leading dot component or any parent component does not. NUL and backslash
// are ordinary bytes here. Non-Unix replay uses the platform's path components.
#[cfg(unix)]
fn relative_path_allowed(path: &str) -> bool {
	!path.trim().is_empty()
		&& !path.starts_with('/')
		&& path.split('/').next() != Some(".")
		&& path.split('/').all(|component| component != "..")
}

#[cfg(not(unix))]
fn relative_path_allowed(path: &str) -> bool {
	let parsed = std::path::Path::new(path);
	!path.trim().is_empty()
		&& !parsed.is_absolute()
		&& parsed.components().all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn diff_allowed(poc: &str) -> bool {
	// Partition at the first hunk before inspecting headers and additions;
	// this oracle has no mutable in-hunk state shared with production.
	let Some(hunk) = poc.lines().position(|line| line.starts_with("@@ ")) else { return false };
	let old = poc.lines().take(hunk).any(|line| line.starts_with("--- "));
	let new = poc.lines().take(hunk).any(|line| line.starts_with("+++ "));
	let added = poc.lines().skip(hunk + 1).any(|line| {
		line.strip_prefix('+')
			.is_some_and(|tail| !tail.starts_with("++") && !tail.trim().is_empty())
	});
	old && new && added
}

pub fn proto_dto_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn proto_dto_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use serde_json::{json, Value};

	use super::*;

	fn admitted<T: NamedDecode + Serialize>(raw: Value) -> Value {
		let bytes = serde_json::to_vec(&raw).unwrap_or_else(|e| panic!("fixture JSON: {e}"));
		let (value, back) = decode::<T>(&bytes).unwrap_or_else(|| {
			panic!("named DTO fixture rejected: {}", std::any::type_name::<T>())
		});
		let actual = serde_json::to_value(value).unwrap_or_else(|e| panic!("DTO encoding: {e}"));
		assert_eq!(
			actual,
			serde_json::to_value(back).unwrap_or_else(|e| panic!("DTO re-encoding: {e}"))
		);
		assert!(T::decode(b"{").is_none(), "malformed JSON unexpectedly admitted");
		assert!(T::decode(b"null").is_none(), "wrong top-level type unexpectedly admitted");
		actual
	}

	fn finding() -> Value {
		json!({"scanner_id":"scanner", "severity":"high", "title":"Exact e\u{301} title",
			"description":"First line\nSecond line", "fingerprint":"fingerprint",
			"file_path":"src/lib.rs", "line_start":1, "line_end":2})
	}

	fn summary() -> Value {
		let mut value = finding();
		let fields =
			value.as_object_mut().unwrap_or_else(|| panic!("finding fixture is not an object"));
		fields.remove("description");
		fields.remove("line_end");
		for (field, scalar) in [("id", 1), ("repo_id", 2), ("job_id", 3), ("created_at", 4)] {
			value[field] = json!(scalar);
		}
		value["state"] = json!("pending");
		value["verification_required"] = json!(true);
		value["approved_by_cn"] = json!("operator");
		value
	}

	#[test]
	fn named_request_decoders_are_reached_with_nonempty_fields() {
		let lease = admitted::<LeaseRequest>(
			json!({"protocol_version":2,"capabilities":["scan","verify:llm-review"],"wait_seconds":4}),
		);
		assert_eq!(lease["capabilities"], json!(["scan", "verify:llm-review"]));
		let batch = admitted::<FindingsBatch>(json!({"protocol_version":2,"findings":[finding()]}));
		assert_eq!(batch["findings"][0], finding());
		let submission = json!({"protocol_version":2,"severity":"high","title":"A sufficiently long title",
			"description":"An attacker-controlled index reaches an unchecked operation and reliably terminates the service process.",
			"file_path":"src/lib.rs","line_start":1,"line_end":2,"cwe":"CWE-129",
			"poc_unified":"--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1,2 @@\n old\n+added\n",
			"fingerprint":"a".repeat(64)});
		assert_eq!(admitted::<LlmFindingSubmission>(submission.clone()), submission);
		let verdict = json!({"protocol_version":2,"verdict":{"outcome":"confirmed","notes":"exact\nnotes","patch":{"patch_unified":"diff\n","notes":"patch notes"}}});
		assert_eq!(admitted::<VerdictSubmission>(verdict.clone()), verdict);
		let complete = json!({"protocol_version":2,"outcome":"failed","head_sha":"original revision","error":"exact\ndiagnostic"});
		assert_eq!(admitted::<CompleteRequest>(complete.clone()), complete);
		let reporting = json!({"kind":"github_issue","target_owner":"org","target_repo":"repo","github_pat":"fake escaped\nPAT"});
		assert_eq!(admitted::<ReportingSetup>(reporting.clone()), reporting);
		let register = json!({"protocol_version":2,"clone_url":"https://example.org/org/repo","reporting":reporting,"scanner_config":{"unknown":[true,null]}});
		assert_eq!(admitted::<RegisterRepoRequest>(register.clone()), register);
		let update = json!({"protocol_version":2,"target_owner":"org","target_repo":"repo","github_pat":"fake PAT"});
		assert_eq!(admitted::<SetRepoGithubReportingRequest>(update.clone()), update);
		let worker = json!({"protocol_version":2,"name":"worker fixture"});
		assert_eq!(admitted::<RegisterWorkerRequest>(worker.clone()), worker);
	}

	#[test]
	fn named_response_and_fragment_decoders_are_reached() {
		let repo = json!({"id":1,"clone_url":"https://example.org/org/repo","host":"example.org","owner":"org","repo":"repo","verification_enabled":false,"created_at":0,
			"reporting":{"kind":"github_issue","target_owner":"org","target_repo":"repo","auth":"pat"}});
		assert_eq!(admitted::<RepoSummary>(repo.clone()), repo);
		assert_eq!(admitted::<ReportingSummary>(repo["reporting"].clone()), repo["reporting"]);
		let repos = json!({"protocol_version":2,"repos":[repo]});
		assert_eq!(admitted::<ListReposResponse>(repos.clone()), repos);
		let app = json!({"app_id":42,"slug":"app-slug"});
		assert_eq!(admitted::<GithubAppSummary>(app.clone()), app);
		let response = json!({"protocol_version":2,"app":app});
		assert_eq!(admitted::<GithubAppResponse>(response.clone()), response);
		let job = admitted::<JobInfo>(
			json!({"job_id":1,"repo_id":2,"kind":"scan","state":"queued","incremental":false,"attempts":0,"enqueued_at":1700000000}),
		);
		assert_eq!(job["kind"], "scan");
		assert_eq!(job["job_id"], 1);
		let summary = summary();
		assert_eq!(admitted::<FindingSummary>(summary.clone()), summary);
		let findings = json!({"protocol_version":2,"findings":[summary.clone()]});
		assert_eq!(admitted::<ListFindingsResponse>(findings.clone()), findings);
		let mut detail = summary;
		detail["protocol_version"] = json!(2);
		detail["description"] = finding()["description"].clone();
		detail["line_end"] = json!(2);
		assert_eq!(admitted::<FindingDetail>(detail.clone()), detail);
		let payload = json!({"kind":"verify","finding_id":1,"finding":finding(),"reviewed_sha":"exact revision"});
		assert_eq!(admitted::<LeasePayload>(payload.clone()), payload);
		let lease = json!({"protocol_version":2,"job_id":1,"repo_id":1,"job_capability":"fake capability",
			"repo":{"host":"example.org","owner":"org","repo":"repo","clone_url":"https://example.org/org/repo"},
			"head_branch":null,"scanner_config":null,"lease_expires_at":300,"github_pat":"fake PAT","payload":payload});
		assert_eq!(admitted::<LeaseEnvelope>(lease.clone()), lease);
		let mut response = lease;
		response["kind"] = json!("lease");
		assert_eq!(admitted::<LeaseResponse>(response.clone()), response);
	}
}
