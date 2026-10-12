//! Byte zero selects one of 36 public DTO types; the rest is raw JSON.
//! Inputs are capped at 512 KiB, allowing report-budget and PoC boundaries.
//! Credential equality uses subtle; other fields retain explicit comparisons
//! when their enclosing DTO no longer derives PartialEq.

use std::fmt::Debug;

use loupe_proto::*;
use loupe_provenance::Secret;
use serde::de::DeserializeOwned;
use serde::Serialize;
use subtle::ConstantTimeEq;

use crate::utils::test_logger;

fn decode<T: DeserializeOwned + Serialize>(raw: &[u8]) -> Option<(T, T)> {
	let value: T = serde_json::from_slice(raw).ok()?;
	let encoded = serde_json::to_vec(&value).unwrap_or_else(|_| panic!("DTO serialization failed"));
	let back: T = serde_json::from_slice(&encoded)
		.unwrap_or_else(|_| panic!("serialized DTO could not be decoded"));
	Some((value, back))
}

fn roundtrip<T: DeserializeOwned + Serialize + PartialEq + Debug>(raw: &[u8]) {
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
		27 => roundtrip::<RegisterWorkerResponse>(raw),
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
	let title_chars = value.title.trim().chars().count();
	let description_chars = value.description.trim().chars().count();
	let content_chars = value.description.chars().count() + value.poc_unified.chars().count();
	let cwe_valid = value.cwe.as_ref().is_none_or(|cwe| {
		cwe.as_bytes().starts_with(b"CWE-")
			&& cwe.len() > 4
			&& cwe.as_bytes().iter().skip(4).all(u8::is_ascii_digit)
	});
	let fingerprint_valid = value.fingerprint.len() == 64
		&& value.fingerprint.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
	(8..=100).contains(&title_chars)
		&& (80..=16_384).contains(&description_chars)
		&& content_chars <= 60_000
		&& value.line_start > 0
		&& value.line_end >= value.line_start
		&& relative_path_allowed(&value.file_path)
		&& cwe_valid
		&& fingerprint_valid
		&& value.poc_unified.len() <= 262_144
		&& diff_allowed(&value.poc_unified)
}

// Independent lexical recognizer for the Unix Path::components behavior the
// validator currently accepts: inner dots and repeated/trailing slashes fold,
// a leading dot component or any parent component does not. NUL and backslash
// are ordinary bytes here; this target records existing behavior, not a policy
// change. Keep a platform-equivalent fallback for non-Unix corpus replay.
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
