//! Exact Operator/Secret observations, before the production legacy exits.
use loupe_provenance::{Ingress, Untrusted};
use serde_json::{json, Value};

use super::*;
use crate::fuzz_support::{error, Decoded};

#[derive(Clone, Copy, Debug)]
pub enum OperatorRequest {
	RegisterRepo,
	UpdateRepo,
	EnqueueScan,
	RetryVerify,
	RegisterWorker,
	RotatePat,
	SetApp,
	SetReporting,
}

fn original(bytes: &[u8]) -> Untrusted<&[u8], Operator> {
	// SAFETY: fixed synthetic Operator message supplied by this fuzz fixture.
	#[allow(unsafe_code)]
	Untrusted::new(bytes, unsafe { Ingress::<Operator>::new() })
}

fn secret(secret: &Secret<String>) -> &str {
	assert_eq!(format!("{secret:?}"), "[redacted]");
	assert_eq!(format!("{secret}"), "[redacted]");
	secret.expose()
}

pub fn operator_request(kind: OperatorRequest, bytes: &[u8]) -> Decoded {
	decode(kind, bytes).map_err(error)
}

fn decode(kind: OperatorRequest, bytes: &[u8]) -> Result<Value, DecodeError> {
	let input = original(bytes);
	Ok(match kind {
		OperatorRequest::RegisterRepo => {
			let value = input.validate(RegisterRepoDecoder)?;
			let url: &BoundedText<policy::CloneUrl, Operator> = &value.clone_url;
			let branch: &Option<BoundedText<policy::GitBranch, Operator>> = &value.branch;
			let derived: &Option<RepoSpec<Operator>> = &value.derived;
			let reporting: &ReportingDestination<Operator> = &value.reporting;
			let reporting = match reporting {
				ReportingDestination::GithubIssue { target_owner, target_repo, pat_secret_id } => {
					assert!(pat_secret_id.is_none());
					json!({"kind":"github_issue", "target_owner":target_owner.expose(), "target_repo":target_repo.expose(), "github_pat":value.pat.as_ref().map(secret)})
				},
				ReportingDestination::Email { to, from, subject_prefix } => {
					json!({"kind":"email", "to":to.iter().map(BoundedText::expose).collect::<Vec<_>>(), "from":from.as_ref().map(BoundedText::expose), "subject_prefix":subject_prefix.as_ref().map(BoundedText::expose)})
				},
				ReportingDestination::Manual => json!({"kind":"manual"}),
			};
			json!({"request": {"protocol_version":value.protocol_version, "clone_url":url.expose(),
				"branch":branch.as_ref().map(BoundedText::expose), "scan_interval_seconds":value.scan_interval_seconds,
				"reporting":reporting, "scanner_config":value.scanner_config.0,
				"verification_enabled":value.verification_enabled, "require_approval":value.require_approval},
				"derived":derived.as_ref().map(|r| (r.host.expose(), r.owner.expose(), r.repo.expose()))})
		},
		OperatorRequest::UpdateRepo => {
			let value = input.validate(UpdateRepoDecoder)?;
			serde_json::to_value(value).expect("scalar request serializes")
		},
		OperatorRequest::EnqueueScan => {
			let value = input.validate(EnqueueScanDecoder)?;
			serde_json::to_value(value).expect("scalar request serializes")
		},
		OperatorRequest::RetryVerify => {
			let value = input.validate(RetryVerifyDecoder)?;
			serde_json::to_value(value).expect("scalar request serializes")
		},
		OperatorRequest::RegisterWorker => {
			let (version, name): (u16, BoundedText<policy::WorkerName, Operator>) =
				input.validate(RegisterWorkerDecoder)?;
			json!({"protocol_version":version, "name":name.expose()})
		},
		OperatorRequest::RotatePat => {
			let value = input.validate(RotateRepoPatDecoder)?;
			json!({"protocol_version":value.protocol_version, "github_pat":secret(&value.github_pat)})
		},
		OperatorRequest::SetApp => {
			let value = input.validate(SetGithubAppDecoder)?;
			json!({"protocol_version":value.protocol_version, "app_id":value.app_id, "private_key_pem":secret(&value.private_key_pem)})
		},
		OperatorRequest::SetReporting => {
			let value = input.validate(SetRepoGithubReportingDecoder)?;
			let owner: &BoundedText<policy::RepoOwner, Operator> = &value.owner;
			let repo: &BoundedText<policy::RepoName, Operator> = &value.repo;
			json!({"protocol_version":value.protocol_version, "target_owner":owner.expose(), "target_repo":repo.expose(), "github_pat":value.pat.as_ref().map(secret)})
		},
	})
}
