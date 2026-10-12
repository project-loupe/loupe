//! Actual CLI response ingress. Original guarded Bytes stays alive through
//! every named decoder. Private legacy exits are removed at atomic M.
use anyhow::{anyhow, Result};
use bytes::Bytes;
use loupe_core::source_migration::text::BoundedText;
use loupe_core::text::{decode_json_string_bounded, policy, Normalization, TextPolicy, Whitespace};
use loupe_provenance::{Ingress, Mark, Server, Untrusted, Unvalidated, Validate};
use serde::Deserialize;
use serde_json::value::RawValue;

mod findings;
mod jobs;
mod registry;
mod reporting;
#[cfg(test)]
pub(crate) mod test_support;
pub(super) use findings::{get_finding_legacy, list_findings_legacy, search_findings_legacy};
#[cfg(fuzzing)]
pub(crate) use findings::{reset_observations, take_observations};
#[cfg(fuzzing)]
pub use findings::{Field, FieldObservation, FieldSource};
pub(super) use jobs::{cancel_job_legacy, get_job_legacy, list_jobs_legacy, retry_job_legacy};
pub(super) use registry::{
	list_repos_legacy, register_worker_bundle_legacy, show_github_app_legacy,
};

fn invalid() -> anyhow::Error {
	anyhow!("server response violates schema or field policy")
}

// Record the function actually entered, independently of the fixture selector.
#[cfg(fuzzing)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
	ShowApp,
	RegisterRepo,
	ListRepos,
	ScanRepo,
	RegisterWorker,
	ListJobs,
	GetJob,
	RetryJob,
	CancelJob,
	ListFindings,
	SearchFindings,
	GetFinding,
	RetryVerification,
	DiscardSuccess,
}
#[cfg(fuzzing)]
thread_local! { static ENTRIES: std::cell::RefCell<Vec<Entry>> = const { std::cell::RefCell::new(Vec::new()) }; }
#[cfg(fuzzing)]
fn entered(entry: Entry) {
	ENTRIES.with(|entries| entries.borrow_mut().push(entry));
}
#[cfg(fuzzing)]
pub(crate) fn take_entries() -> Vec<Entry> {
	ENTRIES.with(|entries| std::mem::take(&mut *entries.borrow_mut()))
}

#[cfg(test)]
thread_local! { static RECEIVED_ALLOCATION: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0,0)) }; }

#[cfg_attr(fuzzing, allow(dead_code))] // The direct fixture bypasses HTTP collection.
#[allow(unsafe_code)]
pub(super) async fn receive(
	resp: reqwest::Response, action: &'static str,
) -> Result<Untrusted<Bytes, Server>> {
	let status = resp.status();
	let bytes = loupe_http::read_response_bytes(resp)
		.await
		.map_err(|error| anyhow!("{action}: server returned {status}: {error}"))?;
	#[cfg(test)]
	RECEIVED_ALLOCATION.with(|seen| seen.set((bytes.as_ptr() as usize, bytes.len())));
	// SAFETY: these exact guarded bytes were read from the actual server response.
	let received = Untrusted::new(bytes, unsafe { Ingress::<Server>::new() });
	if !status.is_success() {
		return Err(received.as_bytes().validate(ServerDiagnostic { status, action })?);
	}
	Ok(received)
}
#[cfg_attr(fuzzing, allow(dead_code))] // Status/error-body integration stays in real HTTP tests.
struct ServerDiagnostic {
	status: reqwest::StatusCode,
	action: &'static str,
}
impl Validate<&[u8], Server> for ServerDiagnostic {
	type Output = anyhow::Error;
	type Error = anyhow::Error;
	fn validate<'v>(self, u: Unvalidated<'v, &[u8]>, _: Mark<'v, Server>) -> Result<Self::Output> {
		// Explicit diagnostic legacy exit: existing lossy presentation, after
		// transport admission. main owns the final terminal escaping.
		Ok(anyhow!("{}: {} — {}", self.action, self.status, String::from_utf8_lossy(u.get())))
	}
}

macro_rules! scalar_decoder {
	($name:ident, $validator:ident, $output:ty) => {
		struct $validator;
		impl Validate<&[u8], Server> for $validator {
			type Output = $output;
			type Error = anyhow::Error;
			fn validate<'v>(
				self, u: Unvalidated<'v, &[u8]>, _: Mark<'v, Server>,
			) -> Result<Self::Output> {
				serde_json::from_slice(u.get()).map_err(|_| invalid())
			}
		}
		pub(super) fn $name(body: Untrusted<Bytes, Server>) -> Result<$output> {
			#[cfg(fuzzing)]
			entered(Entry::$validator);
			body.as_bytes().validate($validator)
		}
	};
}
scalar_decoder!(register_repo, RegisterRepo, loupe_proto::RegisterRepoResponse);
scalar_decoder!(scan_repo, ScanRepo, loupe_proto::ScanResponse);
scalar_decoder!(retry_verification, RetryVerification, loupe_proto::RetryVerifyResponse);

macro_rules! local_policy {
	($name:ident, $field:literal, $multi:literal) => {
		struct $name;
		impl TextPolicy for $name {
			const FIELD: &'static str = $field;
			const MAX_BYTES: usize = policy::LEGACY_TEXT_MAX_BYTES;
			const MAX_CHARS: usize = policy::LEGACY_TEXT_MAX_BYTES;
			const MULTILINE: bool = $multi;
			const ALLOW_EMPTY: bool = true;
			const NORMALIZATION: Normalization = Normalization::Exact;
			const WHITESPACE: Whitespace = Whitespace::Significant;
			const ALLOW_CR: bool = $multi;
		}
	};
}
local_policy!(RevisionText, "revision", false);
local_policy!(AuditName, "audit_common_name", false);
local_policy!(JobDiagnostic, "job_diagnostic", true);
local_policy!(JobKindName, "job_kind", false);

macro_rules! server_field {
	($name:ident, $policy:ty) => {
		fn $name(
			mark: &Mark<'_, Server>, token: &RawValue,
		) -> Result<BoundedText<$policy, Server>> {
			let text = decode_json_string_bounded(
				token.get(),
				<$policy>::FIELD,
				<$policy>::MAX_BYTES,
				<$policy>::MAX_CHARS,
			)
			.map_err(|_| invalid())?;
			BoundedText::new(mark, &text).map_err(|_| invalid())
		}
	};
}
server_field!(revision, RevisionText);
server_field!(audit, AuditName);
server_field!(diagnostic, JobDiagnostic);
server_field!(kind, JobKindName);
server_field!(clone_url, policy::CloneUrl);
server_field!(host, policy::RepoHost);
server_field!(owner, policy::RepoOwner);
server_field!(repo, policy::RepoName);
server_field!(branch, policy::GitBranch);
server_field!(slug, policy::GithubAppSlug);
server_field!(address, policy::MailAddress);
server_field!(subject, policy::MailSubjectPrefix);

// These concrete projections are the only field-level legacy exits. They
// keep each source fixed; there is no caller-selected source or typed decoder.
macro_rules! legacy_server_field {
	($name:ident, $typed:ident) => {
		fn $name(mark: &Mark<'_, Server>, token: &RawValue) -> Result<String> {
			Ok($typed(mark, token)?.expose().to_owned())
		}
	};
}
legacy_server_field!(revision_legacy, revision);
legacy_server_field!(diagnostic_legacy, diagnostic);
legacy_server_field!(clone_url_legacy, clone_url);
legacy_server_field!(host_legacy, host);
legacy_server_field!(owner_legacy, owner);
legacy_server_field!(repo_legacy, repo);
legacy_server_field!(branch_legacy, branch);
legacy_server_field!(slug_legacy, slug);

struct DiscardSuccess;
impl Validate<&[u8], Server> for DiscardSuccess {
	type Output = ();
	type Error = anyhow::Error;
	fn validate<'v>(self, _: Unvalidated<'v, &[u8]>, _: Mark<'v, Server>) -> Result<()> {
		Ok(())
	}
}
pub(super) fn discard(body: Untrusted<Bytes, Server>) -> Result<()> {
	#[cfg(fuzzing)]
	entered(Entry::DiscardSuccess);
	body.as_bytes().validate(DiscardSuccess)
}
