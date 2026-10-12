//! Actual CLI response ingress. Original guarded Bytes stays alive through
//! every named decoder and returns source-bearing domain values.
use anyhow::{anyhow, Result};
use bytes::Bytes;
use loupe_core::text::policy::{AuditName, JobDiagnostic, JobKindName, RevisionText};
use loupe_core::text::{decode_json_string_bounded, policy, BoundedText, TextPolicy};
use loupe_provenance::{Ingress, Mark, Server, Untrusted, Unvalidated, Validate};
use serde::Deserialize;
use serde_json::value::RawValue;

mod findings;
mod jobs;
mod registry;
mod reporting;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg_attr(test, allow(unused_imports))] // Library rendering tests use only detail ingress.
pub(super) use findings::{get_finding, list_findings, search_findings};
#[cfg(fuzzing)]
#[allow(unused_imports)] // Only the library's fuzz fixture reads these shared observations.
pub(crate) use findings::{reset_observations, take_observations};
#[cfg(fuzzing)]
#[allow(unused_imports)] // Only the library's fuzz fixture exports these shared observations.
pub use findings::{Field, FieldObservation, FieldSource};
#[cfg_attr(test, allow(unused_imports))]
// Binary and fuzz fixtures exercise the full inventory.
pub(super) use jobs::{cancel_job, get_job, list_jobs, retry_job};
#[cfg_attr(test, allow(unused_imports))]
// Binary and fuzz fixtures exercise the full inventory.
pub(super) use registry::{list_repos, register_worker_bundle, show_github_app};

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
#[allow(dead_code)] // The binary shares ingress; the library fixture collects its observations.
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
		return Err(received.as_bytes().validate(ServerDiagnostic { status, action })?.into());
	}
	Ok(received)
}
#[cfg_attr(fuzzing, allow(dead_code))] // Status/error-body integration stays in real HTTP tests.
struct ServerDiagnostic {
	status: reqwest::StatusCode,
	action: &'static str,
}
impl Validate<&[u8], Server> for ServerDiagnostic {
	type Output = TerminalDiagnostic;
	type Error = anyhow::Error;
	fn validate<'v>(self, u: Unvalidated<'v, &[u8]>, _: Mark<'v, Server>) -> Result<Self::Output> {
		Ok(TerminalDiagnostic {
			bytes: loupe_provenance::Secret::new(u.get().to_vec()),
			status: self.status,
			action: self.action,
			source: std::marker::PhantomData,
		})
	}
}

/// An intentional Server diagnostic owns its bytes until terminal rendering.
/// Schema/policy errors remain fixed host messages and never use this path.
#[cfg_attr(fuzzing, allow(dead_code))] // The library fuzz fixture bypasses HTTP error collection.
struct TerminalDiagnostic {
	bytes: loupe_provenance::Secret<Vec<u8>>,
	status: reqwest::StatusCode,
	action: &'static str,
	source: std::marker::PhantomData<Server>,
}
impl std::fmt::Debug for TerminalDiagnostic {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("TerminalDiagnostic<Server>([redacted])")
	}
}
impl std::fmt::Display for TerminalDiagnostic {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		// The CLI's final error boundary escapes terminal controls, as before.
		write!(
			f,
			"{}: {} — {}",
			self.action,
			self.status,
			String::from_utf8_lossy(self.bytes.expose())
		)
	}
}
impl std::error::Error for TerminalDiagnostic {}

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
