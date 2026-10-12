//! Fixed synthetic inputs for the actual private CLI owners; cfg(fuzzing) only.
//! This deliberately bypasses HTTP collection and the actual command tree.
use std::ffi::OsStr;

use clap::builder::TypedValueParser;
use loupe_provenance::{Ingress, Secret, Server, Untrusted};

pub use crate::config_input::PatObservation;
pub use crate::ingress::{Entry, Field, FieldObservation, FieldSource};
use crate::{config_input as config, ingress};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCase {
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
impl ResponseCase {
	pub const ALL: [Self; 14] = [
		Self::ShowApp,
		Self::RegisterRepo,
		Self::ListRepos,
		Self::ScanRepo,
		Self::RegisterWorker,
		Self::ListJobs,
		Self::GetJob,
		Self::RetryJob,
		Self::CancelJob,
		Self::ListFindings,
		Self::SearchFindings,
		Self::GetFinding,
		Self::RetryVerification,
		Self::DiscardSuccess,
	];
}
#[derive(Debug)]
pub enum ResponseValue {
	App(loupe_proto::GithubAppResponse<Server>),
	Repo(loupe_proto::RegisterRepoResponse),
	Repos(loupe_proto::ListReposResponse<Server>),
	Scan(loupe_proto::ScanResponse),
	Worker(loupe_proto::RegisterWorkerResponse),
	Jobs(Vec<loupe_proto::JobInfo<Server>>),
	Job(loupe_proto::JobInfo<Server>),
	Findings(loupe_proto::ListFindingsResponse<loupe_provenance::Agent, Server>),
	Finding(loupe_proto::FindingDetail<loupe_provenance::Agent, Server>),
	Verification(loupe_proto::RetryVerifyResponse),
	Discard,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
	SchemaOrPolicy,
}
#[derive(Debug)]
pub struct ResponseObservation {
	pub case: ResponseCase,
	pub result: Result<ResponseValue, Rejection>,
	pub spans: Vec<(usize, usize)>,
	pub typed: Vec<FieldObservation>,
	pub entries: Vec<Entry>,
}
struct FixtureBody(Secret<Vec<u8>>);
impl AsRef<[u8]> for FixtureBody {
	fn as_ref(&self) -> &[u8] {
		self.0.expose()
	}
}
struct Reset;
impl Drop for Reset {
	fn drop(&mut self) {
		ingress::reset_observations();
		let _ = ingress::take_entries();
	}
}
/// Invoke one exact production entry; no arbitrary source or decoder parameter.
#[allow(unsafe_code)]
pub fn observe_response(case: ResponseCase, raw: &[u8]) -> ResponseObservation {
	ingress::reset_observations();
	let _ = ingress::take_entries();
	let _reset = Reset;
	// SAFETY: the harness invented these exact response bytes as a Server fixture.
	let token = unsafe { Ingress::<Server>::new() };
	let input =
		Untrusted::new(bytes::Bytes::from_owner(FixtureBody(Secret::new(raw.to_vec()))), token);
	let result = match case {
		ResponseCase::ShowApp => ingress::show_github_app(input).map(ResponseValue::App),
		ResponseCase::RegisterRepo => ingress::register_repo(input).map(ResponseValue::Repo),
		ResponseCase::ListRepos => ingress::list_repos(input).map(ResponseValue::Repos),
		ResponseCase::ScanRepo => ingress::scan_repo(input).map(ResponseValue::Scan),
		ResponseCase::RegisterWorker => {
			ingress::register_worker_bundle(input).map(ResponseValue::Worker)
		},
		ResponseCase::ListJobs => ingress::list_jobs(input).map(ResponseValue::Jobs),
		ResponseCase::GetJob => ingress::get_job(input).map(ResponseValue::Job),
		ResponseCase::RetryJob => ingress::retry_job(input).map(ResponseValue::Job),
		ResponseCase::CancelJob => ingress::cancel_job(input).map(ResponseValue::Job),
		ResponseCase::ListFindings => ingress::list_findings(input).map(ResponseValue::Findings),
		ResponseCase::SearchFindings => {
			ingress::search_findings(input).map(ResponseValue::Findings)
		},
		ResponseCase::GetFinding => ingress::get_finding(input).map(ResponseValue::Finding),
		ResponseCase::RetryVerification => {
			ingress::retry_verification(input).map(ResponseValue::Verification)
		},
		ResponseCase::DiscardSuccess => ingress::discard(input).map(|()| ResponseValue::Discard),
	}
	.map_err(|error| {
		let expected = "server response violates schema or field policy";
		assert_eq!(error.to_string(), expected);
		assert_eq!(format!("{error:#}"), expected);
		assert_eq!(error.chain().count(), 1);
		// Alternate Debug inspects the wrapped error without anyhow's backtrace.
		assert_eq!(format!("{error:#?}"), format!("{expected:?}"));
		Rejection::SchemaOrPolicy
	});
	let (spans, typed) = ingress::take_observations();
	ResponseObservation { case, result, spans, typed, entries: ingress::take_entries() }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigCase {
	CloneUrl,
	Branch,
	Owner,
	Repo,
	WorkerName,
	Search,
	Hostname,
	CommonName,
	Path,
	Url,
	Pem,
	Pat,
}
impl ConfigCase {
	pub const ALL: [Self; 12] = [
		Self::CloneUrl,
		Self::Branch,
		Self::Owner,
		Self::Repo,
		Self::WorkerName,
		Self::Search,
		Self::Hostname,
		Self::CommonName,
		Self::Path,
		Self::Url,
		Self::Pem,
		Self::Pat,
	];
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommonNameSource {
	CommandLine,
	Environment,
	Default,
}
#[derive(Debug)]
pub enum ConfigValue {
	Text(String),
	Path(std::path::PathBuf),
	Url(reqwest::Url),
	Pem(String),
	Pat(PatObservation),
}
#[derive(Debug)]
pub struct ConfigObservation {
	pub case: ConfigCase,
	pub result: Result<ConfigValue, Rejection>,
	pub mints: usize,
	pub callbacks: Vec<&'static str>,
	pub typed_text: Vec<String>,
}
struct ResetConfig;
impl Drop for ResetConfig {
	fn drop(&mut self) {
		config::reset_mints();
	}
}
/// Calls the actual native-value callbacks; no process environment mutation.
pub fn observe_config(
	case: ConfigCase, value: &OsStr, source: CommonNameSource, actions: &[u8],
) -> ConfigObservation {
	config::reset_mints();
	let _reset = ResetConfig;
	let command = clap::Command::new("fixture");
	let result = match case {
		ConfigCase::CloneUrl => config::CloneUrlArgument
			.parse_ref(&command, None, value)
			.map(|v| ConfigValue::Text(v.expose().to_owned())),
		ConfigCase::Branch => config::BranchArgument
			.parse_ref(&command, None, value)
			.map(|v| ConfigValue::Text(v.expose().to_owned())),
		ConfigCase::Owner => config::OwnerArgument
			.parse_ref(&command, None, value)
			.map(|v| ConfigValue::Text(v.expose().to_owned())),
		ConfigCase::Repo => config::RepoArgument
			.parse_ref(&command, None, value)
			.map(|v| ConfigValue::Text(v.expose().to_owned())),
		ConfigCase::WorkerName => config::WorkerNameArgument
			.parse_ref(&command, None, value)
			.map(|v| ConfigValue::Text(v.expose().to_owned())),
		ConfigCase::Search => config::SearchArgument
			.parse_ref(&command, None, value)
			.map(|v| ConfigValue::Text(v.expose().to_owned())),
		ConfigCase::Hostname => config::HostnameArgument
			.parse_ref(&command, None, value)
			.map(|v| ConfigValue::Text(v.expose().to_owned())),
		ConfigCase::CommonName => config::CommonNameArgument
			.parse_ref_(
				&command,
				None,
				value,
				match source {
					CommonNameSource::CommandLine => clap::parser::ValueSource::CommandLine,
					CommonNameSource::Environment => clap::parser::ValueSource::EnvVariable,
					CommonNameSource::Default => clap::parser::ValueSource::DefaultValue,
				},
			)
			.map(|v| ConfigValue::Text(v.for_certificate().to_owned())),
		ConfigCase::Path => config::PathArgument
			.parse_ref(&command, None, value)
			.map(|v| ConfigValue::Path(v.for_filesystem().to_path_buf())),
		ConfigCase::Url => config::UrlArgument
			.parse_ref(&command, None, value)
			.map(|v| ConfigValue::Url(v.for_request().clone())),
		ConfigCase::Pem => config::PemArgument.parse_ref(&command, None, value).map(|v| {
			assert_eq!(format!("{v:?}"), "ConfiguredPem([redacted])");
			ConfigValue::Pem(v.observe_pem())
		}),
		ConfigCase::Pat => config::Pat
			.parse_ref(&command, None, value)
			.map(|v| ConfigValue::Pat(config::observe_pat(v, actions))),
	}
	.map_err(|error| {
		assert_eq!(error.to_string(), "error: configuration value violates field policy");
		assert!(std::error::Error::source(&error).is_none());
		Rejection::SchemaOrPolicy
	});
	let (callbacks, typed_text) = config::take_callbacks();
	// Preserve the independent target's historical observation vocabulary.
	// Events still originate in the actual callback, never the case selector.
	let callbacks = callbacks
		.into_iter()
		.map(|callback| match callback {
			"CloneUrlArgument" => "CloneUrlLegacy",
			"BranchArgument" => "BranchLegacy",
			"OwnerArgument" => "OwnerLegacy",
			"RepoArgument" => "RepoLegacy",
			"WorkerNameArgument" => "WorkerNameLegacy",
			"SearchArgument" => "SearchLegacy",
			"HostnameArgument" => "HostnameLegacy",
			"CommonNameArgument" => "CommonNameLegacy",
			"PathArgument" => "PathLegacy",
			"UrlArgument" => "UrlLegacy",
			"PemArgument" => "PemLegacy",
			"Pat" => "Pat",
			_ => panic!("unknown actual Config callback"),
		})
		.collect();
	ConfigObservation { case, result, mints: config::mints(), callbacks, typed_text }
}
