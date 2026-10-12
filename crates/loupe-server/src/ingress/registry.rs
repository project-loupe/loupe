//! Closed Operator request schemas. Every legacy projection here is temporary
//! until M moves the route/storage consumers to these source-bearing outputs.
use axum::http::StatusCode;
use loupe_core::source_migration::text::BoundedText;
use loupe_core::source_migration::{RepoSpec, ReportingDestination};
use loupe_core::text::policy;
use loupe_provenance::{Mark, Operator, Secret, Unvalidated, Validate};
use serde::Deserialize;
use serde_json::value::RawValue;

use super::text::{json_secret, json_text};
use super::{DecodeError, OperatorJson};

// No general Serialize/Deserialize/Debug or public Value escape. This exact
// forward document deliberately does not apply semantic Payload normalization.
struct OperatorScannerConfig(serde_json::Value);
impl OperatorScannerConfig {
	fn new(_: &Mark<'_, Operator>, value: serde_json::Value) -> Self {
		Self(value)
	}
}

#[derive(Deserialize)]
struct RawRegisterRepo<'a> {
	protocol_version: u16,
	#[serde(borrow)]
	clone_url: &'a RawValue,
	#[serde(borrow, default)]
	branch: Option<&'a RawValue>,
	#[serde(default)]
	scan_interval_seconds: Option<u64>,
	#[serde(borrow)]
	reporting: &'a RawValue,
	#[serde(borrow, default, rename = "scanner_config")]
	_scanner_config: Option<&'a RawValue>,
	#[serde(default)]
	verification_enabled: Option<bool>,
	#[serde(default)]
	require_approval: Option<bool>,
}

pub(crate) struct RegisterRepoDecoder;

// Retain the original envelope depth, duplicate/unknown rules and forward
// document semantics. Marked fields are validated before this pass; it returns
// the one scanner Value that the legacy route persists, not a second copy.
#[derive(Deserialize)]
struct RegisterContent<'a> {
	#[serde(rename = "protocol_version")]
	_protocol_version: u16,
	#[serde(borrow, rename = "clone_url")]
	_clone_url: &'a RawValue,
	#[serde(borrow, default, rename = "branch")]
	_branch: Option<&'a RawValue>,
	#[serde(default, rename = "scan_interval_seconds")]
	_scan_interval_seconds: Option<u64>,
	#[serde(rename = "reporting")]
	_reporting: super::text::DiscardContent,
	#[serde(default)]
	scanner_config: serde_json::Value,
	#[serde(default, rename = "verification_enabled")]
	_verification_enabled: Option<bool>,
	#[serde(default, rename = "require_approval")]
	_require_approval: Option<bool>,
}
pub(crate) struct RegisterRepoInput {
	protocol_version: u16,
	clone_url: BoundedText<policy::CloneUrl, Operator>,
	branch: Option<BoundedText<policy::GitBranch, Operator>>,
	derived: Option<RepoSpec<Operator>>,
	scan_interval_seconds: Option<u64>,
	reporting: ReportingDestination<Operator>,
	pat: Option<Secret<String>>,
	scanner_config: OperatorScannerConfig,
	verification_enabled: Option<bool>,
	require_approval: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReportingKind {
	GithubIssue,
	Email,
	Manual,
}
// A borrowed &str tag retains the internally tagged enum's string-only tag
// admission, including an escaped tag via a scalar-only closed visitor.
impl ReportingKind {
	fn from_token(token: &RawValue) -> Result<Self, DecodeError> {
		super::text::require_json_string(token.get())?;
		serde_json::from_str(token.get()).map_err(DecodeError::json)
	}
}
#[derive(Deserialize)]
struct RawReportingTag<'a> {
	#[serde(borrow)]
	kind: &'a RawValue,
}
#[derive(Deserialize)]
struct RawGithub<'a> {
	#[serde(borrow, rename = "kind")]
	_kind: &'a RawValue,
	#[serde(borrow)]
	target_owner: &'a RawValue,
	#[serde(borrow)]
	target_repo: &'a RawValue,
	#[serde(borrow, default)]
	github_pat: Option<&'a RawValue>,
}
#[derive(Deserialize)]
struct RawEmail<'a> {
	#[serde(borrow, rename = "kind")]
	_kind: &'a RawValue,
	#[serde(borrow)]
	to: Vec<&'a RawValue>,
	#[serde(borrow, default)]
	from: Option<&'a RawValue>,
	#[serde(borrow, default)]
	subject_prefix: Option<&'a RawValue>,
}

fn reporting(
	mark: &Mark<'_, Operator>, token: &RawValue,
) -> Result<(ReportingDestination<Operator>, Option<Secret<String>>), DecodeError> {
	let tag = if token.get().starts_with('[') {
		serde_json::from_str::<super::text::SequenceTag<'_>>(token.get())
			.map_err(DecodeError::json)?
			.0
	} else {
		serde_json::from_str::<RawReportingTag<'_>>(token.get()).map_err(DecodeError::json)?.kind
	};
	let result = match ReportingKind::from_token(tag)? {
		ReportingKind::GithubIssue => {
			let raw: RawGithub<'_> =
				serde_json::from_str(token.get()).map_err(DecodeError::json)?;
			(
				ReportingDestination::GithubIssue {
					target_owner: json_text(mark, raw.target_owner)?,
					target_repo: json_text(mark, raw.target_repo)?,
					pat_secret_id: None,
				},
				raw.github_pat.map(json_secret).transpose()?,
			)
		},
		ReportingKind::Email => {
			let raw: RawEmail<'_> = serde_json::from_str(token.get()).map_err(DecodeError::json)?;
			(
				ReportingDestination::Email {
					to: raw
						.to
						.into_iter()
						.map(|token| json_text(mark, token))
						.collect::<Result<_, _>>()?,
					from: raw.from.map(|token| json_text(mark, token)).transpose()?,
					subject_prefix: raw
						.subject_prefix
						.map(|token| json_text(mark, token))
						.transpose()?,
				},
				None,
			)
		},
		ReportingKind::Manual => {
			// Unit variants reject surplus sequence elements, while maps ignore
			// unknown fields as before.
			let _: RawReportingTag<'_> =
				serde_json::from_str(token.get()).map_err(DecodeError::json)?;
			(ReportingDestination::Manual, None)
		},
	};
	Ok(result)
}

impl Validate<&[u8], Operator> for RegisterRepoDecoder {
	type Output = RegisterRepoInput;
	type Error = DecodeError;
	fn validate<'view>(
		self, input: Unvalidated<'view, &[u8]>, mark: Mark<'view, Operator>,
	) -> Result<Self::Output, Self::Error> {
		let raw: RawRegisterRepo<'_> =
			serde_json::from_slice(input.get()).map_err(DecodeError::json)?;
		let clone_url = json_text::<policy::CloneUrl, _>(&mark, raw.clone_url)?;
		let branch =
			raw.branch.map(|token| json_text::<policy::GitBranch, _>(&mark, token)).transpose()?;
		// This is the unchanged permissive route parser. Derivatives are marked
		// here, within the original Operator validation call; URL rejection stays
		// after the route's body-version check through the optional result.
		let derived = crate::routes::repos::parse_github_clone_url(clone_url.expose())
			.map(|(host, owner, repo)| {
				Ok::<_, DecodeError>(RepoSpec {
					host: BoundedText::new(&mark, &host)?,
					owner: BoundedText::new(&mark, &owner)?,
					repo: BoundedText::new(&mark, &repo)?,
					clone_url: clone_url.clone(),
					branch: branch.clone(),
				})
			})
			.transpose()?;
		let (reporting, pat) = reporting(&mark, raw.reporting)?;
		let content: RegisterContent<'_> =
			serde_json::from_slice(input.get()).map_err(DecodeError::json)?;
		Ok(RegisterRepoInput {
			protocol_version: raw.protocol_version,
			clone_url,
			branch,
			derived,
			scan_interval_seconds: raw.scan_interval_seconds,
			reporting,
			pat,
			scanner_config: OperatorScannerConfig::new(&mark, content.scanner_config),
			verification_enabled: raw.verification_enabled,
			require_approval: raw.require_approval,
		})
	}
}

pub(crate) struct LegacyRegisteredRepo {
	pub request: loupe_proto::RegisterRepoRequest,
	pub derived: Option<(String, String, String)>,
}
impl RegisterRepoDecoder {
	pub(crate) fn decode_legacy(
		body: OperatorJson,
	) -> Result<LegacyRegisteredRepo, (StatusCode, String)> {
		let input = body.0.as_bytes().validate(Self).map_err(DecodeError::response)?;
		let reporting = match input.reporting {
			ReportingDestination::GithubIssue { target_owner, target_repo, .. } => {
				loupe_proto::ReportingSetup::GithubIssue {
					target_owner: target_owner.expose().to_owned(),
					target_repo: target_repo.expose().to_owned(),
					github_pat: input.pat,
				}
			},
			ReportingDestination::Email { to, from, subject_prefix } => {
				loupe_proto::ReportingSetup::Email {
					to: to.iter().map(|value| value.expose().to_owned()).collect(),
					from: from.map(|value| value.expose().to_owned()),
					subject_prefix: subject_prefix.map(|value| value.expose().to_owned()),
				}
			},
			ReportingDestination::Manual => loupe_proto::ReportingSetup::Manual,
		};
		Ok(LegacyRegisteredRepo {
			derived: input.derived.map(|repo| {
				(
					repo.host.expose().to_owned(),
					repo.owner.expose().to_owned(),
					repo.repo.expose().to_owned(),
				)
			}),
			request: loupe_proto::RegisterRepoRequest {
				protocol_version: input.protocol_version,
				clone_url: input.clone_url.expose().to_owned(),
				branch: input.branch.map(|value| value.expose().to_owned()),
				scan_interval_seconds: input.scan_interval_seconds,
				reporting,
				scanner_config: input.scanner_config.0,
				verification_enabled: input.verification_enabled,
				require_approval: input.require_approval,
			},
		})
	}
}

// These three wire shapes contain only closed scalars; no text escape exists.
macro_rules! scalar_request {
	($decoder:ident, $dto:ty) => {
		pub(crate) struct $decoder;
		impl Validate<&[u8], Operator> for $decoder {
			type Output = $dto;
			type Error = DecodeError;
			fn validate<'view>(
				self, input: Unvalidated<'view, &[u8]>, _: Mark<'view, Operator>,
			) -> Result<Self::Output, Self::Error> {
				serde_json::from_slice(input.get()).map_err(DecodeError::json)
			}
		}
		impl $decoder {
			pub(crate) fn decode_legacy(body: OperatorJson) -> Result<$dto, (StatusCode, String)> {
				body.0.as_bytes().validate(Self).map_err(DecodeError::response)
			}
		}
	};
}
scalar_request!(UpdateRepoDecoder, loupe_proto::UpdateRepoRequest);
scalar_request!(EnqueueScanDecoder, loupe_proto::ScanRequest);
scalar_request!(RetryVerifyDecoder, loupe_proto::RetryVerifyRequest);

#[derive(Deserialize)]
struct RawWorker<'a> {
	protocol_version: u16,
	#[serde(borrow)]
	name: &'a RawValue,
}
pub(crate) struct RegisterWorkerDecoder;
impl Validate<&[u8], Operator> for RegisterWorkerDecoder {
	type Output = (u16, BoundedText<policy::WorkerName, Operator>);
	type Error = DecodeError;
	fn validate<'view>(
		self, input: Unvalidated<'view, &[u8]>, mark: Mark<'view, Operator>,
	) -> Result<Self::Output, Self::Error> {
		let raw: RawWorker<'_> = serde_json::from_slice(input.get()).map_err(DecodeError::json)?;
		Ok((raw.protocol_version, json_text(&mark, raw.name)?))
	}
}
impl RegisterWorkerDecoder {
	pub(crate) fn decode_legacy(
		body: OperatorJson,
	) -> Result<loupe_proto::RegisterWorkerRequest, (StatusCode, String)> {
		let (protocol_version, name) =
			body.0.as_bytes().validate(Self).map_err(DecodeError::response)?;
		Ok(loupe_proto::RegisterWorkerRequest { protocol_version, name: name.expose().to_owned() })
	}
}

#[derive(Deserialize)]
struct RawPat<'a> {
	protocol_version: u16,
	#[serde(borrow)]
	github_pat: &'a RawValue,
}
pub(crate) struct RotateRepoPatDecoder;
impl Validate<&[u8], Operator> for RotateRepoPatDecoder {
	type Output = loupe_proto::RotateRepoPatRequest;
	type Error = DecodeError;
	fn validate<'view>(
		self, input: Unvalidated<'view, &[u8]>, _: Mark<'view, Operator>,
	) -> Result<Self::Output, Self::Error> {
		let raw: RawPat<'_> = serde_json::from_slice(input.get()).map_err(DecodeError::json)?;
		Ok(loupe_proto::RotateRepoPatRequest {
			protocol_version: raw.protocol_version,
			github_pat: json_secret(raw.github_pat)?,
		})
	}
}
impl RotateRepoPatDecoder {
	pub(crate) fn decode_legacy(
		body: OperatorJson,
	) -> Result<loupe_proto::RotateRepoPatRequest, (StatusCode, String)> {
		body.0.as_bytes().validate(Self).map_err(DecodeError::response)
	}
}

#[derive(Deserialize)]
struct RawApp<'a> {
	protocol_version: u16,
	app_id: u64,
	#[serde(borrow)]
	private_key_pem: &'a RawValue,
}
pub(crate) struct SetGithubAppDecoder;
impl Validate<&[u8], Operator> for SetGithubAppDecoder {
	type Output = loupe_proto::SetGithubAppRequest;
	type Error = DecodeError;
	fn validate<'view>(
		self, input: Unvalidated<'view, &[u8]>, _: Mark<'view, Operator>,
	) -> Result<Self::Output, Self::Error> {
		let raw: RawApp<'_> = serde_json::from_slice(input.get()).map_err(DecodeError::json)?;
		Ok(loupe_proto::SetGithubAppRequest {
			protocol_version: raw.protocol_version,
			app_id: raw.app_id,
			private_key_pem: json_secret(raw.private_key_pem)?,
		})
	}
}
impl SetGithubAppDecoder {
	pub(crate) fn decode_legacy(
		body: OperatorJson,
	) -> Result<loupe_proto::SetGithubAppRequest, (StatusCode, String)> {
		body.0.as_bytes().validate(Self).map_err(DecodeError::response)
	}
}

#[derive(Deserialize)]
struct RawSetReporting<'a> {
	protocol_version: u16,
	#[serde(borrow)]
	target_owner: &'a RawValue,
	#[serde(borrow)]
	target_repo: &'a RawValue,
	#[serde(borrow, default)]
	github_pat: Option<&'a RawValue>,
}
pub(crate) struct SetRepoGithubReportingDecoder;
pub(crate) struct SetReportingInput {
	protocol_version: u16,
	owner: BoundedText<policy::RepoOwner, Operator>,
	repo: BoundedText<policy::RepoName, Operator>,
	pat: Option<Secret<String>>,
}
impl Validate<&[u8], Operator> for SetRepoGithubReportingDecoder {
	type Output = SetReportingInput;
	type Error = DecodeError;
	fn validate<'view>(
		self, input: Unvalidated<'view, &[u8]>, mark: Mark<'view, Operator>,
	) -> Result<Self::Output, Self::Error> {
		let raw: RawSetReporting<'_> =
			serde_json::from_slice(input.get()).map_err(DecodeError::json)?;
		Ok(SetReportingInput {
			protocol_version: raw.protocol_version,
			owner: json_text(&mark, raw.target_owner)?,
			repo: json_text(&mark, raw.target_repo)?,
			pat: raw.github_pat.map(json_secret).transpose()?,
		})
	}
}
impl SetRepoGithubReportingDecoder {
	pub(crate) fn decode_legacy(
		body: OperatorJson,
	) -> Result<loupe_proto::SetRepoGithubReportingRequest, (StatusCode, String)> {
		let input = body.0.as_bytes().validate(Self).map_err(DecodeError::response)?;
		Ok(loupe_proto::SetRepoGithubReportingRequest {
			protocol_version: input.protocol_version,
			target_owner: input.owner.expose().to_owned(),
			target_repo: input.repo.expose().to_owned(),
			github_pat: input.pat,
		})
	}
}
