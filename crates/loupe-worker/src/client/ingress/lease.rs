use loupe_core::text::{decode_json_string_bounded, policy, BoundedText};
use loupe_core::{Finding, RepoSpec};
use loupe_provenance::{Agent, Mark, Secret, Server, Unvalidated};
use serde::Deserialize;
use serde_json::value::RawValue;

use super::{finding, scanner};
use crate::host_outcome::{ReviewedRevision, ReviewedRevisionFact};
use crate::ingress_text::{
	json_text, require_string, DecodeError, DiscardContent, RevisionText, SequenceTag,
};

#[derive(Deserialize)]
struct RawTag<'a> {
	#[serde(borrow)]
	kind: &'a RawValue,
}
#[derive(Clone, Copy)]
enum Kind {
	Lease,
	Empty,
	Scan,
	Verify,
}
fn kind(raw: &str) -> Result<Kind, DecodeError> {
	let token = if raw.starts_with('[') {
		serde_json::from_str::<SequenceTag<'_>>(raw)?.0
	} else {
		serde_json::from_str::<RawTag<'_>>(raw)?.kind
	};
	require_string(token.get())?;
	let value = decode_json_string_bounded(token.get(), "kind", 32, 32)?;
	match value.as_ref() {
		"lease" => Ok(Kind::Lease),
		"empty" => Ok(Kind::Empty),
		"scan" => Ok(Kind::Scan),
		"verify" => Ok(Kind::Verify),
		_ => Err(DecodeError::Data("unknown lease kind")),
	}
}
#[derive(Deserialize)]
struct RawEmpty<'a> {
	#[serde(borrow, rename = "kind")]
	_kind: &'a RawValue,
	protocol_version: u16,
}
#[derive(Deserialize)]
struct RawLease<'a> {
	#[serde(borrow, rename = "kind")]
	_kind: &'a RawValue,
	protocol_version: u16,
	job_id: i64,
	#[serde(borrow)]
	job_capability: &'a RawValue,
	repo_id: i64,
	#[serde(borrow)]
	repo: &'a RawValue,
	#[serde(borrow, default)]
	head_branch: Option<&'a RawValue>,
	lease_expires_at: i64,
	#[serde(borrow)]
	scanner_config: &'a RawValue,
	#[serde(borrow, default)]
	github_pat: Option<&'a RawValue>,
	#[serde(borrow)]
	payload: &'a RawValue,
}
#[derive(Deserialize)]
struct RawRepo<'a> {
	#[serde(borrow)]
	host: &'a RawValue,
	#[serde(borrow)]
	owner: &'a RawValue,
	#[serde(borrow)]
	repo: &'a RawValue,
	#[serde(borrow)]
	clone_url: &'a RawValue,
	#[serde(borrow, default)]
	branch: Option<&'a RawValue>,
}
#[derive(Deserialize)]
struct RawScan<'a> {
	#[serde(borrow, rename = "kind")]
	_kind: &'a RawValue,
	#[serde(borrow, default)]
	since_sha: Option<&'a RawValue>,
}
#[derive(Deserialize)]
struct RawVerify<'a> {
	#[serde(borrow, rename = "kind")]
	_kind: &'a RawValue,
	finding_id: i64,
	#[serde(borrow)]
	finding: &'a RawValue,
	#[serde(borrow, default)]
	reviewed_sha: Option<&'a RawValue>,
}

enum Payload {
	Scan { since_sha: Option<BoundedText<RevisionText, Server>> },
	Verify { finding_id: i64, finding: Box<Finding<Agent>>, reviewed_sha: ReviewedRevisionFact },
}
pub(super) struct Envelope {
	protocol_version: u16,
	job_id: i64,
	job_capability: loupe_proto::JobCapability,
	repo_id: i64,
	repo: RepoSpec<Server>,
	head_branch: Option<BoundedText<policy::GitBranch, Server>>,
	lease_expires_at: i64,
	scanner_config: scanner::LeasedScannerDocument,
	github_pat: Option<Secret<String>>,
	payload: Payload,
}
pub(super) enum DecodedLeaseResponse {
	Lease(Box<Envelope>),
	Empty { protocol_version: u16 },
}
fn secret(raw: &RawValue) -> Result<Secret<String>, DecodeError> {
	require_string(raw.get())?;
	let text = decode_json_string_bounded(
		raw.get(),
		"credential",
		loupe_http::MAX_RESPONSE_BYTES,
		loupe_http::MAX_RESPONSE_BYTES,
	)?;
	Ok(Secret::new(text.into_owned()))
}
fn repo(mark: &Mark<'_, Server>, token: &RawValue) -> Result<RepoSpec<Server>, DecodeError> {
	let raw: RawRepo<'_> = serde_json::from_str(token.get())?;
	Ok(RepoSpec {
		host: json_text(mark, raw.host)?,
		owner: json_text(mark, raw.owner)?,
		repo: json_text(mark, raw.repo)?,
		clone_url: json_text(mark, raw.clone_url)?,
		branch: raw.branch.map(|t| json_text(mark, t)).transpose()?,
	})
}

fn reviewed_revision(
	mark: &Mark<'_, Server>, raw: Option<&RawValue>,
) -> Result<ReviewedRevisionFact, DecodeError> {
	let Some(raw) = raw else { return Ok(ReviewedRevisionFact::MissingReviewedRevision) };
	require_string(raw.get())?;
	// Field-specific compatibility fact. Preflight still enforces the same
	// decoded 2 MiB cap before allocation, including whitespace-only input.
	let text = decode_json_string_bounded(
		raw.get(),
		"revision",
		policy::LEGACY_TEXT_MAX_BYTES,
		policy::LEGACY_TEXT_MAX_BYTES,
	)?;
	if text.trim().is_empty() {
		return Ok(ReviewedRevisionFact::MissingReviewedRevision);
	}
	Ok(ReviewedRevisionFact::Available(ReviewedRevision::admitted(BoundedText::new(mark, &text)?)))
}

pub(super) fn decode(
	u: &Unvalidated<'_, &[u8], Server>,
) -> Result<DecodedLeaseResponse, DecodeError> {
	let bytes = *u.get();
	let raw_text = std::str::from_utf8(bytes).map_err(|_| DecodeError::Syntax)?;
	let result = match kind(raw_text.trim_start())? {
		Kind::Empty => {
			let raw: RawEmpty<'_> = serde_json::from_slice(bytes)?;
			DecodedLeaseResponse::Empty { protocol_version: raw.protocol_version }
		},
		Kind::Lease => {
			let raw: RawLease<'_> = serde_json::from_slice(bytes)?;
			let payload = match kind(raw.payload.get())? {
				Kind::Scan => {
					let raw: RawScan<'_> = serde_json::from_str(raw.payload.get())?;
					Payload::Scan {
						since_sha: raw.since_sha.map(|t| json_text(&u.mark(), t)).transpose()?,
					}
				},
				Kind::Verify => {
					let raw: RawVerify<'_> = serde_json::from_str(raw.payload.get())?;
					Payload::Verify {
						finding_id: raw.finding_id,
						finding: Box::new(finding::finding(u, raw.finding)?),
						reviewed_sha: reviewed_revision(&u.mark(), raw.reviewed_sha)?,
					}
				},
				_ => return Err(DecodeError::Data("unknown payload kind")),
			};
			// The capability's bounded decoded allocation moves straight into its
			// existing guarded owner. Never copy from an exposed Secret.
			require_string(raw.job_capability.get())?;
			let capability = decode_json_string_bounded(
				raw.job_capability.get(),
				"job_capability",
				loupe_http::MAX_RESPONSE_BYTES,
				loupe_http::MAX_RESPONSE_BYTES,
			)?;
			DecodedLeaseResponse::Lease(Box::new(Envelope {
				protocol_version: raw.protocol_version,
				job_id: raw.job_id,
				job_capability: loupe_proto::JobCapability::from_secret(capability.into_owned()),
				repo_id: raw.repo_id,
				repo: repo(&u.mark(), raw.repo)?,
				head_branch: raw.head_branch.map(|t| json_text(&u.mark(), t)).transpose()?,
				lease_expires_at: raw.lease_expires_at,
				scanner_config: scanner::decode(&u.mark(), raw.scanner_config)?,
				github_pat: raw.github_pat.map(secret).transpose()?,
				payload,
			}))
		},
		_ => return Err(DecodeError::Data("unknown response kind")),
	};
	// Validate numbers and Unicode across the entire envelope, including ignored
	// fields, at their original depth. Bounded field decoding must happen first.
	let _: DiscardContent = serde_json::from_slice(bytes)?;
	Ok(result)
}
impl DecodedLeaseResponse {
	pub(super) fn into_receipt(self) -> crate::client::LeaseReceipt {
		let reviewed_revision = match &self {
			Self::Lease(env) => match &env.payload {
				Payload::Verify { reviewed_sha, .. } => reviewed_sha.clone(),
				_ => ReviewedRevisionFact::MissingReviewedRevision,
			},
			_ => ReviewedRevisionFact::MissingReviewedRevision,
		};
		let (response, scanner_patch) = match self {
			Self::Empty { protocol_version } => {
				(loupe_proto::LeaseResponse::Empty { protocol_version }, None)
			},
			Self::Lease(env) => {
				let payload = match env.payload {
					Payload::Scan { since_sha } => loupe_proto::LeasePayload::Scan { since_sha },
					Payload::Verify { finding_id, finding, reviewed_sha } => {
						loupe_proto::LeasePayload::Verify {
							finding_id,
							finding,
							reviewed_sha: match reviewed_sha {
								ReviewedRevisionFact::Available(value) => {
									Some(value.into_revision())
								},
								ReviewedRevisionFact::MissingReviewedRevision => None,
							},
						}
					},
				};
				let patch = env.scanner_config.patch;
				let response =
					loupe_proto::LeaseResponse::Lease(Box::new(loupe_proto::LeaseEnvelope {
						protocol_version: env.protocol_version,
						job_id: env.job_id,
						job_capability: env.job_capability,
						repo_id: env.repo_id,
						repo: env.repo,
						head_branch: env.head_branch,
						lease_expires_at: env.lease_expires_at,
						scanner_config: env.scanner_config.document,
						github_pat: env.github_pat,
						payload,
					}));
				(response, patch)
			},
		};
		crate::client::LeaseReceipt { response, reviewed_revision, scanner_patch }
	}
}
