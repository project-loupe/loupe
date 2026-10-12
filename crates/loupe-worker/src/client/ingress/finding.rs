use loupe_core::text::{decode_json_string_bounded, policy, BoundedText, RepoPath};
use loupe_core::{Finding, FindingState, Severity};
use loupe_provenance::{Agent, Mark, Server, Unvalidated, Validate};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::ingress_text::{json_text, require_string, token_range, DecodeError};

macro_rules! field_validator {
	($($name:ident, $policy:ty;)*) => { $(
		struct $name;
		impl Validate<&[u8], Agent> for $name {
			type Output = BoundedText<$policy, Agent>;
			type Error = DecodeError;
			fn validate<'view>(self, u: Unvalidated<'view, &[u8]>, mark: Mark<'view, Agent>) -> Result<Self::Output, DecodeError> {
				let raw: &RawValue = serde_json::from_slice(u.get())?;
				json_text(&mark, raw)
			}
		}
	)* };
}
field_validator! {
	AgentScanner, policy::ScannerIdText;
	AgentTitle, policy::FindingTitle;
	AgentDescription, policy::FindingDescription;
	AgentCwe, policy::CweText;
	AgentPatch, policy::PatchUnified;
	AgentPoc, policy::PocUnified;
	AgentFingerprint, policy::FindingFingerprintText;
}
struct AgentPath;
impl Validate<&[u8], Agent> for AgentPath {
	type Output = RepoPath<Agent>;
	type Error = DecodeError;
	fn validate<'view>(
		self, u: Unvalidated<'view, &[u8]>, mark: Mark<'view, Agent>,
	) -> Result<Self::Output, DecodeError> {
		let raw = std::str::from_utf8(u.get()).map_err(|_| DecodeError::Syntax)?;
		require_string(raw)?;
		let path = decode_json_string_bounded(raw, "repo_path", 512, 512)?;
		Ok(RepoPath::new(&mark, &path)?)
	}
}

// Every invocation fixes both the source pair and concrete field validator.
macro_rules! carry {
	($u:expr, $token:expr, $validator:expr) => {{
		let token = $token;
		let range = token_range($u.get(), token)?;
		#[cfg(fuzzing)]
		crate::ingress_text::observe::agent(range.clone());
		$u.carry::<Agent>(range).ok_or(DecodeError::Syntax)?.validate($validator)?
	}};
}

macro_rules! raw_finding {
	($name:ident, {$($before:tt)*}, {$($after:tt)*}) => {
		#[derive(Deserialize)]
		pub(super) struct $name<'a> {
			$($before)*
			#[serde(borrow)] scanner_id: &'a RawValue,
			severity: Severity,
			#[serde(borrow)] title: &'a RawValue,
			#[serde(borrow)] description: &'a RawValue,
			#[serde(borrow, default)] file_path: Option<&'a RawValue>,
			#[serde(default)] line_start: Option<u32>,
			#[serde(default)] line_end: Option<u32>,
			#[serde(borrow, default)] cwe: Option<&'a RawValue>,
			#[serde(borrow, default)] patch_unified: Option<&'a RawValue>,
			#[serde(borrow, default)] poc_unified: Option<&'a RawValue>,
			#[serde(borrow)] fingerprint: &'a RawValue,
			$($after)*
		}
	};
}
raw_finding!(RawFinding, {}, {});
raw_finding!(RawDetail, {
	protocol_version: u16,
	id: i64,
	repo_id: i64,
	job_id: i64,
}, {
	state: FindingState,
	verification_required: bool,
	created_at: i64,
	#[serde(default)] approved_at: Option<i64>,
	#[serde(borrow, default)] approved_by_cn: Option<&'a RawValue>,
	#[serde(default)] rejected_at: Option<i64>,
	#[serde(borrow, default)] rejected_by_cn: Option<&'a RawValue>,
});

macro_rules! content {
	($u:expr, $raw:expr) => {{
		let raw = $raw;
		Finding {
			scanner_id: carry!($u, raw.scanner_id, AgentScanner),
			severity: raw.severity,
			title: carry!($u, raw.title, AgentTitle),
			description: carry!($u, raw.description, AgentDescription),
			file_path: raw
				.file_path
				.map(|t| Ok::<_, DecodeError>(carry!($u, t, AgentPath)))
				.transpose()?,
			line_start: raw.line_start,
			line_end: raw.line_end,
			cwe: raw.cwe.map(|t| Ok::<_, DecodeError>(carry!($u, t, AgentCwe))).transpose()?,
			patch_unified: raw
				.patch_unified
				.map(|t| Ok::<_, DecodeError>(carry!($u, t, AgentPatch)))
				.transpose()?,
			poc_unified: raw
				.poc_unified
				.map(|t| Ok::<_, DecodeError>(carry!($u, t, AgentPoc)))
				.transpose()?,
			fingerprint: carry!($u, raw.fingerprint, AgentFingerprint),
		}
	}};
}

pub(super) fn finding(
	u: &Unvalidated<'_, &[u8], Server>, raw: &RawValue,
) -> Result<Finding<Agent>, DecodeError> {
	let raw: RawFinding<'_> = serde_json::from_str(raw.get())?;
	Ok(content!(u, raw))
}

pub(super) type DecodedFindingDetail = loupe_proto::FindingDetail<Agent, Server>;

pub(super) fn detail(
	u: &Unvalidated<'_, &[u8], Server>,
) -> Result<DecodedFindingDetail, DecodeError> {
	let raw: RawDetail<'_> = serde_json::from_slice(u.get())?;
	let finding = content!(u, &raw);
	Ok(DecodedFindingDetail {
		protocol_version: raw.protocol_version,
		id: raw.id,
		repo_id: raw.repo_id,
		job_id: raw.job_id,
		scanner_id: finding.scanner_id,
		severity: finding.severity,
		title: finding.title,
		description: finding.description,
		file_path: finding.file_path,
		line_start: finding.line_start,
		line_end: finding.line_end,
		cwe: finding.cwe,
		patch_unified: finding.patch_unified,
		poc_unified: finding.poc_unified,
		fingerprint: finding.fingerprint,
		state: raw.state,
		verification_required: raw.verification_required,
		created_at: raw.created_at,
		approved_at: raw.approved_at,
		approved_by_cn: raw.approved_by_cn.map(|t| json_text(&u.mark(), t)).transpose()?,
		rejected_at: raw.rejected_at,
		rejected_by_cn: raw.rejected_by_cn.map(|t| json_text(&u.mark(), t)).transpose()?,
	})
}

#[derive(Deserialize)]
struct RawSummary<'a> {
	id: i64,
	repo_id: i64,
	job_id: i64,
	#[serde(borrow)]
	scanner_id: &'a RawValue,
	severity: Severity,
	#[serde(borrow)]
	title: &'a RawValue,
	#[serde(borrow, default)]
	file_path: Option<&'a RawValue>,
	#[serde(default)]
	line_start: Option<u32>,
	#[serde(borrow)]
	fingerprint: &'a RawValue,
	state: FindingState,
	verification_required: bool,
	created_at: i64,
	#[serde(default)]
	approved_at: Option<i64>,
	#[serde(borrow, default)]
	approved_by_cn: Option<&'a RawValue>,
	#[serde(default)]
	rejected_at: Option<i64>,
	#[serde(borrow, default)]
	rejected_by_cn: Option<&'a RawValue>,
}

pub(super) type DecodedSummary = loupe_proto::FindingSummary<Agent, Server>;

pub(super) fn summary(
	u: &Unvalidated<'_, &[u8], Server>, token: &RawValue,
) -> Result<DecodedSummary, DecodeError> {
	let raw: RawSummary<'_> = serde_json::from_str(token.get())?;
	Ok(DecodedSummary {
		id: raw.id,
		repo_id: raw.repo_id,
		job_id: raw.job_id,
		scanner_id: carry!(u, raw.scanner_id, AgentScanner),
		severity: raw.severity,
		title: carry!(u, raw.title, AgentTitle),
		file_path: raw
			.file_path
			.map(|t| Ok::<_, DecodeError>(carry!(u, t, AgentPath)))
			.transpose()?,
		line_start: raw.line_start,
		fingerprint: carry!(u, raw.fingerprint, AgentFingerprint),
		state: raw.state,
		verification_required: raw.verification_required,
		created_at: raw.created_at,
		approved_at: raw.approved_at,
		approved_by_cn: raw.approved_by_cn.map(|t| json_text(&u.mark(), t)).transpose()?,
		rejected_at: raw.rejected_at,
		rejected_by_cn: raw.rejected_by_cn.map(|t| json_text(&u.mark(), t)).transpose()?,
	})
}
