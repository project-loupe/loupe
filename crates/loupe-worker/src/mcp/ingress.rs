//! Sandbox records and original Agent argument tokens. No decoded Value is
//! serialized back into a source token; every carry uses a checked byte span.

use std::collections::HashMap;

use anyhow::{Context, Result};
use loupe_core::text::{
	decode_json_string_bounded, policy, BoundedText, Normalization, RepoPath, TextPolicy,
	Whitespace,
};
use loupe_core::Severity;
use loupe_provenance::{Agent, Mark, Sandbox, Unvalidated, Validate, ValidateCarrying};
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::Value;

use crate::ingress_text::{json_text, token_range, DecodeError, DiscardContent};
#[cfg(any(test, fuzzing))]
pub(super) mod fuzz_support;

#[derive(Debug, thiserror::Error)]
pub(super) enum RecordError {
	#[error("MCP record is not UTF-8")]
	Utf8,
	#[error(transparent)]
	Json(#[from] DecodeError),
}
impl From<serde_json::Error> for RecordError {
	fn from(error: serde_json::Error) -> Self {
		Self::Json(error.into())
	}
}

pub(super) struct McpRequestDecoder;
pub(super) struct DecodedRequest {
	pub(super) id: Option<SandboxReplyId>,
	pub(super) method: Method,
	pub(super) call: ToolCall,
}
pub(super) struct SandboxReplyId(Value);
impl SandboxReplyId {
	pub(super) fn into_response_id(self) -> Value {
		self.0
	}
}
pub(super) enum Method {
	Initialize,
	List,
	Call,
	Initialized,
	Ping,
	Unknown(String),
}
impl Method {
	pub(super) fn log_label(&self) -> &'static str {
		match self {
			Self::Initialize => "initialize",
			Self::List => "tools/list",
			Self::Call => "tools/call",
			Self::Initialized => "notifications/initialized",
			Self::Ping => "ping",
			Self::Unknown(_) => "unknown",
		}
	}
}
pub(super) struct ToolCall {
	pub(super) name: ToolName,
	pub(super) arguments: Result<Arguments>,
}
pub(super) enum ToolName {
	Query,
	Get,
	Finding,
	Poc,
	Verdict,
	Patch,
	ValidatePatch,
	Unknown(String),
}
impl ToolName {
	pub(super) fn log_label(&self) -> &'static str {
		match self {
			Self::Query => "query_prior_findings",
			Self::Get => "get_finding_by_id",
			Self::Finding => "submit_finding",
			Self::Poc => "validate_poc",
			Self::Verdict => "submit_verdict",
			Self::Patch => "submit_patch",
			Self::ValidatePatch => "validate_patch",
			Self::Unknown(_) => "unknown",
		}
	}
}

pub(super) enum Arguments {
	Query(DecodedQueryArgs),
	Get(i64),
	Finding(DecodedFindingArgs),
	Poc(BoundedText<policy::PocUnified, Agent>),
	Verdict(DecodedVerdictArgs),
	Patch(DecodedPatchArgs),
	ValidatePatch(BoundedText<policy::PatchUnified, Agent>),
}
pub(super) struct DecodedQueryArgs {
	pub(super) query: BoundedText<QueryText, Agent>,
	pub(super) limit: i64,
}
pub(super) struct DecodedFindingArgs {
	pub(super) severity: Severity,
	pub(super) title: BoundedText<policy::FindingTitle, Agent>,
	pub(super) file: RepoPath<Agent>,
	pub(super) line_start: u32,
	pub(super) line_end: u32,
	pub(super) description: BoundedText<policy::FindingDescription, Agent>,
	pub(super) poc_unified: BoundedText<policy::PocUnified, Agent>,
	pub(super) cwe: Option<BoundedText<policy::CweText, Agent>>,
}
pub(super) struct DecodedVerdictArgs {
	pub(super) verdict: loupe_core::Verdict<Agent>,
}
pub(super) struct DecodedPatchArgs {
	pub(super) patch: loupe_core::VerdictPatch<Agent>,
}

pub struct QueryText;
impl TextPolicy for QueryText {
	const FIELD: &'static str = "query";
	const MAX_BYTES: usize = policy::LEGACY_TEXT_MAX_BYTES;
	const MAX_CHARS: usize = policy::LEGACY_TEXT_MAX_BYTES;
	const MULTILINE: bool = true;
	const ALLOW_CR: bool = true;
	const ALLOW_EMPTY: bool = true;
	const NORMALIZATION: Normalization = Normalization::Exact;
	const WHITESPACE: Whitespace = Whitespace::Significant;
}

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
	AgentFindingTitle, policy::FindingTitle;
	AgentFindingDescription, policy::FindingDescription;
	AgentPoc, policy::PocUnified;
	AgentCwe, policy::CweText;
	AgentVerdictNotes, policy::VerdictNotes;
	AgentVerdictReason, policy::VerdictReason;
	AgentPatch, policy::PatchUnified;
	AgentPatchNotes, policy::PatchNotes;
	AgentQuery, QueryText;
}
struct AgentSubmittedPath;
impl Validate<&[u8], Agent> for AgentSubmittedPath {
	type Output = RepoPath<Agent>;
	type Error = anyhow::Error;
	fn validate<'view>(
		self, u: Unvalidated<'view, &[u8]>, mark: Mark<'view, Agent>,
	) -> Result<Self::Output> {
		let raw = std::str::from_utf8(u.get())?;
		let decoded = decode_json_string_bounded(
			raw,
			"repo_path",
			policy::LEGACY_TEXT_MAX_BYTES,
			policy::LEGACY_TEXT_MAX_BYTES,
		)?;
		let normalized = super::normalize_path_component_rules(&decoded)?;
		Ok(RepoPath::new(&mark, &normalized)?)
	}
}
struct AgentFindingId;
impl Validate<&[u8], Agent> for AgentFindingId {
	type Output = i64;
	type Error = anyhow::Error;
	fn validate<'view>(self, u: Unvalidated<'view, &[u8]>, _: Mark<'view, Agent>) -> Result<i64> {
		let raw = std::str::from_utf8(u.get())?;
		let id = if raw.starts_with('"') {
			let reference = decode_json_string_bounded(
				raw,
				"finding_id",
				policy::LEGACY_TEXT_MAX_BYTES,
				policy::LEGACY_TEXT_MAX_BYTES,
			)?;
			reference
				.strip_prefix("LUP-")
				.and_then(|v| v.parse::<i64>().ok())
				.filter(|id| loupe_core::format_finding_id(*id) == reference)
		} else {
			serde_json::from_str::<Value>(raw).map_err(DecodeError::from)?.as_i64()
		};
		id.filter(|id| *id > 0)
			.context("`id` must be a finding reference such as LUP-1234 or a positive integer")
	}
}

type Fields<'a> = HashMap<String, &'a RawValue>;
fn fields(raw: Option<&RawValue>) -> Result<Fields<'_>, serde_json::Error> {
	match raw {
		Some(raw) if raw.get().starts_with('{') => serde_json::from_str(raw.get()),
		_ => Ok(HashMap::new()),
	}
}
fn required<'a>(fields: &Fields<'a>, name: &'static str) -> Result<&'a RawValue> {
	fields
		.get(name)
		.copied()
		.filter(|v| v.get().starts_with('"'))
		.with_context(|| format!("`{name}` argument is required and must be a string"))
}
fn scalar_string(raw: &RawValue) -> Result<String> {
	Ok(serde_json::from_str(raw.get()).map_err(DecodeError::from)?)
}
fn line(fields: &Fields<'_>, name: &'static str) -> Result<u32> {
	let value = fields
		.get(name)
		.map(|v| serde_json::from_str::<Value>(v.get()))
		.transpose()
		.map_err(DecodeError::from)?;
	Ok(value
		.and_then(|v| v.as_u64())
		.with_context(|| format!("`{name}` argument is required and must be a positive integer"))?
		.min(u32::MAX as u64) as u32)
}
macro_rules! carry {
	($u:expr, $raw:expr, $validator:expr) => {{
		let raw = $raw;
		let range = token_range($u.get(), raw)?;
		#[cfg(fuzzing)]
		crate::ingress_text::observe::agent(range.clone());
		$u.carry::<Agent>(range).ok_or(DecodeError::Syntax)?.validate($validator)?
	}};
}

fn arguments(
	u: &Unvalidated<'_, &[u8], Sandbox>, name: &ToolName, raw: Option<&RawValue>,
) -> Result<Arguments> {
	let fields = fields(raw).map_err(DecodeError::from)?;
	if let Some(version) = fields.get("protocol_version") {
		let value: Value = serde_json::from_str(version.get()).map_err(DecodeError::from)?;
		let version = value.as_u64().context("protocol_version must be an integer")?;
		if version != u64::from(super::LOUPE_MCP_PROTOCOL_VERSION) {
			anyhow::bail!(
				"unsupported Loupe MCP protocol_version {version}; worker supports {}",
				super::LOUPE_MCP_PROTOCOL_VERSION
			);
		}
	}
	Ok(match name {
		ToolName::Query => Arguments::Query(DecodedQueryArgs {
			query: carry!(u, required(&fields, "query")?, AgentQuery),
			limit: fields
				.get("limit")
				.map(|v| serde_json::from_str::<Value>(v.get()))
				.transpose()
				.map_err(DecodeError::from)?
				.and_then(|v| v.as_i64())
				.unwrap_or(20)
				.clamp(1, 100),
		}),
		ToolName::Get => Arguments::Get(carry!(
			u,
			fields.get("id").copied().context(
				"`id` must be a finding reference such as LUP-1234 or a positive integer"
			)?,
			AgentFindingId
		)),
		ToolName::Finding => Arguments::Finding(DecodedFindingArgs {
			severity: {
				let value = scalar_string(required(&fields, "severity")?)?;
				value.parse().map_err(|_| anyhow::anyhow!("unknown severity"))?
			},
			title: carry!(u, required(&fields, "title")?, AgentFindingTitle),
			file: carry!(u, required(&fields, "file")?, AgentSubmittedPath),
			line_start: line(&fields, "line_start")?,
			line_end: line(&fields, "line_end")?,
			description: carry!(u, required(&fields, "description")?, AgentFindingDescription),
			poc_unified: carry!(u, required(&fields, "poc_unified")?, AgentPoc),
			cwe: match fields.get("cwe").filter(|v| v.get().starts_with('"')) {
				Some(raw) => {
					let value = carry!(u, *raw, AgentCwe);
					(!value.expose().is_empty()).then_some(value)
				},
				None => None,
			},
		}),
		ToolName::Poc => Arguments::Poc(carry!(u, required(&fields, "poc_unified")?, AgentPoc)),
		ToolName::ValidatePatch => {
			Arguments::ValidatePatch(carry!(u, required(&fields, "patch_unified")?, AgentPatch))
		},
		ToolName::Patch => Arguments::Patch(DecodedPatchArgs {
			patch: loupe_core::VerdictPatch {
				patch_unified: carry!(u, required(&fields, "patch_unified")?, AgentPatch),
				notes: carry!(u, required(&fields, "notes")?, AgentPatchNotes),
			},
		}),
		ToolName::Verdict => {
			let kind = scalar_string(required(&fields, "verdict")?)?;
			let notes = required(&fields, "notes")?;
			let verdict = match kind.as_str() {
				"confirmed" => loupe_core::Verdict::Confirmed {
					notes: Some(carry!(u, notes, AgentVerdictNotes)),
					patch: None,
				},
				"dismissed" => loupe_core::Verdict::Dismissed {
					notes: Some(carry!(u, notes, AgentVerdictNotes)),
				},
				"inconclusive" => loupe_core::Verdict::Inconclusive {
					reason: carry!(u, notes, AgentVerdictReason),
					terminal: false,
				},
				_ => anyhow::bail!(
					"unknown verdict; must be one of `confirmed`, `dismissed`, `inconclusive`"
				),
			};
			Arguments::Verdict(DecodedVerdictArgs { verdict })
		},
		ToolName::Unknown(_) => return Err(UnknownTool.into()),
	})
}

#[derive(Debug, thiserror::Error)]
#[error("unknown tool")]
pub(super) struct UnknownTool;

impl ToolName {
	/// Explicit sender-facing protocol echo. The name is decoded output from
	/// the Sandbox record, never part of a validation error or log field.
	pub(super) fn unknown_tool_response(&self) -> Option<String> {
		match self {
			Self::Unknown(name) => Some(format!("Error: unknown tool: {name}")),
			_ => None,
		}
	}
}

#[derive(Deserialize)]
struct RawRequest<'a> {
	#[serde(borrow)]
	jsonrpc: &'a RawValue,
	#[serde(borrow, default)]
	id: Option<&'a RawValue>,
	#[serde(borrow)]
	method: &'a RawValue,
	#[serde(borrow, default)]
	params: Option<&'a RawValue>,
}
/// Only id and params were Value in the old envelope. Unknown top-level
/// members remain IgnoredAny, so their numeric/Unicode semantics stay distinct.
#[derive(Deserialize)]
struct EnvelopeContent {
	#[serde(rename = "jsonrpc")]
	_jsonrpc: serde::de::IgnoredAny,
	#[serde(default, rename = "id")]
	_id: Option<DiscardContent>,
	#[serde(rename = "method")]
	_method: serde::de::IgnoredAny,
	#[serde(default, rename = "params")]
	_params: Option<DiscardContent>,
}
/// A newly rejected field must not be decoded by the subsequent compatibility
/// traversal. Its narrower rejection precedence is intentional: retain original
/// id depth, skip the rejected params, then return the ordinary tool error.
#[derive(Deserialize)]
struct RejectedParamsEnvelope {
	#[serde(rename = "jsonrpc")]
	_jsonrpc: serde::de::IgnoredAny,
	#[serde(default, rename = "id")]
	_id: Option<DiscardContent>,
	#[serde(rename = "method")]
	_method: serde::de::IgnoredAny,
	#[serde(default, rename = "params")]
	_params: Option<serde::de::IgnoredAny>,
}
fn new_field_policy_failure(result: &Result<Arguments>) -> bool {
	result.as_ref().err().is_some_and(|error| {
		let policy = match error.downcast_ref::<DecodeError>() {
			Some(DecodeError::Policy(policy)) => Some(policy),
			_ => error.downcast_ref::<loupe_core::text::Error>(),
		};
		// JSON syntax was already rejected by the legacy envelope parser.
		// Only newly invalid field policy may skip the params content pass.
		policy.is_some_and(|error| error.rule != loupe_core::text::Rule::JsonSyntax)
	})
}
impl ValidateCarrying<&[u8], Sandbox> for McpRequestDecoder {
	type Output = Option<DecodedRequest>;
	type Error = RecordError;
	fn validate(self, u: Unvalidated<'_, &[u8], Sandbox>) -> Result<Self::Output, RecordError> {
		let text = std::str::from_utf8(u.get()).map_err(|_| RecordError::Utf8)?;
		if text.trim().is_empty() {
			return Ok(None);
		}
		let raw: RawRequest<'_> = serde_json::from_str(text)?;
		let _: String = serde_json::from_str(raw.jsonrpc.get())?;
		let method: String = serde_json::from_str(raw.method.get())?;
		let method = match method.as_str() {
			"initialize" => Method::Initialize,
			"tools/list" => Method::List,
			"tools/call" => Method::Call,
			"notifications/initialized" => Method::Initialized,
			"ping" => Method::Ping,
			_ => Method::Unknown(method),
		};
		let params = fields(raw.params)?;
		let name = params
			.get("name")
			.filter(|r| r.get().starts_with('"'))
			.map(|r| serde_json::from_str::<String>(r.get()))
			.transpose()?
			.unwrap_or_default();
		let name = match name.as_str() {
			"query_prior_findings" => ToolName::Query,
			"get_finding_by_id" => ToolName::Get,
			"submit_finding" => ToolName::Finding,
			"validate_poc" => ToolName::Poc,
			"submit_verdict" => ToolName::Verdict,
			"submit_patch" => ToolName::Patch,
			"validate_patch" => ToolName::ValidatePatch,
			_ => ToolName::Unknown(name),
		};
		let arguments = if matches!(method, Method::Call) && raw.id.is_some() {
			arguments(&u, &name, params.get("arguments").copied())
		} else {
			// This record will not dispatch a tool. Its params are Sandbox
			// protocol data and retain the full legacy Value syntax traversal.
			Err(anyhow::anyhow!("record does not dispatch tool arguments"))
		};
		// Keep original Value depth and syntax after original-token field checks.
		if new_field_policy_failure(&arguments) {
			let _: RejectedParamsEnvelope = serde_json::from_str(text)?;
		} else {
			let _: EnvelopeContent = serde_json::from_str(text)?;
		}
		let id = raw.id.map(|r| serde_json::from_str(r.get()).map(SandboxReplyId)).transpose()?;
		Ok(Some(DecodedRequest { id, method, call: ToolCall { name, arguments } }))
	}
}

impl DecodedFindingArgs {
	/// Retain the first owner's normalized Agent path and separate Repo membership.
	pub(super) fn into_submission(self, workdir: &std::path::Path) -> Result<McpFindingSubmission> {
		let membership = super::check_submitted_membership(workdir, &self.file)?;
		let fingerprint =
			super::fingerprint_for(workdir, self.file.expose(), self.line_start, self.line_end);
		Ok(McpFindingSubmission {
			protocol_version: loupe_proto::PROTOCOL_VERSION,
			severity: self.severity,
			title: self.title,
			description: self.description,
			file_path: self.file,
			line_start: self.line_start,
			line_end: self.line_end,
			cwe: self.cwe,
			poc_unified: self.poc_unified,
			fingerprint,
			_membership: membership,
		})
	}
}

/// The computed fingerprint is host output; content remains Agent through HTTP.
#[derive(serde::Serialize)]
pub(crate) struct McpFindingSubmission {
	protocol_version: u16,
	pub(super) severity: Severity,
	pub(super) title: BoundedText<policy::FindingTitle, Agent>,
	pub(super) description: BoundedText<policy::FindingDescription, Agent>,
	pub(super) file_path: RepoPath<Agent>,
	pub(super) line_start: u32,
	pub(super) line_end: u32,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) cwe: Option<BoundedText<policy::CweText, Agent>>,
	pub(super) poc_unified: BoundedText<policy::PocUnified, Agent>,
	pub(super) fingerprint: super::repo_ingress::ComputedFingerprint,
	#[serde(skip)]
	_membership: Option<super::repo_ingress::ObservedSubmittedPath>,
}
impl McpFindingSubmission {
	pub(super) fn validate(&self) -> Result<(), String> {
		loupe_proto::validate_llm_finding(&loupe_proto::LlmFindingValidation {
			title: &self.title,
			description: &self.description,
			file_path: &self.file_path,
			line_start: self.line_start,
			line_end: self.line_end,
			cwe: self.cwe.as_ref(),
			poc_unified: &self.poc_unified,
			fingerprint: self.fingerprint.for_submission(),
		})
	}
}
impl std::fmt::Debug for McpFindingSubmission {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("McpFindingSubmission([redacted])")
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn actual_argument_decoder_returns_agent_fields_with_exact_text() {
		let args = super::super::legacy_test_api::arguments(
			"submit_finding",
			&serde_json::json!({
				"severity":"high", "title":" same ", "description":" same ",
				"file":"/workdir/src/cafe\u{301}.rs", "line_start":1, "line_end":u64::MAX,
				"poc_unified":"\r\n\t same \n", "cwe":null
			}),
		)
		.unwrap();
		let Arguments::Finding(args) = args else { panic!("finding") };
		let title: &BoundedText<policy::FindingTitle, Agent> = &args.title;
		let description: &BoundedText<policy::FindingDescription, Agent> = &args.description;
		let path: &RepoPath<Agent> = &args.file;
		assert_eq!(title.expose(), " same ");
		assert_eq!(description.expose(), " same ");
		assert_eq!(path.expose(), "src/cafe\u{301}.rs");
		assert_eq!(args.poc_unified.expose(), "\r\n\t same \n");
		assert_eq!(args.line_end, u32::MAX);
		assert!(args.cwe.is_none());
	}
}
