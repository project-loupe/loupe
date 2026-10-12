//! Closed Worker request schemas; only designated original spans become Agent.
use axum::http::StatusCode;
use loupe_core::source_migration::text::{BoundedText, RepoPath};
use loupe_core::source_migration::Finding;
use loupe_core::text::{decode_json_string_bounded, policy, TextPolicy};
use loupe_provenance::{Agent, Mark, Unvalidated, Validate, ValidateCarrying, Worker};
use serde::Deserialize;
use serde_json::value::RawValue;

use super::text::json_text;
use super::{DecodeError, WorkerBody, WorkerJson};

#[cfg(fuzzing)]
#[path = "jobs_fuzz.rs"]
pub(crate) mod fuzz;

pub(crate) struct LeaseRequestDecoder;
pub(crate) struct LeaseInput {
	protocol_version: u16,
	capabilities: Vec<BoundedText<policy::LeaseCapabilityName, Worker>>,
	wait_seconds: u32,
}

pub(crate) struct HeartbeatDecoder;
impl Validate<&[u8], Worker> for HeartbeatDecoder {
	type Output = Option<loupe_proto::HeartbeatRequest>;
	type Error = DecodeError;
	fn validate<'view>(
		self, input: Unvalidated<'view, &[u8]>, _: Mark<'view, Worker>,
	) -> Result<Self::Output, Self::Error> {
		if input.get().is_empty() {
			return Ok(None);
		}
		serde_json::from_slice(input.get()).map(Some).map_err(DecodeError::json)
	}
}
impl HeartbeatDecoder {
	pub(crate) fn decode_legacy(
		body: WorkerBody,
	) -> Result<Option<loupe_proto::HeartbeatRequest>, (StatusCode, String)> {
		body.0
			.as_bytes()
			.validate(Self)
			.map_err(|error| (StatusCode::BAD_REQUEST, format!("invalid heartbeat body: {error}")))
	}
}

// These owner-specific policies stay local during I; M's inventory must unify
// revision/job-diagnostic names across their real producer/consumer owners.
struct RevisionText;
impl TextPolicy for RevisionText {
	const FIELD: &'static str = "revision";
	const MAX_BYTES: usize = policy::LEGACY_TEXT_MAX_BYTES;
	const MAX_CHARS: usize = policy::LEGACY_TEXT_MAX_BYTES;
	const MULTILINE: bool = false;
	const ALLOW_EMPTY: bool = true;
	const NORMALIZATION: loupe_core::text::Normalization = loupe_core::text::Normalization::Exact;
	const WHITESPACE: loupe_core::text::Whitespace = loupe_core::text::Whitespace::Significant;
}
struct JobDiagnostic;
impl TextPolicy for JobDiagnostic {
	const FIELD: &'static str = "job_diagnostic";
	const MAX_BYTES: usize = policy::LEGACY_TEXT_MAX_BYTES;
	const MAX_CHARS: usize = policy::LEGACY_TEXT_MAX_BYTES;
	const MULTILINE: bool = true;
	const ALLOW_CR: bool = true;
	const ALLOW_EMPTY: bool = true;
	const NORMALIZATION: loupe_core::text::Normalization = loupe_core::text::Normalization::Exact;
	const WHITESPACE: loupe_core::text::Whitespace = loupe_core::text::Whitespace::Significant;
}
#[derive(Deserialize)]
struct RawComplete<'a> {
	protocol_version: u16,
	outcome: loupe_proto::CompleteOutcome,
	#[serde(borrow, default)]
	head_sha: Option<&'a RawValue>,
	#[serde(borrow, default)]
	error: Option<&'a RawValue>,
}
pub(crate) struct CompleteDecoder;
pub(crate) struct CompleteInput {
	protocol_version: u16,
	outcome: loupe_proto::CompleteOutcome,
	head_sha: Option<BoundedText<RevisionText, Worker>>,
	error: Option<BoundedText<JobDiagnostic, Worker>>,
}
impl Validate<&[u8], Worker> for CompleteDecoder {
	type Output = CompleteInput;
	type Error = DecodeError;
	fn validate<'view>(
		self, input: Unvalidated<'view, &[u8]>, mark: Mark<'view, Worker>,
	) -> Result<Self::Output, Self::Error> {
		let raw: RawComplete<'_> =
			serde_json::from_slice(input.get()).map_err(DecodeError::json)?;
		Ok(CompleteInput {
			protocol_version: raw.protocol_version,
			outcome: raw.outcome,
			head_sha: raw.head_sha.map(|token| json_text(&mark, token)).transpose()?,
			error: raw.error.map(|token| json_text(&mark, token)).transpose()?,
		})
	}
}
impl CompleteDecoder {
	pub(crate) fn decode_legacy(
		body: WorkerJson,
	) -> Result<loupe_proto::CompleteRequest, (StatusCode, String)> {
		let input = body.0.as_bytes().validate(Self).map_err(DecodeError::response)?;
		Ok(loupe_proto::CompleteRequest {
			protocol_version: input.protocol_version,
			outcome: input.outcome,
			head_sha: input.head_sha.map(|value| value.expose().to_owned()),
			error: input.error.map(|value| value.expose().to_owned()),
		})
	}
}

macro_rules! agent_text {
	($name:ident, $policy:ty) => {
		struct $name;
		impl Validate<&[u8], Agent> for $name {
			type Output = BoundedText<$policy, Agent>;
			type Error = DecodeError;
			fn validate<'view>(
				self, input: Unvalidated<'view, &[u8]>, mark: Mark<'view, Agent>,
			) -> Result<Self::Output, Self::Error> {
				let token: &RawValue =
					serde_json::from_slice(input.get()).map_err(DecodeError::json)?;
				json_text(&mark, token)
			}
		}
	};
}
agent_text!(AgentScanner, policy::ScannerIdText);
agent_text!(AgentTitle, policy::FindingTitle);
agent_text!(AgentDescription, policy::FindingDescription);
agent_text!(AgentCwe, policy::CweText);
agent_text!(AgentPatch, policy::PatchUnified);
agent_text!(AgentPoc, policy::PocUnified);
agent_text!(AgentFingerprint, policy::FindingFingerprintText);
agent_text!(AgentNotes, policy::VerdictNotes);
agent_text!(AgentReason, policy::VerdictReason);
agent_text!(AgentPatchNotes, policy::PatchNotes);
struct AgentPath;
impl Validate<&[u8], Agent> for AgentPath {
	type Output = RepoPath<Agent>;
	type Error = DecodeError;
	fn validate<'view>(
		self, input: Unvalidated<'view, &[u8]>, mark: Mark<'view, Agent>,
	) -> Result<Self::Output, Self::Error> {
		let token = std::str::from_utf8(input.get()).map_err(|_| DecodeError::Syntax)?;
		super::text::require_json_string(token)?;
		let decoded = decode_json_string_bounded(token, "path", 512, 512)?;
		Ok(RepoPath::new(&mark, &decoded)?)
	}
}

// Only the fixed Worker message owner can carry, only to Agent, and only
// original RawValue subslices. Every call below names its designated field.
macro_rules! carried {
	($view:expr, $token:expr, $validator:expr) => {{
		let token = $token;
		let bytes = *$view.get();
		let start = (token.get().as_ptr() as usize)
			.checked_sub(bytes.as_ptr() as usize)
			.ok_or(DecodeError::Syntax)?;
		let end = start
			.checked_add(token.get().len())
			.filter(|end| *end <= bytes.len())
			.ok_or(DecodeError::Syntax)?;
		#[cfg(fuzzing)]
		crate::fuzz_support::observe_carry(stringify!($validator), start, end);
		$view.carry::<Agent>(start..end).ok_or(DecodeError::Syntax)?.validate($validator)?
	}};
}

#[derive(Deserialize)]
struct RawFinding<'a> {
	#[serde(borrow)]
	scanner_id: &'a RawValue,
	severity: loupe_core::Severity,
	#[serde(borrow)]
	title: &'a RawValue,
	#[serde(borrow)]
	description: &'a RawValue,
	#[serde(borrow, default)]
	file_path: Option<&'a RawValue>,
	#[serde(default)]
	line_start: Option<u32>,
	#[serde(default)]
	line_end: Option<u32>,
	#[serde(borrow, default)]
	cwe: Option<&'a RawValue>,
	#[serde(borrow, default)]
	patch_unified: Option<&'a RawValue>,
	#[serde(borrow, default)]
	poc_unified: Option<&'a RawValue>,
	#[serde(borrow)]
	fingerprint: &'a RawValue,
}
#[derive(Deserialize)]
struct RawBatch<'a> {
	protocol_version: u16,
	#[serde(borrow)]
	findings: Vec<RawFinding<'a>>,
}
pub(crate) struct FindingsBatchDecoder;
pub(crate) struct BatchInput {
	protocol_version: u16,
	findings: Vec<Finding<Agent>>,
}
impl<'a> ValidateCarrying<&'a [u8], Worker> for FindingsBatchDecoder {
	type Output = BatchInput;
	type Error = DecodeError;
	fn validate(
		self, input: Unvalidated<'_, &'a [u8], Worker>,
	) -> Result<Self::Output, Self::Error> {
		let raw: RawBatch<'_> = serde_json::from_slice(input.get()).map_err(DecodeError::json)?;
		let mut findings = Vec::with_capacity(raw.findings.len());
		for finding in raw.findings {
			findings.push(Finding {
				scanner_id: carried!(input, finding.scanner_id, AgentScanner),
				severity: finding.severity,
				title: carried!(input, finding.title, AgentTitle),
				description: carried!(input, finding.description, AgentDescription),
				file_path: finding
					.file_path
					.map(|token| Ok::<_, DecodeError>(carried!(input, token, AgentPath)))
					.transpose()?,
				line_start: finding.line_start,
				line_end: finding.line_end,
				cwe: finding
					.cwe
					.map(|token| Ok::<_, DecodeError>(carried!(input, token, AgentCwe)))
					.transpose()?,
				patch_unified: finding
					.patch_unified
					.map(|token| Ok::<_, DecodeError>(carried!(input, token, AgentPatch)))
					.transpose()?,
				poc_unified: finding
					.poc_unified
					.map(|token| Ok::<_, DecodeError>(carried!(input, token, AgentPoc)))
					.transpose()?,
				fingerprint: carried!(input, finding.fingerprint, AgentFingerprint),
			});
		}
		Ok(BatchInput { protocol_version: raw.protocol_version, findings })
	}
}
impl FindingsBatchDecoder {
	pub(crate) fn decode_legacy(
		body: WorkerJson,
	) -> Result<loupe_proto::FindingsBatch, (StatusCode, String)> {
		let input = body.0.as_bytes().validate_carrying(Self).map_err(DecodeError::response)?;
		Ok(loupe_proto::FindingsBatch {
			protocol_version: input.protocol_version,
			findings: input
				.findings
				.into_iter()
				.map(|finding| loupe_core::Finding {
					scanner_id: finding.scanner_id.expose().to_owned(),
					severity: finding.severity,
					title: finding.title.expose().to_owned(),
					description: finding.description.expose().to_owned(),
					file_path: finding.file_path.map(|value| value.expose().to_owned()),
					line_start: finding.line_start,
					line_end: finding.line_end,
					cwe: finding.cwe.map(|value| value.expose().to_owned()),
					patch_unified: finding.patch_unified.map(|value| value.expose().to_owned()),
					poc_unified: finding.poc_unified.map(|value| value.expose().to_owned()),
					fingerprint: finding.fingerprint.expose().to_owned(),
				})
				.collect(),
		})
	}
}

#[derive(Deserialize)]
struct RawLlm<'a> {
	protocol_version: u16,
	severity: loupe_core::Severity,
	#[serde(borrow)]
	title: &'a RawValue,
	#[serde(borrow)]
	description: &'a RawValue,
	#[serde(borrow)]
	file_path: &'a RawValue,
	line_start: u32,
	line_end: u32,
	#[serde(borrow, default)]
	cwe: Option<&'a RawValue>,
	#[serde(borrow)]
	poc_unified: &'a RawValue,
	#[serde(borrow)]
	fingerprint: &'a RawValue,
}
pub(crate) struct LlmFindingDecoder;
pub(crate) struct LlmInput {
	protocol_version: u16,
	severity: loupe_core::Severity,
	title: BoundedText<policy::FindingTitle, Agent>,
	description: BoundedText<policy::FindingDescription, Agent>,
	file_path: RepoPath<Agent>,
	line_start: u32,
	line_end: u32,
	cwe: Option<BoundedText<policy::CweText, Agent>>,
	poc_unified: BoundedText<policy::PocUnified, Agent>,
	fingerprint: BoundedText<policy::FindingFingerprintText, Agent>,
}
impl<'a> ValidateCarrying<&'a [u8], Worker> for LlmFindingDecoder {
	type Output = LlmInput;
	type Error = DecodeError;
	fn validate(
		self, input: Unvalidated<'_, &'a [u8], Worker>,
	) -> Result<Self::Output, Self::Error> {
		let raw: RawLlm<'_> = serde_json::from_slice(input.get()).map_err(DecodeError::json)?;
		Ok(LlmInput {
			protocol_version: raw.protocol_version,
			severity: raw.severity,
			title: carried!(input, raw.title, AgentTitle),
			description: carried!(input, raw.description, AgentDescription),
			file_path: carried!(input, raw.file_path, AgentPath),
			line_start: raw.line_start,
			line_end: raw.line_end,
			cwe: raw
				.cwe
				.map(|token| Ok::<_, DecodeError>(carried!(input, token, AgentCwe)))
				.transpose()?,
			poc_unified: carried!(input, raw.poc_unified, AgentPoc),
			fingerprint: carried!(input, raw.fingerprint, AgentFingerprint),
		})
	}
}
impl LlmFindingDecoder {
	pub(crate) fn decode_legacy(
		body: WorkerJson,
	) -> Result<loupe_proto::LlmFindingSubmission, (StatusCode, String)> {
		let input = body.0.as_bytes().validate_carrying(Self).map_err(DecodeError::response)?;
		Ok(loupe_proto::LlmFindingSubmission {
			protocol_version: input.protocol_version,
			severity: input.severity,
			title: input.title.expose().to_owned(),
			description: input.description.expose().to_owned(),
			file_path: input.file_path.expose().to_owned(),
			line_start: input.line_start,
			line_end: input.line_end,
			cwe: input.cwe.map(|value| value.expose().to_owned()),
			poc_unified: input.poc_unified.expose().to_owned(),
			fingerprint: input.fingerprint.expose().to_owned(),
		})
	}
}

// This borrows the same nested original tokens as the accepted D verdict
// fixture; it never deserializes an internally tagged Value and reserializes it.
enum Outcome {
	Confirmed,
	Dismissed,
	Inconclusive,
}
impl<'de> Deserialize<'de> for Outcome {
	fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct Tag;
		impl serde::de::Visitor<'_> for Tag {
			type Value = Outcome;
			fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				f.write_str("a verdict outcome string")
			}
			fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Outcome, E> {
				match value {
					"confirmed" => Ok(Outcome::Confirmed),
					"dismissed" => Ok(Outcome::Dismissed),
					"inconclusive" => Ok(Outcome::Inconclusive),
					_ => Err(E::custom("unknown variant")),
				}
			}
		}
		d.deserialize_identifier(Tag)
	}
}
#[derive(Deserialize)]
struct RawVerdict<'a> {
	protocol_version: u16,
	#[serde(borrow)]
	verdict: &'a RawValue,
}
#[derive(Deserialize)]
struct RawOutcome {
	outcome: Outcome,
}
#[derive(Deserialize)]
struct RawConfirmed<'a> {
	#[serde(rename = "outcome")]
	_outcome: Outcome,
	#[serde(borrow, default)]
	notes: Option<&'a RawValue>,
	#[serde(borrow, default)]
	patch: Option<&'a RawValue>,
}
#[derive(Deserialize)]
struct RawDismissed<'a> {
	#[serde(rename = "outcome")]
	_outcome: Outcome,
	#[serde(borrow, default)]
	notes: Option<&'a RawValue>,
}
#[derive(Deserialize)]
struct RawInconclusive<'a> {
	#[serde(rename = "outcome")]
	_outcome: Outcome,
	#[serde(borrow)]
	reason: &'a RawValue,
	#[serde(default)]
	terminal: bool,
}
#[derive(Deserialize)]
struct RawPatch<'a> {
	#[serde(borrow)]
	patch_unified: &'a RawValue,
	#[serde(borrow)]
	notes: &'a RawValue,
}
// Retain the envelope recursion boundary for the old internally tagged enum's
// ignored-content validation. This pass occurs after bounded carried fields.
#[derive(Deserialize)]
struct VerdictContent {
	#[serde(rename = "protocol_version")]
	_protocol_version: u16,
	#[serde(rename = "verdict")]
	_verdict: super::text::DiscardContent,
}
pub(crate) struct VerdictSubmissionDecoder;
impl<'a> ValidateCarrying<&'a [u8], Worker> for VerdictSubmissionDecoder {
	type Output = (u16, loupe_core::source_migration::Verdict<Agent>);
	type Error = DecodeError;
	fn validate(
		self, input: Unvalidated<'_, &'a [u8], Worker>,
	) -> Result<Self::Output, Self::Error> {
		use loupe_core::source_migration::{Verdict, VerdictPatch};
		let raw: RawVerdict<'_> = serde_json::from_slice(input.get()).map_err(DecodeError::json)?;
		let text = raw.verdict.get();
		let outcome = if text.starts_with('[') {
			let tag: super::text::SequenceTag<'_> =
				serde_json::from_str(text).map_err(DecodeError::json)?;
			serde_json::from_str(tag.0.get()).map_err(DecodeError::json)?
		} else {
			serde_json::from_str::<RawOutcome>(text).map_err(DecodeError::json)?.outcome
		};
		let verdict = match outcome {
			Outcome::Confirmed => {
				let raw: RawConfirmed<'_> =
					serde_json::from_str(text).map_err(DecodeError::json)?;
				Verdict::Confirmed {
					notes: raw
						.notes
						.map(|token| Ok::<_, DecodeError>(carried!(input, token, AgentNotes)))
						.transpose()?,
					patch: raw
						.patch
						.map(|token| {
							let patch: RawPatch<'_> =
								serde_json::from_str(token.get()).map_err(DecodeError::json)?;
							Ok::<_, DecodeError>(VerdictPatch {
								patch_unified: carried!(input, patch.patch_unified, AgentPatch),
								notes: carried!(input, patch.notes, AgentPatchNotes),
							})
						})
						.transpose()?,
				}
			},
			Outcome::Dismissed => {
				let raw: RawDismissed<'_> =
					serde_json::from_str(text).map_err(DecodeError::json)?;
				Verdict::Dismissed {
					notes: raw
						.notes
						.map(|token| Ok::<_, DecodeError>(carried!(input, token, AgentNotes)))
						.transpose()?,
				}
			},
			Outcome::Inconclusive => {
				let raw: RawInconclusive<'_> =
					serde_json::from_str(text).map_err(DecodeError::json)?;
				Verdict::Inconclusive {
					reason: carried!(input, raw.reason, AgentReason),
					terminal: raw.terminal,
				}
			},
		};
		serde_json::from_slice::<VerdictContent>(input.get()).map_err(DecodeError::json)?;
		Ok((raw.protocol_version, verdict))
	}
}
impl VerdictSubmissionDecoder {
	pub(crate) fn decode_legacy(
		body: WorkerJson,
	) -> Result<loupe_proto::VerdictSubmission, (StatusCode, String)> {
		use loupe_core::source_migration::Verdict;
		let (protocol_version, verdict) =
			body.0.as_bytes().validate_carrying(Self).map_err(DecodeError::response)?;
		let verdict = match verdict {
			Verdict::Confirmed { notes, patch } => loupe_core::Verdict::Confirmed {
				notes: notes.map(|value| value.expose().to_owned()),
				patch: patch.map(|patch| loupe_core::VerdictPatch {
					patch_unified: patch.patch_unified.expose().to_owned(),
					notes: patch.notes.expose().to_owned(),
				}),
			},
			Verdict::Dismissed { notes } => loupe_core::Verdict::Dismissed {
				notes: notes.map(|value| value.expose().to_owned()),
			},
			Verdict::Inconclusive { reason, terminal } => {
				loupe_core::Verdict::Inconclusive { reason: reason.expose().to_owned(), terminal }
			},
		};
		Ok(loupe_proto::VerdictSubmission { protocol_version, verdict })
	}
}
#[derive(Deserialize)]
struct RawLease<'a> {
	protocol_version: u16,
	#[serde(borrow)]
	capabilities: Vec<&'a RawValue>,
	#[serde(default)]
	wait_seconds: u32,
}
impl Validate<&[u8], Worker> for LeaseRequestDecoder {
	type Output = LeaseInput;
	type Error = DecodeError;
	fn validate<'view>(
		self, input: Unvalidated<'view, &[u8]>, mark: Mark<'view, Worker>,
	) -> Result<Self::Output, Self::Error> {
		let raw: RawLease<'_> = serde_json::from_slice(input.get()).map_err(DecodeError::json)?;
		Ok(LeaseInput {
			protocol_version: raw.protocol_version,
			capabilities: raw
				.capabilities
				.into_iter()
				.map(|token| json_text(&mark, token))
				.collect::<Result<_, _>>()?,
			wait_seconds: raw.wait_seconds,
		})
	}
}
impl LeaseRequestDecoder {
	/// Temporary I exit; M returns the marked fields directly to the route.
	pub(crate) fn decode_legacy(
		body: WorkerJson,
	) -> Result<loupe_proto::LeaseRequest, (StatusCode, String)> {
		let input = body.0.as_bytes().validate(Self).map_err(DecodeError::response)?;
		Ok(loupe_proto::LeaseRequest {
			protocol_version: input.protocol_version,
			capabilities: input
				.capabilities
				.iter()
				.map(|value| value.expose().to_owned())
				.collect(),
			wait_seconds: input.wait_seconds,
		})
	}
}

#[cfg(test)]
mod tests {
	use loupe_provenance::{Ingress, Untrusted};

	use super::*;

	fn worker_fixture(bytes: &[u8]) -> Untrusted<&[u8], Worker> {
		// SAFETY: closed synthetic Worker fixture at this test boundary only.
		#[allow(unsafe_code)]
		let input = unsafe { Ingress::<Worker>::new() };
		Untrusted::new(bytes, input)
	}

	#[test]
	fn original_encoded_agent_tokens_keep_exact_text_and_source() {
		let body = br#"{"protocol_version":2,"findings":[{"scanner_id":"secrets","severity":"high","title":"  Caf\u0065\u0301  ","description":"first\r\n\tsecond","file_path":"src/main.rs","fingerprint":"fp","patch_unified":"","cwe":null}]}"#;
		let output = worker_fixture(body).validate_carrying(FindingsBatchDecoder).unwrap();
		let finding: &Finding<Agent> = &output.findings[0];
		assert_eq!(finding.title.expose(), "  Cafe\u{301}  ");
		assert_eq!(finding.description.expose(), "first\r\n\tsecond");
		assert_eq!(finding.file_path.as_ref().unwrap().expose(), "src/main.rs");
		assert_eq!(finding.patch_unified.as_ref().unwrap().expose(), "");
		assert!(finding.cwe.is_none());
		let rejected = br#"{"protocol_version":2,"findings":[{"scanner_id":"secrets","severity":"high","title":"bad\u001b","description":"description","fingerprint":"fp"}]}"#;
		assert!(worker_fixture(rejected).validate_carrying(FindingsBatchDecoder).is_err());
	}

	#[test]
	fn carry_rejects_a_decoded_or_recreated_token_outside_original_body() {
		struct ForeignToken;
		impl<'a> ValidateCarrying<&'a [u8], Worker> for ForeignToken {
			type Output = BoundedText<policy::FindingTitle, Agent>;
			type Error = DecodeError;
			fn validate(
				self, input: Unvalidated<'_, &'a [u8], Worker>,
			) -> Result<Self::Output, Self::Error> {
				let foreign = RawValue::from_string("\"same text\"".into()).unwrap();
				Ok(carried!(input, foreign.as_ref(), AgentTitle))
			}
		}
		let error = worker_fixture(br#""same text""#).validate_carrying(ForeignToken).unwrap_err();
		assert!(matches!(error, DecodeError::Syntax));
	}

	#[test]
	fn nested_verdict_tokens_preserve_empty_null_and_exact_patch_bytes() {
		use loupe_core::source_migration::Verdict;
		let body = br#"{"protocol_version":2,"verdict":{"outcome":"confirmed","notes":"","patch":{"patch_unified":"diff\r\n\ttext","notes":"Cafe\u0301"}}}"#;
		let (_, verdict): (u16, Verdict<Agent>) =
			worker_fixture(body).validate_carrying(VerdictSubmissionDecoder).unwrap();
		let Verdict::Confirmed { notes, patch } = verdict else { panic!("confirmed variant") };
		assert_eq!(notes.unwrap().expose(), "");
		let patch = patch.unwrap();
		assert_eq!(patch.patch_unified.expose(), "diff\r\n\ttext");
		assert_eq!(patch.notes.expose(), "Cafe\u{301}");
		for body in [
			br#"{"protocol_version":2,"verdict":{"outcome":"dismissed"}}"#.as_slice(),
			br#"{"protocol_version":2,"verdict":{"outcome":"dismissed","notes":null}}"#,
		] {
			let (_, verdict) =
				worker_fixture(body).validate_carrying(VerdictSubmissionDecoder).unwrap();
			assert!(matches!(verdict, Verdict::Dismissed { notes: None }));
		}
	}
}
