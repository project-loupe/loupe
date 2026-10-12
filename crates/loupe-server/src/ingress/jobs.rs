//! Closed Worker request schemas; only designated original spans become Agent.
use axum::http::StatusCode;
use loupe_core::text::{decode_json_string_bounded, policy, BoundedText, RepoPath};
use loupe_core::Finding;
use loupe_provenance::{Agent, Mark, Unvalidated, Validate, ValidateCarrying, Worker};
use serde::Deserialize;
use serde_json::value::RawValue;

use super::text::json_text;
use super::{DecodeError, WorkerBody, WorkerJson};

#[cfg(fuzzing)]
#[path = "jobs_fuzz.rs"]
pub(crate) mod fuzz;

pub(crate) struct LeaseRequestDecoder;
pub(crate) type LeaseInput = loupe_proto::LeaseRequest<Worker>;

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
	pub(crate) fn decode(
		body: WorkerBody,
	) -> Result<Option<loupe_proto::HeartbeatRequest>, (StatusCode, String)> {
		body.0
			.as_bytes()
			.validate(Self)
			.map_err(|error| (StatusCode::BAD_REQUEST, format!("invalid heartbeat body: {error}")))
	}
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
pub(crate) type CompleteInput = loupe_proto::CompleteRequest<Worker, Worker>;
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
	pub(crate) fn decode(body: WorkerJson) -> Result<CompleteInput, (StatusCode, String)> {
		body.0.as_bytes().validate(Self).map_err(DecodeError::response)
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
pub(crate) type BatchInput = loupe_proto::FindingsBatch<Agent>;
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
	pub(crate) fn decode(body: WorkerJson) -> Result<BatchInput, (StatusCode, String)> {
		body.0.as_bytes().validate_carrying(Self).map_err(DecodeError::response)
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
	pub(crate) protocol_version: u16,
	pub(crate) severity: loupe_core::Severity,
	pub(crate) title: BoundedText<policy::FindingTitle, Agent>,
	pub(crate) description: BoundedText<policy::FindingDescription, Agent>,
	pub(crate) file_path: RepoPath<Agent>,
	pub(crate) line_start: u32,
	pub(crate) line_end: u32,
	pub(crate) cwe: Option<BoundedText<policy::CweText, Agent>>,
	pub(crate) poc_unified: BoundedText<policy::PocUnified, Agent>,
	pub(crate) fingerprint: BoundedText<policy::FindingFingerprintText, Agent>,
	scanner_id: BoundedText<policy::ScannerIdText, Agent>,
}
struct LlmTitle;
impl Validate<&[u8], Agent> for LlmTitle {
	type Output =
		(BoundedText<policy::FindingTitle, Agent>, BoundedText<policy::ScannerIdText, Agent>);
	type Error = DecodeError;
	fn validate<'view>(
		self, input: Unvalidated<'view, &[u8]>, mark: Mark<'view, Agent>,
	) -> Result<Self::Output, Self::Error> {
		let token: &RawValue = serde_json::from_slice(input.get()).map_err(DecodeError::json)?;
		let title = json_text(&mark, token)?;
		// Fixed protocol metadata attached at the actual carried Agent-content
		// decoder, not a claim that the model authored this scanner constant.
		let scanner_id = BoundedText::new(&mark, loupe_proto::LLM_CODE_REVIEW_SCANNER_ID)?;
		Ok((title, scanner_id))
	}
}
impl LlmInput {
	pub(crate) fn validate(&self) -> Result<(), String> {
		loupe_proto::validate_llm_finding(&loupe_proto::LlmFindingValidation {
			title: &self.title,
			description: &self.description,
			file_path: &self.file_path,
			line_start: self.line_start,
			line_end: self.line_end,
			cwe: self.cwe.as_ref(),
			poc_unified: &self.poc_unified,
			fingerprint: self.fingerprint.expose(),
		})
	}
	pub(crate) fn into_finding(self) -> Finding<Agent> {
		Finding {
			scanner_id: self.scanner_id,
			severity: self.severity,
			title: self.title,
			description: self.description,
			file_path: Some(self.file_path),
			line_start: Some(self.line_start),
			line_end: Some(self.line_end),
			cwe: self.cwe,
			patch_unified: None,
			poc_unified: Some(self.poc_unified),
			fingerprint: self.fingerprint,
		}
	}
}
impl<'a> ValidateCarrying<&'a [u8], Worker> for LlmFindingDecoder {
	type Output = LlmInput;
	type Error = DecodeError;
	fn validate(
		self, input: Unvalidated<'_, &'a [u8], Worker>,
	) -> Result<Self::Output, Self::Error> {
		let raw: RawLlm<'_> = serde_json::from_slice(input.get()).map_err(DecodeError::json)?;
		let (title, scanner_id) = carried!(input, raw.title, LlmTitle);
		Ok(LlmInput {
			protocol_version: raw.protocol_version,
			severity: raw.severity,
			title,
			scanner_id,
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
	pub(crate) fn decode(body: WorkerJson) -> Result<LlmInput, (StatusCode, String)> {
		body.0.as_bytes().validate_carrying(Self).map_err(DecodeError::response)
	}
}

// Borrow nested original tokens so carried spans refer to the request bytes,
// without deserializing and reserializing an internally tagged Value.
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
// Retain the envelope recursion boundary for the internally tagged enum's
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
	type Output = (u16, loupe_core::Verdict<Agent>);
	type Error = DecodeError;
	fn validate(
		self, input: Unvalidated<'_, &'a [u8], Worker>,
	) -> Result<Self::Output, Self::Error> {
		use loupe_core::{Verdict, VerdictPatch};
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
	pub(crate) fn decode(
		body: WorkerJson,
	) -> Result<loupe_proto::VerdictSubmission<Agent>, (StatusCode, String)> {
		let (protocol_version, verdict) =
			body.0.as_bytes().validate_carrying(Self).map_err(DecodeError::response)?;
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
	pub(crate) fn decode(body: WorkerJson) -> Result<LeaseInput, (StatusCode, String)> {
		body.0.as_bytes().validate(Self).map_err(DecodeError::response)
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
		use loupe_core::Verdict;
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

	#[test]
	fn llm_closed_scanner_composition_keeps_original_agent_fields() {
		let body = br#"{"protocol_version":2,"severity":"high","title":"  Original Caf\u0065\u0301 title  ","description":"  A sufficiently detailed original description that preserves all exact surrounding spaces and bytes.  ","file_path":"src/main.rs","line_start":1,"line_end":2,"cwe":"CWE-79","poc_unified":"--- a/src/main.rs\r\n+++ b/src/main.rs\r\n@@ -1 +1 @@\r\n+\tproof","fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","scanner_id":"caller-cannot-select-this"}"#;
		let value = worker_fixture(body).validate_carrying(LlmFindingDecoder).unwrap();
		value.validate().unwrap();
		let finding: Finding<Agent> = value.into_finding();
		assert_eq!(finding.scanner_id.expose(), loupe_proto::LLM_CODE_REVIEW_SCANNER_ID);
		assert_eq!(finding.title.expose(), "  Original Cafe\u{301} title  ");
		assert_eq!(
			finding.description.expose(),
			"  A sufficiently detailed original description that preserves all exact surrounding spaces and bytes.  "
		);
		assert_eq!(
			finding.poc_unified.unwrap().expose(),
			"--- a/src/main.rs\r\n+++ b/src/main.rs\r\n@@ -1 +1 @@\r\n+\tproof"
		);
		assert_eq!(finding.file_path.unwrap().expose(), "src/main.rs");
	}
}
