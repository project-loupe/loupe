//! Exact observations from the final typed Worker request owners.
use loupe_provenance::{Ingress, Untrusted};
use serde_json::{json, Value};

use super::*;
use crate::fuzz_support::{error, CarriedSpan, Decoded};

#[derive(Clone, Copy, Debug)]
pub enum WorkerRequest {
	Heartbeat,
	Complete,
	Findings,
	LlmFinding,
	Verdict,
	Lease,
}

/// Concrete final DTOs produced by the same named Worker decoders. This lets
/// the DTO harness exercise their real Serialize implementations without
/// restoring a normal-build Deserialize or choosing a source parameter.
pub enum WorkerValue {
	Lease(loupe_proto::LeaseRequest<Worker>),
	Complete(loupe_proto::CompleteRequest<Worker, Worker>),
	Findings(loupe_proto::FindingsBatch<Agent>),
	Llm(loupe_proto::LlmFindingSubmission<Agent>),
	Verdict(loupe_proto::VerdictSubmission<Agent>),
}

pub fn worker_value(kind: WorkerRequest, bytes: &[u8]) -> Option<WorkerValue> {
	let input = original(bytes);
	Some(match kind {
		WorkerRequest::Lease => WorkerValue::Lease(input.validate(LeaseRequestDecoder).ok()?),
		WorkerRequest::Complete => WorkerValue::Complete(input.validate(CompleteDecoder).ok()?),
		WorkerRequest::Findings => {
			WorkerValue::Findings(input.validate_carrying(FindingsBatchDecoder).ok()?)
		},
		WorkerRequest::LlmFinding => {
			let value = input.validate_carrying(LlmFindingDecoder).ok()?;
			WorkerValue::Llm(loupe_proto::LlmFindingSubmission {
				protocol_version: value.protocol_version,
				severity: value.severity,
				title: value.title,
				description: value.description,
				file_path: value.file_path,
				line_start: value.line_start,
				line_end: value.line_end,
				cwe: value.cwe,
				poc_unified: value.poc_unified,
				fingerprint: value.fingerprint,
			})
		},
		WorkerRequest::Verdict => {
			let (protocol_version, verdict) =
				input.validate_carrying(VerdictSubmissionDecoder).ok()?;
			WorkerValue::Verdict(loupe_proto::VerdictSubmission { protocol_version, verdict })
		},
		WorkerRequest::Heartbeat => return None,
	})
}

fn original(bytes: &[u8]) -> Untrusted<&[u8], Worker> {
	// SAFETY: fixed synthetic Worker message supplied by this fuzz fixture.
	#[allow(unsafe_code)]
	Untrusted::new(bytes, unsafe { Ingress::<Worker>::new() })
}

fn finding(finding: &Finding<Agent>) -> Value {
	json!({
		"scanner_id": finding.scanner_id.expose(), "severity": finding.severity,
		"title": finding.title.expose(), "description": finding.description.expose(),
		"file_path": finding.file_path.as_ref().map(RepoPath::expose),
		"line_start": finding.line_start, "line_end": finding.line_end,
		"cwe": finding.cwe.as_ref().map(BoundedText::expose),
		"patch_unified": finding.patch_unified.as_ref().map(BoundedText::expose),
		"poc_unified": finding.poc_unified.as_ref().map(BoundedText::expose),
		"fingerprint": finding.fingerprint.expose(),
	})
}

pub fn worker_request(kind: WorkerRequest, bytes: &[u8]) -> (Decoded, Vec<CarriedSpan>) {
	crate::fuzz_support::observe(|| decode(kind, bytes).map_err(error))
}

fn decode(kind: WorkerRequest, bytes: &[u8]) -> Result<Value, DecodeError> {
	let input = original(bytes);
	Ok(match kind {
		WorkerRequest::Heartbeat => match input.validate(HeartbeatDecoder)? {
			None => Value::Null,
			Some(value) => json!({"protocol_version": value.protocol_version}),
		},
		WorkerRequest::Complete => {
			let value = input.validate(CompleteDecoder)?;
			let head: &Option<BoundedText<policy::RevisionText, Worker>> = &value.head_sha;
			let diagnostic: &Option<BoundedText<policy::JobDiagnostic, Worker>> = &value.error;
			json!({"protocol_version": value.protocol_version, "outcome": value.outcome,
				"head_sha": head.as_ref().map(BoundedText::expose),
				"error": diagnostic.as_ref().map(BoundedText::expose)})
		},
		WorkerRequest::Findings => {
			let value = input.validate_carrying(FindingsBatchDecoder)?;
			json!({"protocol_version": value.protocol_version,
				"findings": value.findings.iter().map(finding).collect::<Vec<_>>()})
		},
		WorkerRequest::LlmFinding => {
			let value = input.validate_carrying(LlmFindingDecoder)?;
			let title: &BoundedText<policy::FindingTitle, Agent> = &value.title;
			let description: &BoundedText<policy::FindingDescription, Agent> = &value.description;
			let path: &RepoPath<Agent> = &value.file_path;
			let cwe: &Option<BoundedText<policy::CweText, Agent>> = &value.cwe;
			let poc: &BoundedText<policy::PocUnified, Agent> = &value.poc_unified;
			let fingerprint: &BoundedText<policy::FindingFingerprintText, Agent> =
				&value.fingerprint;
			json!({"protocol_version": value.protocol_version, "severity": value.severity,
				"title": title.expose(), "description": description.expose(),
				"file_path": path.expose(), "line_start": value.line_start,
				"line_end": value.line_end, "cwe": cwe.as_ref().map(BoundedText::expose),
				"poc_unified": poc.expose(), "fingerprint": fingerprint.expose()})
		},
		WorkerRequest::Verdict => {
			use loupe_core::Verdict;
			let (version, value): (u16, Verdict<Agent>) =
				input.validate_carrying(VerdictSubmissionDecoder)?;
			let verdict = match value {
				Verdict::Confirmed { notes, patch } => json!({"outcome": "confirmed",
					"notes": notes.as_ref().map(BoundedText::expose),
					"patch": patch.map(|p| json!({"patch_unified": p.patch_unified.expose(), "notes": p.notes.expose()}))}),
				Verdict::Dismissed { notes } => {
					json!({"outcome": "dismissed", "notes": notes.as_ref().map(BoundedText::expose)})
				},
				Verdict::Inconclusive { reason, terminal } => {
					json!({"outcome": "inconclusive", "reason": reason.expose(), "terminal": terminal})
				},
			};
			json!({"protocol_version": version, "verdict": verdict})
		},
		WorkerRequest::Lease => {
			let value = input.validate(LeaseRequestDecoder)?;
			let capabilities: &Vec<BoundedText<policy::LeaseCapabilityName, Worker>> =
				&value.capabilities;
			json!({"protocol_version": value.protocol_version,
				"capabilities": capabilities.iter().map(BoundedText::expose).collect::<Vec<_>>(),
				"wait_seconds": value.wait_seconds})
		},
	})
}
