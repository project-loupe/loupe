//! Original bounded Sandbox record fixtures, without tool dispatch or reminting.
#![cfg_attr(test, allow(dead_code))]
use loupe_provenance::{Ingress, Untrusted};
use serde_json::json;

use super::*;

// debug-ok: Cfg-only synthetic observation; raw values support independent source and compatibility assertions.
#[derive(Debug)]
pub struct RequestObservation {
	pub id: Option<Value>,
	pub method: String,
	pub tool: String,
	pub arguments: Result<Value, String>,
}
// debug-ok: Cfg-only synthetic observation; raw values support independent source and compatibility assertions.
#[derive(Debug)]
pub enum RecordObservation {
	Blank { length: usize },
	Request { length: usize, request: RequestObservation, agent_spans: Vec<std::ops::Range<usize>> },
	Syntax { length: usize, error: String },
	Utf8 { length: usize },
	Framing,
}

fn argument_value(arguments: Arguments) -> Value {
	match arguments {
		Arguments::Query(args) => json!({"query":args.query.expose(),"limit":args.limit}),
		Arguments::Get(id) => json!({"id":id}),
		Arguments::Finding(args) => {
			json!({"severity":args.severity,"title":args.title.expose(),"file":args.file.expose(),"line_start":args.line_start,"line_end":args.line_end,"description":args.description.expose(),"poc_unified":args.poc_unified.expose(),"cwe":args.cwe.map(|s|s.expose().to_owned())})
		},
		Arguments::Poc(diff) => json!({"poc_unified":diff.expose()}),
		Arguments::ValidatePatch(diff) => json!({"patch_unified":diff.expose()}),
		Arguments::Patch(args) => {
			json!({"patch_unified":args.patch.patch_unified.expose(),"notes":args.patch.notes.expose()})
		},
		Arguments::Verdict(args) => match args.verdict {
			loupe_core::Verdict::Confirmed { notes, .. } => {
				json!({"verdict":"confirmed","notes":notes.map(|s|s.expose().to_owned())})
			},
			loupe_core::Verdict::Dismissed { notes } => {
				json!({"verdict":"dismissed","notes":notes.map(|s|s.expose().to_owned())})
			},
			loupe_core::Verdict::Inconclusive { reason, terminal } => {
				json!({"verdict":"inconclusive","notes":reason.expose(),"terminal":terminal})
			},
		},
		_ => json!({"survey": true}),
	}
}
fn request_value(request: DecodedRequest) -> RequestObservation {
	let method = match request.method {
		Method::Unknown(name) => name,
		known => known.log_label().to_owned(),
	};
	let tool = match request.call.name {
		ToolName::Unknown(name) => name,
		known => known.log_label().to_owned(),
	};
	RequestObservation {
		id: request.id.map(SandboxReplyId::into_response_id),
		method,
		tool,
		arguments: request.call.arguments.map(argument_value).map_err(|error| error.to_string()),
	}
}

#[allow(unsafe_code)]
pub async fn observe_records(
	original: &[u8], chunk: usize, limit: usize,
) -> Vec<RecordObservation> {
	let mut reader = tokio::io::BufReader::with_capacity(chunk.clamp(1, 8192), original);
	let mut records = Vec::new();
	loop {
		let record = match super::super::framing::next_record(&mut reader, limit).await {
			Ok(Some(record)) => record,
			Ok(None) => return records,
			Err(_) => {
				records.push(RecordObservation::Framing);
				return records;
			},
		};
		let length = record.len();
		let scope = crate::ingress_text::observe::Scope::begin();
		// SAFETY: cfg-only fixture is the original record from the actual bounded framer.
		let record = Untrusted::new(record, unsafe { Ingress::<Sandbox>::new() });
		let parsed = record.as_bytes().validate_carrying(McpRequestDecoder {
			protocol_version: super::super::LEGACY_LOUPE_MCP_PROTOCOL_VERSION,
			catalog: Catalog::Legacy,
		});
		let agent_spans = scope.finish();
		records.push(match parsed {
			Ok(None) => RecordObservation::Blank { length },
			Ok(Some(request)) => {
				RecordObservation::Request { length, request: request_value(request), agent_spans }
			},
			Err(RecordError::Utf8) => {
				records.push(RecordObservation::Utf8 { length });
				return records;
			},
			Err(error) => RecordObservation::Syntax { length, error: error.to_string() },
		});
	}
}

pub(crate) fn arguments_fixture(name: &str, args: &Value) -> Result<Arguments> {
	catalog_fixture(Catalog::Legacy, super::super::LEGACY_LOUPE_MCP_PROTOCOL_VERSION, name, args)
}

#[cfg(test)]
pub(crate) fn survey_arguments_fixture(name: &str, args: &Value) -> Result<Arguments> {
	catalog_fixture(Catalog::Survey, super::super::SURVEY_LOUPE_MCP_PROTOCOL_VERSION, name, args)
}

#[cfg(test)]
pub(crate) fn drilldown_arguments_fixture(name: &str, args: &Value) -> Result<Arguments> {
	catalog_fixture(
		Catalog::Drilldown,
		super::super::DRILLDOWN_LOUPE_MCP_PROTOCOL_VERSION,
		name,
		args,
	)
}

#[allow(unsafe_code)]
fn catalog_fixture(
	catalog: Catalog, protocol_version: u16, name: &str, args: &Value,
) -> Result<Arguments> {
	// Serialization constructs the fixture's original wire record. The production
	// decoder has not interpreted any part of it and receives no decoded Value.
	let original = serde_json::to_vec(
		&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}}),
	)?;
	// SAFETY: cfg-only original complete Sandbox record constructed above.
	let original = Untrusted::new(original, unsafe { Ingress::<Sandbox>::new() });
	let request = original
		.as_bytes()
		.validate_carrying(McpRequestDecoder { protocol_version, catalog })?
		.expect("fixture record");
	request.call.arguments
}

pub(crate) fn finding_fixture(
	workdir: &std::path::Path, args: &Value,
) -> Result<super::McpFindingSubmission> {
	let Arguments::Finding(args) = arguments_fixture("submit_finding", args)? else {
		anyhow::bail!("not finding")
	};
	args.into_submission(workdir)
}

// debug-ok: Cfg-only synthetic observation of one phase record; values are fuzz assertions only.
#[derive(Debug)]
pub struct PhaseObservation {
	/// The decoded tool label and, for accepted arguments, the exact request
	/// bytes the host would send (with placeholder host fields).
	pub decoded: Option<(String, Result<Vec<u8>, String>)>,
	pub agent_spans: Vec<std::ops::Range<usize>>,
}

/// One original record through the survey-catalog decoder.
pub fn observe_survey_record(record: &[u8]) -> PhaseObservation {
	observe_phase_record(
		record,
		Catalog::Survey,
		super::super::SURVEY_LOUPE_MCP_PROTOCOL_VERSION,
		survey_bytes,
	)
}

/// One original record through the drilldown-catalog decoder.
pub fn observe_drilldown_record(record: &[u8]) -> PhaseObservation {
	observe_phase_record(
		record,
		Catalog::Drilldown,
		super::super::DRILLDOWN_LOUPE_MCP_PROTOCOL_VERSION,
		drilldown_bytes,
	)
}

#[allow(unsafe_code)]
fn observe_phase_record(
	record: &[u8], catalog: Catalog, protocol_version: u16, bytes: fn(Arguments) -> Vec<u8>,
) -> PhaseObservation {
	let scope = crate::ingress_text::observe::Scope::begin();
	// SAFETY: cfg-only fixture is one complete original record.
	let original = Untrusted::new(record.to_vec(), unsafe { Ingress::<Sandbox>::new() });
	let parsed =
		original.as_bytes().validate_carrying(McpRequestDecoder { protocol_version, catalog });
	let agent_spans = scope.finish();
	let decoded = match parsed {
		Ok(Some(request)) => {
			let tool = match &request.call.name {
				ToolName::Unknown(_) => "unknown".to_owned(),
				known => known.log_label().to_owned(),
			};
			Some((tool, request.call.arguments.map(bytes).map_err(|e| format!("{e:#}"))))
		},
		_ => None,
	};
	PhaseObservation { decoded, agent_spans }
}

fn survey_bytes(arguments: Arguments) -> Vec<u8> {
	use loupe_proto::review_api::ReviewProtocol;
	let encoded = match arguments {
		Arguments::JobLimits => Ok(Vec::new()),
		Arguments::PublishProfile(profile) => {
			serde_json::to_vec(&loupe_proto::review_api::PublishProfileRequest {
				protocol_version: ReviewProtocol,
				profile,
			})
		},
		Arguments::ProposeUnit(request) => serde_json::to_vec(&*request),
		Arguments::Lead(args) => {
			let args = *args;
			let mut evidence = args.evidence;
			evidence.review_unit_id = args.review_unit_id.map(i64::from);
			evidence.assignment_epoch = args.review_unit_id.map(|_| 1);
			serde_json::to_vec(&loupe_proto::review_evidence::LeadCheckpointRequest {
				protocol_version: ReviewProtocol,
				client_lead_key: args.key,
				evidence,
			})
		},
		Arguments::UnitResult(args) => {
			serde_json::to_vec(&loupe_proto::review_evidence::UnitResultCheckpointRequest {
				protocol_version: ReviewProtocol,
				client_result_key: args.key,
				result: args.result,
			})
		},
		Arguments::Disposition(args) => {
			let args = *args;
			let request = loupe_proto::review_inventory::InventoryDispositionRequest {
				protocol_version: ReviewProtocol,
				client_inventory_disposition_key: args.key,
				source_path: args.path,
				expected_revision: 0,
				disposition: args.disposition,
				reason: args.reason,
				mappings: loupe_proto::review_lease::LeaseList::new(
					args.mapped_review_unit_ids
						.into_iter()
						.map(|review_unit_id| loupe_proto::review_inventory::UnitMapping {
							review_unit_id,
							assignment_epoch: 1,
						})
						.collect(),
				)
				.unwrap_or_else(|_| panic!("decoder admitted more than eight mappings")),
			};
			serde_json::to_vec(&request)
		},
		Arguments::Candidates(query) => {
			assert!(query.validate().is_ok(), "decoder admitted an invalid candidate query");
			Ok(query.query.expose().as_bytes().to_vec())
		},
		Arguments::Finalize(terminal) => {
			serde_json::to_vec(&loupe_proto::review_terminal::FinalizeSurveyRequest {
				protocol_version: ReviewProtocol,
				payload: *terminal,
			})
		},
		_ => panic!("survey catalog decoded a legacy tool"),
	};
	encoded.unwrap_or_else(|_| panic!("decoder admitted arguments that do not serialize"))
}

fn drilldown_bytes(arguments: Arguments) -> Vec<u8> {
	use loupe_proto::review_api::ReviewProtocol;
	let encoded = match arguments {
		Arguments::JobLimits | Arguments::Candidates(_) => return survey_bytes(arguments),
		Arguments::SiblingLead(args) => {
			assert!(args.review_unit_id.is_none(), "a sibling lead named a review unit");
			serde_json::to_vec(&loupe_proto::review_evidence::LeadCheckpointRequest {
				protocol_version: ReviewProtocol,
				client_lead_key: args.key,
				evidence: args.evidence,
			})
		},
		Arguments::FinalizeDrilldown(terminal) => {
			serde_json::to_vec(&loupe_proto::review_drilldown::FinalizeDrilldownRequest {
				protocol_version: ReviewProtocol,
				payload: *terminal,
			})
		},
		_ => panic!("drilldown catalog decoded another catalog's tool"),
	};
	encoded.unwrap_or_else(|_| panic!("decoder admitted arguments that do not serialize"))
}
