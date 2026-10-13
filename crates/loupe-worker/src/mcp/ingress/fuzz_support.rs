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
		let parsed = record.as_bytes().validate_carrying(McpRequestDecoder);
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

#[allow(unsafe_code)]
pub(crate) fn arguments_fixture(name: &str, args: &Value) -> Result<Arguments> {
	// Serialization constructs the fixture's original wire record. The production
	// decoder has not interpreted any part of it and receives no decoded Value.
	let original = serde_json::to_vec(
		&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}}),
	)?;
	// SAFETY: cfg-only original complete Sandbox record constructed above.
	let original = Untrusted::new(original, unsafe { Ingress::<Sandbox>::new() });
	let request =
		original.as_bytes().validate_carrying(McpRequestDecoder)?.expect("fixture record");
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
