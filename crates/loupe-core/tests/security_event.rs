//! Closed event schema and emitter checks, independent of runtime producers.
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use loupe_core::security_event::*;
use serde_json::{json, Value};

fn context() -> EventContext {
	EventContext {
		worker_id: Some(i64::MIN),
		job_id: Some(i64::MAX),
		repo_id: Some(-1),
		campaign_id: None,
	}
}
fn cases() -> Vec<(SecurityEvent, &'static str, Value)> {
	let context = context();
	vec![
        (SecurityEvent::CapabilityDenied {context,operation:Operation::Heartbeat,
            requested:RequestedTarget::Job(0),reason:CapabilityDenial::MissingCapability},
            "CapabilityDenied operation=heartbeat reason=missing_capability requested_target=job requested_id=0 worker_id=-9223372036854775808 job_id=9223372036854775807 repo_id=-1 campaign_id=none",
            json!({"variant":"CapabilityDenied","operation":"heartbeat","reason":"missing_capability","requested_target":"job","requested_id":0})),
        (SecurityEvent::IdentityConflict {context,submitted_finding_id:i64::MIN,canonical_finding_id:i64::MAX},
            "IdentityConflict submitted_finding_id=-9223372036854775808 canonical_finding_id=9223372036854775807 worker_id=-9223372036854775808 job_id=9223372036854775807 repo_id=-1 campaign_id=none",
            json!({"variant":"IdentityConflict","submitted_finding_id":i64::MIN,"canonical_finding_id":i64::MAX})),
        (SecurityEvent::ArtifactPolicyViolation {context,reason:ArtifactPolicy::SizeLimit,bytes:Some(u64::MAX)},
            "ArtifactPolicyViolation reason=size_limit bytes=18446744073709551615 worker_id=-9223372036854775808 job_id=9223372036854775807 repo_id=-1 campaign_id=none",
            json!({"variant":"ArtifactPolicyViolation","reason":"size_limit","bytes":u64::MAX})),
        (SecurityEvent::FanOutLimit {context,attempted:u64::MAX,limit:0},
            "FanOutLimit attempted=18446744073709551615 limit=0 worker_id=-9223372036854775808 job_id=9223372036854775807 repo_id=-1 campaign_id=none",
            json!({"variant":"FanOutLimit","attempted":u64::MAX,"limit":0})),
        (SecurityEvent::CanaryHit {context,broker:Broker::Mcp,category:SecretCategory::HostCredential},
            "CanaryHit broker=mcp category=host_credential worker_id=-9223372036854775808 job_id=9223372036854775807 repo_id=-1 campaign_id=none",
            json!({"variant":"CanaryHit","broker":"mcp","category":"host_credential"})),
        (SecurityEvent::CitationMismatch {context,location_index:u64::MAX,line_start:Some(0),line_end:Some(u32::MAX),reason:CitationFailure::QuoteMismatch},
            "CitationMismatch location_index=18446744073709551615 line_start=0 line_end=4294967295 reason=quote_mismatch worker_id=-9223372036854775808 job_id=9223372036854775807 repo_id=-1 campaign_id=none",
            json!({"variant":"CitationMismatch","location_index":u64::MAX,"line_start":0,"line_end":u32::MAX,"reason":"quote_mismatch"})),
        (SecurityEvent::BudgetExhausted {context,resource:BudgetResource::ModelTokens,used:Some(u64::MAX),limit:Some(0)},
            "BudgetExhausted resource=model_tokens used=18446744073709551615 limit=0 worker_id=-9223372036854775808 job_id=9223372036854775807 repo_id=-1 campaign_id=none",
            json!({"variant":"BudgetExhausted","resource":"model_tokens","used":u64::MAX,"limit":0})),
    ]
}
fn id(_: i64) {}
fn count(_: u64) {}
fn optional_id(value: Option<i64>) {
	if let Some(value) = value {
		id(value)
	}
}
fn optional_count(value: Option<u64>) {
	if let Some(value) = value {
		count(value)
	}
}
fn optional_line(value: Option<u32>) {
	if let Some(value) = value {
		let _: u32 = value;
	}
}
fn allowed_context(context: EventContext) {
	let EventContext { worker_id, job_id, repo_id, campaign_id } = context;
	optional_id(worker_id);
	optional_id(job_id);
	optional_id(repo_id);
	optional_id(campaign_id);
}
fn allowed_requested(target: RequestedTarget) {
	match target {
		RequestedTarget::None => {},
		RequestedTarget::Job(value)
		| RequestedTarget::Repository(value)
		| RequestedTarget::Finding(value) => id(value),
	}
}

fn allowed_operation(value: Operation) {
	match value {
		Operation::Authenticate
		| Operation::RequireAdmin
		| Operation::RequireWorker
		| Operation::Heartbeat
		| Operation::SubmitFindings
		| Operation::SubmitLlmFinding
		| Operation::SubmitVerdict
		| Operation::CompleteJob
		| Operation::SearchFindings
		| Operation::ReadFinding
		| Operation::ModelRequest
		| Operation::McpSubmitFinding
		| Operation::McpSubmitVerdict
		| Operation::McpSubmitPatch => {},
	}
}
#[test]
fn operation_spellings_are_closed_and_exhaustive() {
	for (value, expected) in [
		(Operation::Authenticate, "authenticate"),
		(Operation::RequireAdmin, "require_admin"),
		(Operation::RequireWorker, "require_worker"),
		(Operation::Heartbeat, "heartbeat"),
		(Operation::SubmitFindings, "submit_findings"),
		(Operation::SubmitLlmFinding, "submit_llm_finding"),
		(Operation::SubmitVerdict, "submit_verdict"),
		(Operation::CompleteJob, "complete_job"),
		(Operation::SearchFindings, "search_findings"),
		(Operation::ReadFinding, "read_finding"),
		(Operation::ModelRequest, "model_request"),
		(Operation::McpSubmitFinding, "mcp_submit_finding"),
		(Operation::McpSubmitVerdict, "mcp_submit_verdict"),
		(Operation::McpSubmitPatch, "mcp_submit_patch"),
	] {
		allowed_operation(value);
		assert_eq!(value.as_str(), expected);
		assert_eq!(value.to_string(), expected);
	}
}

fn allowed_capability_denial(value: CapabilityDenial) {
	match value {
		CapabilityDenial::MissingCapability
		| CapabilityDenial::MalformedCapability
		| CapabilityDenial::InactiveLease
		| CapabilityDenial::JobMismatch
		| CapabilityDenial::RepositoryMismatch
		| CapabilityDenial::UnsupportedJobKind
		| CapabilityDenial::MissingAssignedTarget
		| CapabilityDenial::StrictEndpointRequired
		| CapabilityDenial::LeaseInvalidated
		| CapabilityDenial::RoleMismatch
		| CapabilityDenial::Unauthenticated
		| CapabilityDenial::ModelEndpoint
		| CapabilityDenial::ProviderFetch
		| CapabilityDenial::RemoteMcp
		| CapabilityDenial::McpServers
		| CapabilityDenial::UpstreamRedirect
		| CapabilityDenial::NoSubmissionJob
		| CapabilityDenial::NoVerifyAuthority
		| CapabilityDenial::VerdictLocked
		| CapabilityDenial::ConfirmationRequired
		| CapabilityDenial::PatchAlreadySubmitted
		| CapabilityDenial::JobQuarantined => {},
	}
}
#[test]
fn capability_denial_spellings_are_closed_and_exhaustive() {
	for (value, expected) in [
		(CapabilityDenial::MissingCapability, "missing_capability"),
		(CapabilityDenial::MalformedCapability, "malformed_capability"),
		(CapabilityDenial::InactiveLease, "inactive_lease"),
		(CapabilityDenial::JobMismatch, "job_mismatch"),
		(CapabilityDenial::RepositoryMismatch, "repository_mismatch"),
		(CapabilityDenial::UnsupportedJobKind, "unsupported_job_kind"),
		(CapabilityDenial::MissingAssignedTarget, "missing_assigned_target"),
		(CapabilityDenial::StrictEndpointRequired, "strict_endpoint_required"),
		(CapabilityDenial::LeaseInvalidated, "lease_invalidated"),
		(CapabilityDenial::RoleMismatch, "role_mismatch"),
		(CapabilityDenial::Unauthenticated, "unauthenticated"),
		(CapabilityDenial::ModelEndpoint, "model_endpoint"),
		(CapabilityDenial::ProviderFetch, "provider_fetch"),
		(CapabilityDenial::RemoteMcp, "remote_mcp"),
		(CapabilityDenial::McpServers, "mcp_servers"),
		(CapabilityDenial::UpstreamRedirect, "upstream_redirect"),
		(CapabilityDenial::NoSubmissionJob, "no_submission_job"),
		(CapabilityDenial::NoVerifyAuthority, "no_verify_authority"),
		(CapabilityDenial::VerdictLocked, "verdict_locked"),
		(CapabilityDenial::ConfirmationRequired, "confirmation_required"),
		(CapabilityDenial::PatchAlreadySubmitted, "patch_already_submitted"),
		(CapabilityDenial::JobQuarantined, "job_quarantined"),
	] {
		allowed_capability_denial(value);
		assert_eq!(value.as_str(), expected);
		assert_eq!(value.to_string(), expected);
	}
}

fn allowed_artifact_policy(value: ArtifactPolicy) {
	match value {
		ArtifactPolicy::SizeLimit | ArtifactPolicy::InvalidContent => {},
	}
}
#[test]
fn artifact_policy_spellings_are_closed_and_exhaustive() {
	for (value, expected) in [
		(ArtifactPolicy::SizeLimit, "size_limit"),
		(ArtifactPolicy::InvalidContent, "invalid_content"),
	] {
		allowed_artifact_policy(value);
		assert_eq!(value.as_str(), expected);
		assert_eq!(value.to_string(), expected);
	}
}

fn allowed_broker(value: Broker) {
	match value {
		Broker::Model | Broker::Mcp => {},
	}
}
#[test]
fn broker_spellings_are_closed_and_exhaustive() {
	for (value, expected) in [(Broker::Model, "model"), (Broker::Mcp, "mcp")] {
		allowed_broker(value);
		assert_eq!(value.as_str(), expected);
		assert_eq!(value.to_string(), expected);
	}
}

fn allowed_secret_category(value: SecretCategory) {
	match value {
		SecretCategory::Canary | SecretCategory::HostCredential => {},
	}
}
#[test]
fn secret_category_spellings_are_closed_and_exhaustive() {
	for (value, expected) in
		[(SecretCategory::Canary, "canary"), (SecretCategory::HostCredential, "host_credential")]
	{
		allowed_secret_category(value);
		assert_eq!(value.as_str(), expected);
		assert_eq!(value.to_string(), expected);
	}
}

fn allowed_citation_failure(value: CitationFailure) {
	match value {
		CitationFailure::MissingFile
		| CitationFailure::NotRegular
		| CitationFailure::RangeInvalid
		| CitationFailure::QuoteMismatch => {},
	}
}
#[test]
fn citation_failure_spellings_are_closed_and_exhaustive() {
	for (value, expected) in [
		(CitationFailure::MissingFile, "missing_file"),
		(CitationFailure::NotRegular, "not_regular"),
		(CitationFailure::RangeInvalid, "range_invalid"),
		(CitationFailure::QuoteMismatch, "quote_mismatch"),
	] {
		allowed_citation_failure(value);
		assert_eq!(value.as_str(), expected);
		assert_eq!(value.to_string(), expected);
	}
}

fn allowed_budget_resource(value: BudgetResource) {
	match value {
		BudgetResource::WorkerRequests
		| BudgetResource::WorkerBytes
		| BudgetResource::WorkerLeases
		| BudgetResource::WorkerEntries
		| BudgetResource::RequestBodyBytes
		| BudgetResource::ModelRequests
		| BudgetResource::ModelOutputBytes
		| BudgetResource::ModelTokens
		| BudgetResource::ModelConnections
		| BudgetResource::CampaignJobs => {},
		BudgetResource::ReportOutput => {},
	}
}
#[test]
fn budget_resource_spellings_are_closed_and_exhaustive() {
	for (value, expected) in [
		(BudgetResource::WorkerRequests, "worker_requests"),
		(BudgetResource::WorkerBytes, "worker_bytes"),
		(BudgetResource::WorkerLeases, "worker_leases"),
		(BudgetResource::WorkerEntries, "worker_entries"),
		(BudgetResource::RequestBodyBytes, "request_body_bytes"),
		(BudgetResource::ModelRequests, "model_requests"),
		(BudgetResource::ModelOutputBytes, "model_output_bytes"),
		(BudgetResource::ModelTokens, "model_tokens"),
		(BudgetResource::ModelConnections, "model_connections"),
		(BudgetResource::CampaignJobs, "campaign_jobs"),
		(BudgetResource::ReportOutput, "report_output"),
	] {
		allowed_budget_resource(value);
		assert_eq!(value.as_str(), expected);
		assert_eq!(value.to_string(), expected);
	}
}

fn allowed_event(event: SecurityEvent) {
	match event {
		SecurityEvent::CapabilityDenied { context, operation, requested, reason } => {
			allowed_context(context);
			allowed_operation(operation);
			allowed_requested(requested);
			allowed_capability_denial(reason);
		},
		SecurityEvent::IdentityConflict { context, submitted_finding_id, canonical_finding_id } => {
			allowed_context(context);
			id(submitted_finding_id);
			id(canonical_finding_id);
		},
		SecurityEvent::ArtifactPolicyViolation { context, reason, bytes } => {
			allowed_context(context);
			allowed_artifact_policy(reason);
			optional_count(bytes);
		},
		SecurityEvent::FanOutLimit { context, attempted, limit } => {
			allowed_context(context);
			count(attempted);
			count(limit);
		},
		SecurityEvent::CanaryHit { context, broker, category } => {
			allowed_context(context);
			allowed_broker(broker);
			allowed_secret_category(category);
		},
		SecurityEvent::CitationMismatch {
			context,
			location_index,
			line_start,
			line_end,
			reason,
		} => {
			allowed_context(context);
			count(location_index);
			optional_line(line_start);
			optional_line(line_end);
			allowed_citation_failure(reason);
		},
		SecurityEvent::BudgetExhausted { context, resource, used, limit } => {
			allowed_context(context);
			allowed_budget_resource(resource);
			optional_count(used);
			optional_count(limit);
		},
	}
}
#[test]
fn all_seven_variants_have_exact_closed_display_and_allowed_fields() {
	for (event, expected, _) in cases() {
		allowed_event(event);
		assert_eq!(event.to_string(), expected);
		assert!(!event.to_string().contains(['\r', '\n']));
	}
}
#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.0.lock().unwrap().extend_from_slice(bytes);
		Ok(bytes.len())
	}
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}
fn captured(events: &[SecurityEvent], json: bool) -> String {
	let capture = Capture(Arc::new(Mutex::new(Vec::new())));
	let writer = capture.clone();
	let subscriber = tracing_subscriber::fmt()
		.without_time()
		.with_ansi(false)
		.with_target(true)
		.with_writer(move || writer.clone());
	if json {
		tracing::subscriber::with_default(subscriber.json().finish(), || {
			for event in events {
				emit(*event);
			}
		});
	} else {
		tracing::subscriber::with_default(subscriber.finish(), || {
			for event in events {
				emit(*event);
			}
		});
	}
	let bytes = capture.0.lock().unwrap().clone();
	String::from_utf8(bytes).unwrap()
}
#[test]
fn concrete_emitter_records_real_structured_numbers_and_closed_fields() {
	let cases = cases();
	let events = cases.iter().map(|(event, _, _)| *event).collect::<Vec<_>>();
	let raw = captured(&events, true);
	let lines = raw.lines().collect::<Vec<_>>();
	assert_eq!(lines.len(), 7, "capture must contain all seven real emitter calls");
	for (line, (_, _, mut expected)) in lines.iter().zip(cases) {
		let record: Value = serde_json::from_str(line).unwrap();
		assert_eq!(record["target"], "loupe::security_event");
		assert_eq!(record["level"], "WARN");
		let object = expected.as_object_mut().unwrap();
		object.insert("worker_id".into(), json!(i64::MIN));
		object.insert("job_id".into(), json!(i64::MAX));
		object.insert("repo_id".into(), json!(-1));
		assert_eq!(
			record["fields"], expected,
			"unexpected/missing/schema-textified fields: {line}"
		);
		assert_eq!(record.as_object().unwrap().len(), 3, "no ad hoc context or message");
	}
	let text = captured(&events, false);
	assert_eq!(text.lines().count(), 7);
	for (line, event) in text.lines().zip(events) {
		assert!(line.contains("WARN loupe::security_event:"));
		assert!(line.contains(&format!("variant=\"{}\"", event.variant())));
		assert!(line.contains("worker_id=-9223372036854775808"));
		assert!(line.contains("job_id=9223372036854775807"));
		assert!(
			!line.contains("campaign_id="),
			"unknown ids must remain absent in structured logs"
		);
	}
}
#[test]
fn requested_ids_are_separate_and_missing_context_is_not_invented() {
	let mut events = Vec::new();
	for requested in [
		RequestedTarget::None,
		RequestedTarget::Job(i64::MIN),
		RequestedTarget::Repository(0),
		RequestedTarget::Finding(i64::MAX),
	] {
		allowed_requested(requested);
		events.push(SecurityEvent::CapabilityDenied {
			context: EventContext::default(),
			operation: Operation::Authenticate,
			requested,
			reason: CapabilityDenial::Unauthenticated,
		});
	}
	let raw = captured(&events, true);
	let records =
		raw.lines().map(|line| serde_json::from_str::<Value>(line).unwrap()).collect::<Vec<_>>();
	assert_eq!(records.len(), 4);
	for record in &records {
		for field in ["worker_id", "job_id", "repo_id", "campaign_id"] {
			assert!(record["fields"].get(field).is_none(), "unresolved context emitted");
		}
	}
	assert_eq!(records[0]["fields"]["requested_target"], "none");
	assert!(records[0]["fields"].get("requested_id").is_none());
	for (record, (kind, value)) in
		records[1..].iter().zip([("job", i64::MIN), ("repository", 0), ("finding", i64::MAX)])
	{
		assert_eq!(record["fields"]["requested_target"], kind);
		assert_eq!(record["fields"]["requested_id"], value);
	}
	let event = SecurityEvent::BudgetExhausted {
		context: EventContext::default(),
		resource: BudgetResource::WorkerEntries,
		used: None,
		limit: None,
	};
	assert_eq!(event.to_string(),"BudgetExhausted resource=worker_entries used=none limit=none worker_id=none job_id=none repo_id=none campaign_id=none");
	let record: Value = serde_json::from_str(captured(&[event], true).trim()).unwrap();
	assert_eq!(record["fields"], json!({"variant":"BudgetExhausted","resource":"worker_entries"}));
}

#[test]
fn every_context_id_and_optional_measurement_has_numeric_boundary_controls() {
	for value in [i64::MIN, -1, 0, i64::MAX] {
		let context = EventContext {
			worker_id: Some(value),
			job_id: Some(value),
			repo_id: Some(value),
			campaign_id: Some(value),
		};
		let event = SecurityEvent::BudgetExhausted {
			context,
			resource: BudgetResource::CampaignJobs,
			used: Some(0),
			limit: Some(u64::MAX),
		};
		let record: Value = serde_json::from_str(captured(&[event], true).trim()).unwrap();
		for field in ["worker_id", "job_id", "repo_id", "campaign_id"] {
			assert_eq!(
				record["fields"][field],
				json!(value),
				"integer field {field} must not stringify"
			);
		}
		assert!(event.to_string().ends_with(&format!("campaign_id={value}")));
		assert_eq!(record["fields"]["used"], json!(0));
		assert_eq!(record["fields"]["limit"], json!(u64::MAX));
	}
	let events = [
		SecurityEvent::ArtifactPolicyViolation {
			context: EventContext::default(),
			reason: ArtifactPolicy::InvalidContent,
			bytes: None,
		},
		SecurityEvent::CitationMismatch {
			context: EventContext::default(),
			location_index: 0,
			line_start: None,
			line_end: None,
			reason: CitationFailure::RangeInvalid,
		},
	];
	let raw = captured(&events, true);
	let records =
		raw.lines().map(|line| serde_json::from_str::<Value>(line).unwrap()).collect::<Vec<_>>();
	assert_eq!(records.len(), 2);
	assert_eq!(
		records[0]["fields"],
		json!({"variant":"ArtifactPolicyViolation","reason":"invalid_content"})
	);
	assert_eq!(
		records[1]["fields"],
		json!({"variant":"CitationMismatch","reason":"range_invalid","location_index":0})
	);
	assert_eq!(events[0].to_string(),"ArtifactPolicyViolation reason=invalid_content bytes=none worker_id=none job_id=none repo_id=none campaign_id=none");
	assert_eq!(events[1].to_string(),"CitationMismatch location_index=0 line_start=none line_end=none reason=range_invalid worker_id=none job_id=none repo_id=none campaign_id=none");
}
