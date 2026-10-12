//! Closed security-event schema and its concrete tracing emitter.
//!
//! An event contains only host SQL IDs, counts and closed decisions. It does
//! not prove authority or a policy decision; real admission owners emit after
//! making that decision. Requested targets are separate from resolved context.
//! Pure parsers, accounting helpers and fuzz seams must not emit.
//!
//! IdentityConflict, ArtifactPolicyViolation and FanOutLimit currently have no
//! runtime producer. Canary and citation integrations belong to their later S3
//! owners. Schema tests and direct emitter calls do not count as those producers.

use std::fmt;

#[cfg(doctest)]
mod contract;
#[cfg(doctest)]
mod labelled_contract;

/// IDs actually resolved or already held by the emitting host owner.
/// None means unavailable; a requested ID must not be substituted here.
// debug-ok: optional host integer identifiers only; no authority material.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EventContext {
	pub worker_id: Option<i64>,
	pub job_id: Option<i64>,
	pub repo_id: Option<i64>,
	pub campaign_id: Option<i64>,
}

/// A requested subject, which has not necessarily been found or authorized.
// debug-ok: closed target categories containing only integer IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedTarget {
	None,
	Job(i64),
	Repository(i64),
	Finding(i64),
}
impl RequestedTarget {
	const fn kind(self) -> &'static str {
		match self {
			Self::None => "none",
			Self::Job(_) => "job",
			Self::Repository(_) => "repository",
			Self::Finding(_) => "finding",
		}
	}
	const fn id(self) -> Option<i64> {
		match self {
			Self::None => None,
			Self::Job(id) | Self::Repository(id) | Self::Finding(id) => Some(id),
		}
	}
}

macro_rules! closed_vocabulary {
    ($(#[$attribute:meta])* $name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
        $(#[$attribute])*
        // debug-ok: this enum has only the explicitly listed unit variants.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name { $($variant),+ }
        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $label),+ }
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

closed_vocabulary! {
/// The real admission operation, never an RPC name or request URI.
Operation {
	Authenticate => "authenticate",
	RequireAdmin => "require_admin",
	RequireWorker => "require_worker",
	Heartbeat => "heartbeat",
	SubmitFindings => "submit_findings",
	SubmitLlmFinding => "submit_llm_finding",
	SubmitVerdict => "submit_verdict",
	CompleteJob => "complete_job",
	SearchFindings => "search_findings",
	ReadFinding => "read_finding",
	ModelRequest => "model_request",
	McpSubmitFinding => "mcp_submit_finding",
	McpSubmitVerdict => "mcp_submit_verdict",
	McpSubmitPatch => "mcp_submit_patch",
}
}

closed_vocabulary! {
/// Closed denial decisions; internal database/accounting failures are not denials.
CapabilityDenial {
	MissingCapability => "missing_capability",
	MalformedCapability => "malformed_capability",
	InactiveLease => "inactive_lease",
	JobMismatch => "job_mismatch",
	RepositoryMismatch => "repository_mismatch",
	UnsupportedJobKind => "unsupported_job_kind",
	MissingAssignedTarget => "missing_assigned_target",
	StrictEndpointRequired => "strict_endpoint_required",
	LeaseInvalidated => "lease_invalidated",
	RoleMismatch => "role_mismatch",
	Unauthenticated => "unauthenticated",
	ModelEndpoint => "model_endpoint",
	ProviderFetch => "provider_fetch",
	RemoteMcp => "remote_mcp",
	McpServers => "mcp_servers",
	UpstreamRedirect => "upstream_redirect",
	NoSubmissionJob => "no_submission_job",
	NoVerifyAuthority => "no_verify_authority",
	VerdictLocked => "verdict_locked",
	ConfirmationRequired => "confirmation_required",
	PatchAlreadySubmitted => "patch_already_submitted",
	JobQuarantined => "job_quarantined",
}
}

closed_vocabulary! {
/// Reserved artifact admission categories; persistence is not an admission producer.
ArtifactPolicy {
	SizeLimit => "size_limit",
	InvalidContent => "invalid_content",
}
}

closed_vocabulary! {
/// The broker that detected a canary or host-credential submission.
Broker {
	Model => "model",
	Mcp => "mcp",
}
}

closed_vocabulary! {
/// Category only: no canary value, credential prefix, hash or matching bytes.
SecretCategory {
	Canary => "canary",
	HostCredential => "host_credential",
}
}

closed_vocabulary! {
/// Closed citation failure; location is identified numerically, never by path or quote.
CitationFailure {
	MissingFile => "missing_file",
	NotRegular => "not_regular",
	RangeInvalid => "range_invalid",
	QuoteMismatch => "quote_mismatch",
}
}

closed_vocabulary! {
/// Distinct real resource ceilings, without conflating child-work fan-out.
BudgetResource {
	WorkerRequests => "worker_requests",
	WorkerBytes => "worker_bytes",
	WorkerLeases => "worker_leases",
	WorkerEntries => "worker_entries",
	RequestBodyBytes => "request_body_bytes",
	ModelRequests => "model_requests",
	ModelOutputBytes => "model_output_bytes",
	ModelTokens => "model_tokens",
	ModelConnections => "model_connections",
	CampaignJobs => "campaign_jobs",
}
}

/// A decision or detection at a real security boundary.
/// All nested types are closed over integers and unit enums.
// debug-ok: exhaustive scalar/closed-enum composition; no content-bearing fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEvent {
	CapabilityDenied {
		context: EventContext,
		operation: Operation,
		requested: RequestedTarget,
		reason: CapabilityDenial,
	},
	/// Dormant until the actual identity-admission caller is integrated.
	IdentityConflict {
		context: EventContext,
		submitted_finding_id: i64,
		canonical_finding_id: i64,
	},
	/// Dormant; proof persistence alone does not enforce artifact policy.
	ArtifactPolicyViolation {
		context: EventContext,
		reason: ArtifactPolicy,
		bytes: Option<u64>,
	},
	/// Dormant; scheduler capacity and connection limits are different controls.
	FanOutLimit {
		context: EventContext,
		attempted: u64,
		limit: u64,
	},
	CanaryHit {
		context: EventContext,
		broker: Broker,
		category: SecretCategory,
	},
	CitationMismatch {
		context: EventContext,
		location_index: u64,
		line_start: Option<u32>,
		line_end: Option<u32>,
		reason: CitationFailure,
	},
	BudgetExhausted {
		context: EventContext,
		resource: BudgetResource,
		used: Option<u64>,
		limit: Option<u64>,
	},
}
impl SecurityEvent {
	/// Stable structured variant label; independent of Debug formatting.
	pub const fn variant(self) -> &'static str {
		match self {
			Self::CapabilityDenied { .. } => "CapabilityDenied",
			Self::IdentityConflict { .. } => "IdentityConflict",
			Self::ArtifactPolicyViolation { .. } => "ArtifactPolicyViolation",
			Self::FanOutLimit { .. } => "FanOutLimit",
			Self::CanaryHit { .. } => "CanaryHit",
			Self::CitationMismatch { .. } => "CitationMismatch",
			Self::BudgetExhausted { .. } => "BudgetExhausted",
		}
	}
}
struct OptionalId(Option<i64>);
impl fmt::Display for OptionalId {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self.0 {
			Some(id) => write!(f, "{id}"),
			None => f.write_str("none"),
		}
	}
}
struct OptionalCount(Option<u64>);
impl fmt::Display for OptionalCount {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self.0 {
			Some(count) => write!(f, "{count}"),
			None => f.write_str("none"),
		}
	}
}
impl fmt::Display for EventContext {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"worker_id={} job_id={} repo_id={} campaign_id={}",
			OptionalId(self.worker_id),
			OptionalId(self.job_id),
			OptionalId(self.repo_id),
			OptionalId(self.campaign_id)
		)
	}
}
impl fmt::Display for SecurityEvent {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match *self {
            Self::CapabilityDenied {context,operation,requested,reason} =>
                write!(f,"CapabilityDenied operation={operation} reason={reason} requested_target={} requested_id={} {context}",requested.kind(),OptionalId(requested.id())),
            Self::IdentityConflict {context,submitted_finding_id,canonical_finding_id} =>
                write!(f,"IdentityConflict submitted_finding_id={submitted_finding_id} canonical_finding_id={canonical_finding_id} {context}"),
            Self::ArtifactPolicyViolation {context,reason,bytes} =>
                write!(f,"ArtifactPolicyViolation reason={reason} bytes={} {context}",OptionalCount(bytes)),
            Self::FanOutLimit {context,attempted,limit} =>
                write!(f,"FanOutLimit attempted={attempted} limit={limit} {context}"),
            Self::CanaryHit {context,broker,category} =>
                write!(f,"CanaryHit broker={broker} category={category} {context}"),
            Self::CitationMismatch {context,location_index,line_start,line_end,reason} =>
                write!(f,"CitationMismatch location_index={location_index} line_start={} line_end={} reason={reason} {context}",OptionalCount(line_start.map(u64::from)),OptionalCount(line_end.map(u64::from))),
            Self::BudgetExhausted {context,resource,used,limit} =>
                write!(f,"BudgetExhausted resource={resource} used={} limit={} {context}",OptionalCount(used),OptionalCount(limit)),
        }
	}
}

/// Emit one already-decided event at the fixed target loupe::security_event.
/// The API accepts no message, error, context map or formatting callback.
/// Absent facts are omitted by tracing rather than recorded as invented zeros.
pub fn emit(event: SecurityEvent) {
	let variant = event.variant();
	// This private macro only shares the fixed scalar context projection.
	// All event-specific fields remain explicit in the exhaustive match.
	macro_rules! record {
		($context:ident, $($field:ident = $value:expr),+ $(,)?) => {{
            tracing::warn!(target:"loupe::security_event",
                variant,
                worker_id=$context.worker_id,
                job_id=$context.job_id,
                repo_id=$context.repo_id,
                campaign_id=$context.campaign_id,
                $($field = $value),+
            );
		}};
    }
	match event {
		SecurityEvent::CapabilityDenied { context, operation, requested, reason } => record!(
			context,
			operation = operation.as_str(),
			requested_target = requested.kind(),
			requested_id = requested.id(),
			reason = reason.as_str()
		),
		SecurityEvent::IdentityConflict { context, submitted_finding_id, canonical_finding_id } => {
			record!(
				context,
				submitted_finding_id = submitted_finding_id,
				canonical_finding_id = canonical_finding_id
			)
		},
		SecurityEvent::ArtifactPolicyViolation { context, reason, bytes } => {
			record!(context, reason = reason.as_str(), bytes = bytes)
		},
		SecurityEvent::FanOutLimit { context, attempted, limit } => {
			record!(context, attempted = attempted, limit = limit)
		},
		SecurityEvent::CanaryHit { context, broker, category } => {
			record!(context, broker = broker.as_str(), category = category.as_str())
		},
		SecurityEvent::CitationMismatch {
			context,
			location_index,
			line_start,
			line_end,
			reason,
		} => record!(
			context,
			location_index = location_index,
			line_start = line_start.map(u64::from),
			line_end = line_end.map(u64::from),
			reason = reason.as_str()
		),
		SecurityEvent::BudgetExhausted { context, resource, used, limit } => {
			record!(context, resource = resource.as_str(), used = used, limit = limit)
		},
	}
}
