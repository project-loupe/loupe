//! SQL read ownership. Every ingress token labels an actual live SQLite value.
//! The named *_legacy projections are temporary I-stage exits, removed at M.

use loupe_core::source_migration::text::{Anchor, BoundedJson, BoundedText, Identifier, RepoPath};
use loupe_core::text::{self, policy, Error, Normalization, Rule, TextPolicy, Whitespace};
use loupe_provenance::{
	Agent, Db, Ingress, Mark, Untrusted, Unvalidated, Validate, ValidateCarrying,
};
use rusqlite::types::{Type, ValueRef};
use rusqlite::Row;

mod app;
mod refs;
mod reporting;
#[cfg(test)]
mod tests;
pub(crate) use app::{app_legacy, app_summary_legacy};
pub(crate) use refs::{inspected_refs_legacy, unit_refs_legacy};
pub(crate) use reporting::{reporting_legacy, scanner_document_legacy};

// debug-ok: fixed category, static field and closed policy rule only.
#[derive(Debug)]
pub(super) enum ReadError {
	Syntax,
	ExistingPolicy { field: &'static str, rule: Rule },
	Admission { field: &'static str, rule: Rule },
}
impl ReadError {
	fn existing(error: Error) -> Self {
		Self::ExistingPolicy { field: error.field, rule: error.rule }
	}
	fn admission(error: Error) -> Self {
		Self::Admission { field: error.field, rule: error.rule }
	}
	fn decoded(error: Error) -> Self {
		if error.rule == Rule::JsonSyntax {
			Self::Syntax
		} else {
			Self::admission(error)
		}
	}
}
impl std::fmt::Display for ReadError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Syntax => f.write_str("invalid stored value"),
			Self::ExistingPolicy { field, rule } => {
				write!(f, "invalid stored value: {field} {rule:?}")
			},
			Self::Admission { field, rule } => {
				write!(f, "stored text admission failed: {field} {rule:?}")
			},
		}
	}
}
impl std::error::Error for ReadError {}
fn sql_error(index: usize, error: ReadError) -> rusqlite::Error {
	rusqlite::Error::FromSqlConversionFailure(index, Type::Text, Box::new(error))
}
fn invalid() -> Error {
	Error::new("stored_value", Rule::JsonSyntax)
}

// No arbitrary-byte entry point: the borrowed bytes come directly from this
// SQL row, and remain live through each named validator below.
#[allow(unsafe_code)] // Only original SQL TEXT returned by this Row is labelled.
fn column<'a>(row: &'a Row<'_>, index: usize) -> rusqlite::Result<Untrusted<&'a [u8], Db>> {
	let ValueRef::Text(bytes) = row.get_ref(index)? else {
		return Err(sql_error(index, ReadError::Syntax));
	};
	// SAFETY: this is the original TEXT value returned by SQLite, not a
	// reserialized value or a caller-supplied string.
	Ok(Untrusted::new(bytes, unsafe { Ingress::<Db>::new() }))
}
#[allow(unsafe_code)] // Only original SQL BLOB returned by this Row is labelled.
fn blob<'a>(row: &'a Row<'_>, index: usize) -> rusqlite::Result<Untrusted<&'a [u8], Db>> {
	let ValueRef::Blob(bytes) = row.get_ref(index)? else {
		return Err(sql_error(index, ReadError::Syntax));
	};
	// SAFETY: original BLOB from this actual SQL read. Credential decoders
	// immediately guard their owned copy; SQLite's own memory is opaque.
	Ok(Untrusted::new(bytes, unsafe { Ingress::<Db>::new() }))
}
fn is_null(row: &Row<'_>, index: usize) -> rusqlite::Result<bool> {
	Ok(matches!(row.get_ref(index)?, ValueRef::Null))
}
fn utf8(bytes: &[u8]) -> Result<&str, Error> {
	std::str::from_utf8(bytes).map_err(|_| invalid())
}

macro_rules! exact_policy {
	($name:ident, $field:literal, $multi:literal) => {
		pub(super) struct $name;
		impl TextPolicy for $name {
			const FIELD: &'static str = $field;
			const MAX_BYTES: usize = policy::LEGACY_TEXT_MAX_BYTES;
			const MAX_CHARS: usize = policy::LEGACY_TEXT_MAX_BYTES;
			const MULTILINE: bool = $multi;
			const ALLOW_EMPTY: bool = true;
			const NORMALIZATION: Normalization = Normalization::Exact;
			const WHITESPACE: Whitespace = Whitespace::Significant;
			const ALLOW_CR: bool = $multi;
		}
	};
}
exact_policy!(RevisionText, "revision", false);
exact_policy!(AuditName, "audit_common_name", false);
exact_policy!(JobDiagnostic, "job_diagnostic", true);
exact_policy!(JobKindName, "job_kind", false);
exact_policy!(CheckpointOperation, "checkpoint_operation", false);
exact_policy!(InventoryRendering, "inventory_rendering", false);
exact_policy!(CountKey, "count_key", false);

// These macros generate only the listed concrete policy/source combinations.
// There is no source-selectable parser, output generic, or from-legacy mint.
macro_rules! db_field {
	($validator:ident, $read:ident, $kind:ident, $policy:ty, $category:ident) => {
		struct $validator;
		impl Validate<&[u8], Db> for $validator {
			type Output = $kind<$policy, Db>;
			type Error = Error;
			fn validate<'v>(
				self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Db>,
			) -> Result<Self::Output, Error> {
				#[cfg(test)]
				tests::observe("db", stringify!($validator), u.get());
				$kind::new(&mark, utf8(u.get())?)
			}
		}
		fn $read(row: &Row<'_>, index: usize) -> rusqlite::Result<$kind<$policy, Db>> {
			column(row, index)?
				.validate($validator)
				.map_err(|e| sql_error(index, ReadError::$category(e)))
		}
	};
}
macro_rules! agent_field {
	($stored:ident, $validator:ident, $read:ident, $kind:ident, $policy:ty, $category:ident) => {
		struct $stored;
		struct $validator;
		impl<'a> ValidateCarrying<&'a [u8], Db> for $stored {
			type Output = $kind<$policy, Agent>;
			type Error = Error;
			fn validate(self, u: Unvalidated<'_, &'a [u8], Db>) -> Result<Self::Output, Error> {
				#[cfg(test)]
				tests::observe("column", stringify!($validator), u.get());
				u.carry::<Agent>(0..u.get().len()).ok_or_else(invalid)?.validate($validator)
			}
		}
		impl Validate<&[u8], Agent> for $validator {
			type Output = $kind<$policy, Agent>;
			type Error = Error;
			fn validate<'v>(
				self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Agent>,
			) -> Result<Self::Output, Error> {
				#[cfg(test)]
				tests::observe("agent", stringify!($validator), u.get());
				$kind::new(&mark, utf8(u.get())?)
			}
		}
		fn $read(row: &Row<'_>, index: usize) -> rusqlite::Result<$kind<$policy, Agent>> {
			column(row, index)?
				.validate_carrying($stored)
				.map_err(|e| sql_error(index, ReadError::$category(e)))
		}
	};
}
macro_rules! string_exit {
	($exit:ident, $read:ident) => {
		pub(crate) fn $exit(row: &Row<'_>, index: usize) -> rusqlite::Result<String> {
			Ok($read(row, index)?.expose().to_owned())
		}
	};
}
macro_rules! typed_exit {
	($exit:ident, $read:ident, $kind:ident, $policy:ty) => {
		pub(crate) fn $exit(row: &Row<'_>, index: usize) -> rusqlite::Result<text::$kind<$policy>> {
			// Deliberate temporary source erasure after the concrete marked
			// validator. Reusing existing policy mechanics preserves canonical
			// bytes and normalization until M changes the public DAO types.
			text::$kind::new($read(row, index)?.expose())
				.map_err(|e| sql_error(index, ReadError::existing(e)))
		}
	};
}
macro_rules! optional_exit {
	($exit:ident, $required:ident, $output:ty) => {
		pub(crate) fn $exit(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<$output>> {
			if is_null(row, index)? {
				Ok(None)
			} else {
				$required(row, index).map(Some)
			}
		}
	};
}

db_field!(StoredRevision, revision, BoundedText, RevisionText, admission);
string_exit!(revision_legacy, revision);
optional_exit!(optional_revision_legacy, revision_legacy, String);

db_field!(StoredAudit, audit, BoundedText, AuditName, admission);
string_exit!(audit_legacy, audit);
optional_exit!(optional_audit_legacy, audit_legacy, String);

db_field!(StoredDiagnostic, diagnostic, BoundedText, JobDiagnostic, admission);
string_exit!(diagnostic_legacy, diagnostic);
optional_exit!(optional_diagnostic_legacy, diagnostic_legacy, String);

db_field!(StoredWorkerName, worker_name, BoundedText, policy::WorkerName, admission);
string_exit!(worker_name_legacy, worker_name);

db_field!(StoredCloneUrl, clone_url, BoundedText, policy::CloneUrl, admission);
string_exit!(clone_url_legacy, clone_url);

db_field!(StoredRepoHost, repo_host, BoundedText, policy::RepoHost, admission);
string_exit!(repo_host_legacy, repo_host);

db_field!(StoredRepoOwner, repo_owner, BoundedText, policy::RepoOwner, admission);
string_exit!(repo_owner_legacy, repo_owner);

db_field!(StoredRepoName, repo_name, BoundedText, policy::RepoName, admission);
string_exit!(repo_name_legacy, repo_name);

db_field!(StoredBranch, branch, BoundedText, policy::GitBranch, admission);
string_exit!(branch_legacy, branch);
optional_exit!(optional_branch_legacy, branch_legacy, String);

db_field!(StoredOperation, operation, BoundedText, CheckpointOperation, admission);
string_exit!(operation_legacy, operation);

db_field!(StoredInventory, inventory, BoundedText, InventoryRendering, admission);
string_exit!(inventory_legacy, inventory);

db_field!(StoredCountKey, count_key, BoundedText, CountKey, admission);
string_exit!(count_key_legacy, count_key);

db_field!(StoredJobKind, job_kind_text, BoundedText, JobKindName, admission);
string_exit!(job_kind_text_legacy, job_kind_text);

agent_field!(StoredScanner, AgentScanner, scanner, BoundedText, policy::ScannerIdText, admission);
string_exit!(scanner_legacy, scanner);

agent_field!(
	StoredFindingTitle,
	AgentFindingTitle,
	finding_title,
	BoundedText,
	policy::FindingTitle,
	admission
);
string_exit!(finding_title_legacy, finding_title);

agent_field!(
	StoredDescription,
	AgentDescription,
	description,
	BoundedText,
	policy::FindingDescription,
	admission
);
string_exit!(description_legacy, description);

agent_field!(StoredCwe, AgentCwe, cwe, BoundedText, policy::CweText, admission);
string_exit!(cwe_legacy, cwe);
optional_exit!(optional_cwe_legacy, cwe_legacy, String);

agent_field!(StoredPatch, AgentPatch, patch, BoundedText, policy::PatchUnified, admission);
string_exit!(patch_legacy, patch);
optional_exit!(optional_patch_legacy, patch_legacy, String);

agent_field!(StoredPoc, AgentPoc, poc, BoundedText, policy::PocUnified, admission);
string_exit!(poc_legacy, poc);
optional_exit!(optional_poc_legacy, poc_legacy, String);

agent_field!(
	StoredFingerprint,
	AgentFingerprint,
	fingerprint,
	BoundedText,
	policy::FindingFingerprintText,
	admission
);
string_exit!(fingerprint_legacy, fingerprint);

agent_field!(
	StoredPatchNotes,
	AgentPatchNotes,
	patch_notes,
	BoundedText,
	policy::PatchNotes,
	admission
);
string_exit!(patch_notes_legacy, patch_notes);
optional_exit!(optional_patch_notes_legacy, patch_notes_legacy, String);

db_field!(StoredReason, reason, BoundedText, policy::Reason, existing);
typed_exit!(reason_legacy, reason, BoundedText, policy::Reason);
optional_exit!(optional_reason_legacy, reason_legacy, text::BoundedText<policy::Reason>);

db_field!(StoredReceiptTitle, receipt_title, BoundedText, policy::Title, existing);
typed_exit!(receipt_title_legacy, receipt_title, BoundedText, policy::Title);
optional_exit!(
	optional_receipt_title_legacy,
	receipt_title_legacy,
	text::BoundedText<policy::Title>
);

db_field!(StoredDbPayload, db_payload, BoundedJson, policy::Payload, existing);
typed_exit!(db_payload_legacy, db_payload, BoundedJson, policy::Payload);
optional_exit!(optional_db_payload_legacy, db_payload_legacy, text::BoundedJson<policy::Payload>);

db_field!(StoredClientKey, client_key, Identifier, policy::ClientKey, existing);
typed_exit!(client_key_legacy, client_key, Identifier, policy::ClientKey);

agent_field!(StoredTitle, AgentTitle, title, BoundedText, policy::Title, existing);
typed_exit!(title_legacy, title, BoundedText, policy::Title);

agent_field!(StoredObjective, AgentObjective, objective, BoundedText, policy::Objective, existing);
typed_exit!(objective_legacy, objective, BoundedText, policy::Objective);

agent_field!(StoredArgument, AgentArgument, argument, BoundedText, policy::Argument, existing);
typed_exit!(argument_legacy, argument, BoundedText, policy::Argument);
optional_exit!(optional_argument_legacy, argument_legacy, text::BoundedText<policy::Argument>);

agent_field!(
	StoredAgentPayload,
	AgentAgentPayload,
	agent_payload,
	BoundedJson,
	policy::Payload,
	existing
);
typed_exit!(agent_payload_legacy, agent_payload, BoundedJson, policy::Payload);
optional_exit!(
	optional_agent_payload_legacy,
	agent_payload_legacy,
	text::BoundedJson<policy::Payload>
);

agent_field!(StoredFamily, AgentFamily, family, Identifier, policy::Family, existing);
typed_exit!(family_legacy, family, Identifier, policy::Family);

agent_field!(StoredAnchor, AgentAnchor, anchor, Anchor, policy::AnchorText, existing);
typed_exit!(anchor_legacy, anchor, Anchor, policy::AnchorText);

agent_field!(StoredInstance, AgentInstance, instance, Anchor, policy::InstanceKey, existing);
typed_exit!(instance_legacy, instance, Anchor, policy::InstanceKey);
optional_exit!(optional_instance_legacy, instance_legacy, text::Anchor<policy::InstanceKey>);

pub(crate) fn job_kind_legacy(
	row: &Row<'_>, index: usize,
) -> rusqlite::Result<loupe_core::JobKind> {
	Ok(job_kind_text(row, index)?.expose().parse().expect("JobKind parsing is infallible"))
}

struct StoredPath;
struct AgentPath;
impl<'a> ValidateCarrying<&'a [u8], Db> for StoredPath {
	type Output = RepoPath<Agent>;
	type Error = Error;
	fn validate(self, u: Unvalidated<'_, &'a [u8], Db>) -> Result<Self::Output, Error> {
		#[cfg(test)]
		tests::observe("column", "AgentPath", u.get());
		u.carry::<Agent>(0..u.get().len()).ok_or_else(invalid)?.validate(AgentPath)
	}
}
impl Validate<&[u8], Agent> for AgentPath {
	type Output = RepoPath<Agent>;
	type Error = Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Agent>,
	) -> Result<Self::Output, Error> {
		#[cfg(test)]
		tests::observe("agent", "AgentPath", u.get());
		RepoPath::new(&mark, utf8(u.get())?)
	}
}
pub(crate) fn optional_finding_path_legacy(
	row: &Row<'_>, index: usize,
) -> rusqlite::Result<Option<String>> {
	if is_null(row, index)? {
		return Ok(None);
	}
	let path = column(row, index)?
		.validate_carrying(StoredPath)
		.map_err(|e| sql_error(index, ReadError::admission(e)))?;
	Ok(Some(path.expose().to_owned()))
}

struct StoredInventoryPath;
impl Validate<&[u8], Db> for StoredInventoryPath {
	type Output = RepoPath<Db>;
	type Error = Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Db>,
	) -> Result<Self::Output, Error> {
		RepoPath::new(&mark, utf8(u.get())?)
	}
}
pub(crate) fn inventory_path_legacy(
	row: &Row<'_>, index: usize, representable: bool,
) -> rusqlite::Result<String> {
	if representable {
		Ok(column(row, index)?
			.validate(StoredInventoryPath)
			.map_err(|e| sql_error(index, ReadError::existing(e)))?
			.expose()
			.to_owned())
	} else {
		// Display aliases for invalid Git bytes retain their visible status.
		// They must not be reinterpreted as a representable RepoPath.
		inventory_legacy(row, index)
	}
}
