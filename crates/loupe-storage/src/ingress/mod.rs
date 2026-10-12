//! SQL read ownership. Every ingress token labels an actual live SQLite value.
//! Named validators return source-bearing fields without a raw-text exit.

use loupe_core::text::{
	self, policy, Anchor, BoundedJson, BoundedText, Error, Identifier, Normalization, RepoPath,
	Rule, TextPolicy, Whitespace,
};
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
pub(crate) use app::{app, app_summary};
use policy::{AuditName, JobDiagnostic, JobKindName, RevisionText};
pub(crate) use refs::{inspected_refs, unit_refs};
pub(crate) use reporting::{reporting, scanner_document};

// debug-ok: fixed category, static field and closed policy rule only.
#[derive(Debug)]
pub(super) enum ReadError {
	Syntax,
	Source,
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
			Self::Source => f.write_str("invalid stored source"),
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
		pub struct $name;
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
exact_policy!(CheckpointOperation, "checkpoint_operation", false);
exact_policy!(InventoryRendering, "inventory_rendering", false);

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
		pub(crate) fn $read(row: &Row<'_>, index: usize) -> rusqlite::Result<$kind<$policy, Db>> {
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
		pub(crate) fn $read(
			row: &Row<'_>, index: usize,
		) -> rusqlite::Result<$kind<$policy, Agent>> {
			column(row, index)?
				.validate_carrying($stored)
				.map_err(|e| sql_error(index, ReadError::$category(e)))
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
optional_exit!(optional_revision, revision, BoundedText<RevisionText, Db>);

db_field!(StoredAudit, audit, BoundedText, AuditName, admission);
optional_exit!(optional_audit, audit, BoundedText<AuditName, Db>);

db_field!(StoredDiagnostic, diagnostic, BoundedText, JobDiagnostic, admission);
optional_exit!(optional_diagnostic, diagnostic, BoundedText<JobDiagnostic, Db>);

db_field!(StoredWorkerName, worker_name, BoundedText, policy::WorkerName, admission);

db_field!(StoredCloneUrl, clone_url, BoundedText, policy::CloneUrl, admission);

db_field!(StoredRepoHost, repo_host, BoundedText, policy::RepoHost, admission);

db_field!(StoredRepoOwner, repo_owner, BoundedText, policy::RepoOwner, admission);

db_field!(StoredRepoName, repo_name, BoundedText, policy::RepoName, admission);

db_field!(StoredBranch, branch, BoundedText, policy::GitBranch, admission);
optional_exit!(optional_branch, branch, BoundedText<policy::GitBranch, Db>);

db_field!(StoredOperation, operation, BoundedText, CheckpointOperation, admission);

db_field!(StoredInventory, inventory, BoundedText, InventoryRendering, admission);

db_field!(StoredJobKind, job_kind_text, BoundedText, JobKindName, admission);
db_field!(StoredCountJsonKey, count_json_key, Identifier, policy::JsonKey, existing);
db_field!(StoredCountJsonLeaf, count_json_leaf, BoundedText, policy::JsonLeaf, existing);

agent_field!(StoredScanner, AgentScanner, scanner, BoundedText, policy::ScannerIdText, admission);

agent_field!(
	StoredFindingTitle,
	AgentFindingTitle,
	finding_title,
	BoundedText,
	policy::FindingTitle,
	admission
);

agent_field!(
	StoredDescription,
	AgentDescription,
	description,
	BoundedText,
	policy::FindingDescription,
	admission
);

agent_field!(StoredCwe, AgentCwe, cwe, BoundedText, policy::CweText, admission);
optional_exit!(optional_cwe, cwe, BoundedText<policy::CweText, Agent>);

agent_field!(StoredPatch, AgentPatch, patch, BoundedText, policy::PatchUnified, admission);
optional_exit!(optional_patch, patch, BoundedText<policy::PatchUnified, Agent>);

agent_field!(StoredPoc, AgentPoc, poc, BoundedText, policy::PocUnified, admission);
optional_exit!(optional_poc, poc, BoundedText<policy::PocUnified, Agent>);

agent_field!(
	StoredFingerprint,
	AgentFingerprint,
	fingerprint,
	BoundedText,
	policy::FindingFingerprintText,
	admission
);

agent_field!(
	StoredPatchNotes,
	AgentPatchNotes,
	patch_notes,
	BoundedText,
	policy::PatchNotes,
	admission
);
optional_exit!(optional_patch_notes, patch_notes, BoundedText<policy::PatchNotes, Agent>);

db_field!(StoredReason, reason, BoundedText, policy::Reason, existing);
optional_exit!(optional_reason, reason, BoundedText<policy::Reason, Db>);

db_field!(StoredReceiptTitle, receipt_title, BoundedText, policy::Title, existing);
optional_exit!(
	optional_receipt_title,
	receipt_title,
	BoundedText<policy::Title, Db>
);

db_field!(StoredDbPayload, db_payload, BoundedJson, policy::Payload, existing);
optional_exit!(optional_db_payload, db_payload, BoundedJson<policy::Payload, Db>);

db_field!(StoredClientKey, client_key, Identifier, policy::ClientKey, existing);

agent_field!(StoredTitle, AgentTitle, title, BoundedText, policy::Title, existing);

agent_field!(StoredObjective, AgentObjective, objective, BoundedText, policy::Objective, existing);

agent_field!(StoredArgument, AgentArgument, argument, BoundedText, policy::Argument, existing);
optional_exit!(optional_argument, argument, BoundedText<policy::Argument, Agent>);

agent_field!(
	StoredAgentPayload,
	AgentAgentPayload,
	agent_payload,
	BoundedJson,
	policy::Payload,
	existing
);
optional_exit!(
	optional_agent_payload,
	agent_payload,
	BoundedJson<policy::Payload, Agent>
);

agent_field!(StoredFamily, AgentFamily, family, Identifier, policy::Family, existing);

agent_field!(StoredAnchor, AgentAnchor, anchor, Anchor, policy::AnchorText, existing);

agent_field!(StoredInstance, AgentInstance, instance, Anchor, policy::InstanceKey, existing);
optional_exit!(optional_instance, instance, Anchor<policy::InstanceKey, Agent>);

pub(crate) fn job_kind(row: &Row<'_>, index: usize) -> rusqlite::Result<loupe_core::JobKind<Db>> {
	Ok(loupe_core::JobKind::from_text(job_kind_text(row, index)?))
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
pub(crate) fn optional_finding_path(
	row: &Row<'_>, index: usize,
) -> rusqlite::Result<Option<RepoPath<Agent>>> {
	if is_null(row, index)? {
		return Ok(None);
	}
	let path = column(row, index)?
		.validate_carrying(StoredPath)
		.map_err(|e| sql_error(index, ReadError::admission(e)))?;
	Ok(Some(path))
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
pub(crate) fn inventory_path(
	row: &Row<'_>, index: usize, representable: bool,
) -> rusqlite::Result<crate::inventory::InventoryPath<Db>> {
	if representable {
		Ok(crate::inventory::InventoryPath::Representable(
			column(row, index)?
				.validate(StoredInventoryPath)
				.map_err(|e| sql_error(index, ReadError::existing(e)))?,
		))
	} else {
		// Display aliases for invalid Git bytes retain their visible status.
		// They must not be reinterpreted as a representable RepoPath.
		inventory(row, index).map(crate::inventory::InventoryPath::Unrepresentable)
	}
}

/// Only this exact historical classification permits the designated Db→Agent
/// field projections. It says nothing about authorship or authority.
pub(crate) fn require_agent_source(row: &Row<'_>, index: usize) -> rusqlite::Result<()> {
	match row.get_ref(index)? {
		ValueRef::Text(b"agent") => Ok(()),
		_ => Err(sql_error(index, ReadError::Source)),
	}
}

/// Generic write contracts record one of these source names. Admission does
/// not reconstruct a provenance marker from the name: content stays Db.
pub(crate) fn require_known_source(row: &Row<'_>, index: usize) -> rusqlite::Result<()> {
	match row.get_ref(index)? {
		ValueRef::Text(
			b"agent" | b"repo" | b"sandbox" | b"worker" | b"server" | b"operator" | b"provider"
			| b"reporter" | b"db" | b"config" | b"browser",
		) => Ok(()),
		_ => Err(sql_error(index, ReadError::Source)),
	}
}

db_field!(StoredOriginalName, original_name, BoundedText, policy::OriginalName, existing);
db_field!(StoredMediaType, media_type, BoundedText, policy::MediaType, existing);
db_field!(StoredLabel, label, Identifier, policy::Label, existing);
optional_exit!(optional_label,label,Identifier<policy::Label,Db>);
db_field!(StoredVerdictNotes, verdict_notes, BoundedText, policy::VerdictNotes, admission);
db_field!(StoredVerdictReason, verdict_reason, BoundedText, policy::VerdictReason, admission);

pub(crate) fn working_directory(row: &Row<'_>, index: usize) -> rusqlite::Result<()> {
	if matches!(row.get_ref(index)?, ValueRef::Text(b".")) {
		return Ok(());
	}
	inventory_path(row, index, true).map(|_| ())
}

pub(crate) fn missing_value(index: usize, field: &'static str) -> rusqlite::Error {
	sql_error(index, ReadError::ExistingPolicy { field, rule: Rule::Empty })
}

struct QualifiedCheckpointKey<'a>(&'a str);
impl Validate<&[u8], Db> for QualifiedCheckpointKey<'_> {
	type Output = ();
	type Error = Error;
	fn validate<'v>(self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Db>) -> Result<(), Error> {
		let (operation, key) = utf8(u.get())?
			.split_once(':')
			.ok_or_else(|| Error::new("checkpoint_client_key", Rule::Identifier))?;
		if operation != self.0 {
			return Err(Error::new("checkpoint_client_key", Rule::Identifier));
		}
		Identifier::<policy::ClientKey, Db>::new(&mark, key)?;
		Ok(())
	}
}
pub(crate) fn qualified_checkpoint_key(
	row: &Row<'_>, index: usize, operation: &str,
) -> rusqlite::Result<()> {
	column(row, index)?
		.validate(QualifiedCheckpointKey(operation))
		.map_err(|e| sql_error(index, ReadError::existing(e)))
}

#[cfg(test)]
mod source_metadata_tests;
#[cfg(fuzzing)]
pub(crate) use refs::fuzz_decode as fuzz_source_refs;
