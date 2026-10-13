//! Migration diagnostics contain identifiers and closed reasons, never row payloads.

use std::fmt;

// debug-ok: closed migration stages; no stored content or authority material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationStage {
	AcquireLock,
	ReadVersion,
	Sql,
	PreCheck,
	Seed,
	Tables,
	Copy,
	VerifyCopy,
	Replace,
	Indexes,
	Finalize,
	Admission,
	ForeignKeyCheck,
	IntegrityCheck,
	RestoreForeignKeys,
	WriteVersion,
	Commit,
}

// debug-ok: closed diagnostic reasons with no payload-bearing variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationReason {
	Database,
	InvalidVersion,
	NewerSchema,
	LeasedJobs,
	UnknownJobKind,
	CopyMismatch,
	DuplicateVerify,
	ForeignKeyViolation,
	IntegrityViolation,
	ForeignKeySetting,
	InvalidData,
}

/// Safe to log through Display, Debug, or an error source chain. SQLite's
/// messages can contain stored data or schema SQL and are deliberately discarded.
// debug-ok: code-owned static identifiers, numeric metadata, and closed enums only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationFailure {
	pub source_version: Option<u32>,
	pub target_version: u32,
	pub stage: MigrationStage,
	pub table: Option<&'static str>,
	pub column: Option<&'static str>,
	pub rowid: Option<i64>,
	pub reason: MigrationReason,
	pub sqlite_code: Option<i32>,
}

impl MigrationFailure {
	pub fn new(stage: MigrationStage, reason: MigrationReason) -> Self {
		Self {
			source_version: None,
			target_version: 0,
			stage,
			table: None,
			column: None,
			rowid: None,
			reason,
			sqlite_code: None,
		}
	}

	pub fn at(mut self, table: &'static str, column: &'static str, rowid: Option<i64>) -> Self {
		self.table = Some(table);
		self.column = Some(column);
		self.rowid = rowid;
		self
	}

	pub fn sqlite(stage: MigrationStage, error: rusqlite::Error) -> Self {
		let mut failure = Self::new(stage, MigrationReason::Database);
		failure.sqlite_code = error.sqlite_error().map(|code| code.extended_code);
		failure
	}

	pub(super) fn contextualize(mut self, source: Option<u32>, target: u32) -> Self {
		self.source_version = source;
		self.target_version = target;
		self
	}

	pub(super) fn finalizer(error: crate::Error) -> Self {
		match error {
			crate::Error::Migration(failure) => failure,
			crate::Error::Sqlite(error) => Self::sqlite(MigrationStage::Finalize, error),
			crate::Error::UnknownJobKinds(_) => {
				Self::new(MigrationStage::Finalize, MigrationReason::UnknownJobKind)
					.at("jobs", "kind", None)
			},
			_ => Self::new(MigrationStage::Finalize, MigrationReason::InvalidData),
		}
	}
}

impl fmt::Display for MigrationFailure {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "database upgrade from schema ")?;
		match self.source_version {
			Some(version) => write!(f, "{version}")?,
			None => write!(f, "unknown")?,
		}
		write!(f, " to {} failed at {:?}: {:?}", self.target_version, self.stage, self.reason)?;
		if let Some(table) = self.table {
			write!(f, "; table={table}")?;
		}
		if let Some(column) = self.column {
			write!(f, "; column={column}")?;
		}
		if let Some(rowid) = self.rowid {
			write!(f, "; rowid={rowid}")?;
		}
		if let Some(code) = self.sqlite_code {
			write!(f, "; sqlite_code={code}")?;
		}
		match self.reason {
			MigrationReason::NewerSchema => write!(
				f,
				"; this binary supports schema {}; use a newer binary",
				self.target_version
			),
			MigrationReason::LeasedJobs => {
				write!(f, "; wait for leased jobs to finish or cancel them before retrying")
			},
			MigrationReason::DuplicateVerify => {
				write!(f, "; inspect and cancel redundant queued verify jobs before retrying")
			},
			_ => Ok(()),
		}
	}
}

impl std::error::Error for MigrationFailure {}
