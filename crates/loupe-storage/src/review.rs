//! Shared DAO vocabulary and non-authorizing SQL conversion helpers.
use std::str::FromStr;

use rusqlite::types::Type;
use rusqlite::Row;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entity {
	Campaign,
	Generation,
	Inventory,
	Unit,
	UnitResult,
	Lead,
	Job,
	Finding,
	Verification,
	Artifact,
	Blob,
	Execution,
	Proof,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conflict {
	ActiveCampaign,
	ActiveGeneration,
	CampaignState,
	CampaignSummary,
	CampaignPolicy,
	CampaignBudget,
	ActiveDrilldown,
	ActiveVerify,
	JobState,
	GenerationState,
	GenerationPredecessor,
	Coverage,
	InventoryPath,
	InventoryLimit,
	UnitKey,
	UnitState,
	Assignment,
	Corroboration,
	LeadState,
	Checkpoint,
	TerminalReceipt,
	FindingIdentity(i64),
	FindingDetails,
	AttemptDetails,
	ArtifactIdentity,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
	CampaignRoot,
	CampaignContinuation,
	CampaignGeneration,
	CampaignSummary,
	GenerationPredecessor,
	InventoryGeneration,
	CarriedUnit,
	UnitJob,
	ResultJob,
	ResultUnit,
	CorroboratedResult,
	CorroboratedExclusion,
	LeadUnit,
	LeadJob,
	ObservationJob,
	SupersededLead,
	DuplicateLead,
	DuplicateFinding,
	PromotedFinding,
	FindingLead,
	Finding,
	Verification,
	VerificationProof,
	JobGeneration,
	JobLead,
	JobFinding,
	JobContinuation,
	Assignment,
	ArtifactBlob,
	ArtifactJob,
	ExecutionJob,
	ExecutionArtifact,
	ProofFinding,
	ProofVerification,
	ProofArtifact,
	ProofExecution,
}

pub(crate) fn parsed<T: FromStr>(row: &Row<'_>, index: usize) -> rusqlite::Result<T>
where
	T::Err: std::error::Error + Send + Sync + 'static,
{
	row.get::<_, String>(index)?
		.parse()
		.map_err(|e| rusqlite::Error::FromSqlConversionFailure(index, Type::Text, Box::new(e)))
}
pub(crate) fn optional<T: FromStr>(row: &Row<'_>, index: usize) -> rusqlite::Result<Option<T>>
where
	T::Err: std::error::Error + Send + Sync + 'static,
{
	row.get::<_, Option<String>>(index)?
		.map(|s| {
			s.parse().map_err(|e| {
				rusqlite::Error::FromSqlConversionFailure(index, Type::Text, Box::new(e))
			})
		})
		.transpose()
}

/// A duplicate on a UNIQUE index or on a rowid-alias primary key; SQLite
/// reports the latter with the same message but a different extended code.
pub(crate) fn is_unique(error: &rusqlite::Error, columns: &str) -> bool {
	matches!(error, rusqlite::Error::SqliteFailure(code, Some(message))
		if matches!(code.extended_code, rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE | rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY)
		&& message == &format!("UNIQUE constraint failed: {columns}"))
}
pub(crate) fn classify(error: rusqlite::Error, columns: &str, conflict: Conflict) -> crate::Error {
	if is_unique(&error, columns) {
		crate::Error::Conflict(conflict)
	} else {
		error.into()
	}
}
pub(crate) fn changed(count: usize, conflict: Conflict) -> crate::Result<()> {
	if count == 1 {
		Ok(())
	} else {
		Err(crate::Error::Conflict(conflict))
	}
}

macro_rules! string_enum {
	($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
		#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum $name { $($variant),+ }
		impl $name { pub fn as_str(self) -> &'static str { match self { $(Self::$variant => $value),+ } } }
		impl std::str::FromStr for $name {
			type Err = loupe_core::text::Error;
			fn from_str(raw: &str) -> std::result::Result<Self, Self::Err> {
				match raw { $($value => Ok(Self::$variant),)+ _ => Err(loupe_core::text::Error::new(stringify!($name), loupe_core::text::Rule::Identifier)) }
			}
		}
	};
}
pub(crate) use string_enum;

macro_rules! standalone {
	($($name:ident ($($arg:ident : $ty:ty),* $(,)?) -> $result:ty;)+) => {
		/// Convenience entry points that own an IMMEDIATE transaction.
		pub mod standalone { use super::*; $(
			pub fn $name(conn: &mut rusqlite::Connection, $($arg: $ty),*) -> crate::Result<$result> {
				crate::transaction::immediate(conn, |tx| super::$name(tx, $($arg),*))
			}
		)+ }
	};
}
pub(crate) use standalone;
