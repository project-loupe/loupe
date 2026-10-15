//! Upgrade-only admission. Policies stay beside their production DAO readers;
//! this module owns streaming, closed diagnostics, and table coverage only.
use rusqlite::{Connection, Row};

use super::{MigrationFailure as Failure, MigrationReason as Reason, MigrationStage as Stage};
use crate::{Error, Result};

type Validator = fn(&Connection) -> Result<()>;
const TABLES: &[(&str, Validator)] = &[
	("registered_repos", crate::repos::validate_stored_rows),
	("workers", crate::workers::validate_stored_rows),
	("jobs", crate::jobs::validate_stored_rows),
	("findings", crate::findings::validate_stored_rows),
	("finding_verifications", crate::findings::validate_stored_verifications),
	("scan_history", crate::findings::validate_stored_history),
	("review_campaigns", crate::campaigns::validate_stored_rows),
	("review_generations", crate::generations::validate_stored_rows),
	("generation_inventory", crate::inventory::validate_stored_rows),
	("review_units", crate::review_units::validate_stored_rows),
	("review_unit_results", crate::review_unit_results::validate_stored_rows),
	("leads", crate::leads::validate_stored_rows),
	("lead_observations", crate::lead_observations::validate_stored_rows),
	("job_checkpoints", crate::checkpoints::validate_stored_rows),
	("job_terminal_receipts", crate::terminal_receipt::validate_stored_rows),
	("secrets", crate::secrets::validate_stored_rows),
	("finding_review_details", crate::finding_details::validate_stored_reviews),
	("verification_attempt_details", crate::finding_details::validate_stored_attempts),
	("proof_artifact_blobs", crate::proofs::validate_stored_blobs),
	("proof_artifacts", crate::proofs::validate_stored_artifacts),
	("staged_proof_artifacts", crate::proofs::validate_stored_staged),
	("proof_executions", crate::proofs::validate_stored_executions),
	("verification_proofs", crate::proofs::validate_stored_proofs),
];

// These tables carry no user documents; scalar storage and foreign keys are
// sufficient. Keeping their projections explicit also supplies safe names.
const STRUCTURAL: &[(&str, &str)] = &[
	("job_kinds", "kind,legacy"),
	("job_assigned_review_units", "job_id,review_unit_id,position,completed"),
	("verification_proof_artifacts", "repo_id,verification_proof_id,proof_artifact_id"),
	("verification_proof_executions", "repo_id,verification_proof_id,proof_execution_id"),
	("schema_meta", "id,version,applied_at"),
];

pub(crate) fn validate(conn: &Connection) -> Result<()> {
	for (_, validate) in TABLES {
		validate(conn)?;
	}
	for (table, columns) in STRUCTURAL {
		scan(conn, table, columns, |_| Ok::<_, rusqlite::Error>(()))?;
	}
	Ok(())
}

pub(super) fn known_table(name: &str) -> Option<&'static str> {
	TABLES
		.iter()
		.map(|(name, _)| *name)
		.chain(STRUCTURAL.iter().map(|(name, _)| *name))
		.find(|candidate| *candidate == name)
}

/// Unfiltered and bounded by one row, including inactive and unrelated rows.
/// All projection names are code-owned; errors never retain SQLite's strings.
pub(crate) fn scan<T, E: Into<Error>>(
	conn: &Connection, table: &'static str, columns: &'static str,
	mut decode: impl FnMut(&Row<'_>) -> std::result::Result<T, E>,
) -> Result<()> {
	let names: Vec<_> = columns.split(',').map(str::trim).collect();
	let map = |error| diagnostic(error, table, &names, None);
	let mut statement = conn
		.prepare(&format!("SELECT {columns},rowid FROM {table} ORDER BY rowid"))
		.map_err(|e| map(Error::Sqlite(e)))?;
	// SQLite affinity alone permits TEXT in INTEGER/BLOB columns. Cover the
	// scalar fields omitted by rich readers using the existing schema types.
	let mut info =
		conn.prepare(&format!("PRAGMA table_info({table})")).map_err(|e| map(e.into()))?;
	let definitions = info
		.query_map([], |r| {
			Ok((r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, bool>(3)?))
		})
		.map_err(|e| map(e.into()))?
		.collect::<rusqlite::Result<Vec<_>>>()
		.map_err(|e| map(e.into()))?;
	let mut rows = statement.query([]).map_err(|e| map(e.into()))?;
	while let Some(row) = rows.next().map_err(|e| map(e.into()))? {
		let id = row.get::<_, i64>(names.len()).map_err(|e| map(e.into()))?;
		for (index, name) in names.iter().enumerate() {
			if let Some((_, kind, required)) =
				definitions.iter().find(|(column, _, _)| column == name)
			{
				use rusqlite::types::ValueRef;
				let value = row
					.get_ref(index)
					.map_err(|e| diagnostic(e.into(), table, &names, Some(id)))?;
				let valid = match value {
					ValueRef::Null => !required,
					ValueRef::Integer(_) => kind == "INTEGER",
					ValueRef::Text(bytes) => kind == "TEXT" && std::str::from_utf8(bytes).is_ok(),
					ValueRef::Blob(_) => kind == "BLOB",
					ValueRef::Real(_) => false,
				};
				if !valid {
					return Err(Failure::new(Stage::Admission, Reason::SqlType)
						.at(table, name, Some(id))
						.into());
				}
			}
		}
		decode(row).map_err(|e| diagnostic(e.into(), table, &names, Some(id)))?;
	}
	Ok(())
}

fn diagnostic(
	error: Error, table: &'static str, columns: &[&'static str], rowid: Option<i64>,
) -> Error {
	let mut failure = Failure::new(Stage::Admission, Reason::Scalar);
	failure.table = Some(table);
	failure.rowid = rowid;
	match error {
		Error::Migration(mut inner) => {
			inner.rowid = rowid;
			return inner.into();
		},
		Error::Sqlite(error) => {
			use rusqlite::Error::*;
			let index = match &error {
				FromSqlConversionFailure(index, _, _)
				| InvalidColumnType(index, _, _)
				| IntegralValueOutOfRange(index, _) => Some(*index),
				_ => None,
			};
			failure.column = index.and_then(|i| columns.get(i).copied());
			if let FromSqlConversionFailure(_, _, cause) = &error
				&& let Some(reason) = cause.downcast_ref::<crate::ingress::ReadError>()
			{
				use crate::ingress::ReadError;
				match reason {
					ReadError::Syntax => {
						failure.reason = Reason::TextPolicy(loupe_core::text::Rule::JsonSyntax)
					},
					ReadError::ExistingPolicy { field, rule }
					| ReadError::Admission { field, rule } => {
						failure.field = Some(field);
						failure.reason = Reason::TextPolicy(*rule);
					},
					ReadError::Source => failure.reason = Reason::Source,
				}
			}
			failure.sqlite_code = error.sqlite_error().map(|e| e.extended_code);
		},
		Error::Validation(error) => {
			failure.field = Some(error.field);
			failure.reason = Reason::TextPolicy(error.rule);
		},
		_ => {},
	}
	failure.into()
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn every_application_table_has_an_upgrade_validator() {
		let mut conn = Connection::open_in_memory().unwrap();
		crate::migrations::apply_pending(&mut conn).unwrap();
		let names = conn
			.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
			.unwrap()
			.query_map([], |r| r.get::<_, String>(0))
			.unwrap()
			.collect::<rusqlite::Result<Vec<_>>>()
			.unwrap();
		let derived = [
			"findings_fts",
			"findings_fts_config",
			"findings_fts_data",
			"findings_fts_docsize",
			"findings_fts_idx",
		];
		for name in &names {
			assert!(
				known_table(name).is_some() || derived.contains(&name.as_str()),
				"unclassified table {name}"
			);
		}
		for (table, _) in TABLES {
			assert!(names.iter().any(|name| name == table), "missing table {table}");
		}
	}
}
