//! DAO for the `secrets` table.
//!
//! Each row carries a `record_version` byte. `record_version = 1` means
//! "plaintext" — `nonce` is empty and `ciphertext` is the UTF-8 bytes
//! of the secret. M2 will introduce `record_version = 2` for envelope
//! encryption (chacha20poly1305) without requiring a schema migration:
//! the readers just branch on the version.

use rusqlite::{params, Connection, OptionalExtension};

const PLAINTEXT_VERSION: i64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
	GithubPat,
}

impl SecretKind {
	pub fn as_str(self) -> &'static str {
		match self {
			SecretKind::GithubPat => "github_pat",
		}
	}
}

/// Insert a plaintext secret. Returns the assigned id. M1-only — M2
/// callers will go through an `insert_encrypted` variant that does the
/// envelope dance, and this function will be deprecated for write paths.
pub fn insert_plaintext(
	conn: &Connection, kind: SecretKind, label: &str, plaintext: &[u8], now: i64,
) -> rusqlite::Result<i64> {
	conn.execute(
		"INSERT INTO secrets (record_version, kind, label, nonce, ciphertext, created_at)
		 VALUES (?1, ?2, ?3, X'', ?4, ?5)",
		params![PLAINTEXT_VERSION, kind.as_str(), label, plaintext, now],
	)?;
	Ok(conn.last_insert_rowid())
}

/// Read the secret by id. Returns `None` if missing. Errors if the row
/// is at a version this build doesn't understand — the safe stance, so
/// readers don't accidentally hand a still-encrypted blob to the
/// dispatcher.
pub fn read(conn: &Connection, id: i64) -> rusqlite::Result<Option<Vec<u8>>> {
	let row = conn
		.query_row(
			"SELECT record_version, ciphertext FROM secrets WHERE id = ?1",
			params![id],
			|r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
		)
		.optional()?;
	let Some((version, bytes)) = row else { return Ok(None) };
	if version != PLAINTEXT_VERSION {
		return Err(rusqlite::Error::FromSqlConversionFailure(
			0,
			rusqlite::types::Type::Integer,
			format!("unsupported secret record_version {version}").into(),
		));
	}
	Ok(Some(bytes))
}

pub fn delete(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
	let n = conn.execute("DELETE FROM secrets WHERE id = ?1", params![id])?;
	Ok(n > 0)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::Db;

	#[test]
	fn round_trips_plaintext() {
		let db = Db::open_in_memory().unwrap();
		let id = db
			.with_conn(|c| {
				Ok(insert_plaintext(c, SecretKind::GithubPat, "tracker-pat", b"ghp_xxx", 1)?)
			})
			.unwrap();
		let bytes = db.with_conn(|c| Ok(read(c, id)?)).unwrap().unwrap();
		assert_eq!(bytes, b"ghp_xxx");
	}

	#[test]
	fn duplicate_label_per_kind_is_rejected() {
		let db = Db::open_in_memory().unwrap();
		db.with_conn(|c| Ok(insert_plaintext(c, SecretKind::GithubPat, "tracker-pat", b"a", 1)?))
			.unwrap();
		let dup = db.with_conn(|c| {
			Ok(insert_plaintext(c, SecretKind::GithubPat, "tracker-pat", b"b", 1).is_ok())
		});
		assert!(matches!(dup, Ok(false) | Err(_)));
	}

	#[test]
	fn read_missing_returns_none() {
		let db = Db::open_in_memory().unwrap();
		let v = db.with_conn(|c| Ok(read(c, 999)?)).unwrap();
		assert!(v.is_none());
	}

	#[test]
	fn read_rejects_unsupported_version() {
		let db = Db::open_in_memory().unwrap();
		// Sneak in a row at version 2.
		db.with_conn(|c| {
			c.execute(
				"INSERT INTO secrets (record_version, kind, label, nonce, ciphertext, created_at)
				 VALUES (2, 'github_pat', 'future', X'', X'', 0)",
				[],
			)?;
			Ok(())
		})
		.unwrap();
		let id: i64 = db
			.with_conn(|c| {
				Ok(c.query_row("SELECT id FROM secrets WHERE label='future'", [], |r| {
					r.get::<_, i64>(0)
				})?)
			})
			.unwrap();
		let err = db
			.with_conn(|c| {
				let v = read(c, id)?;
				Ok(v)
			})
			.unwrap_err();
		let msg = err.to_string();
		assert!(msg.contains("record_version") || msg.contains("unsupported"), "got: {msg}");
	}
}
