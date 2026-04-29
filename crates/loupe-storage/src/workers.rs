//! DAO for the `workers` table.

use rusqlite::{params, Connection, OptionalExtension};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerKind {
	Worker,
	Admin,
}

impl WorkerKind {
	pub fn as_str(&self) -> &'static str {
		match self {
			WorkerKind::Worker => "worker",
			WorkerKind::Admin => "admin",
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerRow {
	pub id: i64,
	pub name: String,
	pub kind: WorkerKind,
	pub cert_fingerprint: Vec<u8>,
	pub created_at: i64,
	pub last_seen_at: Option<i64>,
	pub revoked_at: Option<i64>,
}

/// Insert a worker row. Returns the assigned id. Caller passes an
/// already-hashed fingerprint (see `loupe-tls::cert_fingerprint`); this
/// DAO never sees raw cert material.
pub fn insert(
	conn: &Connection, name: &str, kind: WorkerKind, cert_fingerprint: &[u8], now: i64,
) -> rusqlite::Result<i64> {
	conn.execute(
		"INSERT INTO workers (name, kind, cert_fingerprint, created_at)
		 VALUES (?1, ?2, ?3, ?4)",
		params![name, kind.as_str(), cert_fingerprint, now],
	)?;
	Ok(conn.last_insert_rowid())
}

/// Look up a worker by certificate fingerprint. Returns `None` for
/// unknown certs or revoked workers — the caller treats both as "deny".
pub fn find_active_by_fingerprint(
	conn: &Connection, cert_fingerprint: &[u8],
) -> rusqlite::Result<Option<WorkerRow>> {
	conn.query_row(
		"SELECT id, name, kind, cert_fingerprint, created_at, last_seen_at, revoked_at
		 FROM workers
		 WHERE cert_fingerprint = ?1 AND revoked_at IS NULL",
		params![cert_fingerprint],
		row_to_worker,
	)
	.optional()
}

pub fn revoke(conn: &Connection, id: i64, now: i64) -> rusqlite::Result<bool> {
	let n = conn.execute(
		"UPDATE workers SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
		params![now, id],
	)?;
	Ok(n > 0)
}

pub fn touch_last_seen(conn: &Connection, id: i64, now: i64) -> rusqlite::Result<()> {
	conn.execute("UPDATE workers SET last_seen_at = ?1 WHERE id = ?2", params![now, id])?;
	Ok(())
}

fn row_to_worker(row: &rusqlite::Row) -> rusqlite::Result<WorkerRow> {
	let kind_str: String = row.get(2)?;
	let kind = match kind_str.as_str() {
		"worker" => WorkerKind::Worker,
		"admin" => WorkerKind::Admin,
		other => {
			return Err(rusqlite::Error::FromSqlConversionFailure(
				2,
				rusqlite::types::Type::Text,
				format!("unknown worker kind: {other}").into(),
			))
		},
	};
	Ok(WorkerRow {
		id: row.get(0)?,
		name: row.get(1)?,
		kind,
		cert_fingerprint: row.get(3)?,
		created_at: row.get(4)?,
		last_seen_at: row.get(5)?,
		revoked_at: row.get(6)?,
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::Db;

	fn open() -> Db {
		Db::open_in_memory().unwrap()
	}

	#[test]
	fn insert_and_lookup_round_trip() {
		let db = open();
		let id = db
			.with_conn(|c| Ok(insert(c, "admin", WorkerKind::Admin, &[1u8; 32], 1_000)?))
			.unwrap();
		let row = db
			.with_conn(|c| Ok(find_active_by_fingerprint(c, &[1u8; 32])?))
			.unwrap()
			.expect("inserted worker should be found");
		assert_eq!(row.id, id);
		assert_eq!(row.name, "admin");
		assert_eq!(row.kind, WorkerKind::Admin);
		assert_eq!(row.cert_fingerprint, vec![1u8; 32]);
	}

	#[test]
	fn unknown_fingerprint_returns_none() {
		let db = open();
		let row = db.with_conn(|c| Ok(find_active_by_fingerprint(c, &[42u8; 32])?)).unwrap();
		assert!(row.is_none());
	}

	#[test]
	fn revoked_worker_no_longer_resolves() {
		let db = open();
		let id =
			db.with_conn(|c| Ok(insert(c, "w1", WorkerKind::Worker, &[2u8; 32], 1_000)?)).unwrap();
		let revoked = db.with_conn(|c| Ok(revoke(c, id, 2_000)?)).unwrap();
		assert!(revoked);
		let row = db.with_conn(|c| Ok(find_active_by_fingerprint(c, &[2u8; 32])?)).unwrap();
		assert!(row.is_none(), "revoked workers must not resolve");
	}

	#[test]
	fn touch_last_seen_updates_column() {
		let db = open();
		let id =
			db.with_conn(|c| Ok(insert(c, "w1", WorkerKind::Worker, &[3u8; 32], 1_000)?)).unwrap();
		db.with_conn(|c| Ok(touch_last_seen(c, id, 5_000)?)).unwrap();
		let row =
			db.with_conn(|c| Ok(find_active_by_fingerprint(c, &[3u8; 32])?)).unwrap().unwrap();
		assert_eq!(row.last_seen_at, Some(5_000));
	}

	#[test]
	fn duplicate_fingerprint_is_rejected() {
		let db = open();
		db.with_conn(|c| Ok(insert(c, "w1", WorkerKind::Worker, &[7u8; 32], 1_000)?)).unwrap();
		let result =
			db.with_conn(|c| Ok(insert(c, "w2", WorkerKind::Worker, &[7u8; 32], 1_000).is_ok()));
		match result {
			Ok(true) => panic!("UNIQUE constraint should have rejected dup fingerprint"),
			Ok(false) => {},
			Err(_) => {},
		}
	}
}
