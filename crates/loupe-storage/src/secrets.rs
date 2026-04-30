//! DAO for the `secrets` table.
//!
//! The whole database is sealed by SQLCipher under [`MasterKey`] — see
//! `Db::open` for where that PRAGMA gets applied. Secrets therefore
//! live as plaintext bytes inside an encrypted database file; this DAO
//! is a thin store/fetch layer with no envelope of its own.
//!
//! Earlier milestones used a per-row `chacha20poly1305` envelope on
//! the `ciphertext` column. That was removed when SQLCipher landed —
//! the whole-file ciphertext supersedes the per-column ciphertext for
//! the at-rest threat model, and keeping both was just doubled cost
//! with no extra coverage we cared about.

use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};

const KEY_BYTES: usize = 32;

/// Database master key. The bytes go straight into SQLCipher's `PRAGMA
/// key = "x'...hex...'"` at connection-open time so the whole DB file
/// is sealed; this struct also doubles as a tiny "make me a fresh key"
/// helper used by `loupe-server init`.
#[derive(Clone)]
pub struct MasterKey {
	bytes: [u8; KEY_BYTES],
}

impl MasterKey {
	pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
		Self { bytes }
	}

	/// 32 fresh random bytes from the OS RNG. Used by
	/// `loupe-server init` when no `LOUPE_MASTER_KEY` was provided in
	/// the env.
	pub fn generate() -> Self {
		let mut bytes = [0u8; KEY_BYTES];
		OsRng.fill_bytes(&mut bytes);
		Self { bytes }
	}

	/// Raw key bytes. Used by `Db::open` when constructing the
	/// `PRAGMA key` value; nothing else should call this.
	pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
		&self.bytes
	}

	/// Lower-case hex (64 chars) of the 32 raw bytes. Convenient
	/// shape for the SQLCipher raw-key form `PRAGMA key = "x'...'"`.
	pub fn to_hex(&self) -> String {
		let mut s = String::with_capacity(KEY_BYTES * 2);
		for b in &self.bytes {
			use std::fmt::Write;
			let _ = write!(s, "{b:02x}");
		}
		s
	}

	/// Fixed-key helper for tests. Produces the same bytes every call
	/// so test fixtures don't have to thread randomness around. Lives
	/// outside `#[cfg(test)]` so integration tests in other crates
	/// (`loupe-server/tests/...`) can construct an in-memory DB
	/// without re-implementing the hex math.
	pub fn for_tests() -> Self {
		Self { bytes: [0u8; KEY_BYTES] }
	}
}

impl std::fmt::Debug for MasterKey {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("MasterKey(redacted)")
	}
}

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

/// Insert a secret. Returns the assigned id. The value column is
/// stored as-is — SQLCipher seals the whole DB at the page level, so
/// per-row encryption would be redundant work.
pub fn insert(
	conn: &Connection, kind: SecretKind, label: &str, value: &[u8], now: i64,
) -> rusqlite::Result<i64> {
	conn.execute(
		"INSERT INTO secrets (kind, label, value, created_at)
		 VALUES (?1, ?2, ?3, ?4)",
		params![kind.as_str(), label, value, now],
	)?;
	Ok(conn.last_insert_rowid())
}

/// Read a secret by id. Returns `Ok(None)` if no such row.
pub fn read(conn: &Connection, id: i64) -> rusqlite::Result<Option<Vec<u8>>> {
	conn.query_row("SELECT value FROM secrets WHERE id = ?1", params![id], |r| {
		r.get::<_, Vec<u8>>(0)
	})
	.optional()
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
	fn round_trips_a_secret() {
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		let id = db
			.with_conn(|c| Ok(insert(c, SecretKind::GithubPat, "tracker-pat", b"ghp_xxx", 1)?))
			.unwrap();
		let bytes = db.with_conn(|c| Ok(read(c, id)?)).unwrap().unwrap();
		assert_eq!(bytes, b"ghp_xxx");
	}

	#[test]
	fn read_missing_returns_none() {
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		let v = db.with_conn(|c| Ok(read(c, 999)?)).unwrap();
		assert!(v.is_none());
	}

	#[test]
	fn duplicate_label_per_kind_is_rejected() {
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		db.with_conn(|c| Ok(insert(c, SecretKind::GithubPat, "tracker-pat", b"a", 1)?)).unwrap();
		let dup =
			db.with_conn(|c| Ok(insert(c, SecretKind::GithubPat, "tracker-pat", b"b", 1).is_ok()));
		assert!(matches!(dup, Ok(false) | Err(_)));
	}

	#[test]
	fn generate_yields_distinct_keys() {
		let a = MasterKey::generate();
		let b = MasterKey::generate();
		assert_ne!(a.bytes, b.bytes, "two generated keys must not collide");
	}

	#[test]
	fn to_hex_is_64_lowercase_chars() {
		let k = MasterKey::from_bytes([0xABu8; 32]);
		let hex = k.to_hex();
		assert_eq!(hex.len(), 64);
		assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
		assert_eq!(&hex[..4], "abab");
	}
}
