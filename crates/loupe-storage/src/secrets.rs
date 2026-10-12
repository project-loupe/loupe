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

use loupe_provenance::{Secret, Zeroise};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};

const KEY_BYTES: usize = 32;

/// Database master key. The bytes go straight into SQLCipher's `PRAGMA
/// key = "x'...hex...'"` at connection-open time so the whole DB file
/// is sealed; this struct also doubles as a tiny "make me a fresh key"
/// helper used by `loupe-server init`.
///
/// Master keys cannot silently duplicate their owned bytes:
///
/// ```compile_fail,E0599
/// use loupe_storage::secrets::MasterKey;
/// let key = MasterKey::for_tests();
/// let duplicate = key.clone();
/// ```
pub struct MasterKey {
	bytes: Secret<[u8; KEY_BYTES]>,
}

impl MasterKey {
	pub fn from_bytes(mut bytes: [u8; KEY_BYTES]) -> Self {
		let key = Self { bytes: Secret::new(bytes) };
		bytes.zeroise();
		key
	}

	/// 32 fresh random bytes from the OS RNG. Used by
	/// `loupe-server init` when no `LOUPE_MASTER_KEY` was provided in
	/// the env.
	pub fn generate() -> Self {
		let mut bytes = [0u8; KEY_BYTES];
		OsRng.fill_bytes(&mut bytes);
		let key = Self::from_bytes(bytes);
		bytes.zeroise();
		key
	}

	/// Lower-case hex (64 chars), guarded until the init file/export sink.
	pub fn to_hex(&self) -> Secret<String> {
		let mut s = String::with_capacity(KEY_BYTES * 2);
		self.write_hex(&mut s);
		Secret::new(s)
	}

	/// SQLCipher's raw-key syntax, built without an intermediate hex copy.
	pub(crate) fn sqlcipher_key(&self) -> Secret<String> {
		let mut s = String::with_capacity(KEY_BYTES * 2 + 3);
		s.push_str("x'");
		self.write_hex(&mut s);
		s.push('\'');
		Secret::new(s)
	}

	fn write_hex(&self, output: &mut String) {
		const HEX: &[u8; 16] = b"0123456789abcdef";
		for byte in self.bytes.expose() {
			output.push(char::from(HEX[usize::from(byte >> 4)]));
			output.push(char::from(HEX[usize::from(byte & 15)]));
		}
	}

	/// Fixed-key helper for tests. Produces the same bytes every call
	/// so test fixtures don't have to thread randomness around. Lives
	/// outside `#[cfg(test)]` so integration tests in other crates
	/// (`loupe-server/tests/...`) can construct an in-memory DB
	/// without re-implementing the hex math.
	pub fn for_tests() -> Self {
		Self::from_bytes([0u8; KEY_BYTES])
	}
}

impl std::fmt::Debug for MasterKey {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("[redacted]")
	}
}

impl std::fmt::Display for MasterKey {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("[redacted]")
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
	GithubPat,
	/// The server-wide GitHub App credential; see `github_app`.
	GithubApp,
}

impl SecretKind {
	pub fn as_str(self) -> &'static str {
		match self {
			SecretKind::GithubPat => "github_pat",
			SecretKind::GithubApp => "github_app",
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
pub fn read(conn: &Connection, id: i64) -> rusqlite::Result<Option<Secret<Vec<u8>>>> {
	conn.query_row("SELECT value FROM secrets WHERE id = ?1", params![id], |r| {
		r.get::<_, Vec<u8>>(0).map(Secret::new)
	})
	.optional()
}

pub(crate) fn validate_stored_rows(conn: &Connection) -> crate::Result<()> {
	// app() expects its credential BLOB at column zero and guards every
	// owned allocation. Generic secrets stay opaque borrowed BLOBs.
	crate::migrations::admission::scan(conn, "secrets", "value,id,kind,label,created_at", |row| {
		if matches!(row.get_ref(2)?, rusqlite::types::ValueRef::Text(b"github_app"))
			&& matches!(row.get_ref(3)?, rusqlite::types::ValueRef::Text(b"server"))
		{
			crate::ingress::app(row)?;
		}
		Ok::<_, rusqlite::Error>(())
	})
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
	fn master_key_debug_uses_exact_redaction_contract() {
		let key = MasterKey::from_bytes([0xAB; 32]);
		assert_eq!(format!("{key:?}"), "[redacted]", "master-key Debug contract");
		assert_eq!(format!("{key:#?}"), "[redacted]");
	}

	#[test]
	fn master_key_display_uses_exact_redaction_contract() {
		let key = MasterKey::from_bytes([0xAB; 32]);
		assert_eq!(format!("{key}"), "[redacted]");
		assert_eq!(format!("{key:#}"), "[redacted]");
	}

	#[test]
	fn credential_secret_read_debug_is_redacted() {
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		let id = db
			.with_conn(|c| Ok(insert(c, SecretKind::GithubPat, "debug", b"fake_pat_sentinel", 1)?))
			.unwrap();
		let secret = db.with_conn(|c| Ok(read(c, id)?)).unwrap().unwrap();
		assert_eq!(format!("{secret:?}"), "[redacted]", "secret DAO read Debug must be redacted");
		assert_eq!(format!("{secret:#?}"), "[redacted]");
	}

	#[test]
	fn credential_master_key_hex_debug_is_redacted() {
		let key = MasterKey::from_bytes([0xAB; 32]);
		let hex = key.to_hex();
		assert_eq!(format!("{hex:?}"), "[redacted]", "master-key hex Debug must be redacted");
		assert_eq!(format!("{hex:#?}"), "[redacted]");
	}

	#[test]
	fn round_trips_a_secret() {
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		let id = db
			.with_conn(|c| Ok(insert(c, SecretKind::GithubPat, "tracker-pat", b"ghp_xxx", 1)?))
			.unwrap();
		let bytes = db.with_conn(|c| Ok(read(c, id)?)).unwrap().unwrap();
		assert_eq!(bytes.expose(), b"ghp_xxx");
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
		assert_ne!(a.bytes.expose(), b.bytes.expose(), "two generated keys must not collide");
	}

	#[test]
	fn to_hex_is_64_lowercase_chars() {
		let k = MasterKey::from_bytes([0xABu8; 32]);
		let hex = k.to_hex();
		assert_eq!(hex.expose().len(), 64);
		assert!(hex.expose().chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
		assert_eq!(&hex.expose()[..4], "abab");
	}
}
