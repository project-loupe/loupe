//! DAO for the `secrets` table.
//!
//! Each row carries a `record_version`:
//!
//! * `record_version = 1` — plaintext. `nonce` is empty,
//!   `ciphertext` is the secret bytes verbatim. M1 used this; M2
//!   keeps it readable so an in-flight upgrade doesn't break.
//! * `record_version = 2` — chacha20poly1305 envelope. `nonce` is a
//!   random 12-byte nonce; `ciphertext` is `seal(plaintext)` with the
//!   `MasterKey` as the AEAD key. M2+ writers always use this.
//!
//! Readers branch on the version. v1 reads work without a key; v2
//! reads require the master key and error if missing.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};

const PLAINTEXT_VERSION: i64 = 1;
const ENCRYPTED_VERSION: i64 = 2;
const NONCE_BYTES: usize = 12;

/// AEAD master key. Held by the server in memory and constructed from
/// the `LOUPE_MASTER_KEY` env var (base64-encoded 32 bytes). Cheap to
/// clone (just an Arc internally is the caller's choice).
#[derive(Clone)]
pub struct MasterKey {
	bytes: [u8; 32],
}

impl MasterKey {
	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		Self { bytes }
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

/// Insert a plaintext secret. Returns the assigned id. Use only for
/// migration paths or when no master key is configured; new code should
/// prefer `insert_with_key` so secrets land on disk encrypted.
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

/// Insert an encrypted secret. Picks a fresh random 12-byte nonce per
/// row; the same `(label, kind, plaintext)` triple won't produce the
/// same ciphertext twice. Returns the assigned id.
pub fn insert_encrypted(
	conn: &Connection, kind: SecretKind, label: &str, plaintext: &[u8], key: &MasterKey, now: i64,
) -> rusqlite::Result<i64> {
	let cipher = ChaCha20Poly1305::new((&key.bytes).into());
	let mut nonce_bytes = [0u8; NONCE_BYTES];
	OsRng.fill_bytes(&mut nonce_bytes);
	let nonce = Nonce::from_slice(&nonce_bytes);
	let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
		rusqlite::Error::ToSqlConversionFailure(
			format!("chacha20poly1305 encrypt failed: {e}").into(),
		)
	})?;
	conn.execute(
		"INSERT INTO secrets (record_version, kind, label, nonce, ciphertext, created_at)
		 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
		params![ENCRYPTED_VERSION, kind.as_str(), label, nonce_bytes.as_slice(), ciphertext, now],
	)?;
	Ok(conn.last_insert_rowid())
}

/// Read a secret by id. Decrypts on the fly when the row is at
/// `record_version = 2`; v1 rows are returned verbatim. Errors if the
/// row is at a version this build doesn't understand or if a v2 row is
/// requested without a key.
pub fn read(
	conn: &Connection, id: i64, key: Option<&MasterKey>,
) -> rusqlite::Result<Option<Vec<u8>>> {
	let row = conn
		.query_row(
			"SELECT record_version, nonce, ciphertext FROM secrets WHERE id = ?1",
			params![id],
			|r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, Vec<u8>>(2)?)),
		)
		.optional()?;
	let Some((version, nonce_bytes, ciphertext)) = row else { return Ok(None) };
	match version {
		v if v == PLAINTEXT_VERSION => Ok(Some(ciphertext)),
		v if v == ENCRYPTED_VERSION => {
			let key = key.ok_or_else(|| {
				rusqlite::Error::FromSqlConversionFailure(
					0,
					rusqlite::types::Type::Blob,
					"encrypted secret read without master key".into(),
				)
			})?;
			if nonce_bytes.len() != NONCE_BYTES {
				return Err(rusqlite::Error::FromSqlConversionFailure(
					1,
					rusqlite::types::Type::Blob,
					format!("expected {NONCE_BYTES}-byte nonce, got {}", nonce_bytes.len()).into(),
				));
			}
			let cipher = ChaCha20Poly1305::new((&key.bytes).into());
			let nonce = Nonce::from_slice(&nonce_bytes);
			let plaintext = cipher.decrypt(nonce, ciphertext.as_slice()).map_err(|e| {
				rusqlite::Error::FromSqlConversionFailure(
					2,
					rusqlite::types::Type::Blob,
					format!("chacha20poly1305 decrypt failed: {e}").into(),
				)
			})?;
			Ok(Some(plaintext))
		},
		other => Err(rusqlite::Error::FromSqlConversionFailure(
			0,
			rusqlite::types::Type::Integer,
			format!("unsupported secret record_version {other}").into(),
		)),
	}
}

pub fn delete(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
	let n = conn.execute("DELETE FROM secrets WHERE id = ?1", params![id])?;
	Ok(n > 0)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::Db;

	fn fresh_key() -> MasterKey {
		MasterKey::from_bytes([0xAA; 32])
	}

	#[test]
	fn round_trips_plaintext() {
		let db = Db::open_in_memory().unwrap();
		let id = db
			.with_conn(|c| {
				Ok(insert_plaintext(c, SecretKind::GithubPat, "tracker-pat", b"ghp_xxx", 1)?)
			})
			.unwrap();
		let bytes = db.with_conn(|c| Ok(read(c, id, None)?)).unwrap().unwrap();
		assert_eq!(bytes, b"ghp_xxx");
	}

	#[test]
	fn round_trips_encrypted() {
		let db = Db::open_in_memory().unwrap();
		let key = fresh_key();
		let id = db
			.with_conn(|c| {
				Ok(insert_encrypted(c, SecretKind::GithubPat, "pat", b"ghp_secret", &key, 0)?)
			})
			.unwrap();
		let bytes = db.with_conn(|c| Ok(read(c, id, Some(&key))?)).unwrap().unwrap();
		assert_eq!(bytes, b"ghp_secret");
	}

	#[test]
	fn encrypted_ciphertext_does_not_equal_plaintext_in_db() {
		let db = Db::open_in_memory().unwrap();
		let key = fresh_key();
		db.with_conn(|c| {
			Ok(insert_encrypted(c, SecretKind::GithubPat, "pat", b"ghp_secret", &key, 0)?)
		})
		.unwrap();
		// Read the ciphertext column directly. It must not contain the
		// plaintext substring.
		let blob: Vec<u8> = db
			.with_conn(|c| {
				Ok(c.query_row("SELECT ciphertext FROM secrets LIMIT 1", [], |r| {
					r.get::<_, Vec<u8>>(0)
				})?)
			})
			.unwrap();
		assert!(
			!blob.windows(b"ghp_secret".len()).any(|w| w == b"ghp_secret"),
			"plaintext must not survive in ciphertext column"
		);
	}

	#[test]
	fn encrypted_read_without_key_errors() {
		let db = Db::open_in_memory().unwrap();
		let key = fresh_key();
		let id = db
			.with_conn(|c| Ok(insert_encrypted(c, SecretKind::GithubPat, "pat", b"x", &key, 0)?))
			.unwrap();
		let err = db
			.with_conn(|c| {
				let v = read(c, id, None)?;
				Ok(v)
			})
			.unwrap_err();
		assert!(err.to_string().contains("master key"), "got: {err}");
	}

	#[test]
	fn encrypted_read_with_wrong_key_errors() {
		let db = Db::open_in_memory().unwrap();
		let key = fresh_key();
		let id = db
			.with_conn(|c| Ok(insert_encrypted(c, SecretKind::GithubPat, "pat", b"x", &key, 0)?))
			.unwrap();
		let bad = MasterKey::from_bytes([0xBB; 32]);
		let err = db
			.with_conn(|c| {
				let v = read(c, id, Some(&bad))?;
				Ok(v)
			})
			.unwrap_err();
		assert!(err.to_string().contains("decrypt"), "got: {err}");
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
		let v = db.with_conn(|c| Ok(read(c, 999, None)?)).unwrap();
		assert!(v.is_none());
	}

	#[test]
	fn read_rejects_unsupported_version() {
		let db = Db::open_in_memory().unwrap();
		db.with_conn(|c| {
			c.execute(
				"INSERT INTO secrets (record_version, kind, label, nonce, ciphertext, created_at)
				 VALUES (99, 'github_pat', 'future', X'', X'', 0)",
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
				let v = read(c, id, None)?;
				Ok(v)
			})
			.unwrap_err();
		let msg = err.to_string();
		assert!(msg.contains("record_version") || msg.contains("unsupported"), "got: {msg}");
	}
}
