//! DAO for the server-wide GitHub App credential.
//!
//! One loupe-server deployment reports through at most one GitHub App,
//! so the credential lives in a single `secrets` row (`kind =
//! "github_app"`, `label = "server"`) rather than in a table of its own.
//! The value is a JSON blob holding the app id, its slug (for display),
//! and the private key PEM; SQLCipher seals the whole file, so the PEM
//! is stored as-is like a PAT would be.

use loupe_provenance::Secret;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::secrets::SecretKind;

const LABEL: &str = "server";

pub struct StoredGithubApp {
	pub app_id: u64,
	pub slug: String,
	pub private_key_pem: Secret<String>,
}

impl std::fmt::Debug for StoredGithubApp {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("StoredGithubApp")
			.field("app_id", &self.app_id)
			.field("slug", &self.slug)
			.field("private_key_pem", &self.private_key_pem)
			.finish()
	}
}

/// Metadata decoded without materializing the private PEM field.
#[derive(Deserialize)]
pub struct StoredGithubAppSummary {
	pub app_id: u64,
	pub slug: String,
}

#[derive(Serialize)]
struct StoredAppWrite<'a> {
	app_id: u64,
	slug: &'a str,
	private_key_pem: &'a str,
}

/// Store (or replace) the credential.
pub fn set(conn: &Connection, app: &StoredGithubApp, now: i64) -> rusqlite::Result<()> {
	let record = StoredAppWrite {
		app_id: app.app_id,
		slug: &app.slug,
		private_key_pem: app.private_key_pem.expose(),
	};
	let value = Secret::new(serde_json::to_vec(&record).map_err(|_| {
		rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(
			"could not encode stored GitHub App credential",
		)))
	})?);
	conn.execute(
		"INSERT INTO secrets (kind, label, value, created_at)
		 VALUES (?1, ?2, ?3, ?4)
		 ON CONFLICT(kind, label) DO UPDATE SET value = excluded.value,
		                                       created_at = excluded.created_at",
		params![SecretKind::GithubApp.as_str(), LABEL, value.expose(), now],
	)?;
	Ok(())
}

/// Read the credential. `Ok(None)` when no app has been configured.
pub fn get(conn: &Connection) -> rusqlite::Result<Option<StoredGithubApp>> {
	conn.query_row(
		"SELECT value FROM secrets WHERE kind = ?1 AND label = ?2",
		params![SecretKind::GithubApp.as_str(), LABEL],
		crate::ingress::app_legacy,
	)
	.optional()
}

/// Read display metadata without allocating a decoded PEM string. Full
/// credential existence/validity checks must continue to use get.
pub fn summary(conn: &Connection) -> rusqlite::Result<Option<StoredGithubAppSummary>> {
	conn.query_row(
		"SELECT value FROM secrets WHERE kind = ?1 AND label = ?2",
		params![SecretKind::GithubApp.as_str(), LABEL],
		crate::ingress::app_summary_legacy,
	)
	.optional()
}

/// Remove the credential. Returns whether one was stored.
pub fn clear(conn: &Connection) -> rusqlite::Result<bool> {
	let n = conn.execute(
		"DELETE FROM secrets WHERE kind = ?1 AND label = ?2",
		params![SecretKind::GithubApp.as_str(), LABEL],
	)?;
	Ok(n > 0)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::secrets::MasterKey;
	use crate::Db;

	#[test]
	fn credential_stored_app_debug_redacts_private_pem() {
		let app = app(42);
		for formatted in [format!("{app:?}"), format!("{app:#?}")] {
			assert!(
				!formatted.contains("BEGIN RSA PRIVATE KEY"),
				"stored App Debug must not expose private PEM"
			);
		}
	}

	#[test]
	fn credential_malformed_stored_app_errors_do_not_reflect_bytes() {
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		// A malformed record can put private bytes in the wrong JSON field.
		let bytes = br#"{"app_id":"FAKE_PRIVATE_RECORD_SENTINEL","slug":"app","private_key_pem":"fake pem"}"#;
		db.with_conn(|c| Ok(crate::secrets::insert(c, SecretKind::GithubApp, LABEL, bytes, 1)?))
			.unwrap();
		let error = db.with_conn(|c| Ok(get(c)?)).unwrap_err();
		for formatted in [format!("{error}"), format!("{error:#}"), format!("{error:?}")] {
			assert!(
				!formatted.contains("FAKE_PRIVATE_RECORD_SENTINEL"),
				"stored App decoding errors must not reflect private record bytes"
			);
		}
	}

	fn app(app_id: u64) -> StoredGithubApp {
		StoredGithubApp {
			app_id,
			slug: format!("loupe-{app_id}"),
			private_key_pem: Secret::new(
				"-----BEGIN RSA PRIVATE KEY-----\nxx\n-----END RSA PRIVATE KEY-----\n".into(),
			),
		}
	}

	#[test]
	fn get_is_none_until_set() {
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		assert!(db.with_conn(|c| Ok(get(c)?)).unwrap().is_none());
	}

	#[test]
	fn round_trips_and_overwrites() {
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		db.with_conn(|c| Ok(set(c, &app(1), 10)?)).unwrap();
		assert_stored_app(&db, &app(1));
		db.with_conn(|c| Ok(set(c, &app(2), 20)?)).unwrap();
		assert_stored_app(&db, &app(2));
		let rows: i64 = db
			.with_conn(|c| {
				Ok(c.query_row(
					"SELECT COUNT(*) FROM secrets WHERE kind = 'github_app'",
					[],
					|r| r.get(0),
				)?)
			})
			.unwrap();
		assert_eq!(rows, 1, "set must replace, not accumulate");
	}

	fn assert_stored_app(db: &Db, expected: &StoredGithubApp) {
		let actual = db.with_conn(|c| Ok(get(c)?)).unwrap().unwrap();
		assert_eq!(actual.app_id, expected.app_id);
		assert_eq!(actual.slug, expected.slug);
		assert_eq!(actual.private_key_pem.expose(), expected.private_key_pem.expose());
		let metadata = db.with_conn(|c| Ok(summary(c)?)).unwrap().unwrap();
		assert_eq!(metadata.app_id, expected.app_id);
		assert_eq!(metadata.slug, expected.slug);
	}

	#[test]
	fn clear_reports_whether_anything_was_stored() {
		let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
		assert!(!db.with_conn(|c| Ok(clear(c)?)).unwrap());
		db.with_conn(|c| Ok(set(c, &app(1), 10)?)).unwrap();
		assert!(db.with_conn(|c| Ok(clear(c)?)).unwrap());
		assert!(db.with_conn(|c| Ok(get(c)?)).unwrap().is_none());
	}
}
