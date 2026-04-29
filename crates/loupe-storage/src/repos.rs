//! DAO for the `registered_repos` table.

use loupe_core::ReportingDestination;
use rusqlite::{params, Connection, OptionalExtension};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoRow {
	pub id: i64,
	pub clone_url: String,
	pub host: String,
	pub owner: String,
	pub repo: String,
	pub default_branch: Option<String>,
	pub scan_interval_seconds: Option<i64>,
	pub scanner_config: serde_json::Value,
	pub reporting: ReportingDestination,
	pub last_scanned_sha: Option<String>,
	pub last_scanned_at: Option<i64>,
	pub created_at: i64,
	pub disabled_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewRepo {
	pub clone_url: String,
	pub host: String,
	pub owner: String,
	pub repo: String,
	pub default_branch: Option<String>,
	pub scan_interval_seconds: Option<i64>,
	pub scanner_config: serde_json::Value,
	pub reporting: ReportingDestination,
}

pub fn insert(conn: &Connection, new: &NewRepo, now: i64) -> rusqlite::Result<i64> {
	conn.execute(
		"INSERT INTO registered_repos
		   (clone_url, host, owner, repo, default_branch, scan_interval_seconds,
		    scanner_config, reporting, created_at)
		 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
		params![
			new.clone_url,
			new.host,
			new.owner,
			new.repo,
			new.default_branch,
			new.scan_interval_seconds,
			serde_json::to_string(&new.scanner_config).unwrap_or_else(|_| "{}".into()),
			serde_json::to_string(&new.reporting).expect("reporting is always serialisable"),
			now,
		],
	)?;
	Ok(conn.last_insert_rowid())
}

pub fn list(conn: &Connection) -> rusqlite::Result<Vec<RepoRow>> {
	let mut stmt = conn.prepare(SELECT_REPO_COLUMNS)?;
	let rows = stmt.query_map([], row_to_repo)?.collect::<rusqlite::Result<Vec<_>>>()?;
	Ok(rows)
}

pub fn get(conn: &Connection, id: i64) -> rusqlite::Result<Option<RepoRow>> {
	let mut stmt = conn.prepare(&format!("{SELECT_REPO_COLUMNS} WHERE id = ?1"))?;
	stmt.query_row(params![id], row_to_repo).optional()
}

pub fn delete(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
	let n = conn.execute("DELETE FROM registered_repos WHERE id = ?1", params![id])?;
	Ok(n > 0)
}

/// Repos that have a scan interval set and whose next scan is due
/// (i.e. `last_scanned_at + scan_interval_seconds < now`, or
/// `last_scanned_at` is NULL meaning "never scanned"). Disabled repos
/// are skipped. Returns full rows so the caller can decide whether to
/// pass `since_sha` for incremental.
pub fn list_due_for_scan(conn: &Connection, now: i64) -> rusqlite::Result<Vec<RepoRow>> {
	let mut stmt = conn.prepare(&format!(
		"{SELECT_REPO_COLUMNS}
		 WHERE scan_interval_seconds IS NOT NULL
		   AND disabled_at IS NULL
		   AND (last_scanned_at IS NULL OR last_scanned_at + scan_interval_seconds < ?1)"
	))?;
	let rows = stmt.query_map(params![now], row_to_repo)?.collect::<rusqlite::Result<Vec<_>>>()?;
	Ok(rows)
}

const SELECT_REPO_COLUMNS: &str = r#"
SELECT id, clone_url, host, owner, repo, default_branch, scan_interval_seconds,
       scanner_config, reporting, last_scanned_sha, last_scanned_at, created_at, disabled_at
FROM registered_repos
"#;

fn row_to_repo(row: &rusqlite::Row) -> rusqlite::Result<RepoRow> {
	let scanner_config_text: String = row.get(7)?;
	let reporting_text: String = row.get(8)?;
	let scanner_config: serde_json::Value =
		serde_json::from_str(&scanner_config_text).unwrap_or(serde_json::Value::Null);
	let reporting: ReportingDestination = serde_json::from_str(&reporting_text).map_err(|e| {
		rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, e.into())
	})?;
	Ok(RepoRow {
		id: row.get(0)?,
		clone_url: row.get(1)?,
		host: row.get(2)?,
		owner: row.get(3)?,
		repo: row.get(4)?,
		default_branch: row.get(5)?,
		scan_interval_seconds: row.get(6)?,
		scanner_config,
		reporting,
		last_scanned_sha: row.get(9)?,
		last_scanned_at: row.get(10)?,
		created_at: row.get(11)?,
		disabled_at: row.get(12)?,
	})
}

#[cfg(test)]
mod tests {
	use loupe_core::ReportingDestination;

	use super::*;
	use crate::secrets::{self, SecretKind};
	use crate::Db;

	fn fake_repo(secret_id: i64) -> NewRepo {
		NewRepo {
			clone_url: "https://github.com/acme/widget.git".into(),
			host: "github.com".into(),
			owner: "acme".into(),
			repo: "widget".into(),
			default_branch: Some("main".into()),
			scan_interval_seconds: Some(3600),
			scanner_config: serde_json::json!({"regex": {"enabled": true}}),
			reporting: ReportingDestination::GithubIssue {
				target_owner: "acme".into(),
				target_repo: "tracker".into(),
				pat_secret_id: secret_id,
			},
		}
	}

	#[test]
	fn insert_list_and_delete() {
		let db = Db::open_in_memory().unwrap();
		let secret_id = db
			.with_conn(|c| {
				Ok(secrets::insert_plaintext(c, SecretKind::GithubPat, "pat", b"ghp", 0)?)
			})
			.unwrap();
		let id = db.with_conn(|c| Ok(insert(c, &fake_repo(secret_id), 100)?)).unwrap();

		let listed = db.with_conn(|c| Ok(list(c)?)).unwrap();
		assert_eq!(listed.len(), 1);
		assert_eq!(listed[0].id, id);
		assert_eq!(listed[0].clone_url, "https://github.com/acme/widget.git");

		let one = db.with_conn(|c| Ok(get(c, id)?)).unwrap().unwrap();
		assert_eq!(one.scan_interval_seconds, Some(3600));
		match one.reporting {
			ReportingDestination::GithubIssue { pat_secret_id, .. } => {
				assert_eq!(pat_secret_id, secret_id)
			},
		}

		assert!(db.with_conn(|c| Ok(delete(c, id)?)).unwrap());
		assert!(db.with_conn(|c| Ok(list(c)?)).unwrap().is_empty());
	}

	#[test]
	fn duplicate_clone_url_is_rejected() {
		let db = Db::open_in_memory().unwrap();
		let sid = db
			.with_conn(|c| {
				Ok(secrets::insert_plaintext(c, SecretKind::GithubPat, "pat", b"ghp", 0)?)
			})
			.unwrap();
		db.with_conn(|c| Ok(insert(c, &fake_repo(sid), 1)?)).unwrap();
		let dup = db.with_conn(|c| Ok(insert(c, &fake_repo(sid), 1).is_ok()));
		assert!(matches!(dup, Ok(false) | Err(_)));
	}

	#[test]
	fn delete_missing_returns_false() {
		let db = Db::open_in_memory().unwrap();
		assert!(!db.with_conn(|c| Ok(delete(c, 9_999)?)).unwrap());
	}

	#[test]
	fn list_due_picks_unscanned_and_overdue_repos() {
		let db = Db::open_in_memory().unwrap();
		let sid = db
			.with_conn(|c| Ok(secrets::insert_plaintext(c, SecretKind::GithubPat, "p", b"x", 0)?))
			.unwrap();
		// Repo A: never scanned, interval=60. Due immediately.
		let a = NewRepo {
			clone_url: "https://github.com/a/a.git".into(),
			host: "github.com".into(),
			owner: "a".into(),
			repo: "a".into(),
			default_branch: None,
			scan_interval_seconds: Some(60),
			scanner_config: serde_json::Value::Null,
			reporting: ReportingDestination::GithubIssue {
				target_owner: "x".into(),
				target_repo: "y".into(),
				pat_secret_id: sid,
			},
		};
		// Repo B: scanned at t=1000, interval=60. Due at t=1060.
		let b = NewRepo {
			clone_url: "https://github.com/a/b.git".into(),
			repo: "b".into(),
			..a.clone()
		};
		// Repo C: no interval — never picked up.
		let no_interval = NewRepo {
			clone_url: "https://github.com/a/c.git".into(),
			repo: "c".into(),
			scan_interval_seconds: None,
			..a.clone()
		};
		db.with_conn(|conn| Ok(insert(conn, &a, 0)?)).unwrap();
		let b_id = db.with_conn(|conn| Ok(insert(conn, &b, 0)?)).unwrap();
		db.with_conn(|conn| Ok(insert(conn, &no_interval, 0)?)).unwrap();
		// Stamp B's last_scanned_at via raw SQL.
		db.with_conn(|c| {
			c.execute(
				"UPDATE registered_repos SET last_scanned_at = 1000 WHERE id = ?1",
				params![b_id],
			)?;
			Ok(())
		})
		.unwrap();

		// At t=500: A is due (never scanned), B is not (1000+60>500), C never.
		let due = db.with_conn(|c| Ok(list_due_for_scan(c, 500)?)).unwrap();
		let names: Vec<&str> = due.iter().map(|r| r.repo.as_str()).collect();
		assert_eq!(names, vec!["a"]);

		// At t=2000: A and B both due, C still skipped.
		let due = db.with_conn(|c| Ok(list_due_for_scan(c, 2000)?)).unwrap();
		let mut names: Vec<&str> = due.iter().map(|r| r.repo.as_str()).collect();
		names.sort();
		assert_eq!(names, vec!["a", "b"]);
	}

	#[test]
	fn list_due_skips_disabled_repos() {
		let db = Db::open_in_memory().unwrap();
		let sid = db
			.with_conn(|c| Ok(secrets::insert_plaintext(c, SecretKind::GithubPat, "p", b"x", 0)?))
			.unwrap();
		let id = db.with_conn(|c| Ok(insert(c, &fake_repo(sid), 0)?)).unwrap();
		// Originally `fake_repo` has scan_interval=3600 set, so it'd
		// otherwise be due. Disable it and confirm it drops out.
		db.with_conn(|c| {
			c.execute("UPDATE registered_repos SET disabled_at = 1 WHERE id = ?1", params![id])?;
			Ok(())
		})
		.unwrap();
		let due = db.with_conn(|c| Ok(list_due_for_scan(c, 1_000_000)?)).unwrap();
		assert!(due.is_empty(), "disabled repo must not appear as due");
	}
}
