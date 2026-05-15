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
	pub verification_enabled: bool,
	/// Tri-state per-repo override of the human-in-the-loop approval
	/// gate. `None` → fall back to the server-level default
	/// (`require_approval_default`); `Some(true)`/`Some(false)` →
	/// pin the value for this repo regardless of the server default.
	pub require_approval: Option<bool>,
	pub last_scanned_sha: Option<String>,
	pub last_scanned_at: Option<i64>,
	pub created_at: i64,
	pub disabled_at: Option<i64>,
}

impl RepoRow {
	/// Resolve the effective `require_approval` for this repo. Per-repo
	/// override wins; falls through to the server default otherwise.
	pub fn effective_require_approval(&self, server_default: bool) -> bool {
		self.require_approval.unwrap_or(server_default)
	}
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
	pub verification_enabled: bool,
	/// `None` lets the server default decide; `Some(_)` pins the per-repo
	/// override on insert.
	pub require_approval: Option<bool>,
}

pub fn insert(conn: &Connection, new: &NewRepo, now: i64) -> rusqlite::Result<i64> {
	conn.execute(
		"INSERT INTO registered_repos
		   (clone_url, host, owner, repo, default_branch, scan_interval_seconds,
		    scanner_config, reporting, verification_enabled, require_approval, created_at)
		 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
		params![
			new.clone_url,
			new.host,
			new.owner,
			new.repo,
			new.default_branch,
			new.scan_interval_seconds,
			serde_json::to_string(&new.scanner_config).unwrap_or_else(|_| "{}".into()),
			serde_json::to_string(&new.reporting).expect("reporting is always serialisable"),
			new.verification_enabled as i64,
			new.require_approval.map(|b| b as i64),
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

pub fn update_reporting(
	conn: &Connection, id: i64, reporting: &ReportingDestination,
) -> rusqlite::Result<bool> {
	let n = conn.execute(
		"UPDATE registered_repos SET reporting = ?1 WHERE id = ?2",
		params![serde_json::to_string(reporting).expect("reporting is always serialisable"), id,],
	)?;
	Ok(n > 0)
}

pub fn count_github_pat_references(conn: &Connection, secret_id: i64) -> rusqlite::Result<usize> {
	let mut stmt = conn.prepare("SELECT reporting FROM registered_repos")?;
	let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
	let mut count = 0usize;
	for row in rows {
		let reporting_text = row?;
		let reporting: ReportingDestination =
			serde_json::from_str(&reporting_text).map_err(|e| {
				rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, e.into())
			})?;
		if matches!(
			reporting,
			ReportingDestination::GithubIssue { pat_secret_id, .. } if pat_secret_id == secret_id
		) {
			count += 1;
		}
	}
	Ok(count)
}

/// Optional patches to apply to a registered repo. `None` means "leave
/// the existing value alone". Toggling `disabled` to `Some(true)` stamps
/// `disabled_at = now`; `Some(false)` clears it. `require_approval`
/// uses `Option<Option<bool>>`: outer `None` = leave alone, inner
/// `None` = clear back to "inherit server default", `Some(Some(b))` =
/// pin per-repo. Returns `Ok(true)` if a row matched, `Ok(false)` if
/// `id` is unknown.
#[derive(Debug, Default, Clone)]
pub struct RepoUpdate {
	pub disabled: Option<bool>,
	pub scan_interval_seconds: Option<i64>,
	pub verification_enabled: Option<bool>,
	pub require_approval: Option<Option<bool>>,
}

pub fn update(conn: &Connection, id: i64, patch: &RepoUpdate, now: i64) -> rusqlite::Result<bool> {
	if patch.disabled.is_none()
		&& patch.scan_interval_seconds.is_none()
		&& patch.verification_enabled.is_none()
		&& patch.require_approval.is_none()
	{
		return Ok(get(conn, id)?.is_some());
	}
	let mut sets: Vec<&str> = Vec::new();
	let mut binds: Vec<rusqlite::types::Value> = Vec::new();
	if let Some(d) = patch.disabled {
		if d {
			sets.push("disabled_at = ?");
			binds.push(now.into());
		} else {
			sets.push("disabled_at = NULL");
		}
	}
	if let Some(secs) = patch.scan_interval_seconds {
		sets.push("scan_interval_seconds = ?");
		binds.push(secs.into());
	}
	if let Some(v) = patch.verification_enabled {
		sets.push("verification_enabled = ?");
		binds.push((v as i64).into());
	}
	if let Some(ra) = patch.require_approval {
		match ra {
			None => sets.push("require_approval = NULL"),
			Some(b) => {
				sets.push("require_approval = ?");
				binds.push((b as i64).into());
			},
		}
	}
	binds.push(id.into());
	let sql = format!("UPDATE registered_repos SET {} WHERE id = ?", sets.join(", "),);
	let n = conn.execute(&sql, rusqlite::params_from_iter(binds.iter()))?;
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
       scanner_config, reporting, verification_enabled, require_approval,
       last_scanned_sha, last_scanned_at, created_at, disabled_at
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
		verification_enabled: row.get::<_, i64>(9)? != 0,
		require_approval: row.get::<_, Option<i64>>(10)?.map(|v| v != 0),
		last_scanned_sha: row.get(11)?,
		last_scanned_at: row.get(12)?,
		created_at: row.get(13)?,
		disabled_at: row.get(14)?,
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
			verification_enabled: false,
			require_approval: None,
		}
	}

	#[test]
	fn insert_list_and_delete() {
		let db = Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
		let secret_id = db
			.with_conn(|c| Ok(secrets::insert(c, SecretKind::GithubPat, "pat", b"ghp", 0)?))
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
			ReportingDestination::Email { .. } | ReportingDestination::Manual => {
				panic!("fixture builds a github_issue destination")
			},
		}

		assert!(db.with_conn(|c| Ok(delete(c, id)?)).unwrap());
		assert!(db.with_conn(|c| Ok(list(c)?)).unwrap().is_empty());
	}

	#[test]
	fn duplicate_clone_url_is_rejected() {
		let db = Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
		let sid = db
			.with_conn(|c| Ok(secrets::insert(c, SecretKind::GithubPat, "pat", b"ghp", 0)?))
			.unwrap();
		db.with_conn(|c| Ok(insert(c, &fake_repo(sid), 1)?)).unwrap();
		let dup = db.with_conn(|c| Ok(insert(c, &fake_repo(sid), 1).is_ok()));
		assert!(matches!(dup, Ok(false) | Err(_)));
	}

	#[test]
	fn delete_missing_returns_false() {
		let db = Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
		assert!(!db.with_conn(|c| Ok(delete(c, 9_999)?)).unwrap());
	}

	#[test]
	fn list_due_picks_unscanned_and_overdue_repos() {
		let db = Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
		let sid =
			db.with_conn(|c| Ok(secrets::insert(c, SecretKind::GithubPat, "p", b"x", 0)?)).unwrap();
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
			verification_enabled: false,
			require_approval: None,
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
	fn update_toggles_disabled_and_changes_interval() {
		let db = Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
		let sid =
			db.with_conn(|c| Ok(secrets::insert(c, SecretKind::GithubPat, "p", b"x", 0)?)).unwrap();
		let id = db.with_conn(|c| Ok(insert(c, &fake_repo(sid), 0)?)).unwrap();

		// Disable.
		let updated = db
			.with_conn(|c| {
				Ok(update(c, id, &RepoUpdate { disabled: Some(true), ..Default::default() }, 123)?)
			})
			.unwrap();
		assert!(updated);
		let row = db.with_conn(|c| Ok(get(c, id)?)).unwrap().unwrap();
		assert_eq!(row.disabled_at, Some(123));

		// Re-enable + change interval + flip verification.
		let updated = db
			.with_conn(|c| {
				Ok(update(
					c,
					id,
					&RepoUpdate {
						disabled: Some(false),
						scan_interval_seconds: Some(7200),
						verification_enabled: Some(true),
						require_approval: Some(Some(true)),
					},
					456,
				)?)
			})
			.unwrap();
		assert!(updated);
		let row = db.with_conn(|c| Ok(get(c, id)?)).unwrap().unwrap();
		assert_eq!(row.disabled_at, None);
		assert_eq!(row.scan_interval_seconds, Some(7200));
		assert!(row.verification_enabled);
		assert_eq!(row.require_approval, Some(true));

		// Clearing require_approval drops back to "inherit".
		db.with_conn(|c| {
			Ok(update(
				c,
				id,
				&RepoUpdate { require_approval: Some(None), ..Default::default() },
				789,
			)?)
		})
		.unwrap();
		let row = db.with_conn(|c| Ok(get(c, id)?)).unwrap().unwrap();
		assert_eq!(row.require_approval, None);

		// Empty patch on missing id returns false.
		let touched = db.with_conn(|c| Ok(update(c, 9_999, &RepoUpdate::default(), 0)?)).unwrap();
		assert!(!touched);
	}

	#[test]
	fn update_reporting_repoints_a_github_pat_secret() {
		let db = Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
		let old_sid = db
			.with_conn(|c| Ok(secrets::insert(c, SecretKind::GithubPat, "old", b"old", 0)?))
			.unwrap();
		let new_sid = db
			.with_conn(|c| Ok(secrets::insert(c, SecretKind::GithubPat, "new", b"new", 1)?))
			.unwrap();
		let id = db.with_conn(|c| Ok(insert(c, &fake_repo(old_sid), 0)?)).unwrap();

		db.with_conn(|c| {
			Ok(update_reporting(
				c,
				id,
				&ReportingDestination::GithubIssue {
					target_owner: "acme".into(),
					target_repo: "tracker".into(),
					pat_secret_id: new_sid,
				},
			)?)
		})
		.unwrap();

		let row = db.with_conn(|c| Ok(get(c, id)?)).unwrap().unwrap();
		match row.reporting {
			ReportingDestination::GithubIssue { pat_secret_id, .. } => {
				assert_eq!(pat_secret_id, new_sid)
			},
			ReportingDestination::Email { .. } | ReportingDestination::Manual => {
				panic!("fixture builds a github_issue destination")
			},
		}
		assert_eq!(db.with_conn(|c| Ok(count_github_pat_references(c, old_sid)?)).unwrap(), 0);
		assert_eq!(db.with_conn(|c| Ok(count_github_pat_references(c, new_sid)?)).unwrap(), 1);
	}

	#[test]
	fn count_github_pat_references_tracks_shared_secrets() {
		let db = Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
		let sid = db
			.with_conn(|c| Ok(secrets::insert(c, SecretKind::GithubPat, "shared", b"x", 0)?))
			.unwrap();
		let mut a = fake_repo(sid);
		a.clone_url = "https://github.com/acme/a.git".into();
		a.repo = "a".into();
		let mut b = fake_repo(sid);
		b.clone_url = "https://github.com/acme/b.git".into();
		b.repo = "b".into();
		db.with_conn(|c| Ok(insert(c, &a, 0)?)).unwrap();
		db.with_conn(|c| Ok(insert(c, &b, 0)?)).unwrap();

		assert_eq!(db.with_conn(|c| Ok(count_github_pat_references(c, sid)?)).unwrap(), 2);
	}

	#[test]
	fn list_due_skips_disabled_repos() {
		let db = Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
		let sid =
			db.with_conn(|c| Ok(secrets::insert(c, SecretKind::GithubPat, "p", b"x", 0)?)).unwrap();
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
