//! DAO for the `registered_repos` table.

use loupe_core::text::policy::*;
use loupe_core::text::BoundedText;
use loupe_core::{ReportingDestination, ScannerDocument};
use loupe_provenance::{Db, Source};
use rusqlite::{params, Connection, OptionalExtension};

use crate::scope::RepoScope;

/// Read only the repository selected by the issuer.
pub fn get(scope: &RepoScope<'_>) -> crate::Result<Option<RepoRow>> {
	Ok(get_raw(scope.conn, scope.repo_id)?)
}

/// Delete only the selected repository; callers cannot supply a replacement ID.
/// ```compile_fail,E0061
/// # fn foreign(scope: &loupe_storage::scope::RepoScope<'_>) {
/// loupe_storage::repos::delete(scope, 2);
/// # }
/// ```
pub fn delete(scope: &RepoScope<'_>) -> crate::Result<bool> {
	scope.require_operator()?;
	Ok(delete_raw(scope.conn, scope.repo_id)?)
}

pub fn update(scope: &RepoScope<'_>, patch: &RepoUpdate, now: i64) -> crate::Result<bool> {
	scope.require_operator()?;
	Ok(update_raw(scope.conn, scope.repo_id, patch, now)?)
}

/// Replace this repository's GitHub destination without accepting a secret ID.
pub fn set_github_reporting<S: Source>(
	scope: &RepoScope<'_>, target_owner: &BoundedText<RepoOwner, S>,
	target_repo: &BoundedText<RepoName, S>, pat: Option<&loupe_provenance::Secret<String>>,
	now: i64,
) -> crate::Result<crate::registry::ReportingWrite<bool>> {
	scope.require_operator()?;
	let Some(old) = get(scope)? else {
		return Ok(crate::registry::ReportingWrite::Done(false));
	};
	let previous = match old.reporting {
		ReportingDestination::GithubIssue { pat_secret_id, .. } => pat_secret_id,
		_ => None,
	};
	let secret_id = match pat {
		Some(pat) => Some(crate::secrets::insert(
			scope.conn,
			crate::secrets::SecretKind::GithubPat,
			&format!(
				"pat:{}:{}/{}:repo:{}:replaces:{}:at:{now}",
				old.host.expose(),
				target_owner.expose(),
				target_repo.expose(),
				scope.repo_id,
				previous.unwrap_or(0)
			),
			pat.expose().as_bytes(),
			now,
		)?),
		None if crate::github_app::get(scope.conn)?.is_none() => {
			return Ok(crate::registry::ReportingWrite::NoApp)
		},
		None => None,
	};
	let reporting = ReportingDestination::GithubIssue {
		target_owner: target_owner.clone(),
		target_repo: target_repo.clone(),
		pat_secret_id: secret_id,
	};
	let changed = update_reporting(scope.conn, scope.repo_id, &reporting)?;
	if let Some(previous) = previous
		&& count_github_pat_references(scope.conn, previous)? == 0
	{
		crate::secrets::delete(scope.conn, previous)?;
	}
	Ok(crate::registry::ReportingWrite::Done(changed))
}

// debug-ok: PAT rotation outcomes are closed variants without credential bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatRotation {
	Rotated,
	Missing,
	AppMode,
	OtherDestination,
}

pub fn rotate_github_pat(
	scope: &RepoScope<'_>, pat: &loupe_provenance::Secret<String>, now: i64,
) -> crate::Result<PatRotation> {
	scope.require_operator()?;
	let Some(old) = get(scope)? else {
		return Ok(PatRotation::Missing);
	};
	match old.reporting {
		ReportingDestination::GithubIssue { target_owner, target_repo, pat_secret_id: Some(_) } => {
			set_github_reporting(scope, &target_owner, &target_repo, Some(pat), now)?;
			Ok(PatRotation::Rotated)
		},
		ReportingDestination::GithubIssue { .. } => Ok(PatRotation::AppMode),
		_ => Ok(PatRotation::OtherDestination),
	}
}

// debug-ok: content members delegate to redacted typed owners; other members are numeric identifiers or closed states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoRow {
	pub id: i64,
	pub clone_url: BoundedText<CloneUrl, Db>,
	pub host: BoundedText<RepoHost, Db>,
	pub owner: BoundedText<RepoOwner, Db>,
	pub repo: BoundedText<RepoName, Db>,
	pub default_branch: Option<BoundedText<GitBranch, Db>>,
	pub scan_interval_seconds: Option<i64>,
	pub scanner_config: ScannerDocument<Db>,
	pub reporting: ReportingDestination<Db>,
	pub verification_enabled: bool,
	/// Tri-state per-repo override of the human-in-the-loop approval
	/// gate. `None` → fall back to the server-level default
	/// (`require_approval_default`); `Some(true)`/`Some(false)` →
	/// pin the value for this repo regardless of the server default.
	pub require_approval: Option<bool>,
	pub last_scanned_sha: Option<BoundedText<RevisionText, Db>>,
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

// debug-ok: content members delegate to redacted typed owners; other members are numeric identifiers or closed states.
#[derive(Debug)]
pub struct NewRepo<S: Source> {
	pub clone_url: BoundedText<CloneUrl, S>,
	pub host: BoundedText<RepoHost, S>,
	pub owner: BoundedText<RepoOwner, S>,
	pub repo: BoundedText<RepoName, S>,
	pub default_branch: Option<BoundedText<GitBranch, S>>,
	pub scan_interval_seconds: Option<i64>,
	pub scanner_config: ScannerDocument<S>,
	pub reporting: ReportingDestination<S>,
	pub verification_enabled: bool,
	/// `None` lets the server default decide; `Some(_)` pins the per-repo
	/// override on insert.
	pub require_approval: Option<bool>,
}

impl<S: Source> Clone for NewRepo<S> {
	fn clone(&self) -> Self {
		Self {
			clone_url: self.clone_url.clone(),
			host: self.host.clone(),
			owner: self.owner.clone(),
			repo: self.repo.clone(),
			default_branch: self.default_branch.clone(),
			scan_interval_seconds: self.scan_interval_seconds,
			scanner_config: self.scanner_config.clone(),
			reporting: self.reporting.clone(),
			verification_enabled: self.verification_enabled,
			require_approval: self.require_approval,
		}
	}
}

pub(crate) fn insert<S: Source>(
	conn: &Connection, new: &NewRepo<S>, now: i64,
) -> rusqlite::Result<i64> {
	#[expect(
		clippy::expect_used,
		reason = "ReportingDestination serializes only its closed enum, typed strings and integers into String"
	)]
	let reporting =
		serde_json::to_string(&new.reporting).expect("reporting is always serialisable");
	conn.execute(
		"INSERT INTO registered_repos
		   (clone_url, host, owner, repo, default_branch, scan_interval_seconds,
		    scanner_config, reporting, verification_enabled, require_approval, created_at)
		 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
		params![
			new.clone_url.expose(),
			new.host.expose(),
			new.owner.expose(),
			new.repo.expose(),
			new.default_branch.as_ref().map(BoundedText::expose),
			new.scan_interval_seconds,
			serde_json::to_string(&new.scanner_config).unwrap_or_else(|_| "{}".into()),
			reporting,
			new.verification_enabled as i64,
			new.require_approval.map(|b| b as i64),
			now,
		],
	)?;
	Ok(conn.last_insert_rowid())
}

pub(crate) fn list(conn: &Connection, limit: Option<i64>) -> rusqlite::Result<Vec<RepoRow>> {
	let Some(limit) = limit else {
		let mut stmt = conn.prepare(&format!("SELECT {REPO_COLUMNS} FROM registered_repos"))?;
		let rows = stmt.query_map([], row_to_repo)?.collect::<rusqlite::Result<Vec<_>>>()?;
		return Ok(rows);
	};
	let mut stmt =
		conn.prepare(&format!("SELECT {REPO_COLUMNS} FROM registered_repos LIMIT ?1"))?;
	let rows =
		stmt.query_map(params![limit], row_to_repo)?.collect::<rusqlite::Result<Vec<_>>>()?;
	Ok(rows)
}

pub(crate) fn get_raw(conn: &Connection, id: i64) -> rusqlite::Result<Option<RepoRow>> {
	let mut stmt =
		conn.prepare(&format!("SELECT {REPO_COLUMNS} FROM registered_repos WHERE id = ?1"))?;
	stmt.query_row(params![id], row_to_repo).optional()
}

pub(crate) fn delete_raw(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
	let n = conn.execute("DELETE FROM registered_repos WHERE id = ?1", params![id])?;
	Ok(n > 0)
}

pub(crate) fn update_reporting<S: Source>(
	conn: &Connection, id: i64, reporting: &ReportingDestination<S>,
) -> rusqlite::Result<bool> {
	#[expect(
		clippy::expect_used,
		reason = "ReportingDestination serializes only its closed enum, typed strings and integers into String"
	)]
	let reporting = serde_json::to_string(reporting).expect("reporting is always serialisable");
	let n = conn.execute(
		"UPDATE registered_repos SET reporting = ?1 WHERE id = ?2",
		params![reporting, id],
	)?;
	Ok(n > 0)
}

/// How many repos file issues with the PAT stored under `secret_id`.
pub(crate) fn count_github_pat_references(
	conn: &Connection, secret_id: i64,
) -> rusqlite::Result<usize> {
	count_github_destinations(conn, |pat_secret_id| pat_secret_id == Some(secret_id))
}

/// How many repos file issues through the server-wide GitHub App, i.e.
/// GitHub destinations without a PAT of their own.
pub(crate) fn count_github_app_references(conn: &Connection) -> rusqlite::Result<usize> {
	count_github_destinations(conn, |pat_secret_id| pat_secret_id.is_none())
}

fn count_github_destinations(
	conn: &Connection, matches: impl Fn(Option<i64>) -> bool,
) -> rusqlite::Result<usize> {
	let mut stmt = conn.prepare("SELECT reporting FROM registered_repos")?;
	let rows = stmt.query_map([], |row| crate::ingress::reporting(row, 0))?;
	let mut count = 0usize;
	for row in rows {
		let reporting = row?;
		if let ReportingDestination::GithubIssue { pat_secret_id, .. } = reporting
			&& matches(pat_secret_id)
		{
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
// debug-ok: repository updates contain only booleans and an optional numeric scan interval.
#[derive(Debug, Default, Clone)]
pub struct RepoUpdate {
	pub disabled: Option<bool>,
	pub scan_interval_seconds: Option<i64>,
	pub verification_enabled: Option<bool>,
	pub require_approval: Option<Option<bool>>,
}

pub(crate) fn update_raw(
	conn: &Connection, id: i64, patch: &RepoUpdate, now: i64,
) -> rusqlite::Result<bool> {
	if patch.disabled.is_none()
		&& patch.scan_interval_seconds.is_none()
		&& patch.verification_enabled.is_none()
		&& patch.require_approval.is_none()
	{
		return Ok(get_raw(conn, id)?.is_some());
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
pub(crate) fn list_due_for_scan(conn: &Connection, now: i64) -> rusqlite::Result<Vec<RepoRow>> {
	let mut stmt = conn.prepare(&format!(
		"SELECT {REPO_COLUMNS} FROM registered_repos
		 WHERE scan_interval_seconds IS NOT NULL
		   AND disabled_at IS NULL
		   AND (last_scanned_at IS NULL OR last_scanned_at + scan_interval_seconds < ?1)"
	))?;
	let rows = stmt.query_map(params![now], row_to_repo)?.collect::<rusqlite::Result<Vec<_>>>()?;
	Ok(rows)
}

const REPO_COLUMNS: &str = r#"
       id, clone_url, host, owner, repo, default_branch, scan_interval_seconds,
       scanner_config, reporting, verification_enabled, require_approval,
       last_scanned_sha, last_scanned_at, created_at, disabled_at
"#;

fn row_to_repo(row: &rusqlite::Row) -> rusqlite::Result<RepoRow> {
	let scanner_config = crate::ingress::scanner_document(row, 7)?;
	let reporting = crate::ingress::reporting(row, 8)?;
	Ok(RepoRow {
		id: row.get(0)?,
		clone_url: crate::ingress::clone_url(row, 1)?,
		host: crate::ingress::repo_host(row, 2)?,
		owner: crate::ingress::repo_owner(row, 3)?,
		repo: crate::ingress::repo_name(row, 4)?,
		default_branch: crate::ingress::optional_branch(row, 5)?,
		scan_interval_seconds: row.get(6)?,
		scanner_config,
		reporting,
		verification_enabled: row.get::<_, i64>(9)? != 0,
		require_approval: row.get::<_, Option<i64>>(10)?.map(|v| v != 0),
		last_scanned_sha: crate::ingress::optional_revision(row, 11)?,
		last_scanned_at: row.get(12)?,
		created_at: row.get(13)?,
		disabled_at: row.get(14)?,
	})
}

pub(crate) fn validate_stored_rows(conn: &Connection) -> crate::Result<()> {
	crate::migrations::admission::scan(conn, "registered_repos", REPO_COLUMNS, row_to_repo)
}

#[cfg(test)]
mod tests {
	use loupe_core::ReportingDestination;

	use super::*;
	use crate::secrets::{self, SecretKind};
	use crate::Db;

	fn fake_repo(secret_id: i64) -> NewRepo<loupe_provenance::Db> {
		NewRepo {
			clone_url: crate::test_support::db_text("https://github.com/acme/widget.git").unwrap(),
			host: crate::test_support::db_text("github.com").unwrap(),
			owner: crate::test_support::db_text("acme").unwrap(),
			repo: crate::test_support::db_text("widget").unwrap(),
			default_branch: Some(crate::test_support::db_text("main").unwrap()),
			scan_interval_seconds: Some(3600),
			scanner_config: crate::test_support::scanner(
				serde_json::json!({"regex": {"enabled": true}}),
			),
			reporting: ReportingDestination::GithubIssue {
				target_owner: crate::test_support::db_text("acme").unwrap(),
				target_repo: crate::test_support::db_text("tracker").unwrap(),
				pat_secret_id: Some(secret_id),
			},
			verification_enabled: false,
			require_approval: None,
		}
	}

	#[test]
	fn clone_needs_only_source_and_preserves_all_fields() {
		fn cloned<S: Source>(value: &NewRepo<S>) -> NewRepo<S> {
			value.clone()
		}

		let mut original = fake_repo(7);
		original.verification_enabled = true;
		original.require_approval = Some(false);
		let copy = cloned(&original);
		assert_eq!(copy.clone_url, original.clone_url);
		assert_eq!(copy.host, original.host);
		assert_eq!(copy.owner, original.owner);
		assert_eq!(copy.repo, original.repo);
		assert_eq!(copy.default_branch, original.default_branch);
		assert_eq!(copy.scan_interval_seconds, original.scan_interval_seconds);
		assert_eq!(copy.scanner_config, original.scanner_config);
		assert_eq!(copy.reporting, original.reporting);
		assert_eq!(copy.verification_enabled, original.verification_enabled);
		assert_eq!(copy.require_approval, original.require_approval);
	}

	#[test]
	fn insert_list_and_delete() {
		let db = Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
		let secret_id = db
			.with_conn(|c| Ok(secrets::insert(c, SecretKind::GithubPat, "pat", b"ghp", 0)?))
			.unwrap();
		let id = db.with_conn(|c| Ok(insert(c, &fake_repo(secret_id), 100)?)).unwrap();

		let listed = db.with_conn(|c| Ok(list(c, None)?)).unwrap();
		assert_eq!(listed.len(), 1);
		assert_eq!(listed[0].id, id);
		assert_eq!(listed[0].clone_url.expose(), "https://github.com/acme/widget.git");

		let one = db.with_conn(|c| Ok(get_raw(c, id)?)).unwrap().unwrap();
		assert_eq!(one.scan_interval_seconds, Some(3600));
		match one.reporting {
			ReportingDestination::GithubIssue { pat_secret_id, .. } => {
				assert_eq!(pat_secret_id, Some(secret_id))
			},
			ReportingDestination::Email { .. } | ReportingDestination::Manual => {
				panic!("fixture builds a github_issue destination")
			},
		}

		assert!(db.with_conn(|c| Ok(delete_raw(c, id)?)).unwrap());
		assert!(db.with_conn(|c| Ok(list(c, None)?)).unwrap().is_empty());
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
		assert!(!db.with_conn(|c| Ok(delete_raw(c, 9_999)?)).unwrap());
	}

	#[test]
	fn list_due_picks_unscanned_and_overdue_repos() {
		let db = Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
		let sid =
			db.with_conn(|c| Ok(secrets::insert(c, SecretKind::GithubPat, "p", b"x", 0)?)).unwrap();
		// Repo A: never scanned, interval=60. Due immediately.
		let a = NewRepo {
			clone_url: crate::test_support::db_text("https://github.com/a/a.git").unwrap(),
			host: crate::test_support::db_text("github.com").unwrap(),
			owner: crate::test_support::db_text("a").unwrap(),
			repo: crate::test_support::db_text("a").unwrap(),
			default_branch: None,
			scan_interval_seconds: Some(60),
			scanner_config: crate::test_support::scanner(serde_json::Value::Null),
			reporting: ReportingDestination::GithubIssue {
				target_owner: crate::test_support::db_text("x").unwrap(),
				target_repo: crate::test_support::db_text("y").unwrap(),
				pat_secret_id: Some(sid),
			},
			verification_enabled: false,
			require_approval: None,
		};
		// Repo B: scanned at t=1000, interval=60. Due at t=1060.
		let b = NewRepo {
			clone_url: crate::test_support::db_text("https://github.com/a/b.git").unwrap(),
			repo: crate::test_support::db_text("b").unwrap(),
			..a.clone()
		};
		// Repo C: no interval — never picked up.
		let no_interval = NewRepo {
			clone_url: crate::test_support::db_text("https://github.com/a/c.git").unwrap(),
			repo: crate::test_support::db_text("c").unwrap(),
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
		let names: Vec<&str> = due.iter().map(|r| r.repo.expose()).collect();
		assert_eq!(names, vec!["a"]);

		// At t=2000: A and B both due, C still skipped.
		let due = db.with_conn(|c| Ok(list_due_for_scan(c, 2000)?)).unwrap();
		let mut names: Vec<&str> = due.iter().map(|r| r.repo.expose()).collect();
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
				Ok(update_raw(
					c,
					id,
					&RepoUpdate { disabled: Some(true), ..Default::default() },
					123,
				)?)
			})
			.unwrap();
		assert!(updated);
		let row = db.with_conn(|c| Ok(get_raw(c, id)?)).unwrap().unwrap();
		assert_eq!(row.disabled_at, Some(123));

		// Re-enable + change interval + flip verification.
		let updated = db
			.with_conn(|c| {
				Ok(update_raw(
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
		let row = db.with_conn(|c| Ok(get_raw(c, id)?)).unwrap().unwrap();
		assert_eq!(row.disabled_at, None);
		assert_eq!(row.scan_interval_seconds, Some(7200));
		assert!(row.verification_enabled);
		assert_eq!(row.require_approval, Some(true));

		// Clearing require_approval drops back to "inherit".
		db.with_conn(|c| {
			Ok(update_raw(
				c,
				id,
				&RepoUpdate { require_approval: Some(None), ..Default::default() },
				789,
			)?)
		})
		.unwrap();
		let row = db.with_conn(|c| Ok(get_raw(c, id)?)).unwrap().unwrap();
		assert_eq!(row.require_approval, None);

		// Empty patch on missing id returns false.
		let touched =
			db.with_conn(|c| Ok(update_raw(c, 9_999, &RepoUpdate::default(), 0)?)).unwrap();
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
					target_owner: crate::test_support::db_text("acme").unwrap(),
					target_repo: crate::test_support::db_text("tracker").unwrap(),
					pat_secret_id: Some(new_sid),
				},
			)?)
		})
		.unwrap();

		let row = db.with_conn(|c| Ok(get_raw(c, id)?)).unwrap().unwrap();
		match row.reporting {
			ReportingDestination::GithubIssue { pat_secret_id, .. } => {
				assert_eq!(pat_secret_id, Some(new_sid))
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
		a.clone_url = crate::test_support::db_text("https://github.com/acme/a.git").unwrap();
		a.repo = crate::test_support::db_text("a").unwrap();
		let mut b = fake_repo(sid);
		b.clone_url = crate::test_support::db_text("https://github.com/acme/b.git").unwrap();
		b.repo = crate::test_support::db_text("b").unwrap();
		db.with_conn(|c| Ok(insert(c, &a, 0)?)).unwrap();
		db.with_conn(|c| Ok(insert(c, &b, 0)?)).unwrap();

		assert_eq!(db.with_conn(|c| Ok(count_github_pat_references(c, sid)?)).unwrap(), 2);
	}

	#[test]
	fn count_github_app_references_counts_only_pat_less_github_destinations() {
		let db = Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
		let sid =
			db.with_conn(|c| Ok(secrets::insert(c, SecretKind::GithubPat, "p", b"x", 0)?)).unwrap();
		let pat_repo = fake_repo(sid);
		let mut app_repo = fake_repo(sid);
		app_repo.clone_url =
			crate::test_support::db_text("https://github.com/acme/app.git").unwrap();
		app_repo.repo = crate::test_support::db_text("app").unwrap();
		app_repo.reporting = ReportingDestination::GithubIssue {
			target_owner: crate::test_support::db_text("acme").unwrap(),
			target_repo: crate::test_support::db_text("tracker").unwrap(),
			pat_secret_id: None,
		};
		let mut manual_repo = fake_repo(sid);
		manual_repo.clone_url =
			crate::test_support::db_text("https://github.com/acme/manual.git").unwrap();
		manual_repo.repo = crate::test_support::db_text("manual").unwrap();
		manual_repo.reporting = ReportingDestination::Manual;
		for repo in [&pat_repo, &app_repo, &manual_repo] {
			db.with_conn(|c| Ok(insert(c, repo, 0)?)).unwrap();
		}

		assert_eq!(db.with_conn(|c| Ok(count_github_app_references(c)?)).unwrap(), 1);
		// An app-mode destination references no PAT secret at all.
		assert_eq!(db.with_conn(|c| Ok(count_github_pat_references(c, sid)?)).unwrap(), 1);
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
