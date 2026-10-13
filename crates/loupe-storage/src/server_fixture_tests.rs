//! Private persistence checks paired with server integration fixtures.
//!
//! HTTP status, rendered output, and public readback assertions remain in the
//! integration tests. SQL-only observations stay beside the storage owner.

use loupe_core::{FindingState, JobKind, JobState, ReportingDestination, Verdict};
use loupe_provenance::{Db as DbSource, Secret};

use crate::{
	findings, jobs, registry, reports, repos, scheduler, scope, test_support as fixture, Db,
};

fn database(verification: bool, approval: bool) -> (Db, i64, i64) {
	let db = Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
	let authority = fixture::operator_ingress();
	let worker = registry::register_worker(
		&db,
		&authority,
		&fixture::db_text("fixture-worker").unwrap(),
		&[87; 32],
		0,
	)
	.unwrap();
	let registry::ReportingWrite::Done(repo) = registry::register_repository(
		&db,
		&authority,
		&repos::NewRepo {
			clone_url: fixture::db_text("https://github.com/acme/widget.git").unwrap(),
			host: fixture::db_text("github.com").unwrap(),
			owner: fixture::db_text("acme").unwrap(),
			repo: fixture::db_text("widget").unwrap(),
			default_branch: None,
			scan_interval_seconds: None,
			scanner_config: fixture::scanner(serde_json::Value::Null),
			reporting: ReportingDestination::Manual,
			verification_enabled: verification,
			require_approval: Some(approval),
		},
		None,
		0,
	)
	.unwrap() else {
		panic!("manual fixture registration")
	};
	(db, repo, worker)
}

fn with_repo<T>(
	db: &Db, repo: i64, body: impl for<'tx> FnOnce(&scope::RepoScope<'tx>) -> crate::Result<T>,
) -> T {
	scope::with_operator_repository(
		db,
		&fixture::operator_ingress(),
		scope::OperatorTarget::Repository(repo),
		body,
	)
	.unwrap()
}

fn claim(db: &Db, worker: i64, kind: JobKind<DbSource>, now: i64) -> i64 {
	scheduler::claim(
		db,
		&scheduler::ClaimRequest {
			worker_id: worker,
			kinds: &[kind],
			now,
			capability_hash: &[87; 32],
			legacy_lease_seconds: 1000,
			policy: &scheduler::ClaimPolicy::default(),
		},
	)
	.unwrap()
	.unwrap()
	.claimed
	.job
	.id
}

fn with_lease<T>(
	db: &Db, worker: i64, job: i64, now: i64,
	body: impl for<'tx> FnOnce(&scope::AssignmentScope<'tx>) -> crate::Result<T>,
) -> T {
	scope::with_active_lease(
		db,
		jobs::ActiveLease {
			identity: jobs::LeaseIdentity {
				job_id: job,
				worker_id: worker,
				capability_hash: &[87; 32],
			},
			now,
		},
		body,
	)
	.unwrap()
	.unwrap()
}

fn scan(db: &Db, repo: i64, worker: i64) -> (i64, i64) {
	let job = with_repo(db, repo, |scope| {
		jobs::enqueue(
			scope,
			&jobs::QueuedJob::<DbSource> {
				kind: JobKind::Scan,
				incremental: false,
				since_sha: None,
				parent_job_id: None,
				target_finding_id: None,
			},
			0,
		)
	});
	assert_eq!(claim(db, worker, JobKind::Scan, 1), job);
	let finding = with_lease(db, worker, job, 2, |scope| {
		let finding =
			findings::submit(scope, &findings::tests::sample("private-server-fixture"))?.unwrap();
		let _prepared = reports::complete_assignment::<DbSource, DbSource>(
			scope,
			JobState::Succeeded,
			Some(&fixture::db_text("reviewed-revision").unwrap()),
			None,
			false,
			100,
		)?;
		Ok(finding)
	});
	(job, finding)
}

// Manual approval must not stamp reported_at.
#[test]
fn manual_approval_preserves_unreported_sql_audit() {
	let (db, repo, worker) = database(false, true);
	let (_, finding) = scan(&db, repo, worker);
	with_repo(&db, repo, |scope| {
		let (outcome, prepared) =
			reports::approve(scope, finding, &fixture::db_text("admin").unwrap(), 3)?;
		assert_eq!(outcome, findings::ApprovalOutcome::Applied);
		assert!(matches!(prepared, reports::Preparation::NoReport));
		let (state, reported_at, approved_by): (String, Option<i64>, Option<String>) =
			scope.conn.query_row(
				"SELECT state, reported_at, approved_by_cn FROM findings WHERE id=?1",
				[finding],
				|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
			)?;
		assert_eq!(state, "confirmed");
		assert!(reported_at.is_none(), "reported_at must wait for an actual reporter");
		assert_eq!(approved_by.as_deref(), Some("admin"));
		Ok(())
	});
}

// A verifier-issued row is bound to its actual job.
#[test]
fn verifier_confirmation_persists_exact_assigned_job() {
	let (db, repo, worker) = database(true, false);
	let (_, finding) = scan(&db, repo, worker);
	let verify = claim(&db, worker, JobKind::Verify, 3);
	with_lease(&db, worker, verify, 4, |scope| {
		let (state, _) = reports::submit_verdict(
			scope,
			&Verdict::Confirmed {
				notes: Some(fixture::text("OOB confirmed on empty slice").unwrap()),
				patch: None,
			},
			&fixture::db_text("fixture-worker").unwrap(),
			false,
			false,
		)?;
		assert_eq!(state, Some(FindingState::Confirmed));
		Ok(())
	});
	db.with_conn(|conn| {
		let (count, with_job): (i64, i64) = conn.query_row(
			"SELECT COUNT(*), SUM(CASE WHEN job_id IS NOT NULL THEN 1 ELSE 0 END) FROM finding_verifications", [], |r| Ok((r.get(0)?, r.get(1)?)))?;
		assert_eq!(count, 1);
		assert_eq!(with_job, 1, "verifier-issued verdict must carry a job_id");
		let selected: (i64, i64) = conn.query_row("SELECT finding_id,job_id FROM finding_verifications", [], |r| Ok((r.get(0)?,r.get(1)?)))?;
		assert_eq!(selected, (finding, verify));
		Ok(())
	}).unwrap();
}

// Credential replacement preserves exact bytes, removes superseded secrets,
// and creates no PAT row for App authentication.
#[test]
fn github_pat_replacement_and_app_switch_preserve_private_secret_rows() {
	let (db, repo, _) = database(false, false);
	let owner = fixture::db_text("acme").unwrap();
	let target = fixture::db_text("tracker").unwrap();
	let mut previous = None;
	for value in ["ghp_secret_value", "ghp_old", "ghp_new", "ghp_first", "ghp_second"] {
		with_repo(&db, repo, |scope| {
			if value == "ghp_new" {
				assert_eq!(
					repos::rotate_github_pat(scope, &Secret::new(value.into()), 3)?,
					repos::PatRotation::Rotated
				);
			} else {
				assert_eq!(
					repos::set_github_reporting(
						scope,
						&owner,
						&target,
						Some(&Secret::new(value.into())),
						3
					)?,
					registry::ReportingWrite::Done(true)
				);
			}
			let ReportingDestination::GithubIssue { pat_secret_id: Some(id), .. } =
				repos::get(scope)?.unwrap().reporting
			else {
				panic!("stored PAT")
			};
			assert_eq!(crate::secrets::read(scope.conn, id)?.unwrap().expose(), value.as_bytes());
			if let Some(old) = previous {
				assert_ne!(id, old);
				assert!(
					crate::secrets::read(scope.conn, old)?.is_none(),
					"replaced PAT must be deleted"
				);
			}
			let reporting: String = scope.conn.query_row(
				"SELECT reporting FROM registered_repos WHERE id=?1",
				[repo],
				|row| row.get(0),
			)?;
			assert!(
				!reporting.contains(value),
				"PAT must not be persisted in registered_repos.reporting"
			);
			assert!(reporting.contains("pat_secret_id"));
			previous = Some(id);
			Ok(())
		});
	}
	registry::store_github_app(
		&db,
		&fixture::operator_ingress(),
		&crate::github_app::StoredGithubApp {
			app_id: 4242,
			slug: fixture::db_text("loupe-reporter").unwrap(),
			private_key_pem: Secret::new("synthetic stored key".into()),
		},
		4,
	)
	.unwrap();
	with_repo(&db, repo, |scope| {
		assert_eq!(
			repos::set_github_reporting(scope, &owner, &target, None, 5)?,
			registry::ReportingWrite::Done(true)
		);
		assert!(
			crate::secrets::read(scope.conn, previous.unwrap())?.is_none(),
			"orphaned PAT must be dropped"
		);
		let pat_rows: i64 = scope.conn.query_row(
			"SELECT COUNT(*) FROM secrets WHERE kind='github_pat'",
			[],
			|r| r.get(0),
		)?;
		assert_eq!(pat_rows, 0, "app mode must not create a PAT secret");
		assert_eq!(
			repos::set_github_reporting(
				scope,
				&owner,
				&target,
				Some(&Secret::new("ghp_back".into())),
				6
			)?,
			registry::ReportingWrite::Done(true)
		);
		let ReportingDestination::GithubIssue { pat_secret_id: Some(id), .. } =
			repos::get(scope)?.unwrap().reporting
		else {
			panic!("PAT restored")
		};
		assert_eq!(crate::secrets::read(scope.conn, id)?.unwrap().expose(), b"ghp_back");
		Ok(())
	});
}

// Registration stores the secret separately; App-only registration creates no PAT row.
#[test]
fn github_registration_stores_pat_separately_and_app_registration_creates_none() {
	let db = Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
	let authority = fixture::operator_ingress();
	let mut new = repos::NewRepo {
		clone_url: fixture::db_text("https://github.com/acme/widget.git").unwrap(),
		host: fixture::db_text("github.com").unwrap(),
		owner: fixture::db_text("acme").unwrap(),
		repo: fixture::db_text("widget").unwrap(),
		default_branch: None,
		scan_interval_seconds: None,
		scanner_config: fixture::scanner(serde_json::Value::Null),
		reporting: ReportingDestination::GithubIssue {
			target_owner: fixture::db_text("acme").unwrap(),
			target_repo: fixture::db_text("tracker").unwrap(),
			pat_secret_id: None,
		},
		verification_enabled: false,
		require_approval: Some(false),
	};
	let registry::ReportingWrite::Done(repo) = registry::register_repository(
		&db,
		&authority,
		&new,
		Some(&Secret::new("ghp_secret_value".into())),
		0,
	)
	.unwrap() else {
		panic!("PAT registration")
	};
	db.with_conn(|conn| {
		let stored_secret: Vec<u8> =
			conn.query_row("SELECT value FROM secrets WHERE kind='github_pat' LIMIT 1", [], |r| {
				r.get(0)
			})?;
		assert_eq!(stored_secret, b"ghp_secret_value");
		let reporting: String =
			conn.query_row("SELECT reporting FROM registered_repos WHERE id=?1", [repo], |r| {
				r.get(0)
			})?;
		assert!(
			!reporting.contains("ghp_secret_value"),
			"PAT must not be persisted in registered_repos.reporting"
		);
		assert!(reporting.contains("pat_secret_id"));
		Ok(())
	})
	.unwrap();
	let app_db = Db::open_in_memory(&crate::secrets::MasterKey::for_tests()).unwrap();
	registry::store_github_app(
		&app_db,
		&authority,
		&crate::github_app::StoredGithubApp {
			app_id: 4242,
			slug: fixture::db_text("loupe-reporter").unwrap(),
			private_key_pem: Secret::new("synthetic stored key".into()),
		},
		0,
	)
	.unwrap();
	new.repo = fixture::db_text("app-widget").unwrap();
	assert!(matches!(
		registry::register_repository(&app_db, &authority, &new, None, 0).unwrap(),
		registry::ReportingWrite::Done(_)
	));
	app_db
		.with_conn(|conn| {
			let pat_rows: i64 =
				conn.query_row("SELECT COUNT(*) FROM secrets WHERE kind='github_pat'", [], |r| {
					r.get(0)
				})?;
			assert_eq!(pat_rows, 0, "app mode must not create a PAT secret");
			Ok(())
		})
		.unwrap();
}

// Scheduler TEMP tables belong to its own connection.
#[test]
fn legacy_verify_first_claims_leave_campaign_fairness_untouched() {
	let (db, repo, worker) = database(false, false);
	let enqueue = |kind, at, parent_job_id, target_finding_id| {
		with_repo(&db, repo, |scope| {
			jobs::enqueue(
				scope,
				&jobs::QueuedJob::<DbSource> {
					kind,
					incremental: false,
					since_sha: None,
					parent_job_id,
					target_finding_id,
				},
				at,
			)
		})
	};
	let first = enqueue(JobKind::Scan, 1, None, None);
	let second = enqueue(JobKind::Scan, 2, None, None);
	let finding = db.with_conn(|conn| {
		conn.execute("INSERT INTO findings(repo_id,job_id,scanner_id,severity,title,description,fingerprint,state,created_at,report_identity) VALUES(?1,?2,'test','high','t','d','scheduler-parity','validating',0,randomblob(16))", (repo,first))?;
		Ok(conn.last_insert_rowid())
	}).unwrap();
	let verify = enqueue(JobKind::Verify, 3, Some(first), Some(finding));
	for (capability, expected) in [(1, verify), (2, first), (3, second)] {
		let selected = scheduler::claim(
			&db,
			&scheduler::ClaimRequest::<DbSource> {
				worker_id: worker,
				kinds: &[JobKind::Verify, JobKind::Scan],
				now: 4,
				capability_hash: &[capability; 32],
				legacy_lease_seconds: 100,
				policy: &scheduler::ClaimPolicy::default(),
			},
		)
		.unwrap()
		.unwrap();
		assert_eq!(selected.claimed.job.id, expected);
	}
	db.with_conn(|conn| {
		assert_eq!(
			conn.query_row("SELECT COUNT(*) FROM scheduler_repo_state", [], |r| r
				.get::<_, i64>(0))?,
			0,
			"legacy jobs must not alter campaign fairness"
		);
		assert_eq!(
			conn.query_row("SELECT seq FROM scheduler_clock", [], |r| r.get::<_, i64>(0))?,
			0
		);
		Ok(())
	})
	.unwrap();
}
