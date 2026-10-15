//! Concrete installation, authentication and Operator registry operations.
//! These own global selection and never expose a SQL connection or callback.
use loupe_core::text::policy::WorkerName;
use loupe_core::text::BoundedText;
use loupe_core::ReportingDestination;
use loupe_provenance::{Ingress, Operator, Secret, Source};

use crate::github_app::{StoredGithubApp, StoredGithubAppSummary};
use crate::repos::{NewRepo, RepoRow};
use crate::workers::{WorkerKind, WorkerRow};
use crate::{github_app, repos, secrets, workers, Db, Error, Result};

pub fn bootstrap_admin(db: &Db, fingerprint: &[u8], now: i64) -> Result<i64> {
	db.with_conn(|conn| Ok(workers::insert_bootstrap_admin(conn, fingerprint, now)?))
}

pub fn authenticate(db: &Db, fingerprint: &[u8]) -> Result<Option<WorkerRow>> {
	db.with_conn(|conn| Ok(workers::find_active_by_fingerprint(conn, fingerprint)?))
}

pub fn touch_authenticated(db: &Db, worker_id: i64, now: i64) -> Result<()> {
	db.with_conn(|conn| Ok(workers::touch_last_seen(conn, worker_id, now)?))
}

pub fn register_worker<S: Source>(
	db: &Db, _operator: &Ingress<Operator>, name: &BoundedText<WorkerName, S>, fingerprint: &[u8],
	now: i64,
) -> Result<i64> {
	db.with_conn(|conn| Ok(workers::insert(conn, name, WorkerKind::Worker, fingerprint, now)?))
}

pub fn revoke_worker(db: &Db, _operator: &Ingress<Operator>, id: i64, now: i64) -> Result<bool> {
	db.with_conn(|conn| Ok(workers::revoke(conn, id, now)?))
}

pub fn store_github_app<S: Source>(
	db: &Db, _operator: &Ingress<Operator>, app: &StoredGithubApp<S>, now: i64,
) -> Result<()> {
	db.with_conn(|conn| Ok(github_app::set(conn, app, now)?))
}

pub fn github_app_summary(
	db: &Db, _operator: &Ingress<Operator>,
) -> Result<Option<StoredGithubAppSummary>> {
	db.with_conn(|conn| Ok(github_app::summary(conn)?))
}

// debug-ok: App removal outcomes contain only closed states and a reference count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearedApp {
	Removed,
	Missing,
	InUse(usize),
}

pub fn clear_github_app(db: &Db, _operator: &Ingress<Operator>) -> Result<ClearedApp> {
	db.with_conn(|conn| {
		crate::transaction::immediate(conn, |tx| {
			let references = repos::count_github_app_references(tx)?;
			if references != 0 {
				return Ok(ClearedApp::InUse(references));
			}
			Ok(if github_app::clear(tx)? { ClearedApp::Removed } else { ClearedApp::Missing })
		})
	})
}

// debug-ok: current producers return integer IDs or booleans; generic formatting delegates to T::Debug and does not promise payload redaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportingWrite<T> {
	Done(T),
	NoApp,
}

/// Register a repository and its selected credential atomically. An input
/// cannot point at a preexisting secret; storage selects the newly stored PAT.
pub fn register_repository<S: Source>(
	db: &Db, _operator: &Ingress<Operator>, new: &NewRepo<S>, pat: Option<&Secret<String>>,
	now: i64,
) -> Result<ReportingWrite<i64>> {
	db.with_conn(|conn| {
		crate::transaction::immediate(conn, |tx| {
			let mut selected = new.clone();
			match &mut selected.reporting {
				ReportingDestination::GithubIssue { target_owner, target_repo, pat_secret_id } => {
					if pat_secret_id.is_some() {
						return Err(Error::ScopeDenied);
					}
					*pat_secret_id = match pat {
						Some(pat) => Some(secrets::insert(
							tx,
							secrets::SecretKind::GithubPat,
							&format!(
								"pat:{}:{}/{}",
								new.host.expose(),
								target_owner.expose(),
								target_repo.expose()
							),
							pat.expose().as_bytes(),
							now,
						)?),
						None if github_app::get(tx)?.is_none() => return Ok(ReportingWrite::NoApp),
						None => None,
					};
				},
				_ if pat.is_some() => return Err(Error::ScopeDenied),
				_ => {},
			}
			Ok(ReportingWrite::Done(repos::insert(tx, &selected, now)?))
		})
	})
}

pub fn repositories(
	db: &Db, _operator: &Ingress<Operator>, limit: Option<i64>,
) -> Result<Vec<RepoRow>> {
	db.with_conn(|conn| Ok(repos::list(conn, limit)?))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{findings, jobs, reports, scheduler, scope, test_support as fixture};

	#[test]
	fn public_producer_path_prepares_a_committed_exact_batch_without_sql_access() {
		let db = Db::open_in_memory(&secrets::MasterKey::for_tests()).unwrap();
		let operator = fixture::operator_ingress();
		let worker = register_worker(
			&db,
			&operator,
			&fixture::db_text("fixture-worker").unwrap(),
			&[9; 32],
			0,
		)
		.unwrap();
		let new = NewRepo {
			clone_url: fixture::db_text("https://github.com/example/repo.git").unwrap(),
			host: fixture::db_text("github.com").unwrap(),
			owner: fixture::db_text("example").unwrap(),
			repo: fixture::db_text("repo").unwrap(),
			default_branch: None,
			scan_interval_seconds: None,
			scanner_config: fixture::scanner(serde_json::json!(null)),
			reporting: ReportingDestination::GithubIssue {
				target_owner: fixture::db_text("example").unwrap(),
				target_repo: fixture::db_text("tracker").unwrap(),
				pat_secret_id: None,
			},
			verification_enabled: false,
			require_approval: Some(false),
		};
		let ReportingWrite::Done(repo) =
			register_repository(&db, &operator, &new, Some(&Secret::new("fixture-pat".into())), 0)
				.unwrap()
		else {
			panic!("PAT registration must succeed")
		};
		let job = scope::with_operator_repository(
			&db,
			&operator,
			scope::OperatorTarget::Repository(repo),
			|scope| {
				jobs::enqueue(
					scope,
					&jobs::QueuedJob::<loupe_provenance::Db> {
						kind: loupe_core::JobKind::Scan,
						incremental: false,
						since_sha: None,
						parent_job_id: None,
						target_finding_id: None,
					},
					0,
				)
			},
		)
		.unwrap();
		let claimed = scheduler::claim(
			&db,
			&scheduler::ClaimRequest::<loupe_provenance::Db> {
				worker_id: worker,
				kinds: &[loupe_core::JobKind::Scan],
				now: 1,
				capability_hash: &[7; 32],
				legacy_lease_seconds: 600,
				policy: &scheduler::ClaimPolicy::default(),
			},
		)
		.unwrap()
		.unwrap();
		assert_eq!(claimed.claimed.job.id, job);
		assert_eq!(claimed.repository.id, repo);
		let finding = findings::tests::sample("original-fixture-fingerprint");
		let revision = fixture::db_text("reviewed-sha").unwrap();
		let prepared = scope::with_active_lease(
			&db,
			jobs::ActiveLease {
				identity: jobs::LeaseIdentity {
					job_id: job,
					worker_id: worker,
					capability_hash: &[7; 32],
				},
				now: 2,
			},
			|scope| {
				assert!(findings::submit(scope, &finding)?.is_some());
				reports::complete_assignment::<_, loupe_provenance::Db>(
					scope,
					loupe_core::JobState::Succeeded,
					Some(&revision),
					None,
					false,
					99,
				)
			},
		)
		.unwrap()
		.unwrap();
		let reports::Preparation::Ready(mut batch) = prepared else {
			panic!("ready batch required")
		};
		batch.check_committed().unwrap();
		assert_eq!(batch.entries().len(), 1);
		let selected = batch.entries()[0].content().unwrap();
		assert_eq!(selected.finding(), &finding);
		assert_eq!(selected.reviewed_revision().unwrap().expose(), "reviewed-sha");
		assert_eq!(batch.mark_all(&db, 3).unwrap(), 1);
		assert_eq!(batch.mark_all(&db, 4).unwrap(), 0);
	}
}
