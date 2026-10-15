//! Pure ownership decisions over facts loaded in the caller's transaction.
//!
//! Only owned results can escape either synchronous issuer.
//! ```
//! use loupe_provenance::{Ingress, Operator};
//! use loupe_storage::scope::{with_operator_repository, OperatorTarget};
//! use loupe_storage::{Db, Result};
//! #[rustfmt::skip]
//! fn owned(db: &Db, operator: &Ingress<Operator>) -> Result<i64> {
//!     with_operator_repository(db, operator, OperatorTarget::Repository(1), |scope| {
//!         Ok(scope.repository_id())
//!     })
//! }
//! ```
//! ```compile_fail
//! use loupe_storage::{Db, scope::{with_operator_repository, OperatorTarget}};
//! use loupe_provenance::{Ingress, Operator};
//! fn escape(db: &Db, operator: &Ingress<Operator>) {
//!     let _ = with_operator_repository(db, operator, OperatorTarget::Repository(1), |scope| Ok(scope));
//! }
//! ```
//! ```compile_fail
//! use loupe_storage::{Db, scope::with_active_lease, jobs::ActiveLease};
//! fn escape(db: &Db, lease: ActiveLease<'_>) {
//!     let _ = with_active_lease(db, lease, |scope| Ok(async move { scope.job().id }));
//! }
//! ```
//! ```compile_fail,E0308
//! use loupe_storage::{Db, scope::{with_operator_repository, OperatorTarget}};
//! use loupe_provenance::{Ingress, Worker};
//! fn worker(db: &Db, worker: &Ingress<Worker>) {
//!     let _ = with_operator_repository(db, worker, OperatorTarget::Repository(1), |_| Ok(()));
//! }
//! ```
//! ```compile_fail,E0599
//! use loupe_storage::scope::RepoScope;
//! let _ = RepoScope::default();
//! ```
//! ```compile_fail,E0308
//! use loupe_storage::scope::RepoScope;
//! fn copy<'a>(scope: &RepoScope<'a>) -> RepoScope<'a> { scope.clone() }
//! ```
//! ```compile_fail,E0277
//! use loupe_storage::scope::RepoScope;
//! let _: RepoScope<'_> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail
//! use loupe_storage::{Db, scope::{with_operator_repository, OperatorTarget}};
//! use loupe_provenance::{Ingress, Operator};
//! fn send(db: &Db, operator: &Ingress<Operator>) {
//!     with_operator_repository(db, operator, OperatorTarget::Repository(1), |scope| {
//!         std::thread::spawn(move || scope.repository_id());
//!         Ok(())
//!     });
//! }
//! ```
//! ```compile_fail,E0599
//! use loupe_storage::scope::RepoScope;
//! fn sql(scope: &RepoScope<'_>) { scope.execute_batch("DELETE FROM findings"); }
//! ```
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use loupe_provenance::{Ingress, Operator};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use crate::Ownership;

/// Repository authority borrows the connection of its issuing transaction.
/// It has no public constructor, connection accessor, clone or retargeting.
pub struct RepoScope<'tx> {
	pub(crate) conn: &'tx Connection,
	pub(crate) repo_id: i64,
	pub(crate) identity: &'tx Arc<crate::db::DbIdentity>,
	pub(crate) operator: bool,
	pub(crate) committed: &'tx Arc<AtomicBool>,
}

/// Authority for the exact active lease selected in the issuing transaction.
pub struct AssignmentScope<'tx> {
	pub(crate) repo: RepoScope<'tx>,
	pub(crate) job: crate::jobs::JobRow,
	pub(crate) lease: crate::jobs::ActiveLease<'tx>,
}

impl RepoScope<'_> {
	pub fn repository_id(&self) -> i64 {
		self.repo_id
	}
	pub(crate) fn require_operator(&self) -> crate::Result<()> {
		if self.operator {
			Ok(())
		} else {
			Err(crate::Error::ScopeDenied)
		}
	}
}
impl AssignmentScope<'_> {
	pub fn repo(&self) -> &RepoScope<'_> {
		&self.repo
	}
	pub fn job(&self) -> &crate::jobs::JobRow {
		&self.job
	}
}

// debug-ok: operator targets contain only a closed entity kind and integer row ID.
#[derive(Debug, Clone, Copy)]
pub enum OperatorTarget {
	Repository(i64),
	Job(i64),
	Finding(i64),
}

/// Only owned results can leave this synchronous transaction callback.
pub fn with_operator_repository<T>(
	db: &crate::Db, _operator: &Ingress<Operator>, target: OperatorTarget,
	body: impl for<'tx> FnOnce(&RepoScope<'tx>) -> crate::Result<T>,
) -> crate::Result<T> {
	db.with_conn(|conn| {
		let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
		let repo_id = match target {
			OperatorTarget::Repository(id) => id,
			OperatorTarget::Job(id) => tx
				.query_row("SELECT repo_id FROM jobs WHERE id=?1", [id], |row| row.get(0))
				.optional()?
				.ok_or(crate::Error::NotFound(crate::Entity::Job, id))?,
			OperatorTarget::Finding(id) => tx
				.query_row("SELECT repo_id FROM findings WHERE id=?1", [id], |row| row.get(0))
				.optional()?
				.ok_or(crate::Error::NotFound(crate::Entity::Finding, id))?,
		};
		let committed = Arc::new(AtomicBool::new(false));
		let scope = RepoScope {
			conn: &tx,
			repo_id,
			identity: &db.identity,
			operator: true,
			committed: &committed,
		};
		let result = body(&scope)?;
		tx.commit()?;
		committed.store(true, Ordering::Release);
		Ok(result)
	})
}

/// Checks the exact capability under IMMEDIATE before invoking the callback.
pub fn with_active_lease<T>(
	db: &crate::Db, lease: crate::jobs::ActiveLease<'_>,
	body: impl for<'tx> FnOnce(&AssignmentScope<'tx>) -> crate::Result<T>,
) -> crate::Result<Option<T>> {
	db.with_conn(|conn| {
		let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
		let Some(job) = crate::jobs::get_active_by_capability_hash(
			&tx,
			lease.identity.worker_id,
			lease.identity.capability_hash,
			lease.now,
		)?
		else {
			return Ok(None);
		};
		if job.id != lease.identity.job_id {
			return Ok(None);
		}
		let committed = Arc::new(AtomicBool::new(false));
		let repo = RepoScope {
			conn: &tx,
			repo_id: job.repo_id,
			identity: &db.identity,
			operator: false,
			committed: &committed,
		};
		let assignment = AssignmentScope { repo, job, lease };
		let result = body(&assignment)?;
		tx.commit()?;
		committed.store(true, Ordering::Release);
		Ok(Some(result))
	})
}

// debug-ok: assignment facts contain only a closed entity kind and integer row ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Assignment {
	Job(i64),
	Finding(i64),
	Verification(i64),
}

// debug-ok: subject kinds contain closed relations and integer repository/assignment IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubjectKind {
	Record,
	/// A generation-less, host-authored job can use its campaign's repository.
	Job {
		campaign_repo: Option<i64>,
	},
	Assigned(Assignment),
}

// debug-ok: ownership subjects contain only integer repository, generation, campaign and assignment IDs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Subject {
	pub repo: i64,
	pub generation: Option<i64>,
	pub campaign: Option<i64>,
	pub kind: SubjectKind,
}

impl Subject {
	pub fn repository(repo: i64) -> Self {
		Self { repo, generation: None, campaign: None, kind: SubjectKind::Record }
	}
}

// debug-ok: pure ownership facts contain only integer repository, generation, campaign and assignment IDs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Scope {
	pub repo: i64,
	pub generation: Option<i64>,
	pub campaign: Option<i64>,
	pub assignment: Option<Assignment>,
}

impl Scope {
	pub fn repository(repo: i64) -> Self {
		Self { repo, generation: None, campaign: None, assignment: None }
	}

	// Ownership is a diagnostic label, not a policy selector: e.g. JobLead is
	// used by both repository- and generation-bound callers. The loaded scope
	// and subject kind carry the actual constraints.
	pub fn admits(&self, subject: &Subject, _relation: Ownership) -> bool {
		if subject.repo != self.repo {
			return false;
		}
		if let Some(generation) = self.generation {
			let campaign_fallback = subject.generation.is_none()
				&& matches!(subject.kind, SubjectKind::Job { campaign_repo: Some(repo) } if repo == self.repo);
			if subject.generation != Some(generation) && !campaign_fallback {
				return false;
			}
		}
		if self.campaign.is_some() && subject.campaign != self.campaign {
			return false;
		}
		if self
			.assignment
			.is_some_and(|assignment| subject.kind != SubjectKind::Assigned(assignment))
		{
			return false;
		}
		true
	}

	/// Missing and foreign rows deliberately have the same public error.
	pub fn check(&self, subject: Option<&Subject>, relation: Ownership) -> Result<(), Ownership> {
		if subject.is_some_and(|subject| self.admits(subject, relation)) {
			Ok(())
		} else {
			Err(relation)
		}
	}
}
