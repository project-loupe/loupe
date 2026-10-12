use std::sync::Arc;

use loupe_storage::Db;
use loupe_tls::Ca;
use tokio::sync::Notify;

use crate::reporters::{EmailReporter, GithubReporter};

/// Shared state passed to every axum handler. Cheap to clone — wraps
/// `Arc`s around storage, the internal CA, and the reporter that the
/// dispatcher hands findings to.
///
/// `job_arrived` is poked whenever a new job lands in `queued`. Long-
/// polling lease handlers wait on it so workers don't have to busy-poll.
///
/// At-rest encryption of the database itself (including secrets,
/// findings, and everything else) is handled by SQLCipher inside
/// [`Db`] — the master key is consumed at `Db::open` time and is no
/// longer in the AppState.
#[derive(Clone)]
pub struct AppState {
	pub db: Arc<Db>,
	pub ca: Arc<Ca>,
	pub github_reporter: Arc<GithubReporter>,
	pub email_reporter: Arc<EmailReporter>,
	pub job_arrived: Arc<Notify>,
	pub review_policy: Arc<crate::review::policy::ReviewPolicy>,
	pub worker_budgets: Arc<crate::request_budget::WorkerBudgets>,
	/// Server-wide default for the human-in-the-loop approval gate.
	/// Used when a repo has `require_approval = NULL` (the wire-side
	/// default — i.e. the operator didn't pin a per-repo override).
	/// `false` keeps the existing immediate-dispatch behaviour.
	pub require_approval_default: bool,
	/// Server-wide default for the verify flow. Used when a repo
	/// registration omits `verification_enabled`; the resolved value is
	/// stored on the repo row so later server config changes do not
	/// silently change existing repos.
	pub verification_default: bool,
	/// Tracker owners that app-mode GitHub destinations may point at.
	/// `None` leaves the GitHub App's own installation as the only
	/// limit; `Some` additionally refuses a `target_owner` (compared
	/// case-insensitively) that is not listed. Enforced when a repo is
	/// registered or re-pointed *and again at every dispatch*, so
	/// tightening the list later also stops repos registered before the
	/// change. PAT destinations are not restricted — the PAT already
	/// scopes them.
	pub github_app_allowed_owners: Option<
		Vec<
			loupe_core::text::BoundedText<
				loupe_core::text::policy::RepoOwner,
				loupe_provenance::Config,
			>,
		>,
	>,
}

impl AppState {
	/// Apply `github_app_allowed_owners` to one app-mode tracker owner.
	/// The error text names the owner and the list so both registration
	/// (as a 400) and dispatch (as a failed report) can surface it as-is.
	pub fn check_github_app_target_owner<S: loupe_provenance::Source>(
		&self, target_owner: &loupe_core::text::BoundedText<loupe_core::text::policy::RepoOwner, S>,
	) -> Result<(), String> {
		let target_owner = target_owner.expose();
		match &self.github_app_allowed_owners {
			Some(allowed)
				if !allowed
					.iter()
					.any(|owner| owner.expose().eq_ignore_ascii_case(target_owner)) =>
			{
				Err(format!(
					"GitHub App reporting is restricted to tracker owners {}; {target_owner} is \
					 not allowed (pass a PAT to report elsewhere)",
					allowed.iter().map(|owner| owner.expose()).collect::<Vec<_>>().join(", ")
				))
			},
			_ => Ok(()),
		}
	}
}

impl AppState {
	pub fn new(db: Arc<Db>, ca: Arc<Ca>, github_reporter: Arc<GithubReporter>) -> Self {
		Self {
			db,
			ca,
			github_reporter,
			email_reporter: Arc::new(EmailReporter::new()),
			job_arrived: Arc::new(Notify::new()),
			review_policy: Arc::new(crate::review::policy::ReviewPolicy::default()),
			worker_budgets: Arc::new(
				crate::request_budget::WorkerBudgets::new(
					crate::request_budget::WorkerBudgetConfig::default(),
				)
				.expect("default worker budgets are valid"),
			),
			require_approval_default: false,
			verification_default: false,
			github_app_allowed_owners: None,
		}
	}

	pub fn with_github_app_allowed_owners(
		mut self,
		owners: Option<
			Vec<
				loupe_core::text::BoundedText<
					loupe_core::text::policy::RepoOwner,
					loupe_provenance::Config,
				>,
			>,
		>,
	) -> Self {
		self.github_app_allowed_owners = owners;
		self
	}

	pub fn with_email_reporter(mut self, reporter: EmailReporter) -> Self {
		self.email_reporter = Arc::new(reporter);
		self
	}

	pub fn with_worker_budgets(
		mut self, config: crate::request_budget::WorkerBudgetConfig,
	) -> anyhow::Result<Self> {
		self.worker_budgets = Arc::new(crate::request_budget::WorkerBudgets::new(config)?);
		Ok(self)
	}

	pub fn with_review_policy(
		mut self, policy: crate::review::policy::ReviewPolicy,
	) -> Result<Self, crate::review::policy::PolicyError> {
		policy.validate()?;
		self.review_policy = Arc::new(policy);
		Ok(self)
	}

	pub fn with_require_approval_default(mut self, on: bool) -> Self {
		self.require_approval_default = on;
		self
	}

	pub fn with_verification_default(mut self, on: bool) -> Self {
		self.verification_default = on;
		self
	}
}
