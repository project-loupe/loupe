//! Host preparation of review-phase attempts: the phase-agnostic checkout
//! and pin, and the survey's inventory upload and limits read. Nothing
//! here runs an agent.

use std::num::NonZeroU32;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use loupe_core::review_metadata::ReviewCommit;
use loupe_core::security_event::Operation;
use loupe_core::RepoSpec;
use loupe_proto::review_api::{
	ManifestProgress, PhaseLimitsResponse, PinTargetRequest, PinTargetResponse, ReviewErrorCode,
	ReviewProtocol,
};
use loupe_proto::review_lease::{
	BootstrapTarget, FrozenReviewProfile, OrdinarySurveyRecipe, ReviewAssignments,
	ReviewGeneration, ReviewLimits, ReviewSurveyContext, ReviewSurveyLease,
};
use loupe_proto::{JobCapability, LeaseEnvelope, LeasePayload};
use loupe_provenance::{Agent, Repo, Secret, Server};
use tokio_util::sync::CancellationToken;

use super::inventory::{CommitDecoder, Inventory, InventoryDecoder, InventoryError};
use crate::canary::JobSecurity;
use crate::client::{PhaseError, PhaseJob, ServerClient};
use crate::runner::{
	checkout_latest, checkout_revision, observe_commit, CheckedOutWorktree, LeaseRepo, Runner,
};

/// Why an attempt could not be prepared. Closed and free of repository,
/// server or agent text.
// debug-ok: static classifications and the content-free phase error.
#[derive(Debug, thiserror::Error)]
pub enum PrepareError {
	#[error("lease is not a survey this worker runs")]
	UnsupportedLease,
	#[error("hard deadline reached")]
	HardDeadline,
	#[error("repository checkout failed")]
	Checkout,
	#[error("checkout exceeds the workdir size cap")]
	WorkdirTooLarge,
	#[error("inventory unsupported: {0}")]
	Inventory(#[from] InventoryError),
	#[error("checkout conflict")]
	CheckoutConflict,
	#[error("server inventory progress does not match this inventory")]
	ManifestMismatch,
	#[error("job quarantined")]
	Quarantined,
	#[error("job cancelled")]
	Cancelled,
	#[error("host task failed")]
	Internal,
	#[error(transparent)]
	Phase(#[from] PhaseError),
}

/// The survey's recipe after preparation.
// debug-ok: closed recipe names only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurveyRecipe {
	Bootstrap,
	ResolveTarget,
	Ordinary(OrdinarySurveyRecipe),
}

/// Everything later stages of a survey attempt need.
pub struct PreparedSurvey {
	pub job_id: i64,
	pub job_capability: JobCapability,
	pub repo_id: i64,
	pub recipe: SurveyRecipe,
	pub attempt: NonZeroU32,
	pub campaign_id: i64,
	/// The lease's deadlines and quotas.
	pub limits: ReviewLimits,
	/// The lease context as claimed.
	pub context: ReviewSurveyContext<Agent, Server>,
	/// The generation the pin prepared, and the commit checked out for it.
	pub generation: ReviewGeneration<Server>,
	pub commit: ReviewCommit<Repo>,
	/// The frozen profile, once published.
	pub profile: Option<FrozenReviewProfile<Agent, Server>>,
	/// Ordinary surveys' assignment batch, possibly empty.
	pub assignments: Option<ReviewAssignments<Agent>>,
	/// Remaining capacity read after the pin.
	pub phase_limits: PhaseLimitsResponse,
	/// The pinned checkout the agent reads.
	pub worktree: CheckedOutWorktree,
}

impl PreparedSurvey {
	/// Whether the generation has a published profile; only a bootstrap can
	/// lack one.
	pub fn profile_published(&self) -> bool {
		self.profile.is_some() || self.recipe != SurveyRecipe::Bootstrap
	}
}

impl std::fmt::Debug for PreparedSurvey {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("PreparedSurvey([redacted])")
	}
}

impl PreparedSurvey {
	/// The phase-call context of this attempt, bounded by its hard deadline.
	pub fn phase_job(&self) -> PhaseJob<'_> {
		PhaseJob {
			job_id: self.job_id,
			capability: &self.job_capability,
			deadline: at(self.limits.hard_deadline_at),
		}
	}
}

// debug-ok: redacted survey state or no content.
#[derive(Debug)]
pub enum Preparation {
	Ready(Box<PreparedSurvey>),
	/// The server deferred the pin and already ended the job: there is
	/// nothing to complete.
	Deferred,
}

/// Prepare one survey attempt for `env`. Corroboration surveys and leases
/// past their hard deadline fail closed before any repository access.
pub async fn prepare(
	runner: &Runner, env: LeaseEnvelope<Agent, Server>, security: &JobSecurity,
	cancel: &CancellationToken,
) -> Result<Preparation, PrepareError> {
	let LeaseEnvelope {
		job_id,
		job_capability,
		repo_id,
		repo,
		head_branch,
		github_pat,
		payload,
		..
	} = env;
	let LeasePayload::ReviewSurvey(lease) = payload else {
		return Err(PrepareError::UnsupportedLease);
	};
	let ReviewSurveyLease { provenance, context } = *lease;
	let recipe = match &context {
		ReviewSurveyContext::Bootstrap { .. } => SurveyRecipe::Bootstrap,
		ReviewSurveyContext::ResolveTarget {} => SurveyRecipe::ResolveTarget,
		ReviewSurveyContext::Ordinary { ordinary_recipe, .. } => {
			SurveyRecipe::Ordinary(*ordinary_recipe)
		},
		ReviewSurveyContext::Corroboration { .. } => return Err(PrepareError::UnsupportedLease),
	};
	let limits = provenance.limits;
	let job =
		PhaseJob { job_id, capability: &job_capability, deadline: at(limits.hard_deadline_at) };
	let revision = match &context {
		ReviewSurveyContext::Bootstrap { target: BootstrapTarget::Pinned { generation, .. } }
		| ReviewSurveyContext::Ordinary { generation, .. } => Some(generation.commit_sha.expose()),
		_ => None,
	};
	let source = CheckoutSource {
		repo: &repo,
		github_pat,
		branch: head_branch.as_ref().map(|branch| branch.expose()),
		revision,
	};
	let observe =
		if recipe == SurveyRecipe::Bootstrap { Observe::Inventory } else { Observe::Commit };
	let Pinned { worktree, commit, inventory, response } =
		checkout_and_pin(runner, &job, source, observe, security, cancel).await?;
	let (generation, profile, assignments) = match response {
		PinTargetResponse::Prepared { generation, profile, assignments, .. } => {
			(generation, profile, assignments)
		},
		PinTargetResponse::Deferred { .. } => return Ok(Preparation::Deferred),
	};

	let client = runner.client();
	if let Some(inventory) = &inventory {
		upload(client, &job, security, inventory, cancel).await?;
	}
	let profile = profile.or_else(|| match &context {
		ReviewSurveyContext::Bootstrap {
			target: BootstrapTarget::Pinned { published_profile, .. },
		} => published_profile.clone(),
		_ => None,
	});
	let phase_limits = client.limits(&job).await?;
	Ok(Preparation::Ready(Box::new(PreparedSurvey {
		job_id,
		job_capability: job_capability.clone(),
		repo_id,
		recipe,
		attempt: provenance.attempt,
		campaign_id: provenance.campaign_id.into(),
		limits,
		context,
		generation,
		commit,
		profile,
		assignments,
		phase_limits,
		worktree,
	})))
}

/// Where a phase attempt's checkout comes from.
pub(crate) struct CheckoutSource<'a> {
	pub repo: &'a RepoSpec<Server>,
	pub github_pat: Option<Secret<String>>,
	pub branch: Option<&'a str>,
	/// The commit to check out; `None` follows the branch tip.
	pub revision: Option<&'a str>,
}

/// What to read from the checked-out commit before the pin.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Observe {
	Commit,
	Inventory,
}

/// A checkout the server accepted as the job's target.
pub(crate) struct Pinned {
	pub worktree: CheckedOutWorktree,
	pub commit: ReviewCommit<Repo>,
	/// Present when [`Observe::Inventory`] was asked for.
	pub inventory: Option<Inventory>,
	/// The pin response; a `Prepared` generation always names `commit`.
	pub response: PinTargetResponse<Agent, Server>,
}

/// Check out the job's target (recloning once on failure), enforce the
/// workdir cap, observe the commit, and pin it. Fails closed past the
/// job's hard deadline before any repository access.
pub(crate) async fn checkout_and_pin(
	runner: &Runner, job: &PhaseJob<'_>, source: CheckoutSource<'_>, observe: Observe,
	security: &JobSecurity, cancel: &CancellationToken,
) -> Result<Pinned, PrepareError> {
	if SystemTime::now() >= job.deadline {
		return Err(PrepareError::HardDeadline);
	}
	let cancelled = || if cancel.is_cancelled() { Err(PrepareError::Cancelled) } else { Ok(()) };
	let CheckoutSource { repo, github_pat, branch, revision: target } = source;

	cancelled()?;
	let mut cached = LeaseRepo::ensure(runner.cache(), repo, github_pat)
		.await
		.map_err(|_| PrepareError::Checkout)?;
	let checkout = |bare: std::path::PathBuf| async move {
		match target {
			Some(sha) => checkout_revision(&bare, sha).await,
			None => checkout_latest(&bare, branch).await,
		}
	};
	let (worktree, revision) = match checkout(cached.path().to_owned()).await {
		Ok(done) => done,
		Err(_) => {
			cached = cached.reclone().await.map_err(|_| PrepareError::Checkout)?;
			checkout(cached.path().to_owned()).await.map_err(|_| PrepareError::Checkout)?
		},
	};
	runner
		.enforce_workdir_cap(crate::repo_cache::dir_size(worktree.path()))
		.map_err(|_| PrepareError::WorkdirTooLarge)?;

	cancelled()?;
	// Enumerated from the bare clone while this job still holds its pin.
	let bare = cached.path().to_owned();
	let sha = revision.expose().to_owned();
	let (commit, inventory) = tokio::task::spawn_blocking(move || match observe {
		Observe::Inventory => {
			let inventory = observe_commit(&bare, &sha, InventoryDecoder)?;
			Ok((inventory.commit().clone(), Some(inventory)))
		},
		Observe::Commit => {
			Ok::<_, InventoryError>((observe_commit(&bare, &sha, CommitDecoder)?, None))
		},
	})
	.await
	.map_err(|_| PrepareError::Internal)??;
	let worktree = cached.pin(worktree);
	cancelled()?;

	let pin = PinTargetRequest { protocol_version: ReviewProtocol, commit_sha: commit.clone() };
	let response = guarded(security, Operation::PinTarget, runner.client().pin_target(job, &pin))
		.await?
		.map_err(|error| match error {
			PhaseError::Rejected {
				status: 409, code: ReviewErrorCode::CheckoutConflict, ..
			} => PrepareError::CheckoutConflict,
			other => PrepareError::Phase(other),
		})?;
	if let PinTargetResponse::Prepared { generation, .. } = &response
		&& generation.commit_sha.expose() != commit.expose()
	{
		return Err(PrepareError::CheckoutConflict);
	}
	Ok(Pinned { worktree, commit, inventory, response })
}

/// Send chunk 0, continue from the server's received prefix, and seal.
/// A byte-identical chunk inside the received range only reports progress.
async fn upload(
	client: &ServerClient, job: &PhaseJob<'_>, security: &JobSecurity, inventory: &Inventory,
	cancel: &CancellationToken,
) -> Result<(), PrepareError> {
	let ranges = inventory.chunks();
	let mut next = 0;
	loop {
		if cancel.is_cancelled() {
			return Err(PrepareError::Cancelled);
		}
		let range = ranges.get(next).ok_or(PrepareError::ManifestMismatch)?.clone();
		let batch = inventory.batch(range);
		let progress =
			guarded(security, Operation::UploadInventory, client.inventory_batch(job, &batch))
				.await??;
		check(&progress, inventory)?;
		if progress.sealed {
			return Ok(());
		}
		if progress.received_entry_count == inventory.len() {
			break;
		}
		let received = usize::try_from(progress.received_entry_count)
			.map_err(|_| PrepareError::ManifestMismatch)?;
		// Each call must extend the prefix to a later chunk boundary.
		next = ranges
			.iter()
			.position(|range| range.start == received)
			.filter(|position| *position > next)
			.ok_or(PrepareError::ManifestMismatch)?;
	}
	let sealed = guarded(security, Operation::SealInventory, client.seal_inventory(job)).await??;
	check(&sealed, inventory)?;
	if !sealed.sealed {
		return Err(PrepareError::ManifestMismatch);
	}
	Ok(())
}

fn check(progress: &ManifestProgress<Server>, inventory: &Inventory) -> Result<(), PrepareError> {
	if progress.expected_entry_count != inventory.len()
		|| progress.expected_digest.expose() != inventory.digest().expose()
		|| progress.received_entry_count > inventory.len()
	{
		return Err(PrepareError::ManifestMismatch);
	}
	Ok(())
}

/// Run one phase call under the job's security admission, keeping its
/// typed error.
async fn guarded<T>(
	security: &JobSecurity, operation: Operation,
	call: impl std::future::Future<Output = Result<T, PhaseError>>,
) -> Result<Result<T, PhaseError>, PrepareError> {
	security
		.run(operation, async { Ok::<_, std::convert::Infallible>(call.await) })
		.await
		.map_err(|_| PrepareError::Quarantined)
}

pub(crate) fn at(epoch_seconds: i64) -> SystemTime {
	UNIX_EPOCH + Duration::from_secs(u64::try_from(epoch_seconds).unwrap_or(0))
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use loupe_proto::LeaseResponse;
	use serde_json::json;

	use super::*;
	use crate::repo_cache::RepoCache;

	fn lease(context: serde_json::Value, hard_deadline_at: i64) -> LeaseEnvelope<Agent, Server> {
		lease_from(context, hard_deadline_at, "file:///nonexistent/missing")
	}

	fn lease_from(
		context: serde_json::Value, hard_deadline_at: i64, clone_url: &str,
	) -> LeaseEnvelope<Agent, Server> {
		let body = json!({"kind":"lease","protocol_version":3,"job_id":1,
			"job_capability":"test-capability","repo_id":1,
			"repo":{"host":"invalid.test","owner":"test","repo":"test","clone_url":clone_url},
			"head_branch":null,"lease_expires_at":200,"scanner_config":null,
			"payload":{"kind":"review_survey","provenance":{"workflow_contract_version":1,
				"campaign_id":2,"attempt":1,"limits":{"soft_deadline_at":100,"submit_by":100,
				"hard_deadline_at":hard_deadline_at,"token_budget":null,"new_unit_limit":32,
				"lead_limit":16,"sibling_limit":4}},"context":context}});
		let LeaseResponse::Lease(env) =
			crate::client::test_lease(body.to_string().as_bytes()).response
		else {
			panic!("lease fixture")
		};
		*env
	}

	#[tokio::test]
	async fn corroboration_and_expired_leases_never_touch_the_repository() {
		let cache_dir = tempfile::tempdir().unwrap();
		let cache = Arc::new(RepoCache::new(cache_dir.path().join("cache"), 1024, None).unwrap());
		let client = Arc::new(ServerClient::from_parts(
			reqwest::Client::new(),
			"http://127.0.0.1:9/".parse().unwrap(),
		));
		let runner = Runner::new(client, cache, Vec::new());
		let security = JobSecurity::new(Default::default(), vec![]).unwrap();
		let future = i64::MAX / 2;
		let corroboration = json!({"recipe":"corroboration",
			"generation":{"generation_id":3,"commit_sha":"a".repeat(40)},"assignments":[]});
		let error =
			prepare(&runner, lease(corroboration, future), &security, &CancellationToken::new())
				.await
				.unwrap_err();
		assert!(matches!(error, PrepareError::UnsupportedLease), "{error}");
		let bootstrap = json!({"recipe":"bootstrap","target":{"kind":"unresolved"}});
		let error = prepare(&runner, lease(bootstrap, 1), &security, &CancellationToken::new())
			.await
			.unwrap_err();
		assert!(matches!(error, PrepareError::HardDeadline), "{error}");
		let cached = std::fs::read_dir(cache_dir.path().join("cache")).map(|dir| dir.count());
		assert!(matches!(cached, Ok(0) | Err(_)), "repository cache was touched");
	}

	/// A one-commit origin on `main`.
	fn origin() -> (tempfile::TempDir, String) {
		let dir = tempfile::tempdir().unwrap();
		let mut options = git2::RepositoryInitOptions::new();
		options.initial_head("main");
		let repo = git2::Repository::init_opts(dir.path().join("origin"), &options).unwrap();
		let blob = repo.blob(b"fn main() {}\n").unwrap();
		let mut tree = repo.treebuilder(None).unwrap();
		tree.insert("main.rs", blob, 0o100644).unwrap();
		let tree = repo.find_tree(tree.write().unwrap()).unwrap();
		let sig = git2::Signature::now("loupe-test", "loupe-test@example.com").unwrap();
		repo.commit(Some("refs/heads/main"), &sig, &sig, "fixture", &tree, &[]).unwrap();
		let url = format!("file://{}", dir.path().join("origin").display());
		(dir, url)
	}

	/// Answers every request with `status` and `body`, counting requests.
	async fn server(
		status: u16, body: String,
	) -> (reqwest::Url, Arc<std::sync::atomic::AtomicUsize>) {
		use tokio::io::{AsyncReadExt, AsyncWriteExt};
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let base = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
		let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
		let seen = count.clone();
		tokio::spawn(async move {
			loop {
				let (mut stream, _) = listener.accept().await.unwrap();
				let mut request = Vec::new();
				loop {
					let mut buf = [0; 8192];
					let read = stream.read(&mut buf).await.unwrap();
					request.extend_from_slice(&buf[..read]);
					let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
						if read == 0 {
							break;
						}
						continue;
					};
					let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
					let length: usize = head
						.lines()
						.find_map(|line| line.strip_prefix("content-length:"))
						.map_or(0, |value| value.trim().parse().unwrap());
					if request.len() >= end + 4 + length || read == 0 {
						break;
					}
				}
				seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
				let response = format!(
					"HTTP/1.1 {status} X\r\nX-Loupe-Protocol: 3\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
					body.len()
				);
				let _ = stream.write_all(response.as_bytes()).await;
			}
		});
		(base, count)
	}

	fn runner(base: reqwest::Url, cache: &std::path::Path) -> Runner {
		let cache = Arc::new(RepoCache::new(cache.to_owned(), u64::MAX, None).unwrap());
		Runner::new(
			Arc::new(ServerClient::from_parts(reqwest::Client::new(), base)),
			cache,
			Vec::new(),
		)
	}

	fn unresolved() -> serde_json::Value {
		json!({"recipe":"bootstrap","target":{"kind":"unresolved"}})
	}

	#[tokio::test]
	async fn a_pin_prepared_for_another_commit_is_a_checkout_conflict() {
		let (_origin, url) = origin();
		let other = json!({"outcome":"prepared","protocol_version":3,
			"generation":{"generation_id":3,"commit_sha":"f".repeat(40)},
			"profile":null,"assignments":null});
		let (base, requests) = server(200, other.to_string()).await;
		let cache = tempfile::tempdir().unwrap();
		let runner = runner(base, cache.path());
		let security = JobSecurity::new(Default::default(), vec![]).unwrap();
		let lease = lease_from(unresolved(), i64::MAX / 2, &url);
		let error =
			prepare(&runner, lease, &security, &CancellationToken::new()).await.unwrap_err();
		assert!(matches!(error, PrepareError::CheckoutConflict), "{error}");
		assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1, "only the pin was sent");
	}

	#[tokio::test]
	async fn a_cancelled_job_stops_before_the_repository_and_the_server() {
		let (_origin, url) = origin();
		let (base, requests) = server(500, String::new()).await;
		let cache = tempfile::tempdir().unwrap();
		let runner = runner(base, &cache.path().join("cache"));
		let security = JobSecurity::new(Default::default(), vec![]).unwrap();
		let cancel = CancellationToken::new();
		cancel.cancel();
		let lease = lease_from(unresolved(), i64::MAX / 2, &url);
		let error = prepare(&runner, lease, &security, &cancel).await.unwrap_err();
		assert!(matches!(error, PrepareError::Cancelled), "{error}");
		assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0);
		let cached = std::fs::read_dir(cache.path().join("cache")).map(|dir| dir.count());
		assert!(matches!(cached, Ok(0) | Err(_)), "repository cache was touched");
	}
}
