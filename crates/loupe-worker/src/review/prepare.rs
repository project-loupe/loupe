//! Host preparation of one survey attempt: check out the target, pin it,
//! upload and seal the bootstrap inventory, and read the job's limits.
//! Nothing here runs an agent.

use std::num::NonZeroU32;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use loupe_core::review_metadata::ReviewCommit;
use loupe_core::security_event::Operation;
use loupe_proto::review_api::{
	ManifestProgress, PhaseLimitsResponse, PinTargetRequest, PinTargetResponse, ReviewErrorCode,
	ReviewProtocol,
};
use loupe_proto::review_lease::{
	BootstrapTarget, FrozenReviewProfile, OrdinarySurveyRecipe, ReviewAssignments,
	ReviewGeneration, ReviewLimits, ReviewSurveyContext, ReviewSurveyLease,
};
use loupe_proto::{JobCapability, LeaseEnvelope, LeasePayload};
use loupe_provenance::{Agent, Repo, Server};

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
	/// A bootstrap whose profile is not published yet.
	pub needs_profile: bool,
	/// Remaining capacity read after the pin.
	pub phase_limits: PhaseLimitsResponse,
	/// The pinned checkout the agent reads.
	pub worktree: CheckedOutWorktree,
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
	let hard_deadline = at(limits.hard_deadline_at);
	if SystemTime::now() >= hard_deadline {
		return Err(PrepareError::HardDeadline);
	}
	let job = PhaseJob { job_id, capability: &job_capability, deadline: hard_deadline };
	let target = match &context {
		ReviewSurveyContext::Bootstrap { target: BootstrapTarget::Pinned { generation, .. } }
		| ReviewSurveyContext::Ordinary { generation, .. } => Some(generation.commit_sha.expose()),
		_ => None,
	};

	let mut cached = LeaseRepo::ensure(runner.cache(), &repo, github_pat)
		.await
		.map_err(|_| PrepareError::Checkout)?;
	let branch = head_branch.as_ref().map(|branch| branch.expose());
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

	// Enumerated from the bare clone while this job still holds its pin.
	let bare = cached.path().to_owned();
	let sha = revision.expose().to_owned();
	let bootstrap = recipe == SurveyRecipe::Bootstrap;
	let (commit, inventory) = tokio::task::spawn_blocking(move || {
		if bootstrap {
			let inventory = observe_commit(&bare, &sha, InventoryDecoder)?;
			Ok((inventory.commit().clone(), Some(inventory)))
		} else {
			Ok::<_, InventoryError>((observe_commit(&bare, &sha, CommitDecoder)?, None))
		}
	})
	.await
	.map_err(|_| PrepareError::Checkout)??;
	let worktree = cached.pin(worktree);

	let client = runner.client();
	let pin = PinTargetRequest { protocol_version: ReviewProtocol, commit_sha: commit.clone() };
	let pinned = guarded(security, Operation::PinTarget, client.pin_target(&job, &pin))
		.await?
		.map_err(|error| match error {
			PhaseError::Rejected {
				status: 409, code: ReviewErrorCode::CheckoutConflict, ..
			} => PrepareError::CheckoutConflict,
			other => PrepareError::Phase(other),
		})?;
	let (generation, profile, assignments) = match pinned {
		PinTargetResponse::Prepared { generation, profile, assignments, .. } => {
			(generation, profile, assignments)
		},
		PinTargetResponse::Deferred { .. } => return Ok(Preparation::Deferred),
	};

	if let Some(inventory) = &inventory {
		upload(client, &job, security, inventory).await?;
	}
	let profile = profile.or_else(|| match &context {
		ReviewSurveyContext::Bootstrap {
			target: BootstrapTarget::Pinned { published_profile, .. },
		} => published_profile.clone(),
		_ => None,
	});
	let needs_profile = bootstrap && profile.is_none();
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
		needs_profile,
		phase_limits,
		worktree,
	})))
}

/// Send chunk 0, continue from the server's received prefix, and seal.
/// A byte-identical chunk inside the received range only reports progress.
async fn upload(
	client: &ServerClient, job: &PhaseJob<'_>, security: &JobSecurity, inventory: &Inventory,
) -> Result<(), PrepareError> {
	let ranges = inventory.chunks();
	let mut next = 0;
	loop {
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

fn at(epoch_seconds: i64) -> SystemTime {
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
		let body = json!({"kind":"lease","protocol_version":3,"job_id":1,
			"job_capability":"test-capability","repo_id":1,
			"repo":{"host":"invalid.test","owner":"test","repo":"test","clone_url":"file:///nonexistent/missing"},
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
		let error = prepare(&runner, lease(corroboration, future), &security).await.unwrap_err();
		assert!(matches!(error, PrepareError::UnsupportedLease), "{error}");
		let bootstrap = json!({"recipe":"bootstrap","target":{"kind":"unresolved"}});
		let error = prepare(&runner, lease(bootstrap, 1), &security).await.unwrap_err();
		assert!(matches!(error, PrepareError::HardDeadline), "{error}");
		let cached = std::fs::read_dir(cache_dir.path().join("cache")).map(|dir| dir.count());
		assert!(matches!(cached, Ok(0) | Err(_)), "repository cache was touched");
	}
}
