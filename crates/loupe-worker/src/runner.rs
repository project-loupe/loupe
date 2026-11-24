//! Worker runner loop: lease → ensure_repo → checkout → scan → submit → complete.
//!
//! The runner long-polls for scan or verify jobs, checks out a fresh
//! worktree, runs the matching scanner, submits any in-process findings
//! or verdicts, and completes the lease.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use loupe_core::security_event::Operation;
use loupe_core::text::policy::RevisionText;
use loupe_core::text::BoundedText;
use loupe_proto::{
	CompleteOutcome, JobCapability, LeaseEnvelope, LeasePayload, LeaseResponse, PROTOCOL_VERSION,
};
use loupe_provenance::{Agent, Ingress, Repo, Server, Untrusted};
use tokio_util::sync::CancellationToken;

use crate::client::ServerClient;
use crate::host_outcome::{CheckoutFailure, HostVerifyReason, ReviewedRevisionFact};
use crate::repo_cache::{RepoCache, RepoKey};
use crate::scanner::Scanner;
#[cfg(test)]
use crate::scanner::{ScanContext, VerifyContext};
mod legacy;
mod repo_ingress;
#[cfg(fuzzing)]
pub use repo_ingress::fuzz_support as fuzz_repo;

/// How often the runner heartbeat-pings during a long scan.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);
/// Long-poll budget on `POST /v1/jobs/lease`. Tuned just under the
/// typical proxy idle timeout so a TCP connection won't get killed
/// mid-wait. The server still answers immediately if a job is already
/// queued, so this doesn't cost anything when the queue is hot.
const LEASE_WAIT_SECONDS: u32 = 25;
/// Default ceiling on the worktree size; 5 GB matches the bkb-ingest
/// per-repo default. The runner fails the job rather than fill the
/// worker host. Operators can override per-runner.
pub const DEFAULT_MAX_WORKDIR_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// Successful repository checkout, retained independently of each scanner task.
/// Its constructor is private to the actual checkout owner below.
#[derive(Clone)]
pub struct CheckedOutWorktree {
	directory: Arc<tempfile::TempDir>,
	pin: Option<Arc<crate::repo_cache::PinGuard>>,
}
impl std::fmt::Debug for CheckedOutWorktree {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("CheckedOutWorktree([redacted])")
	}
}
impl CheckedOutWorktree {
	pub fn path(&self) -> &Path {
		self.directory.path()
	}
	fn pinned(mut self, pin: crate::repo_cache::PinGuard) -> Self {
		self.pin = Some(Arc::new(pin));
		self
	}
	pub fn sandbox_path(&self) -> crate::sandbox::SandboxPath {
		crate::sandbox::SandboxPath::checkout(self)
	}
}

#[derive(serde::Serialize)]
#[serde(untagged)]
pub(crate) enum CompletionRevision {
	CheckedOut(BoundedText<RevisionText, Repo>),
	Reviewed(BoundedText<RevisionText, Server>),
}

/// The original error (including any typed diagnostic cause) stays alive
/// until the named completion serializer intentionally displays it.
struct CompletionDiagnostic(anyhow::Error);
impl serde::Serialize for CompletionDiagnostic {
	fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		serializer.collect_str(&self.0)
	}
}
#[derive(serde::Serialize)]
pub(crate) struct RunnerCompletion {
	protocol_version: u16,
	outcome: CompleteOutcome,
	#[serde(skip_serializing_if = "Option::is_none")]
	head_sha: Option<CompletionRevision>,
	#[serde(skip_serializing_if = "Option::is_none")]
	error: Option<CompletionDiagnostic>,
}

/// A lease's repository in the bare cache, pinned against eviction
/// while a job uses it.
pub(crate) struct LeaseRepo {
	cache: Arc<RepoCache>,
	key: RepoKey,
	clone_url: BoundedText<loupe_core::text::policy::CloneUrl, Server>,
	github_pat: Option<Arc<loupe_provenance::Secret<String>>>,
	ensured: crate::repo_cache::EnsuredRepo,
}

impl LeaseRepo {
	/// Refresh (or clone) the lease's repository into the cache.
	pub(crate) async fn ensure(
		cache: &Arc<RepoCache>, repo: &loupe_core::RepoSpec<Server>,
		github_pat: Option<loupe_provenance::Secret<String>>,
	) -> Result<Self> {
		let key = RepoKey::new(repo.host.expose(), repo.owner.expose(), repo.repo.expose())?;
		let clone_url = repo.clone_url.clone();
		let github_pat = github_pat.map(Arc::new);
		let ensured = cache.ensure_repo(&key, clone_url.expose(), github_pat.as_ref()).await?;
		Ok(Self { cache: cache.clone(), key, clone_url, github_pat, ensured })
	}

	/// Path of the bare cache clone.
	pub(crate) fn path(&self) -> &Path {
		&self.ensured.path
	}

	/// Discard the cached clone and clone it afresh. The current pin is
	/// released first so the cache may replace the entry.
	pub(crate) async fn reclone(self) -> Result<Self> {
		let Self { cache, key, clone_url, github_pat, ensured } = self;
		drop(ensured);
		let ensured = cache.reclone_repo(&key, clone_url.expose(), github_pat.as_ref()).await?;
		Ok(Self { cache, key, clone_url, github_pat, ensured })
	}

	/// Hand the cache pin to a worktree checked out from this clone.
	pub(crate) fn pin(self, worktree: CheckedOutWorktree) -> CheckedOutWorktree {
		worktree.pinned(self.ensured._pin)
	}
}

/// The agent backend of each review phase this worker runs.
#[derive(Default)]
struct PhaseBackends {
	survey: Option<Arc<dyn crate::llm::LlmBackend>>,
	drilldown: Option<Arc<dyn crate::llm::LlmBackend>>,
}

impl PhaseBackends {
	fn for_payload(
		&self, payload: &LeasePayload<Agent, Server>,
	) -> Option<&Arc<dyn crate::llm::LlmBackend>> {
		match payload {
			LeasePayload::ReviewSurvey(_) => self.survey.as_ref(),
			LeasePayload::ReviewDrilldown(_) => self.drilldown.as_ref(),
			LeasePayload::ReviewVerify(_)
			| LeasePayload::Scan { .. }
			| LeasePayload::Verify { .. } => None,
		}
	}

	fn capabilities(&self) -> Vec<loupe_proto::review_lease::ReviewCapability> {
		use loupe_proto::review_lease::ReviewCapability;
		[
			self.survey.as_ref().map(|_| ReviewCapability::Survey),
			self.drilldown.as_ref().map(|_| ReviewCapability::Drilldown),
		]
		.into_iter()
		.flatten()
		.collect()
	}
}

pub struct Runner {
	client: Arc<ServerClient>,
	cache: Arc<RepoCache>,
	scanners: Vec<Arc<dyn Scanner>>,
	capabilities: Vec<&'static str>,
	max_workdir_bytes: u64,
	credential_watches: Vec<crate::llm::model_broker::CredentialWatch>,
	/// A phase without its backend is not advertised, and its leases fail
	/// closed.
	phase_backends: PhaseBackends,
	phase_clock: crate::review::session::Clock,
}

impl Runner {
	pub fn new(
		client: Arc<ServerClient>, cache: Arc<RepoCache>, scanners: Vec<Arc<dyn Scanner>>,
	) -> Self {
		let capabilities: Vec<&'static str> =
			scanners.iter().flat_map(|s| s.capabilities().iter().copied()).collect();
		Self {
			client,
			cache,
			scanners,
			capabilities,
			max_workdir_bytes: DEFAULT_MAX_WORKDIR_BYTES,
			credential_watches: Vec::new(),
			phase_backends: PhaseBackends::default(),
			phase_clock: Arc::new(std::time::SystemTime::now),
		}
	}

	/// Run survey leases with `backend`.
	pub fn with_survey_backend(mut self, backend: Arc<dyn crate::llm::LlmBackend>) -> Self {
		self.phase_backends.survey = Some(backend);
		self
	}

	/// Run drilldown leases with `backend`.
	pub fn with_drilldown_backend(mut self, backend: Arc<dyn crate::llm::LlmBackend>) -> Self {
		self.phase_backends.drilldown = Some(backend);
		self
	}

	pub(crate) fn phase_clock(&self) -> &crate::review::session::Clock {
		&self.phase_clock
	}

	/// Replace the clock phase sessions read their deadlines against.
	#[cfg(any(test, feature = "test-support"))]
	pub fn with_phase_clock(mut self, clock: crate::review::session::Clock) -> Self {
		self.phase_clock = clock;
		self
	}
	pub fn with_credential_watches(
		mut self, watches: Vec<crate::llm::model_broker::CredentialWatch>,
	) -> Self {
		self.credential_watches = watches;
		self
	}

	/// Override the per-job workdir size cap. A scan whose checkout
	/// exceeds this size fails immediately; the host's disk stays safe.
	pub fn with_max_workdir_bytes(mut self, bytes: u64) -> Self {
		self.max_workdir_bytes = bytes;
		self
	}

	/// Review phases this worker runs: survey and drilldown, each exactly
	/// when it has a backend. Verify is not run, so never advertised.
	fn review_capabilities(
		&self,
	) -> Result<loupe_proto::review_lease::LeaseList<loupe_proto::review_lease::ReviewCapability, 3>>
	{
		loupe_proto::review_lease::LeaseList::new(self.phase_backends.capabilities())
			.map_err(|error| anyhow::anyhow!(error))
	}

	pub(crate) fn client(&self) -> &ServerClient {
		&self.client
	}

	pub(crate) fn cache(&self) -> &Arc<RepoCache> {
		&self.cache
	}

	/// Fail a job whose checkout exceeds the per-job workdir size cap.
	pub(crate) fn enforce_workdir_cap(&self, workdir_size: u64) -> Result<()> {
		if workdir_size > self.max_workdir_bytes {
			anyhow::bail!(
				"checkout size {workdir_size} bytes exceeds max_workdir_bytes {}",
				self.max_workdir_bytes
			);
		}
		Ok(())
	}

	/// Run one iteration: long-poll for a job and, if one arrives, run
	/// it. Returns `true` if a job was processed, `false` if the long-
	/// poll window elapsed without one.
	pub async fn step(&self, cancel: &CancellationToken) -> Result<bool> {
		let receipt = self
			.client
			.lease_with(self.capabilities.clone(), self.review_capabilities()?, LEASE_WAIT_SECONDS)
			.await?;
		match receipt.response {
			LeaseResponse::Empty { .. } => Ok(false),
			LeaseResponse::Lease(env) => {
				self.run_lease(*env, receipt.reviewed_revision, receipt.scanner_patch, cancel)
					.await?;
				Ok(true)
			},
		}
	}

	/// Run forever until cancelled. The server's long-poll absorbs idle
	/// time, so the worker only has to back off on errors.
	pub async fn run_forever(&self, cancel: CancellationToken) -> Result<()> {
		while !cancel.is_cancelled() {
			match self.step(&cancel).await {
				Ok(_) => {},
				Err(_) => {
					tracing::warn!("runner step failed; backing off");
					tokio::select! {
						_ = tokio::time::sleep(Duration::from_secs(5)) => {},
						_ = cancel.cancelled() => break,
					}
				},
			}
		}
		Ok(())
	}

	async fn run_lease(
		&self, env: LeaseEnvelope<Agent, Server>, reviewed_revision: ReviewedRevisionFact,
		scanner_patch: Option<crate::source_discovery::ScannerConfigPatch>,
		cancel: &CancellationToken,
	) -> Result<()> {
		let job_id = env.job_id;
		let job_capability = env.job_capability.clone();
		tracing::info!(job_id, "leased job");
		let scan_cancel = cancel.child_token();
		let security = crate::canary::JobSecurity::new(
			loupe_core::security_event::EventContext {
				job_id: Some(job_id),
				repo_id: Some(env.repo_id),
				..Default::default()
			},
			self.credential_watches.clone(),
		)?;
		let (heartbeat, phase_heartbeat) = match self.phase_hard_deadline(&env) {
			Some(deadline) => {
				let phase = PhaseHeartbeat::new(scan_cancel.child_token());
				let task =
					self.spawn_phase_heartbeat(job_id, job_capability.clone(), deadline, &phase);
				(task, Some(phase))
			},
			None => {
				(self.spawn_heartbeat(job_id, job_capability.clone(), scan_cancel.clone()), None)
			},
		};
		let execution_cancel = scan_cancel.child_token();
		let task_cancel = execution_cancel.clone();
		let quarantine_cancel = security.cancellation();
		let cancellation = tokio::spawn(async move {
			tokio::select! {
				biased;
				_ = quarantine_cancel.cancelled() => task_cancel.cancel(),
				_ = task_cancel.cancelled() => {},
			}
		});

		let outcome = self
			.execute(
				env,
				reviewed_revision,
				scanner_patch,
				execution_cancel.clone(),
				security.clone(),
				phase_heartbeat,
			)
			.await;
		// Heartbeat cleanup cancels this token even after a healthy execution.
		let execution_cancelled = execution_cancel.is_cancelled();

		// Stop the heartbeat task before completing — otherwise it might
		// race the complete and turn into a 403.
		scan_cancel.cancel();
		let _ = heartbeat.await;
		let _ = cancellation.await;
		let outcome = match outcome {
			Ok(Executed::Reported) => return Ok(()),
			Ok(Executed::Legacy(head_sha)) => Ok(head_sha),
			Err(error) => Err(error),
		};
		let outcome = if security.is_quarantined() {
			Err(crate::canary::JobQuarantined.into())
		} else if execution_cancelled || cancel.is_cancelled() {
			Err(anyhow::anyhow!("job cancelled"))
		} else {
			outcome
		};

		match outcome {
			Ok(head_sha) => {
				let req = RunnerCompletion {
					protocol_version: PROTOCOL_VERSION,
					outcome: CompleteOutcome::Succeeded,
					head_sha,
					error: None,
				};
				if let Err(error) = security
					.run(
						Operation::CompleteJob,
						self.client.complete_runner(job_id, &job_capability, &req),
					)
					.await
				{
					if security.is_quarantined() {
						self.complete_failed(
							job_id,
							&job_capability,
							crate::canary::JobQuarantined.into(),
						)
						.await;
						return Ok(());
					}
					return Err(error);
				}
				tracing::info!(job_id, "job succeeded");
			},
			Err(e) => {
				self.complete_failed(job_id, &job_capability, e).await;
			},
		}
		Ok(())
	}

	async fn complete_failed(&self, job_id: i64, capability: &JobCapability, error: anyhow::Error) {
		tracing::warn!(job_id, "job failed");
		let req = RunnerCompletion {
			protocol_version: PROTOCOL_VERSION,
			outcome: CompleteOutcome::Failed,
			head_sha: None,
			error: Some(CompletionDiagnostic(error)),
		};
		// The host completion authority remains available after quarantine.
		if self.client.complete_runner(job_id, capability, &req).await.is_err() {
			tracing::warn!(job_id, "complete(Failed) call failed too");
		}
	}

	/// Dispatch one lease to the handler for its payload.
	async fn execute(
		&self, env: LeaseEnvelope<Agent, Server>, reviewed_revision: ReviewedRevisionFact,
		scanner_patch: Option<crate::source_discovery::ScannerConfigPatch>,
		cancel: CancellationToken, security: Arc<crate::canary::JobSecurity>,
		heartbeat: Option<PhaseHeartbeat>,
	) -> Result<Executed> {
		anyhow::ensure!(!cancel.is_cancelled(), "job cancelled");
		match (&env.payload, self.phase_backends.for_payload(&env.payload), heartbeat) {
			(LeasePayload::ReviewSurvey(_), Some(backend), Some(heartbeat)) => {
				crate::review::survey::run(self, backend, env, cancel, security, heartbeat).await;
				Ok(Executed::Reported)
			},
			(LeasePayload::ReviewDrilldown(_), Some(backend), Some(heartbeat)) => {
				crate::review::drilldown::run(self, backend, env, cancel, security, heartbeat)
					.await;
				Ok(Executed::Reported)
			},
			(
				LeasePayload::ReviewSurvey(_)
				| LeasePayload::ReviewDrilldown(_)
				| LeasePayload::ReviewVerify(_),
				..,
			) => self.execute_review(env).map(Executed::Legacy),
			(LeasePayload::Scan { .. } | LeasePayload::Verify { .. }, ..) => {
				legacy::run(self, env, reviewed_revision, scanner_patch, cancel, security)
					.await
					.map(Executed::Legacy)
			},
		}
	}

	/// The hard deadline of a phase lease this runner executes.
	fn phase_hard_deadline(&self, env: &LeaseEnvelope<Agent, Server>) -> Option<SystemTime> {
		self.phase_backends.for_payload(&env.payload)?;
		let limits = crate::review::phase::limits(&env.payload)?;
		Some(crate::review::prepare::at(limits.hard_deadline_at))
	}

	/// Review phase leases fail closed: an unexpected server response
	/// must not fetch repository contents.
	fn execute_review(
		&self, _env: LeaseEnvelope<Agent, Server>,
	) -> Result<Option<CompletionRevision>> {
		anyhow::bail!("review lease arrived but phase execution is not enabled");
	}

	async fn submit_revision_unavailable_verdict(
		&self, job_id: i64, job_capability: &JobCapability, finding_id: i64,
		reason: HostVerifyReason, security: &crate::canary::JobSecurity,
		cancel: &CancellationToken,
	) -> Result<()> {
		anyhow::ensure!(!cancel.is_cancelled(), "job cancelled");
		tracing::warn!(
			job_id,
			finding_id,
			"submitting terminal inconclusive verdict for unavailable verify revision",
		);
		security
			.run(
				Operation::SubmitVerdict,
				self.client.submit_host_verdict(job_id, job_capability, reason),
			)
			.await
	}

	/// The phase lease heartbeat. Its response only feeds the log; the
	/// phase handler learns of lost authority from its own calls.
	fn spawn_phase_heartbeat(
		&self, job_id: i64, job_capability: JobCapability, deadline: SystemTime,
		heartbeat: &PhaseHeartbeat,
	) -> tokio::task::JoinHandle<()> {
		let client = self.client.clone();
		let cancel = heartbeat.stop.clone();
		let stopped = heartbeat.stopped.clone();
		tokio::spawn(async move {
			let _stopped = stopped.drop_guard();
			let job = crate::client::PhaseJob { job_id, capability: &job_capability, deadline };
			loop {
				tokio::select! {
					biased;
					_ = cancel.cancelled() => return,
					result = async {
						tokio::time::sleep(HEARTBEAT_INTERVAL).await;
						client.phase_heartbeat(&job).await
					} => match result {
						Ok(response) => tracing::debug!(
							job_id,
							lease_expires_at = response.lease_expires_at,
							"phase heartbeat"
						),
						Err(_) => tracing::warn!(job_id, "phase heartbeat failed"),
					},
				}
			}
		})
	}

	fn spawn_heartbeat(
		&self, job_id: i64, job_capability: JobCapability, cancel: CancellationToken,
	) -> tokio::task::JoinHandle<()> {
		let client = self.client.clone();
		tokio::spawn(async move {
			loop {
				tokio::select! {
					biased;
					_ = cancel.cancelled() => return,
					result = async {
						tokio::time::sleep(HEARTBEAT_INTERVAL).await;
						client.heartbeat(job_id, &job_capability).await
					} => {
						if result.is_err() {
							tracing::warn!(job_id, "heartbeat failed");
						}
					},
				}
			}
		})
	}
}

/// How `execute` ended a lease that did not fail.
pub(crate) enum Executed {
	/// The legacy handler finished; the runner sends its completion.
	Legacy(Option<CompletionRevision>),
	/// A phase handler already sent the job's terminal call, if any.
	Reported,
}

/// Produce a fresh worktree from the bare clone at `bare` checked out
/// to `branch` (or the remote/default HEAD if `None`). Returns the
/// worktree dir (a `TempDir` for cleanup) plus the resolved commit SHA.
pub async fn checkout_latest(
	bare: &Path, branch: Option<&str>,
) -> Result<(CheckedOutWorktree, BoundedText<RevisionText, Repo>)> {
	checkout(bare, CheckoutTarget::Latest { branch: branch.map(str::to_owned) }).await
}

/// Produce a fresh worktree from the bare clone at `bare` checked out
/// to one exact commit SHA.
pub async fn checkout_revision(
	bare: &Path, sha: &str,
) -> Result<(CheckedOutWorktree, BoundedText<RevisionText, Repo>)> {
	checkout(bare, CheckoutTarget::Revision(sha.to_owned())).await
}

enum CheckoutTarget {
	Latest { branch: Option<String> },
	Revision(String),
}

/// Collect the gitlink paths in `tree`. A checkout materializes these
/// as empty directories, so scanners never see submodule contents.
fn submodule_paths(tree: &git2::Tree<'_>) -> Result<Vec<repo_ingress::RepositoryGitlinkPath>> {
	let mut paths = Vec::new();
	tree.walk(git2::TreeWalkMode::PreOrder, |root, entry| {
		if entry.filemode() == i32::from(git2::FileMode::Commit) {
			let name =
				repo_ingress::GitlinkName { root: root.as_bytes(), name: entry.name_bytes() };
			// SAFETY: original prefix/name bytes from this libgit2 tree callback,
			// before any worker path formatting or lossy UTF-8 display.
			#[allow(unsafe_code)]
			let name = Untrusted::new(name, unsafe { Ingress::<Repo>::new() });
			paths.push(
				name.validate(repo_ingress::RepositoryGitlinkPathDecoder)
					.expect("infallible gitlink decoding"),
			);
		}
		git2::TreeWalkResult::Ok
	})
	.context("inspecting repository submodules")?;
	Ok(paths)
}

/// One commit in a bare clone, as libgit2 reports it.
pub(crate) struct CommitObservation<'a> {
	pub(crate) repo: &'a git2::Repository,
	pub(crate) commit: &'a git2::Commit<'a>,
}

/// The commit `sha` in the bare clone at `bare`, unavailable to `decoder`
/// except as a `Repo` observation. Blocking.
pub(crate) fn observe_commit<V, T>(
	bare: &Path, sha: &str, decoder: V,
) -> Result<T, crate::review::inventory::InventoryError>
where
	V: for<'a> loupe_provenance::Validate<
		CommitObservation<'a>,
		Repo,
		Output = T,
		Error = crate::review::inventory::InventoryError,
	>,
{
	use crate::review::inventory::InventoryError;
	let repo = git2::Repository::open_bare(bare).map_err(|_| InventoryError::CommitUnavailable)?;
	let oid = git2::Oid::from_str(sha).map_err(|_| InventoryError::CommitUnavailable)?;
	let commit = repo.find_commit(oid).map_err(|_| InventoryError::CommitUnavailable)?;
	// SAFETY: the actual libgit2 repository and commit handles; every path,
	// mode and object id the decoder reads comes from them before formatting.
	#[allow(unsafe_code)]
	let observation = Untrusted::new(CommitObservation { repo: &repo, commit: &commit }, unsafe {
		Ingress::<Repo>::new()
	});
	observation.validate(decoder)
}

async fn checkout(
	bare: &Path, target: CheckoutTarget,
) -> Result<(CheckedOutWorktree, BoundedText<RevisionText, Repo>)> {
	let bare = bare.to_path_buf();
	let tmp = tempfile::tempdir().map_err(|_| CheckoutFailure::CreateWorktree)?;
	let workdir = tmp.path().to_path_buf();
	let head_sha =
		tokio::task::spawn_blocking(move || -> Result<BoundedText<RevisionText, Repo>> {
			let repo =
				git2::Repository::open_bare(&bare).map_err(|_| CheckoutFailure::OpenRepository)?;
			let commit = match target {
				CheckoutTarget::Latest { branch } => {
					let target_ref = match branch.as_deref() {
						Some(b) => repo
							.find_reference(&format!("refs/remotes/origin/{b}"))
							.or_else(|_| repo.find_reference(&format!("refs/heads/{b}")))
							.map_err(|_| CheckoutFailure::LocateBranch)?,
						None => repo
							.find_reference("refs/remotes/origin/HEAD")
							.or_else(|_| repo.find_reference("HEAD"))
							.map_err(|_| CheckoutFailure::LocateHead)?,
					};
					target_ref.peel_to_commit().map_err(|_| CheckoutFailure::ResolveReference)?
				},
				CheckoutTarget::Revision(sha) => {
					let oid =
						git2::Oid::from_str(&sha).map_err(|_| CheckoutFailure::ParseRevision)?;
					let object =
						repo.find_object(oid, None).map_err(|_| CheckoutFailure::LocateRevision)?;
					object.peel_to_commit().map_err(|_| CheckoutFailure::ResolveRevision)?
				},
			};
			let tree = commit.tree().map_err(|_| CheckoutFailure::ResolveTree)?;
			// Diagnostics only: never fail a checkout over the warning.
			match submodule_paths(&tree) {
				Ok(paths) if !paths.is_empty() => {
					let count = paths.len();
					let path_bytes = paths
						.iter()
						.map(repo_ingress::RepositoryGitlinkPath::byte_count)
						.sum::<usize>();
					tracing::warn!(
						submodule_count = count,
						submodule_path_bytes = path_bytes,
						"checkout leaves submodules unpopulated; their contents are not scanned",
					);
				},
				Ok(_) => {},
				Err(_) => tracing::debug!("could not inspect submodules for warning"),
			}
			// `target_dir` alone leaves the handle bare, and libgit2 refuses
			// to resolve a gitlink without a working tree. Point this handle
			// at the temp dir; with `update_gitlink` false nothing is
			// persisted, so the shared bare cache is untouched.
			repo.set_workdir(&workdir, false).map_err(|_| CheckoutFailure::AttachWorktree)?;
			let mut opts = git2::build::CheckoutBuilder::new();
			// Never touch the index in the bare cache: it is shared by every
			// job checking out of this mirror, and the checkout is
			// content-only, so scanners read the files directly.
			opts.target_dir(&workdir).recreate_missing(true).force().update_index(false);
			repo.checkout_tree(tree.as_object(), Some(&mut opts))
				.map_err(|_| CheckoutFailure::CheckoutTree)?;
			let oid = commit.id();
			// SAFETY: binary object id read from the actual checked-out Git commit,
			// before hexadecimal String formatting.
			#[allow(unsafe_code)]
			let oid = Untrusted::new(oid.as_bytes(), unsafe { Ingress::<Repo>::new() });
			Ok(oid.validate(repo_ingress::CheckedOutRevisionDecoder)?.into_revision())
		})
		.await
		.map_err(|_| CheckoutFailure::Task)??;
	Ok((CheckedOutWorktree { directory: Arc::new(tmp), pin: None }, head_sha))
}

/// Control over a phase lease's heartbeat task, which the phase handler
/// stops before its terminal call.
pub(crate) struct PhaseHeartbeat {
	stop: CancellationToken,
	stopped: CancellationToken,
}

impl PhaseHeartbeat {
	fn new(stop: CancellationToken) -> Self {
		Self { stop, stopped: CancellationToken::new() }
	}

	/// A handle with no heartbeat task behind it.
	#[cfg(test)]
	fn idle() -> Self {
		let heartbeat = Self::new(CancellationToken::new());
		heartbeat.stopped.cancel();
		heartbeat
	}

	/// The token that stops the heartbeat without waiting for it.
	pub(crate) fn stop_token(&self) -> CancellationToken {
		self.stop.clone()
	}

	/// Stop the heartbeat and wait until no heartbeat request is in flight.
	pub(crate) async fn stop(&self) {
		self.stop.cancel();
		self.stopped.cancelled().await;
	}
}

#[cfg(test)]
mod heartbeat_tests {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::net::{TcpListener, TcpStream};

	use super::*;

	async fn receive_heartbeat(listener: &TcpListener) -> TcpStream {
		let (mut socket, _) = listener.accept().await.unwrap();
		let mut headers = Vec::new();
		while !headers.ends_with(b"\r\n\r\n") {
			let mut byte = [0];
			socket.read_exact(&mut byte).await.unwrap();
			headers.push(byte[0]);
			assert!(headers.len() < 8192, "fixture heartbeat headers exceeded cap");
		}
		let headers = String::from_utf8(headers).unwrap();
		assert!(headers.starts_with("POST /v1/jobs/7/heartbeat HTTP/1.1\r\n"));
		let length = headers
			.lines()
			.find_map(|line| {
				let (name, value) = line.split_once(':')?;
				name.eq_ignore_ascii_case("content-length")
					.then(|| value.trim().parse::<usize>().unwrap())
			})
			.expect("heartbeat JSON has a content length");
		assert!(length < 8192, "fixture heartbeat body exceeded cap");
		let mut body = vec![0; length];
		socket.read_exact(&mut body).await.unwrap();
		let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
		assert_eq!(body["protocol_version"], PROTOCOL_VERSION);
		socket
	}

	fn client(listener: &TcpListener) -> Arc<ServerClient> {
		Arc::new(ServerClient::from_parts(
			reqwest::Client::builder().no_proxy().build().unwrap(),
			format!("http://{}", listener.local_addr().unwrap()).parse().unwrap(),
		))
	}

	#[tokio::test]
	async fn inflight_heartbeat_stops_when_parent_is_cancelled() {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let client = client(&listener);
		let cache_dir = tempfile::tempdir().unwrap();
		let cache = Arc::new(RepoCache::new(cache_dir.path().to_owned(), 1024, None).unwrap());
		let runner = Runner::new(client, cache, Vec::new());
		let parent = CancellationToken::new();
		let mut heartbeat = runner.spawn_heartbeat(
			7,
			JobCapability::from_secret("fixture-capability"),
			parent.child_token(),
		);
		let received = tokio::time::timeout(
			HEARTBEAT_INTERVAL + Duration::from_secs(15),
			receive_heartbeat(&listener),
		)
		.await;
		let Ok(socket) = received else {
			heartbeat.abort();
			let _ = heartbeat.await;
			panic!("fixture never received the full heartbeat request: {received:?}");
		};

		parent.cancel();
		let finished = tokio::time::timeout(Duration::from_secs(2), &mut heartbeat).await;
		if finished.is_err() {
			heartbeat.abort();
			let _ = heartbeat.await;
		}
		assert!(
			matches!(finished, Ok(Ok(()))),
			"in-flight heartbeat did not stop after parent cancellation: {finished:?}",
		);
		drop(socket);
	}

	#[tokio::test]
	async fn idle_heartbeat_stops_when_parent_is_cancelled() {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let cache_dir = tempfile::tempdir().unwrap();
		let cache = Arc::new(RepoCache::new(cache_dir.path().to_owned(), 1024, None).unwrap());
		let runner = Runner::new(client(&listener), cache, Vec::new());
		let parent = CancellationToken::new();
		let mut heartbeat = runner.spawn_heartbeat(
			7,
			JobCapability::from_secret("fixture-capability"),
			parent.child_token(),
		);
		parent.cancel();
		let finished = tokio::time::timeout(Duration::from_secs(2), &mut heartbeat).await;
		if finished.is_err() {
			heartbeat.abort();
			let _ = heartbeat.await;
		}
		assert!(matches!(finished, Ok(Ok(()))), "idle heartbeat failed to stop: {finished:?}");
	}

	#[tokio::test]
	async fn heartbeat_decodes_a_successful_response() {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let client = client(&listener);
		let peer = tokio::spawn(async move {
			let mut socket = receive_heartbeat(&listener).await;
			let body =
				format!(r#"{{"protocol_version":{PROTOCOL_VERSION},"lease_expires_at":1234}}"#);
			let response = format!(
				"HTTP/1.1 200 OK\r\n{}: {PROTOCOL_VERSION}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
				loupe_proto::PROTOCOL_VERSION_HEADER,
				body.len(),
			);
			socket.write_all(response.as_bytes()).await.unwrap();
		});
		let response = tokio::time::timeout(
			Duration::from_secs(2),
			client.heartbeat(7, &JobCapability::from_secret("fixture-capability")),
		)
		.await;
		if response.is_err() {
			peer.abort();
		}
		let served = peer.await;
		assert_eq!(response.unwrap().unwrap().lease_expires_at, 1234);
		served.unwrap();
	}
}

#[cfg(test)]
mod tests {
	#[tokio::test]
	async fn checkout_diagnostics_omit_repo_paths_and_revision() {
		if !crate::test_env::in_env(
			"runner::tests::checkout_diagnostics_omit_repo_paths_and_revision",
			"checkout-i8",
			&[],
		) {
			return;
		}
		let capture = crate::test_support::LogCapture::default();
		capture.install();
		let remote = tempfile::tempdir().unwrap();
		init_git_repo(remote.path());
		let commit = commit_file(remote.path(), "original\n", "Original");
		let revision = commit_submodule_gitlink(remote.path(), &commit);
		let cache =
			tempfile::Builder::new().prefix("private-checkout-path-sentinel").tempdir().unwrap();
		let bare = cache.path().join("repo.git");
		clone_bare(remote.path(), &bare);
		let (workdir, observed) = checkout_revision(&bare, &revision).await.unwrap();
		assert_eq!(observed.expose(), revision);
		assert!(workdir.path().join("vendor/dependency").is_dir());
		let logs = capture.text();
		assert!(logs.contains("checkout leaves submodules unpopulated"));
		assert_eq!(
			(
				logs.contains("private-checkout-path-sentinel"),
				logs.contains("vendor/dependency"),
				logs.contains(&revision)
			),
			(false, false, false),
			"repository paths and revision must stay out of checkout diagnostics"
		);
	}

	#[tokio::test]
	async fn checkout_path_errors_omit_original_bytes_from_the_chain() {
		let directory = tempfile::tempdir().unwrap();
		let path = directory.path().join("private-checkout-path-sentinel/missing.git");
		let error = super::checkout_latest(&path, None).await.unwrap_err();
		assert!(
			error.downcast_ref::<crate::host_outcome::CheckoutFailure>().is_some(),
			"checkout must retain its operational failure category"
		);
		assert!(
			!format!("{error:#}").contains("private-checkout-path-sentinel"),
			"checkout path leaked through the public error chain"
		);
	}
	use std::process::Command;

	use super::*;

	#[path = "ingress_tests.rs"]
	mod ingress_tests;

	mod quarantine_tests;

	struct StubScanner {
		id: &'static str,
		caps: &'static [&'static str],
	}

	#[async_trait::async_trait]
	impl Scanner for StubScanner {
		fn id(&self) -> &'static str {
			self.id
		}
		fn capabilities(&self) -> &[&'static str] {
			self.caps
		}
		async fn scan(&self, _: &ScanContext) -> Result<Vec<loupe_core::Finding<Repo>>> {
			Ok(vec![])
		}
	}

	#[test]
	fn capabilities_aggregate_from_scanners() {
		let scanners: Vec<Arc<dyn Scanner>> = vec![
			Arc::new(StubScanner { id: "a", caps: &["scan:a"] }),
			Arc::new(StubScanner { id: "b", caps: &["scan:b", "verify:b"] }),
		];
		let caps: Vec<String> = scanners
			.iter()
			.flat_map(|s| s.capabilities().iter().map(|c| (*c).to_owned()))
			.collect();
		assert_eq!(caps, vec!["scan:a", "scan:b", "verify:b"]);
	}

	#[tokio::test]
	async fn unexpected_review_leases_never_touch_checkout_or_submit_findings() {
		use std::sync::atomic::{AtomicUsize, Ordering};

		use axum::extract::Json;
		use axum::routing::post;
		use loupe_proto::PROTOCOL_VERSION_HEADER;
		use serde_json::json;

		let tmp = tempfile::tempdir().unwrap();
		let cache_path = tmp.path().join("cache");
		let leased = Arc::new(std::sync::Mutex::new(None::<serde_json::Value>));
		let response_lease = leased.clone();
		let unexpected_calls = Arc::new(AtomicUsize::new(0));
		let observed_calls = unexpected_calls.clone();
		let app = axum::Router::new()
			.route(
				"/v1/jobs/lease",
				post(move || {
					let response_lease = response_lease.clone();
					async move {
						(
							[(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string())],
							Json(response_lease.lock().unwrap().take().unwrap()),
						)
					}
				}),
			)
			.fallback(move || {
				observed_calls.fetch_add(1, Ordering::SeqCst);
				async { axum::http::StatusCode::INTERNAL_SERVER_ERROR }
			});
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let base = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
		let stop = CancellationToken::new();
		let shutdown = stop.clone();
		let server = tokio::spawn(async move {
			axum::serve(listener, app)
				.with_graceful_shutdown(shutdown.cancelled_owned())
				.await
				.unwrap();
		});
		let client = Arc::new(ServerClient::from_parts(reqwest::Client::new(), base));
		let cache = Arc::new(RepoCache::new(cache_path.clone(), 1024, None).unwrap());
		let runner = Runner::new(client, cache, vec![Arc::new(NeverRunReviewScanner)]);
		let provenance = json!({"workflow_contract_version":1,"campaign_id":2,"attempt":1,
			"limits":{"soft_deadline_at":100,"submit_by":100,"hard_deadline_at":200,
			"token_budget":null,"new_unit_limit":32,"lead_limit":16,"sibling_limit":4}});
		let generation = json!({"generation_id":3,"commit_sha":"a".repeat(40)});
		let profile = json!({"profile_version":1,"profile_digest":"b".repeat(64),"profile":{"purpose":"test"}});
		let evidence = json!({"version":1,"l2_argument":{"attacker_source":"Remote request","control":"Request length",
			"sink":"Allocation","reachable_path":"Handler calls allocator","trust_boundary":"Request to memory"},
			"material_locations":[{"role":"sink","file":"src/lib.rs"}],"counterevidence":"Authentication precedes allocation",
			"assumptions_gaps":"Authenticated attacker","confidence":"medium"});
		let payloads = [
			json!({"kind":"review_survey","provenance":provenance,"context":{"recipe":"bootstrap",
				"target":{"kind":"unresolved"}}}),
			json!({"kind":"review_drilldown","provenance":provenance,"generation":generation,"profile":profile,
				"lead":{"lead_id":4,"producer_commit_sha":"a".repeat(40),"identity_family":"memory-safety",
					"identity_anchor":"request allocation","hypothesis":"Unbounded allocation","source_refs":[{"path":"src/lib.rs"}],
					"next_proof_step":"Trace allocation","counterevidence":"Authentication","proof_gaps":"No reproducer"}}),
			json!({"kind":"review_verify","provenance":provenance,"generation":generation,"profile":profile,
				"finding":{"finding_id":4,"reviewed_commit_sha":"a".repeat(40),"severity":"high",
					"title":"Unbounded allocation","description":"Requests allocate without a limit",
					"identity_family":"memory-safety","identity_anchor":"request allocation","evidence":evidence}}),
		];
		for payload in payloads {
			let kind = payload["kind"].as_str().unwrap().to_owned();
			*leased.lock().unwrap() = Some(
				json!({"kind":"lease","protocol_version":PROTOCOL_VERSION,
				"job_id":1,"job_capability":"test-capability","repo_id":1,
				"repo":{"host":"invalid.test","owner":"test","repo":"test","clone_url":format!("file://{}/missing",tmp.path().display())},
				"head_branch":null,"lease_expires_at":200,"scanner_config":null,"payload":payload}),
			);
			let receipt = runner.client.lease_for_runner(runner.capabilities.clone(), 0).await;
			assert!(
				receipt.is_ok(),
				"valid {kind} must reach the execution gate: {:?}",
				receipt.as_ref().err()
			);
			let receipt = receipt.unwrap();
			let LeaseResponse::Lease(env) = receipt.response else { panic!("lease fixture") };
			let security = crate::canary::JobSecurity::new(Default::default(), vec![]).unwrap();
			let error = runner
				.execute(
					*env,
					receipt.reviewed_revision,
					receipt.scanner_patch,
					CancellationToken::new(),
					security,
					None,
				)
				.await
				.err()
				.expect("unexpected review phase must fail closed");
			assert_eq!(
				error.to_string(),
				"review lease arrived but phase execution is not enabled",
				"{kind}"
			);
			assert_eq!(
				std::fs::read_dir(&cache_path).unwrap().count(),
				0,
				"{kind} accessed repository cache"
			);
		}
		assert_eq!(
			unexpected_calls.load(Ordering::SeqCst),
			0,
			"unsupported phases must not write findings or verdicts"
		);
		stop.cancel();
		server.await.unwrap();
	}

	#[tokio::test]
	async fn a_phase_backend_runs_survey_and_drilldown_and_leaves_verify_failing_closed() {
		assert_phases_run(true, true).await;
	}

	#[tokio::test]
	async fn a_phase_without_its_backend_is_not_advertised_and_fails_closed() {
		assert_phases_run(true, false).await;
		assert_phases_run(false, true).await;
	}

	/// A runner with backends for the named phases advertises and executes
	/// those only; every other phase lease fails closed.
	async fn assert_phases_run(survey: bool, drilldown: bool) {
		use axum::body::Bytes;
		use axum::extract::Json;
		use loupe_proto::review_lease::ReviewCapability;
		use loupe_proto::PROTOCOL_VERSION_HEADER;
		use serde_json::json;

		let seen = Arc::new(std::sync::Mutex::new(Vec::<(String, serde_json::Value)>::new()));
		let record = seen.clone();
		let app = axum::Router::new().fallback(move |uri: axum::http::Uri, body: Bytes| {
			let record = record.clone();
			async move {
				let body = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
				record.lock().unwrap().push((uri.path().to_owned(), body));
				(
					[(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION.to_string())],
					Json(
						json!({"protocol_version":3,"job_id":1,"state":"queued","eligible_at":null}),
					),
				)
			}
		});
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let base = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
		let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
		let tmp = tempfile::tempdir().unwrap();
		let cache_path = tmp.path().join("cache");
		let cache = Arc::new(RepoCache::new(cache_path.clone(), 1024, None).unwrap());
		let client = Arc::new(ServerClient::from_parts(reqwest::Client::new(), base));
		let backend = crate::llm::testing::StubLlmBackend::new("never-run", |_| {
			panic!("no lease in this test may reach the phase agent")
		});
		let backend = Arc::new(backend);
		let mut runner = Runner::new(client, cache, Vec::new());
		let mut advertised = Vec::new();
		if survey {
			runner = runner.with_survey_backend(backend.clone());
			advertised.push(ReviewCapability::Survey);
		}
		if drilldown {
			runner = runner.with_drilldown_backend(backend);
			advertised.push(ReviewCapability::Drilldown);
		}
		assert_eq!(runner.review_capabilities().unwrap().as_slice(), advertised);
		let provenance = json!({"workflow_contract_version":1,"campaign_id":2,"attempt":1,
			"limits":{"soft_deadline_at":100,"submit_by":100,"hard_deadline_at":200,
			"token_budget":null,"new_unit_limit":32,"lead_limit":16,"sibling_limit":4}});
		let generation = json!({"generation_id":3,"commit_sha":"a".repeat(40)});
		let profile = json!({"profile_version":1,"profile_digest":"b".repeat(64),"profile":{"purpose":"test"}});
		let lead = json!({"lead_id":4,"producer_commit_sha":"a".repeat(40),
			"identity_family":"memory-safety","identity_anchor":"request allocation",
			"hypothesis":"Unbounded allocation","source_refs":[{"path":"src/lib.rs"}],
			"next_proof_step":"Trace allocation","counterevidence":"Authentication",
			"proof_gaps":"No reproducer"});
		let evidence = json!({"version":1,"l2_argument":{"attacker_source":"Remote request",
			"control":"Request length","sink":"Allocation","reachable_path":"Handler calls allocator",
			"trust_boundary":"Request to memory"},"material_locations":[{"role":"sink","file":"src/lib.rs"}],
			"counterevidence":"Authentication precedes allocation",
			"assumptions_gaps":"Authenticated attacker","confidence":"medium"});
		let finding = json!({"finding_id":4,"reviewed_commit_sha":"a".repeat(40),"severity":"high",
			"title":"Unbounded allocation","description":"Requests allocate without a limit",
			"identity_family":"memory-safety","identity_anchor":"request allocation","evidence":evidence});
		let cases = [
			(
				json!({"kind":"review_verify","provenance":provenance,"generation":generation,
				"profile":profile,"finding":finding}),
				None,
			),
			(
				json!({"kind":"review_drilldown","provenance":provenance,"generation":generation,
				"profile":profile,"lead":lead}),
				drilldown.then_some("hard deadline reached"),
			),
			(
				json!({"kind":"review_survey","provenance":provenance,"context":{
				"recipe":"corroboration","generation":generation,"assignments":[]}}),
				survey.then_some("survey recipe unsupported"),
			),
		];
		for (payload, reported) in cases {
			let lease = json!({"kind":"lease","protocol_version":PROTOCOL_VERSION,
				"job_id":1,"job_capability":"test-capability","repo_id":1,
				"repo":{"host":"invalid.test","owner":"test","repo":"test",
					"clone_url":format!("file://{}/missing",tmp.path().display())},
				"head_branch":null,"lease_expires_at":200,"scanner_config":null,"payload":payload});
			let receipt = crate::client::test_lease(lease.to_string().as_bytes());
			let LeaseResponse::Lease(env) = receipt.response else { panic!("lease fixture") };
			let security = crate::canary::JobSecurity::new(Default::default(), vec![]).unwrap();
			let deadline = runner.phase_hard_deadline(&env);
			assert_eq!(deadline.is_some(), reported.is_some(), "phase heartbeat");
			let executed = runner
				.execute(
					*env,
					receipt.reviewed_revision,
					receipt.scanner_patch,
					CancellationToken::new(),
					security,
					Some(PhaseHeartbeat::idle()),
				)
				.await;
			let requests = std::mem::take(&mut *seen.lock().unwrap());
			if let Some(reason) = reported {
				assert!(matches!(executed, Ok(Executed::Reported)), "{reason} is reported");
				assert_eq!(
					requests,
					[(
						"/v1/jobs/1/complete".to_owned(),
						json!({"protocol_version":3,"outcome":"failed","error":reason})
					)]
				);
			} else {
				assert_eq!(
					executed.err().map(|error| error.to_string()).as_deref(),
					Some("review lease arrived but phase execution is not enabled")
				);
				assert!(requests.is_empty(), "{requests:?}");
			}
			let cached = std::fs::read_dir(&cache_path).unwrap().count();
			assert_eq!(cached, 0, "an unsupported review lease touched the repository cache");
		}
		server.abort();
	}

	struct NeverRunReviewScanner;
	#[async_trait::async_trait]
	impl Scanner for NeverRunReviewScanner {
		fn id(&self) -> &'static str {
			"never-run"
		}
		fn capabilities(&self) -> &[&'static str] {
			&["scan:test", "verify:test"]
		}
		async fn scan(&self, _: &ScanContext) -> Result<Vec<loupe_core::Finding<Repo>>> {
			panic!("review lease reached legacy scan")
		}
		async fn verify(&self, _: &VerifyContext) -> Result<crate::VerifyOutcome> {
			panic!("review lease reached legacy verify")
		}
	}

	fn git(dir: &Path, args: &[&str]) -> String {
		let output = Command::new("git").current_dir(dir).args(args).output().unwrap();
		assert!(
			output.status.success(),
			"git {:?} in {} failed: {}",
			args,
			dir.display(),
			String::from_utf8_lossy(&output.stderr)
		);
		String::from_utf8_lossy(&output.stdout).trim().to_owned()
	}

	fn init_git_repo(path: &Path) {
		std::fs::create_dir_all(path).unwrap();
		let output = Command::new("git")
			.current_dir(path)
			.args(["init", "-q", "-b", "main"])
			.output()
			.unwrap();
		assert!(
			output.status.success(),
			"git init failed: {}",
			String::from_utf8_lossy(&output.stderr)
		);
		git(path, &["config", "user.email", "loupe-test@example.com"]);
		git(path, &["config", "user.name", "loupe-test"]);
	}

	fn commit_file(repo: &Path, contents: &str, message: &str) -> String {
		std::fs::write(repo.join("file.txt"), contents).unwrap();
		git(repo, &["add", "file.txt"]);
		git(repo, &["commit", "-q", "-m", message]);
		git(repo, &["rev-parse", "HEAD"])
	}

	/// Commit a gitlink at `vendor/dependency` pointing at
	/// `submodule_commit`, plus the matching `.gitmodules` entry. Uses
	/// `update-index --cacheinfo` so no real submodule clone is needed.
	fn commit_submodule_gitlink(repo: &Path, submodule_commit: &str) -> String {
		std::fs::write(
			repo.join(".gitmodules"),
			"[submodule \"dependency\"]\n\tpath = vendor/dependency\n\turl = https://example.com/dependency.git\n",
		)
		.unwrap();
		git(repo, &["add", ".gitmodules"]);
		git(
			repo,
			&[
				"update-index",
				"--add",
				"--cacheinfo",
				&format!("160000,{submodule_commit},vendor/dependency"),
			],
		);
		git(repo, &["commit", "-q", "-m", "Add a submodule"]);
		git(repo, &["rev-parse", "HEAD"])
	}

	/// Bare-clone `remote` into `dest`, mirroring how the repo cache
	/// populates a bare mirror before jobs check out of it.
	fn clone_bare(remote: &Path, dest: &Path) {
		let url = format!("file://{}", remote.display());
		let output = Command::new("git")
			.args(["clone", "--bare", "--quiet"])
			.arg(&url)
			.arg(dest)
			.output()
			.unwrap();
		assert!(
			output.status.success(),
			"git clone --bare failed: {}",
			String::from_utf8_lossy(&output.stderr)
		);
	}

	#[tokio::test]
	async fn checkout_tolerates_submodule_gitlinks() {
		let remote_tmp = tempfile::tempdir().unwrap();
		init_git_repo(remote_tmp.path());
		let submodule_commit = commit_file(remote_tmp.path(), "one\n", "One");
		let head = commit_submodule_gitlink(remote_tmp.path(), &submodule_commit);

		let bare_tmp = tempfile::tempdir().unwrap();
		let bare = bare_tmp.path().join("cache.git");
		clone_bare(remote_tmp.path(), &bare);

		let bare_repo = git2::Repository::open_bare(&bare).unwrap();
		let tree = bare_repo.head().unwrap().peel_to_tree().unwrap();
		assert_eq!(
			submodule_paths(&tree)
				.unwrap()
				.iter()
				.map(repo_ingress::RepositoryGitlinkPath::fixture_text)
				.collect::<Vec<_>>(),
			vec!["vendor/dependency".to_owned()]
		);

		// Both checkout entry points must survive the gitlink, leaving
		// the submodule as an empty directory rather than failing.
		for (label, checked_out, workdir) in [
			{
				let (workdir, sha) = checkout_latest(&bare, Some("main"))
					.await
					.unwrap_or_else(|e| panic!("checkout_latest rejected the gitlink: {e:#}"));
				("checkout_latest", sha, workdir)
			},
			{
				let (workdir, sha) = checkout_revision(&bare, &head)
					.await
					.unwrap_or_else(|e| panic!("checkout_revision rejected the gitlink: {e:#}"));
				("checkout_revision", sha, workdir)
			},
		] {
			assert_eq!(checked_out.expose(), head, "{label} resolved the wrong commit");
			let submodule = workdir.path().join("vendor/dependency");
			assert!(submodule.is_dir(), "{label} did not create the submodule dir");
			assert_eq!(
				std::fs::read_dir(&submodule).unwrap().count(),
				0,
				"{label} populated the submodule",
			);
			assert!(
				workdir.path().join(".gitmodules").is_file(),
				"{label} did not check out .gitmodules",
			);
		}
	}

	#[tokio::test]
	async fn checkout_does_not_write_an_index_into_the_bare_cache() {
		let remote_tmp = tempfile::tempdir().unwrap();
		init_git_repo(remote_tmp.path());
		let head = commit_file(remote_tmp.path(), "one\n", "One");

		let bare_tmp = tempfile::tempdir().unwrap();
		let bare = bare_tmp.path().join("cache.git");
		clone_bare(remote_tmp.path(), &bare);
		assert!(!bare.join("index").exists(), "a fresh bare mirror has no index");

		let (_workdir, sha) = checkout_latest(&bare, Some("main")).await.unwrap();
		assert_eq!(sha.expose(), head);
		assert!(
			!bare.join("index").exists(),
			"checkout must not write an index into the shared bare cache",
		);
	}

	#[tokio::test]
	async fn checkout_revision_uses_original_sha_not_latest_branch_tip() {
		let remote_tmp = tempfile::tempdir().unwrap();
		init_git_repo(remote_tmp.path());
		let first = commit_file(remote_tmp.path(), "one\n", "One");
		let second = commit_file(remote_tmp.path(), "two\n", "Two");

		let bare_tmp = tempfile::tempdir().unwrap();
		let bare = bare_tmp.path().join("cache.git");
		clone_bare(remote_tmp.path(), &bare);

		let (latest_workdir, latest_sha) = checkout_latest(&bare, Some("main")).await.unwrap();
		assert_eq!(latest_sha.expose(), second);
		assert_eq!(
			std::fs::read_to_string(latest_workdir.path().join("file.txt")).unwrap(),
			"two\n"
		);

		let (review_workdir, reviewed_sha) = checkout_revision(&bare, &first).await.unwrap();
		assert_eq!(reviewed_sha.expose(), first);
		assert_eq!(
			std::fs::read_to_string(review_workdir.path().join("file.txt")).unwrap(),
			"one\n"
		);
	}
}
