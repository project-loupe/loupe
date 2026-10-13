//! Worker runner loop: lease → ensure_repo → checkout → scan → submit → complete.
//!
//! The runner long-polls for scan or verify jobs, checks out a fresh
//! worktree, runs the matching scanner, submits any in-process findings
//! or verdicts, and completes the lease.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use loupe_core::security_event::Operation;
use loupe_core::text::policy::RevisionText;
use loupe_core::text::BoundedText;
use loupe_proto::{
	CompleteOutcome, FindingsBatch, JobCapability, LeaseEnvelope, LeasePayload, LeaseResponse,
	VerdictSubmission, PROTOCOL_VERSION,
};
use loupe_provenance::{Agent, Ingress, Repo, Server, Untrusted};
use tokio_util::sync::CancellationToken;

use crate::client::ServerClient;
use crate::host_outcome::{CheckoutFailure, HostVerifyReason, ReviewedRevisionFact};
use crate::repo_cache::{RepoCache, RepoKey};
use crate::scanner::{ScanContext, Scanner, VerifyContext};
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
enum CompletionRevision {
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

pub struct Runner {
	client: Arc<ServerClient>,
	cache: Arc<RepoCache>,
	scanners: Vec<Arc<dyn Scanner>>,
	capabilities: Vec<&'static str>,
	max_workdir_bytes: u64,
	credential_watches: Vec<crate::llm::model_broker::CredentialWatch>,
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
		}
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

	/// Run one iteration: long-poll for a job and, if one arrives, run
	/// it. Returns `true` if a job was processed, `false` if the long-
	/// poll window elapsed without one.
	pub async fn step(&self, cancel: &CancellationToken) -> Result<bool> {
		let receipt =
			self.client.lease_for_runner(self.capabilities.clone(), LEASE_WAIT_SECONDS).await?;
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
		let heartbeat = self.spawn_heartbeat(job_id, job_capability.clone(), scan_cancel.clone());
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
			.execute(env, reviewed_revision, scanner_patch, execution_cancel, security.clone())
			.await;
		let outcome = if security.is_quarantined() {
			Err(crate::canary::JobQuarantined.into())
		} else {
			outcome
		};

		// Stop the heartbeat task before completing — otherwise it might
		// race the complete and turn into a 403.
		scan_cancel.cancel();
		let _ = heartbeat.await;
		let _ = cancellation.await;

		match outcome {
			Ok((head_sha, _findings_count)) => {
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

	/// Returns (head_sha, findings_count).
	async fn execute(
		&self, env: LeaseEnvelope<Agent, Server>, reviewed_revision: ReviewedRevisionFact,
		scanner_patch: Option<crate::source_discovery::ScannerConfigPatch>,
		cancel: CancellationToken, security: Arc<crate::canary::JobSecurity>,
	) -> Result<(Option<CompletionRevision>, usize)> {
		let tool_boundary = crate::llm::prompt::JobToolBoundary::new()?;
		let key =
			RepoKey::new(env.repo.host.expose(), env.repo.owner.expose(), env.repo.repo.expose());
		let clone_url = env.repo.clone_url.clone();
		let github_pat = env.github_pat.map(Arc::new);
		let mut ensured =
			self.cache.ensure_repo(&key, env.repo.clone_url.expose(), github_pat.as_ref()).await?;
		// `ensured` (and its pin) lives until the end of this fn; the
		// repo cache won't evict the bare clone while the worktree
		// alternate is still in use.

		match env.payload {
			LeasePayload::Verify { finding_id, finding, reviewed_sha: _ } => {
				let ReviewedRevisionFact::Available(revision) = reviewed_revision else {
					self.submit_revision_unavailable_verdict(
						env.job_id,
						&env.job_capability,
						finding_id,
						HostVerifyReason::MissingReviewedRevision,
						&security,
					)
					.await?;
					return Ok((None, 0));
				};
				// The lease decoder retains the Server mark through this operational view.
				let reviewed_sha = revision.clone().into_revision();
				let (workdir, head_sha) =
					match checkout_revision(&ensured.path, reviewed_sha.expose()).await {
						Ok(ok) => ok,
						Err(first_error) => {
							tracing::warn!(
								job_id = env.job_id,
								finding_id,
								reviewed_sha = %reviewed_sha.expose(),
								error = %first_error,
								"verify revision missing from refreshed cache; re-cloning",
							);
							drop(ensured);
							ensured = self
								.cache
								.reclone_repo(&key, clone_url.expose(), github_pat.as_ref())
								.await?;
							match checkout_revision(&ensured.path, reviewed_sha.expose()).await {
								Ok(ok) => ok,
								Err(second_error) => {
									self.submit_revision_unavailable_verdict(
										env.job_id,
										&env.job_capability,
										finding_id,
										HostVerifyReason::ReviewedRevisionUnavailable {
											revision,
											failure: second_error
												.downcast_ref::<CheckoutFailure>()
												.copied()
												.unwrap_or(CheckoutFailure::Task),
										},
										&security,
									)
									.await?;
									return Ok((
										Some(CompletionRevision::Reviewed(reviewed_sha)),
										0,
									));
								},
							}
						},
					};
				let workdir = workdir.pinned(ensured._pin);
				let workdir_size = crate::repo_cache::dir_size(workdir.path());
				if workdir_size > self.max_workdir_bytes {
					anyhow::bail!(
						"checkout size {workdir_size} bytes exceeds max_workdir_bytes {}",
						self.max_workdir_bytes
					);
				}
				let vctx = VerifyContext {
					sandbox_workdir: workdir.sandbox_path(),
					security: security.clone(),
					tool_boundary,
					workdir: workdir.path().to_path_buf(),
					repo: env.repo.clone(),
					repo_id: env.repo_id,
					job_id: env.job_id,
					job_capability: env.job_capability.clone(),
					finding_id,
					finding: *finding,
					config: scanner_patch,
					cancel: cancel.clone(),
				};
				// The server filters leases by advertised capabilities. This worker
				// selects the first scanner with any verify:* tag, without per-tag matching.
				let verifier = self
					.scanners
					.iter()
					.find(|s| s.capabilities().iter().any(|c| c.starts_with("verify:")))
					.ok_or_else(|| {
						anyhow::anyhow!(
							"verify lease arrived but worker advertises no verify:* scanner"
						)
					})?;
				let outcome = verifier.verify(&vctx).await?;
				security.admit(Operation::SubmitVerdict)?;
				match outcome {
					crate::VerifyOutcome::Host(reason) => {
						security
							.run(
								Operation::SubmitVerdict,
								self.client.submit_host_verdict(
									env.job_id,
									&env.job_capability,
									reason,
								),
							)
							.await?;
					},
					crate::VerifyOutcome::Verdict(verdict) => {
						tracing::info!(
							job_id = env.job_id,
							finding_id,
							verifier = verifier.id(),
							"submitting verdict (in-process verifier)"
						);
						security
							.run(
								Operation::SubmitVerdict,
								self.client.submit_verdict(
									env.job_id,
									&env.job_capability,
									&VerdictSubmission {
										protocol_version: PROTOCOL_VERSION,
										verdict,
									},
								),
							)
							.await?;
					},
					crate::VerifyOutcome::Submitted => {
						// MCP-driven verifier already POSTed via the MCP
						// child's session-end flush. POSTing again from
						// here would land a duplicate verification row;
						// the runner stays out of the way.
						tracing::info!(
							job_id = env.job_id,
							finding_id,
							verifier = verifier.id(),
							"verifier submitted verdict via MCP (runner skipping POST)"
						);
					},
				}
				Ok((Some(CompletionRevision::CheckedOut(head_sha)), 0))
			},
			LeasePayload::Scan { since_sha } => {
				tracing::info!(job_id = env.job_id, "checking out worktree");
				let (workdir, head_sha) = match checkout_latest(
					&ensured.path,
					env.head_branch.as_ref().map(|v| v.expose()),
				)
				.await
				{
					Ok(ok) => ok,
					Err(first_error) => {
						tracing::warn!(
							job_id = env.job_id,
							error = %first_error,
							"scan checkout failed from refreshed cache; re-cloning",
						);
						drop(ensured);
						ensured = self
							.cache
							.reclone_repo(&key, clone_url.expose(), github_pat.as_ref())
							.await?;
						checkout_latest(&ensured.path, env.head_branch.as_ref().map(|v| v.expose()))
							.await?
					},
				};
				let workdir = workdir.pinned(ensured._pin);
				let workdir_size = crate::repo_cache::dir_size(workdir.path());
				tracing::info!(job_id = env.job_id, workdir_bytes = workdir_size, "worktree ready");
				if workdir_size > self.max_workdir_bytes {
					anyhow::bail!(
						"checkout size {workdir_size} bytes exceeds max_workdir_bytes {}",
						self.max_workdir_bytes
					);
				}
				let ctx = ScanContext {
					sandbox_workdir: workdir.sandbox_path(),
					security: security.clone(),
					tool_boundary,
					workdir: workdir.path().to_path_buf(),
					repo: env.repo.clone(),
					repo_id: env.repo_id,
					job_id: env.job_id,
					job_capability: env.job_capability.clone(),
					head_sha: head_sha.clone(),
					base_sha: since_sha,
					config: scanner_patch,
					cancel: cancel.clone(),
				};

				let mut all = Vec::new();
				for s in &self.scanners {
					security.admit(Operation::SubmitFindings)?;
					tracing::info!(job_id = env.job_id, scanner = s.id(), "running scanner");
					let result = s.scan(&ctx).await;
					security.admit(Operation::SubmitFindings)?;
					match result {
						Ok(mut findings) => {
							// `returned_count` is the number of findings the
							// scanner handed back for the runner to batch-POST
							// to `/v1/jobs/{id}/findings` below. It's NOT the
							// total submission count for the job — agent-driven
							// scanners (e.g. `llm-code-review`) submit
							// mid-session via the MCP `submit_finding` tool and
							// always return an empty `Vec`, so a zero here only
							// means "nothing was added to the batch." Check the
							// server's findings table for the actual emission
							// count when an agent scanner runs.
							tracing::info!(
								job_id = env.job_id,
								scanner = s.id(),
								returned_count = findings.len(),
								"scanner finished",
							);
							all.append(&mut findings);
						},
						Err(_) => tracing::warn!(scanner = s.id(), "scanner failed"),
					}
				}
				if !all.is_empty() {
					let batch =
						FindingsBatch { protocol_version: PROTOCOL_VERSION, findings: all.clone() };
					security
						.run(
							Operation::SubmitFindings,
							self.client.submit_findings(env.job_id, &env.job_capability, &batch),
						)
						.await?;
				}
				Ok((Some(CompletionRevision::CheckedOut(head_sha)), all.len()))
			},
		}
	}

	async fn submit_revision_unavailable_verdict(
		&self, job_id: i64, job_capability: &JobCapability, finding_id: i64,
		reason: HostVerifyReason, security: &crate::canary::JobSecurity,
	) -> Result<()> {
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

	fn spawn_heartbeat(
		&self, job_id: i64, job_capability: JobCapability, cancel: CancellationToken,
	) -> tokio::task::JoinHandle<()> {
		let client = self.client.clone();
		tokio::spawn(async move {
			loop {
				tokio::select! {
					_ = cancel.cancelled() => return,
					_ = tokio::time::sleep(HEARTBEAT_INTERVAL) => {
						if client.heartbeat(job_id, &job_capability).await.is_err() {
							tracing::warn!(job_id, "heartbeat failed");
						}
					},
				}
			}
		})
	}
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
