//! Worker runner loop: lease → ensure_repo → checkout → scan → submit → complete.
//!
//! M1 polls when the queue is empty (long-poll happens in M2 when the
//! server adds streaming) and runs the regex scanner on every leased
//! scan job. Verify-kind jobs are leased but not yet executed —
//! verifier scanners arrive in M2.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use loupe_proto::{
	CompleteOutcome, CompleteRequest, FindingsBatch, LeaseEnvelope, LeasePayload, LeaseResponse,
	PROTOCOL_VERSION,
};
use tokio_util::sync::CancellationToken;

use crate::client::ServerClient;
use crate::repo_cache::{RepoCache, RepoKey};
use crate::scanner::{ScanContext, Scanner};

/// How often the runner heartbeat-pings during a long scan.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);
/// Idle pause when the queue is empty.
const IDLE_POLL: Duration = Duration::from_secs(5);

pub struct Runner {
	client: Arc<ServerClient>,
	cache: Arc<RepoCache>,
	scanners: Vec<Arc<dyn Scanner>>,
	capabilities: Vec<String>,
}

impl Runner {
	pub fn new(
		client: Arc<ServerClient>, cache: Arc<RepoCache>, scanners: Vec<Arc<dyn Scanner>>,
	) -> Self {
		let capabilities: Vec<String> = scanners
			.iter()
			.flat_map(|s| s.capabilities().iter().map(|c| (*c).to_owned()))
			.collect();
		Self { client, cache, scanners, capabilities }
	}

	/// Run one iteration: try to lease a job, run it if there is one,
	/// otherwise return false (caller can sleep then try again).
	pub async fn step(&self, cancel: &CancellationToken) -> Result<bool> {
		let resp = self.client.lease(self.capabilities.clone()).await?;
		match resp {
			LeaseResponse::Empty { .. } => Ok(false),
			LeaseResponse::Lease(env) => {
				self.run_lease(*env, cancel).await?;
				Ok(true)
			},
		}
	}

	/// Run forever until cancelled. Pauses [`IDLE_POLL`] between empty
	/// leases so we don't hammer the server.
	pub async fn run_forever(&self, cancel: CancellationToken) -> Result<()> {
		while !cancel.is_cancelled() {
			match self.step(&cancel).await {
				Ok(true) => {},
				Ok(false) => {
					tokio::select! {
						_ = tokio::time::sleep(IDLE_POLL) => {},
						_ = cancel.cancelled() => break,
					}
				},
				Err(e) => {
					tracing::warn!(error = %e, "runner step failed; backing off");
					tokio::select! {
						_ = tokio::time::sleep(IDLE_POLL) => {},
						_ = cancel.cancelled() => break,
					}
				},
			}
		}
		Ok(())
	}

	async fn run_lease(&self, env: LeaseEnvelope, cancel: &CancellationToken) -> Result<()> {
		let job_id = env.job_id;
		tracing::info!(job_id, repo = %env.repo.clone_url, "leased job");
		let scan_cancel = cancel.child_token();
		let heartbeat = self.spawn_heartbeat(job_id, scan_cancel.clone());

		let outcome = self.execute(env, scan_cancel.clone()).await;

		// Stop the heartbeat task before completing — otherwise it might
		// race the complete and turn into a 403.
		scan_cancel.cancel();
		let _ = heartbeat.await;

		match outcome {
			Ok((head_sha, _findings_count)) => {
				let req = CompleteRequest {
					protocol_version: PROTOCOL_VERSION,
					outcome: CompleteOutcome::Succeeded,
					head_sha: Some(head_sha),
					error: None,
				};
				self.client.complete(job_id, &req).await?;
				tracing::info!(job_id, "job succeeded");
			},
			Err(e) => {
				tracing::warn!(job_id, error = %e, "job failed");
				let req = CompleteRequest {
					protocol_version: PROTOCOL_VERSION,
					outcome: CompleteOutcome::Failed,
					head_sha: None,
					error: Some(e.to_string()),
				};
				if let Err(ce) = self.client.complete(job_id, &req).await {
					tracing::warn!(job_id, error = %ce, "complete(Failed) call failed too");
				}
			},
		}
		Ok(())
	}

	/// Returns (head_sha, findings_count).
	async fn execute(
		&self, env: LeaseEnvelope, cancel: CancellationToken,
	) -> Result<(String, usize)> {
		let key = RepoKey::new(&env.repo.host, &env.repo.owner, &env.repo.repo);
		let bare =
			self.cache.ensure_repo(&key, &env.repo.clone_url, env.github_pat.as_deref()).await?;

		match env.payload {
			LeasePayload::Verify { .. } => {
				// M2 wires verifier execution. For now the worker should
				// not have leased a verify job because it doesn't advertise
				// any `verify:*` capability.
				anyhow::bail!("verify-kind jobs are not yet executed by this worker");
			},
			LeasePayload::Scan { since_sha } => {
				let (workdir, head_sha) = checkout(&bare, env.head_branch.as_deref()).await?;
				let ctx = ScanContext {
					workdir: workdir.path().to_path_buf(),
					repo: env.repo.clone(),
					head_sha: head_sha.clone(),
					base_sha: since_sha,
					config: env.scanner_config,
					cancel: cancel.clone(),
				};

				let mut all = Vec::new();
				for s in &self.scanners {
					match s.scan(&ctx).await {
						Ok(mut findings) => all.append(&mut findings),
						Err(e) => tracing::warn!(scanner = s.id(), error = %e, "scanner failed"),
					}
				}
				if !all.is_empty() {
					let batch =
						FindingsBatch { protocol_version: PROTOCOL_VERSION, findings: all.clone() };
					self.client.submit_findings(env.job_id, &batch).await?;
				}
				Ok((head_sha, all.len()))
			},
		}
	}

	fn spawn_heartbeat(
		&self, job_id: i64, cancel: CancellationToken,
	) -> tokio::task::JoinHandle<()> {
		let client = self.client.clone();
		tokio::spawn(async move {
			loop {
				tokio::select! {
					_ = cancel.cancelled() => return,
					_ = tokio::time::sleep(HEARTBEAT_INTERVAL) => {
						if let Err(e) = client.heartbeat(job_id).await {
							tracing::warn!(job_id, error = %e, "heartbeat failed");
						}
					},
				}
			}
		})
	}
}

/// Produce a fresh worktree from the bare clone at `bare` checked out
/// to `branch` (or the default branch if `None`). Returns the worktree
/// dir (a `TempDir` for cleanup) plus the resolved commit SHA.
pub async fn checkout(bare: &Path, branch: Option<&str>) -> Result<(tempfile::TempDir, String)> {
	let bare = bare.to_path_buf();
	let branch = branch.map(|s| s.to_owned());
	let tmp = tempfile::tempdir().context("creating temp worktree dir")?;
	let workdir = tmp.path().to_path_buf();
	let head_sha = tokio::task::spawn_blocking(move || -> Result<String> {
		let repo = git2::Repository::open_bare(&bare)
			.with_context(|| format!("opening bare repo at {}", bare.display()))?;
		let target_ref = match branch.as_deref() {
			Some(b) => repo
				.find_reference(&format!("refs/heads/{b}"))
				.or_else(|_| repo.find_reference(&format!("refs/remotes/origin/{b}")))
				.with_context(|| format!("locating ref for branch {b}"))?,
			None => repo
				.find_reference("HEAD")
				.or_else(|_| repo.find_reference("refs/remotes/origin/HEAD"))
				.context("locating HEAD reference")?,
		};
		let commit = target_ref.peel_to_commit().context("resolving ref to commit")?;
		let tree = commit.tree().context("resolving commit tree")?;
		let mut opts = git2::build::CheckoutBuilder::new();
		opts.target_dir(&workdir).recreate_missing(true).force();
		repo.checkout_tree(tree.as_object(), Some(&mut opts))
			.context("checking out tree into worktree dir")?;
		Ok(commit.id().to_string())
	})
	.await
	.map_err(|e| anyhow::anyhow!("checkout task panicked: {e}"))??;
	Ok((tmp, head_sha))
}

#[cfg(test)]
mod tests {
	use super::*;

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
		async fn scan(&self, _: &ScanContext) -> Result<Vec<loupe_core::Finding>> {
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
}
