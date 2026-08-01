//! Worker runner loop: lease → ensure_repo → checkout → scan → submit → complete.
//!
//! The runner long-polls for scan or verify jobs, checks out a fresh
//! worktree, runs the matching scanner, submits any in-process findings
//! or verdicts, and completes the lease.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use loupe_core::Verdict;
use loupe_proto::{
	CompleteOutcome, CompleteRequest, FindingsBatch, LeaseEnvelope, LeasePayload, LeaseResponse,
	VerdictSubmission, PROTOCOL_VERSION,
};
use tokio_util::sync::CancellationToken;

use crate::client::ServerClient;
use crate::repo_cache::{RepoCache, RepoKey};
use crate::scanner::{ScanContext, Scanner, VerifyContext};

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

pub struct Runner {
	client: Arc<ServerClient>,
	cache: Arc<RepoCache>,
	scanners: Vec<Arc<dyn Scanner>>,
	capabilities: Vec<String>,
	max_workdir_bytes: u64,
	fetch_submodules: bool,
}

impl Runner {
	pub fn new(
		client: Arc<ServerClient>, cache: Arc<RepoCache>, scanners: Vec<Arc<dyn Scanner>>,
	) -> Self {
		let capabilities: Vec<String> = scanners
			.iter()
			.flat_map(|s| s.capabilities().iter().map(|c| (*c).to_owned()))
			.collect();
		Self {
			client,
			cache,
			scanners,
			capabilities,
			max_workdir_bytes: DEFAULT_MAX_WORKDIR_BYTES,
			fetch_submodules: false,
		}
	}

	/// Override the per-job workdir size cap. A scan whose checkout
	/// exceeds this size fails immediately; the host's disk stays safe.
	pub fn with_max_workdir_bytes(mut self, bytes: u64) -> Self {
		self.max_workdir_bytes = bytes;
		self
	}

	/// Materialise submodules declared in `.gitmodules` after checkout.
	///
	/// Off by default. A bare clone cannot carry submodule contents, so a
	/// repository that keeps dependencies in submodules is otherwise scanned
	/// with those paths empty. Turning this on clones each declared submodule
	/// at the commit the superproject pins.
	///
	/// It is opt-in because scan cost scales with file count: materialising
	/// submodules on a repository that vendors large irrelevant trees can
	/// multiply an operator's bill without them asking for it. The `--max-
	/// workdir-bytes` cap still applies to the resulting checkout.
	pub fn with_fetch_submodules(mut self, fetch: bool) -> Self {
		self.fetch_submodules = fetch;
		self
	}

	/// Run one iteration: long-poll for a job and, if one arrives, run
	/// it. Returns `true` if a job was processed, `false` if the long-
	/// poll window elapsed without one.
	pub async fn step(&self, cancel: &CancellationToken) -> Result<bool> {
		let resp = self.client.lease(self.capabilities.clone(), LEASE_WAIT_SECONDS).await?;
		match resp {
			LeaseResponse::Empty { .. } => Ok(false),
			LeaseResponse::Lease(env) => {
				self.run_lease(*env, cancel).await?;
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
				Err(e) => {
					tracing::warn!(error = %e, "runner step failed; backing off");
					tokio::select! {
						_ = tokio::time::sleep(Duration::from_secs(5)) => {},
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
					head_sha,
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
	) -> Result<(Option<String>, usize)> {
		let key = RepoKey::new(&env.repo.host, &env.repo.owner, &env.repo.repo);
		let clone_url = env.repo.clone_url.clone();
		let github_pat = env.github_pat.clone();
		let mut ensured =
			self.cache.ensure_repo(&key, &env.repo.clone_url, env.github_pat.as_deref()).await?;
		// `ensured` (and its pin) lives until the end of this fn; the
		// repo cache won't evict the bare clone while the worktree
		// alternate is still in use.

		match env.payload {
			LeasePayload::Verify { finding_id, finding, reviewed_sha } => {
				let Some(reviewed_sha) = reviewed_sha.filter(|sha| !sha.trim().is_empty()) else {
					self.submit_revision_unavailable_verdict(
						env.job_id,
						finding_id,
						None,
						"verify lease did not carry the original reviewed revision",
					)
					.await?;
					return Ok((None, 0));
				};
				let (workdir, head_sha) =
					match checkout_revision(&ensured.path, &reviewed_sha, self.fetch_submodules)
						.await
					{
						Ok(ok) => ok,
						Err(first_error) => {
							tracing::warn!(
								job_id = env.job_id,
								finding_id,
								reviewed_sha = %reviewed_sha,
								error = %first_error,
								"verify revision missing from refreshed cache; re-cloning",
							);
							drop(ensured);
							ensured = self
								.cache
								.reclone_repo(&key, &clone_url, github_pat.as_deref())
								.await?;
							match checkout_revision(
								&ensured.path,
								&reviewed_sha,
								self.fetch_submodules,
							)
							.await
							{
								Ok(ok) => ok,
								Err(second_error) => {
									self.submit_revision_unavailable_verdict(
										env.job_id,
										finding_id,
										Some(&reviewed_sha),
										&second_error.to_string(),
									)
									.await?;
									return Ok((Some(reviewed_sha), 0));
								},
							}
						},
					};
				let workdir_size = crate::repo_cache::dir_size(workdir.path());
				if workdir_size > self.max_workdir_bytes {
					anyhow::bail!(
						"checkout size {workdir_size} bytes exceeds max_workdir_bytes {}",
						self.max_workdir_bytes
					);
				}
				let vctx = VerifyContext {
					workdir: workdir.path().to_path_buf(),
					repo: env.repo.clone(),
					repo_id: env.repo_id,
					job_id: env.job_id,
					finding_id,
					finding: *finding,
					config: env.scanner_config,
					cancel: cancel.clone(),
				};
				// Pick the first scanner advertising any verify:* tag.
				// Refining to per-tag matching can come later; today
				// the server already filtered the lease so we know
				// some verifier on this worker is eligible.
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
				match outcome {
					crate::VerifyOutcome::Verdict(verdict) => {
						tracing::info!(
							job_id = env.job_id,
							finding_id,
							verifier = verifier.id(),
							"submitting verdict (in-process verifier)"
						);
						self.client
							.submit_verdict(
								env.job_id,
								&VerdictSubmission { protocol_version: PROTOCOL_VERSION, verdict },
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
				Ok((Some(head_sha), 0))
			},
			LeasePayload::Scan { since_sha } => {
				tracing::info!(job_id = env.job_id, "checking out worktree");
				let (workdir, head_sha) = match checkout_latest(
					&ensured.path,
					env.head_branch.as_deref(),
					self.fetch_submodules,
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
							.reclone_repo(&key, &clone_url, github_pat.as_deref())
							.await?;
						checkout_latest(
							&ensured.path,
							env.head_branch.as_deref(),
							self.fetch_submodules,
						)
						.await?
					},
				};
				let workdir_size = crate::repo_cache::dir_size(workdir.path());
				tracing::info!(
					job_id = env.job_id,
					head_sha = %head_sha,
					workdir_bytes = workdir_size,
					"worktree ready"
				);
				if workdir_size > self.max_workdir_bytes {
					anyhow::bail!(
						"checkout size {workdir_size} bytes exceeds max_workdir_bytes {}",
						self.max_workdir_bytes
					);
				}
				let ctx = ScanContext {
					workdir: workdir.path().to_path_buf(),
					repo: env.repo.clone(),
					repo_id: env.repo_id,
					job_id: env.job_id,
					head_sha: head_sha.clone(),
					base_sha: since_sha,
					config: env.scanner_config,
					cancel: cancel.clone(),
				};

				let mut all = Vec::new();
				for s in &self.scanners {
					tracing::info!(job_id = env.job_id, scanner = s.id(), "running scanner");
					match s.scan(&ctx).await {
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
						Err(e) => tracing::warn!(scanner = s.id(), error = %e, "scanner failed"),
					}
				}
				if !all.is_empty() {
					let batch =
						FindingsBatch { protocol_version: PROTOCOL_VERSION, findings: all.clone() };
					self.client.submit_findings(env.job_id, &batch).await?;
				}
				Ok((Some(head_sha), all.len()))
			},
		}
	}

	async fn submit_revision_unavailable_verdict(
		&self, job_id: i64, finding_id: i64, reviewed_sha: Option<&str>, detail: &str,
	) -> Result<()> {
		let reason = match reviewed_sha {
			Some(sha) => format!(
				"original reviewed revision {sha} is unavailable after refreshing and re-cloning the repository: {detail}"
			),
			None => format!("original reviewed revision is unavailable: {detail}"),
		};
		tracing::warn!(
			job_id,
			finding_id,
			reviewed_sha = reviewed_sha.unwrap_or(""),
			"submitting terminal inconclusive verdict for unavailable verify revision",
		);
		self.client
			.submit_verdict(
				job_id,
				&VerdictSubmission {
					protocol_version: PROTOCOL_VERSION,
					verdict: Verdict::Inconclusive { reason, terminal: true },
				},
			)
			.await
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
/// to `branch` (or the remote/default HEAD if `None`). Returns the
/// worktree dir (a `TempDir` for cleanup) plus the resolved commit SHA.
pub async fn checkout_latest(
	bare: &Path, branch: Option<&str>, fetch_submodules: bool,
) -> Result<(tempfile::TempDir, String)> {
	checkout(bare, CheckoutTarget::Latest { branch: branch.map(str::to_owned) }, fetch_submodules)
		.await
}

/// Produce a fresh worktree from the bare clone at `bare` checked out
/// to one exact commit SHA.
pub async fn checkout_revision(
	bare: &Path, sha: &str, fetch_submodules: bool,
) -> Result<(tempfile::TempDir, String)> {
	checkout(bare, CheckoutTarget::Revision(sha.to_owned()), fetch_submodules).await
}

enum CheckoutTarget {
	Latest { branch: Option<String> },
	Revision(String),
}

async fn checkout(
	bare: &Path, target: CheckoutTarget, fetch_submodules: bool,
) -> Result<(tempfile::TempDir, String)> {
	let bare = bare.to_path_buf();
	let tmp = tempfile::tempdir().context("creating temp worktree dir")?;
	let workdir = tmp.path().to_path_buf();
	let head_sha = tokio::task::spawn_blocking(move || -> Result<String> {
		let repo = git2::Repository::open_bare(&bare)
			.with_context(|| format!("opening bare repo at {}", bare.display()))?;
		let commit = match target {
			CheckoutTarget::Latest { branch } => {
				let target_ref = match branch.as_deref() {
					Some(b) => repo
						.find_reference(&format!("refs/remotes/origin/{b}"))
						.or_else(|_| repo.find_reference(&format!("refs/heads/{b}")))
						.with_context(|| format!("locating ref for branch {b}"))?,
					None => repo
						.find_reference("refs/remotes/origin/HEAD")
						.or_else(|_| repo.find_reference("HEAD"))
						.context("locating HEAD reference")?,
				};
				target_ref.peel_to_commit().context("resolving ref to commit")?
			},
			CheckoutTarget::Revision(sha) => {
				let oid = git2::Oid::from_str(&sha)
					.with_context(|| format!("parsing reviewed revision {sha}"))?;
				let object = repo
					.find_object(oid, None)
					.with_context(|| format!("locating reviewed revision {sha}"))?;
				object.peel_to_commit().context("resolving reviewed revision to commit")?
			},
		};
		let tree = commit.tree().context("resolving commit tree")?;
		let mut opts = git2::build::CheckoutBuilder::new();
		opts.target_dir(&workdir).recreate_missing(true).force();
		repo.checkout_tree(tree.as_object(), Some(&mut opts))
			.context("checking out tree into worktree dir")?;
		if fetch_submodules {
			materialise_submodules(&tree, &workdir);
		}
		Ok(commit.id().to_string())
	})
	.await
	.map_err(|e| anyhow::anyhow!("checkout task panicked: {e}"))??;
	for path in unpopulated_submodules(tmp.path()) {
		tracing::warn!(
			submodule = %path,
			"submodule directory is empty; its contents are absent from this checkout \
			 and scanners will not see them. Set fetch_submodules to include them."
		);
	}
	Ok((tmp, head_sha))
}

/// `(path, url)` pairs declared in a `.gitmodules` file.
///
/// Deliberately tolerant: `.gitmodules` is INI-ish, and a submodule whose
/// stanza we fail to parse should be skipped rather than failing the scan.
fn parse_gitmodules(text: &str) -> Vec<(String, String)> {
	let mut out: Vec<(String, String)> = Vec::new();
	let (mut path, mut url) = (None::<String>, None::<String>);
	let mut flush = |path: &mut Option<String>, url: &mut Option<String>| {
		if let (Some(p), Some(u)) = (path.take(), url.take()) {
			out.push((p, u));
		}
	};
	for line in text.lines() {
		let line = line.trim();
		if line.starts_with('[') {
			flush(&mut path, &mut url);
		} else if let Some(v) =
			line.strip_prefix("path").and_then(|r| r.trim_start().strip_prefix('='))
		{
			path = Some(v.trim().to_owned());
		} else if let Some(v) =
			line.strip_prefix("url").and_then(|r| r.trim_start().strip_prefix('='))
		{
			url = Some(v.trim().to_owned());
		}
	}
	flush(&mut path, &mut url);
	out
}

/// Clone each declared submodule into `workdir` at the commit the
/// superproject pins.
///
/// The pinned commit lives in the superproject's tree as a gitlink entry, so
/// we read the OID from `tree` rather than trusting the submodule's default
/// branch — a scan must analyse the code this revision actually builds
/// against, not whatever upstream has moved to since.
///
/// Failures are logged and skipped, never fatal. A submodule that has moved,
/// gone private, or needs credentials should degrade the scan's coverage, not
/// abort a job that can still produce useful findings on the rest of the tree.
/// The empty-directory warning still fires for anything that did not land.
fn materialise_submodules(tree: &git2::Tree<'_>, workdir: &Path) {
	let text = match std::fs::read_to_string(workdir.join(".gitmodules")) {
		Ok(t) => t,
		Err(_) => return,
	};
	for (rel, url) in parse_gitmodules(&text) {
		let pinned = match tree.get_path(Path::new(&rel)) {
			Ok(entry) => entry.id(),
			Err(e) => {
				tracing::warn!(submodule = %rel, error = %e, "no gitlink entry for submodule; skipping");
				continue;
			},
		};
		let dest = workdir.join(&rel);
		if let Some(parent) = dest.parent() {
			let _ = std::fs::create_dir_all(parent);
		}
		let _ = std::fs::remove_dir(&dest);
		let cloned = std::process::Command::new("git")
			.args(["clone", "--quiet", "--no-checkout", &url])
			.arg(&dest)
			.output();
		match cloned {
			Ok(o) if o.status.success() => {},
			Ok(o) => {
				tracing::warn!(
					submodule = %rel,
					stderr = %String::from_utf8_lossy(&o.stderr).trim(),
					"cloning submodule failed; its contents stay absent from this checkout"
				);
				continue;
			},
			Err(e) => {
				tracing::warn!(submodule = %rel, error = %e, "spawning git clone for submodule failed");
				continue;
			},
		}
		let checked_out = std::process::Command::new("git")
			.arg("-C")
			.arg(&dest)
			.args(["checkout", "--quiet", "--detach", &pinned.to_string()])
			.output();
		match checked_out {
			Ok(o) if o.status.success() => {
				tracing::info!(submodule = %rel, commit = %pinned, "materialised submodule");
			},
			Ok(o) => tracing::warn!(
				submodule = %rel,
				commit = %pinned,
				stderr = %String::from_utf8_lossy(&o.stderr).trim(),
				"submodule cloned but the pinned commit could not be checked out"
			),
			Err(e) => {
				tracing::warn!(submodule = %rel, error = %e, "spawning git checkout for submodule failed")
			},
		}
	}
}

/// Submodule paths declared in `.gitmodules` that are empty on disk.
///
/// `git clone --bare` does not fetch submodules, and checking a tree out of a
/// bare clone writes gitlink entries as empty directories. A repository that
/// keeps dependencies in submodules is therefore only partly present in the
/// worktree, and a scanner will analyse a fraction of the program without
/// anything in its output saying so.
///
/// This warns rather than fetching. Many repositories vendor submodules that
/// are irrelevant to a review, and materialising them unconditionally would
/// multiply an operator's scan cost without being asked. The goal is only that
/// an incomplete checkout is never silent.
fn unpopulated_submodules(workdir: &Path) -> Vec<String> {
	let Ok(text) = std::fs::read_to_string(workdir.join(".gitmodules")) else {
		return Vec::new();
	};
	text.lines()
		.filter_map(|line| {
			let rest = line.trim().strip_prefix("path")?.trim_start();
			let rest = rest.strip_prefix('=')?.trim();
			(!rest.is_empty()).then(|| rest.to_owned())
		})
		.filter(|rel| match std::fs::read_dir(workdir.join(rel)) {
			Ok(mut entries) => entries.next().is_none(),
			Err(_) => true,
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use std::process::Command;

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
	fn parse_gitmodules_pairs_path_with_url() {
		let text =
			"[submodule \"external/a\"]\n\tpath = external/a\n\turl = https://x.invalid/a.git\n\
		            [submodule \"external/b\"]\n\turl = https://x.invalid/b.git\n\tpath = external/b\n\
		            [submodule \"broken\"]\n\tpath = external/c\n";
		assert_eq!(
			parse_gitmodules(text),
			vec![
				("external/a".to_owned(), "https://x.invalid/a.git".to_owned()),
				("external/b".to_owned(), "https://x.invalid/b.git".to_owned()),
			]
		);
	}

	/// `materialise_submodules` must clone the dependency at the commit the
	/// superproject pins, not at whatever the dependency's branch has moved to.
	/// Scanning a revision means scanning what it actually builds against.
	#[test]
	fn materialise_submodules_uses_the_pinned_commit_not_the_tip() {
		fn git(dir: &std::path::Path, args: &[&str]) {
			let out = Command::new("git")
				.current_dir(dir)
				.args(args)
				.env("GIT_AUTHOR_NAME", "t")
				.env("GIT_AUTHOR_EMAIL", "t@t")
				.env("GIT_COMMITTER_NAME", "t")
				.env("GIT_COMMITTER_EMAIL", "t@t")
				.output()
				.unwrap();
			assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
		}
		fn head(dir: &std::path::Path) -> String {
			String::from_utf8(
				Command::new("git")
					.current_dir(dir)
					.args(["rev-parse", "HEAD"])
					.output()
					.unwrap()
					.stdout,
			)
			.unwrap()
			.trim()
			.to_owned()
		}

		let tmp = tempfile::tempdir().unwrap();
		let root = tmp.path();

		// Dependency with two commits; the superproject will pin the first.
		let dep = root.join("dep");
		std::fs::create_dir_all(&dep).unwrap();
		git(&dep, &["init", "--quiet", "-b", "main"]);
		std::fs::write(dep.join("lib.c"), "int pinned(void){return 1;}\n").unwrap();
		git(&dep, &["add", "-A"]);
		git(&dep, &["commit", "--quiet", "-m", "pinned"]);
		let pinned = head(&dep);
		std::fs::write(dep.join("lib.c"), "int moved_on(void){return 2;}\n").unwrap();
		git(&dep, &["add", "-A"]);
		git(&dep, &["commit", "--quiet", "-m", "later tip"]);
		assert_ne!(pinned, head(&dep));

		// Superproject with a gitlink at the pinned commit.
		let sup = root.join("sup");
		std::fs::create_dir_all(&sup).unwrap();
		git(&sup, &["init", "--quiet", "-b", "main"]);
		std::fs::write(
			sup.join(".gitmodules"),
			format!(
				"[submodule \"external/dep\"]\n\tpath = external/dep\n\turl = {}\n",
				dep.display()
			),
		)
		.unwrap();
		std::fs::write(sup.join("main.c"), "int main(void){return 0;}\n").unwrap();
		git(&sup, &["add", "-A"]);
		git(
			&sup,
			&["update-index", "--add", "--cacheinfo", &format!("160000,{pinned},external/dep")],
		);
		git(&sup, &["commit", "--quiet", "-m", "pin dep"]);

		let repo = git2::Repository::open(&sup).unwrap();
		let tree = repo.head().unwrap().peel_to_commit().unwrap().tree().unwrap();

		// A worktree as a bare checkout leaves it: .gitmodules present, path empty.
		let work = root.join("work");
		std::fs::create_dir_all(work.join("external/dep")).unwrap();
		std::fs::copy(sup.join(".gitmodules"), work.join(".gitmodules")).unwrap();
		assert_eq!(unpopulated_submodules(&work), vec!["external/dep".to_owned()]);

		materialise_submodules(&tree, &work);

		let body = std::fs::read_to_string(work.join("external/dep/lib.c"))
			.expect("submodule contents must be present after materialising");
		assert!(body.contains("pinned"), "expected the pinned commit, got: {body}");
		assert!(!body.contains("moved_on"), "must not follow the dependency's later tip");
		assert!(unpopulated_submodules(&work).is_empty());
	}

	#[test]
	fn unpopulated_submodules_reports_only_empty_paths() {
		let tmp = tempfile::tempdir().unwrap();
		let root = tmp.path();
		std::fs::write(
			root.join(".gitmodules"),
			"[submodule \"external/empty\"]\n\tpath = external/empty\n\turl = https://example.invalid/e.git\n\
			 [submodule \"external/filled\"]\n\tpath = external/filled\n\turl = https://example.invalid/f.git\n",
		)
		.unwrap();
		std::fs::create_dir_all(root.join("external/empty")).unwrap();
		std::fs::create_dir_all(root.join("external/filled")).unwrap();
		std::fs::write(root.join("external/filled/src.c"), "int main(void){return 0;}\n").unwrap();

		assert_eq!(unpopulated_submodules(root), vec!["external/empty".to_owned()]);
	}

	#[test]
	fn unpopulated_submodules_is_empty_without_gitmodules() {
		let tmp = tempfile::tempdir().unwrap();
		assert!(unpopulated_submodules(tmp.path()).is_empty());
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

	#[tokio::test]
	async fn checkout_revision_uses_original_sha_not_latest_branch_tip() {
		let remote_tmp = tempfile::tempdir().unwrap();
		init_git_repo(remote_tmp.path());
		let first = commit_file(remote_tmp.path(), "one\n", "One");
		let second = commit_file(remote_tmp.path(), "two\n", "Two");

		let bare_tmp = tempfile::tempdir().unwrap();
		let bare = bare_tmp.path().join("cache.git");
		let url = format!("file://{}", remote_tmp.path().display());
		let output = Command::new("git")
			.arg("clone")
			.arg("--bare")
			.arg("--quiet")
			.arg(&url)
			.arg(&bare)
			.output()
			.unwrap();
		assert!(
			output.status.success(),
			"git clone failed: {}",
			String::from_utf8_lossy(&output.stderr)
		);

		let (latest_workdir, latest_sha) =
			checkout_latest(&bare, Some("main"), false).await.unwrap();
		assert_eq!(latest_sha, second);
		assert_eq!(
			std::fs::read_to_string(latest_workdir.path().join("file.txt")).unwrap(),
			"two\n"
		);

		let (review_workdir, reviewed_sha) = checkout_revision(&bare, &first, false).await.unwrap();
		assert_eq!(reviewed_sha, first);
		assert_eq!(
			std::fs::read_to_string(review_workdir.path().join("file.txt")).unwrap(),
			"one\n"
		);
	}
}
