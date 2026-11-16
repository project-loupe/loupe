//! Legacy scan and verify jobs: check out the repository, run the
//! matching scanner, and submit its findings or verdict.

use std::sync::Arc;

use anyhow::Result;
use loupe_core::security_event::Operation;
use loupe_proto::{
	FindingsBatch, LeaseEnvelope, LeasePayload, VerdictSubmission, PROTOCOL_VERSION,
};
use loupe_provenance::{Agent, Server};
use tokio_util::sync::CancellationToken;

use super::{checkout_latest, checkout_revision, CompletionRevision, LeaseRepo, Runner};
use crate::host_outcome::{CheckoutFailure, HostVerifyReason, ReviewedRevisionFact};
use crate::scanner::{ScanContext, VerifyContext};

pub(super) async fn run(
	runner: &Runner, env: LeaseEnvelope<Agent, Server>, reviewed_revision: ReviewedRevisionFact,
	scanner_patch: Option<crate::source_discovery::ScannerConfigPatch>, cancel: CancellationToken,
	security: Arc<crate::canary::JobSecurity>,
) -> Result<Option<CompletionRevision>> {
	let tool_boundary = crate::llm::prompt::JobToolBoundary::new()?;
	let mut repo = LeaseRepo::ensure(&runner.cache, &env.repo, env.github_pat).await?;
	// `repo` (and its pin) lives until the end of this fn; the
	// repo cache won't evict the bare clone while the worktree
	// alternate is still in use.

	match env.payload {
		LeasePayload::ReviewSurvey(_)
		| LeasePayload::ReviewDrilldown(_)
		| LeasePayload::ReviewVerify(_) => {
			unreachable!("review payloads are dispatched before repository access")
		},
		LeasePayload::Verify { finding_id, finding, reviewed_sha: _ } => {
			let ReviewedRevisionFact::Available(revision) = reviewed_revision else {
				runner
					.submit_revision_unavailable_verdict(
						env.job_id,
						&env.job_capability,
						finding_id,
						HostVerifyReason::MissingReviewedRevision,
						&security,
						&cancel,
					)
					.await?;
				return Ok(None);
			};
			// The lease decoder retains the Server mark through this operational view.
			let reviewed_sha = revision.clone().into_revision();
			let (workdir, head_sha) =
				match checkout_revision(repo.path(), reviewed_sha.expose()).await {
					Ok(ok) => ok,
					Err(first_error) => {
						tracing::warn!(
							job_id = env.job_id,
							finding_id,
							error = %first_error,
							"verify revision missing from refreshed cache; re-cloning",
						);
						repo = repo.reclone().await?;
						match checkout_revision(repo.path(), reviewed_sha.expose()).await {
							Ok(ok) => ok,
							Err(second_error) => {
								runner
									.submit_revision_unavailable_verdict(
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
										&cancel,
									)
									.await?;
								return Ok(Some(CompletionRevision::Reviewed(reviewed_sha)));
							},
						}
					},
				};
			let workdir = repo.pin(workdir);
			let workdir_size = crate::repo_cache::dir_size(workdir.path());
			runner.enforce_workdir_cap(workdir_size)?;
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
			let verifier = runner
				.scanners
				.iter()
				.find(|s| s.capabilities().iter().any(|c| c.starts_with("verify:")))
				.ok_or_else(|| {
					anyhow::anyhow!(
						"verify lease arrived but worker advertises no verify:* scanner"
					)
				})?;
			anyhow::ensure!(!cancel.is_cancelled(), "job cancelled");
			let outcome = verifier.verify(&vctx).await?;
			security.admit(Operation::SubmitVerdict)?;
			anyhow::ensure!(!cancel.is_cancelled(), "job cancelled");
			match outcome {
				crate::VerifyOutcome::Host(reason) => {
					security
						.run(
							Operation::SubmitVerdict,
							runner.client.submit_host_verdict(
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
							runner.client.submit_verdict(
								env.job_id,
								&env.job_capability,
								&VerdictSubmission { protocol_version: PROTOCOL_VERSION, verdict },
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
			Ok(Some(CompletionRevision::CheckedOut(head_sha)))
		},
		LeasePayload::Scan { since_sha } => {
			tracing::info!(job_id = env.job_id, "checking out worktree");
			let (workdir, head_sha) =
				match checkout_latest(repo.path(), env.head_branch.as_ref().map(|v| v.expose()))
					.await
				{
					Ok(ok) => ok,
					Err(first_error) => {
						tracing::warn!(
							job_id = env.job_id,
							error = %first_error,
							"scan checkout failed from refreshed cache; re-cloning",
						);
						repo = repo.reclone().await?;
						checkout_latest(repo.path(), env.head_branch.as_ref().map(|v| v.expose()))
							.await?
					},
				};
			let workdir = repo.pin(workdir);
			let workdir_size = crate::repo_cache::dir_size(workdir.path());
			tracing::info!(job_id = env.job_id, workdir_bytes = workdir_size, "worktree ready");
			runner.enforce_workdir_cap(workdir_size)?;
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
			for s in &runner.scanners {
				security.admit(Operation::SubmitFindings)?;
				anyhow::ensure!(!cancel.is_cancelled(), "job cancelled");
				tracing::info!(job_id = env.job_id, scanner = s.id(), "running scanner");
				let result = s.scan(&ctx).await;
				security.admit(Operation::SubmitFindings)?;
				anyhow::ensure!(!cancel.is_cancelled(), "job cancelled");
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
					Err(_) => {
						tracing::warn!(scanner = s.id(), "scanner failed");
						anyhow::bail!("scanner failed");
					},
				}
			}
			anyhow::ensure!(!cancel.is_cancelled(), "job cancelled");
			if !all.is_empty() {
				let batch = FindingsBatch { protocol_version: PROTOCOL_VERSION, findings: all };
				security
					.run(
						Operation::SubmitFindings,
						runner.client.submit_findings(env.job_id, &env.job_capability, &batch),
					)
					.await?;
			}
			Ok(Some(CompletionRevision::CheckedOut(head_sha)))
		},
	}
}
