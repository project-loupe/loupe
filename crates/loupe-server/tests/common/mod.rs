//! Shared helpers for `loupe-server` integration tests.
//!
//! Each `tests/*.rs` is a separate binary, so this module is pulled
//! in via `mod common;` per file rather than auto-imported. The
//! helpers here aren't part of any public crate surface — they exist
//! only to dedupe what would otherwise be 9× copies of the same
//! reqwest-PEM plumbing.
//!
//! `#[allow(dead_code)]` because a given test file might use only
//! one of these — mod-level dead-code warnings fire per-binary.

#![allow(dead_code)]
#![deny(unsafe_code)]

pub mod marked;
pub mod offline;
pub mod wire;

use clap::builder::TypedValueParser;
use loupe_server::config::{ConfiguredHostname, ConfiguredPath, ConfiguredPem};

pub fn with_repo<T>(
	db: &loupe_storage::Db, repo_id: i64,
	f: impl for<'tx> FnOnce(&loupe_storage::scope::RepoScope<'tx>) -> loupe_storage::Result<T>,
) -> loupe_storage::Result<T> {
	loupe_storage::scope::with_operator_repository(
		db,
		&marked::operator_ingress(),
		loupe_storage::scope::OperatorTarget::Repository(repo_id),
		f,
	)
}

pub fn repo(db: &loupe_storage::Db, repo_id: i64) -> loupe_storage::repos::RepoRow {
	with_repo(db, repo_id, loupe_storage::repos::get).unwrap().unwrap()
}

pub fn findings(db: &loupe_storage::Db, repo_id: i64) -> Vec<loupe_storage::findings::FindingRow> {
	with_repo(db, repo_id, |scope| loupe_storage::findings::list_for_repo(scope, i64::MAX)).unwrap()
}

pub fn job(db: &loupe_storage::Db, repo_id: i64, id: i64) -> loupe_storage::jobs::JobRow {
	with_repo(db, repo_id, |scope| loupe_storage::jobs::get(scope, id)).unwrap().unwrap()
}

pub fn finding(
	db: &loupe_storage::Db, repo_id: i64, id: i64,
) -> loupe_storage::findings::FindingRow {
	with_repo(db, repo_id, |scope| loupe_storage::findings::get(scope, id)).unwrap().unwrap()
}

pub fn jobs(db: &loupe_storage::Db, repo_id: i64) -> Vec<loupe_storage::jobs::JobRow> {
	loupe_storage::jobs::catalog(
		db,
		&marked::operator_ingress(),
		&loupe_storage::jobs::JobFilter::<loupe_provenance::Operator>::default(),
	)
	.unwrap()
	.into_iter()
	.filter(|job| job.repo_id == repo_id)
	.collect()
}

pub fn new_repo() -> loupe_storage::repos::NewRepo<loupe_provenance::Operator> {
	loupe_storage::repos::NewRepo {
		clone_url: marked::operator::text("https://github.com/example/repo.git"),
		host: marked::operator::text("github.com"),
		owner: marked::operator::text("example"),
		repo: marked::operator::text("repo"),
		default_branch: None,
		scan_interval_seconds: None,
		scanner_config: marked::scanner_config("null"),
		reporting: loupe_core::ReportingDestination::Manual,
		verification_enabled: false,
		require_approval: Some(false),
	}
}

pub fn register_repo(
	db: &loupe_storage::Db, new: &loupe_storage::repos::NewRepo<loupe_provenance::Operator>,
	pat: Option<&loupe_provenance::Secret<String>>,
) -> i64 {
	let loupe_storage::registry::ReportingWrite::Done(id) =
		loupe_storage::registry::register_repository(db, &marked::operator_ingress(), new, pat, 0)
			.unwrap()
	else {
		panic!("fixture repository registration requires configured reporting")
	};
	id
}

/// Register authored worker fixtures with a local clone and the real credential owner.
pub fn register_local_repo(
	db: &loupe_storage::Db, clone_url: &str, request: wire::RegisterRepoRequest,
) -> i64 {
	use loupe_core::ReportingDestination;
	let parsed = reqwest::Url::parse(&request.clone_url).unwrap();
	let mut parts = parsed.path().trim_matches('/').split('/');
	let owner = parts.next().unwrap();
	let name = parts.next().unwrap().trim_end_matches(".git");
	let (reporting, pat) = match request.reporting {
		wire::ReportingSetup::GithubIssue { target_owner, target_repo, github_pat } => (
			ReportingDestination::GithubIssue {
				target_owner: marked::operator::text(&target_owner),
				target_repo: marked::operator::text(&target_repo),
				pat_secret_id: None,
			},
			github_pat,
		),
		wire::ReportingSetup::Manual => (ReportingDestination::Manual, None),
		wire::ReportingSetup::Email { to, from, subject_prefix } => (
			ReportingDestination::Email {
				to: to.iter().map(|value| marked::operator::text(value)).collect(),
				from: from.as_deref().map(marked::operator::text),
				subject_prefix: subject_prefix.as_deref().map(marked::operator::text),
			},
			None,
		),
	};
	register_repo(
		db,
		&loupe_storage::repos::NewRepo {
			clone_url: marked::operator::text(clone_url),
			host: marked::operator::text(parsed.host_str().unwrap()),
			owner: marked::operator::text(owner),
			repo: marked::operator::text(name),
			default_branch: request.branch.as_deref().map(marked::operator::text),
			scan_interval_seconds: request
				.scan_interval_seconds
				.map(|seconds| i64::try_from(seconds).unwrap()),
			scanner_config: marked::scanner_config(&request.scanner_config.to_string()),
			reporting,
			verification_enabled: request.verification_enabled.unwrap(),
			require_approval: request.require_approval,
		},
		pat.as_ref(),
	)
}

/// Produce one confirmed finding using a claimed scan and normal completion.
pub fn confirmed_finding(
	db: &loupe_storage::Db, repo_id: i64, finding: &loupe_core::Finding<loupe_provenance::Agent>,
) -> i64 {
	use loupe_storage::{findings, jobs, registry, reports, scheduler, scope};
	let worker_id = registry::register_worker(
		db,
		&marked::operator_ingress(),
		&marked::operator::text("fixture-producer"),
		&[87; 32],
		0,
	)
	.unwrap();
	let job_id = with_repo(db, repo_id, |scope| {
		jobs::enqueue(
			scope,
			&jobs::QueuedJob::<loupe_provenance::Operator> {
				kind: loupe_core::JobKind::Scan,
				incremental: false,
				since_sha: None,
				parent_job_id: None,
				target_finding_id: None,
			},
			0,
		)
	})
	.unwrap();
	let claimed = scheduler::claim(
		db,
		&scheduler::ClaimRequest::<loupe_provenance::Operator> {
			worker_id,
			kinds: &[loupe_core::JobKind::Scan],
			now: 0,
			capability_hash: &[87; 32],
			legacy_lease_seconds: 100,
			policy: &scheduler::ClaimPolicy::default(),
		},
	)
	.unwrap()
	.unwrap();
	assert_eq!(claimed.claimed.job.id, job_id);
	scope::with_active_lease(
		db,
		jobs::ActiveLease {
			identity: jobs::LeaseIdentity { job_id, worker_id, capability_hash: &[87; 32] },
			now: 1,
		},
		|scope| {
			let id = findings::submit(scope, finding)?.unwrap();
			let _prepared = reports::complete_assignment::<
				loupe_provenance::Operator,
				loupe_provenance::Operator,
			>(
				scope,
				loupe_core::JobState::Succeeded,
				Some(&marked::operator::text("fixture-revision")),
				None,
				false,
				99,
			)?;
			Ok(id)
		},
	)
	.unwrap()
	.unwrap()
}

/// Feed synthetic native arguments through the real Config ingress callback.
pub fn config_path(path: impl AsRef<std::path::Path>) -> ConfiguredPath {
	loupe_server::config::PathParser
		.parse_ref(&clap::Command::new("fixture"), None, path.as_ref().as_os_str())
		.unwrap()
}

pub fn config_hostname(name: &str) -> ConfiguredHostname {
	loupe_server::config::HostnameParser
		.parse_ref(&clap::Command::new("fixture"), None, std::ffi::OsStr::new(name))
		.unwrap()
}

pub fn config_pem(pem: &str) -> ConfiguredPem {
	let argument = loupe_server::config::PemParser
		.parse_ref(&clap::Command::new("fixture"), None, std::ffi::OsStr::new(pem))
		.unwrap();
	loupe_server::config::select_tls_pem("fixture", Some(argument), None, None, "missing").unwrap()
}

/// Reporter fixtures obtain Db owners through the actual SQL reader.
pub fn reporter_repo() -> loupe_storage::repos::RepoRow {
	let db =
		loupe_storage::Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests()).unwrap();
	let mut new = new_repo();
	new.reporting = loupe_core::ReportingDestination::GithubIssue {
		target_owner: marked::operator::text("example"),
		target_repo: marked::operator::text("repo"),
		pat_secret_id: None,
	};
	let id = register_repo(&db, &new, Some(&loupe_provenance::Secret::new("fake-test-pat".into())));
	repo(&db, id)
}

/// Select a real stored report, including its guarded reporting credential.
pub fn prepared_report(app: bool) -> loupe_storage::reports::PreparedReport {
	use loupe_storage::{jobs, registry, reports, scheduler, scope};
	let db =
		loupe_storage::Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests()).unwrap();
	let operator = marked::operator_ingress();
	if app {
		registry::store_github_app(
			&db,
			&operator,
			&loupe_storage::github_app::StoredGithubApp {
				app_id: 1,
				slug: marked::operator::text("fixture"),
				private_key_pem: loupe_provenance::Secret::new(
					loupe_server::reporters::github_app::testing::APP_PRIVATE_KEY_PEM.to_owned(),
				),
			},
			0,
		)
		.unwrap();
	}
	let mut new = new_repo();
	new.reporting = loupe_core::ReportingDestination::GithubIssue {
		target_owner: marked::operator::text("example"),
		target_repo: marked::operator::text("repo"),
		pat_secret_id: None,
	};
	let pat = loupe_provenance::Secret::new("fake-test-pat".into());
	let repo_id = register_repo(&db, &new, if app { None } else { Some(&pat) });
	let worker_id =
		registry::register_worker(&db, &operator, &marked::operator::text("fixture"), &[7], 0)
			.unwrap();
	let job_id = with_repo(&db, repo_id, |scope| {
		jobs::enqueue(
			scope,
			&jobs::QueuedJob::<loupe_provenance::Operator> {
				kind: loupe_core::JobKind::Scan,
				incremental: false,
				since_sha: None,
				parent_job_id: None,
				target_finding_id: None,
			},
			0,
		)
	})
	.unwrap();
	let claimed = scheduler::claim(
		&db,
		&scheduler::ClaimRequest::<loupe_provenance::Operator> {
			worker_id,
			kinds: &[loupe_core::JobKind::Scan],
			now: 0,
			capability_hash: &[7; 32],
			legacy_lease_seconds: 100,
			policy: &scheduler::ClaimPolicy::default(),
		},
	)
	.unwrap()
	.unwrap();
	assert_eq!(claimed.claimed.job.id, job_id);
	let finding = loupe_core::Finding {
		scanner_id: marked::agent::text("fixture"),
		severity: loupe_core::Severity::High,
		title: marked::agent::text("title"),
		description: marked::agent::text("description"),
		file_path: None,
		line_start: None,
		line_end: None,
		cwe: None,
		patch_unified: None,
		poc_unified: None,
		fingerprint: marked::agent::text("fixture"),
	};
	match scope::with_active_lease(
		&db,
		jobs::ActiveLease {
			identity: jobs::LeaseIdentity { job_id, worker_id, capability_hash: &[7; 32] },
			now: 1,
		},
		|scope| {
			assert!(loupe_storage::findings::submit(scope, &finding)?.is_some());
			reports::complete_assignment::<loupe_provenance::Operator, loupe_provenance::Operator>(
				scope,
				loupe_core::JobState::Succeeded,
				Some(&marked::operator::text("fixture-revision")),
				None,
				false,
				99,
			)
		},
	)
	.unwrap()
	.unwrap()
	{
		reports::Preparation::Ready(batch) => *batch,
		_ => panic!("report fixture must prepare"),
	}
}

pub fn file_config(raw: &str) -> anyhow::Result<loupe_server::FileConfig> {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("config.toml");
	std::fs::write(&path, raw).unwrap();
	loupe_server::FileConfig::load(&path)
}

pub fn allowed_owners(
	owners: Option<Vec<String>>,
) -> Option<
	Vec<
		loupe_core::text::BoundedText<
			loupe_core::text::policy::RepoOwner,
			loupe_provenance::Config,
		>,
	>,
> {
	owners.map(|owners| {
		let list = serde_json::to_string(&owners).unwrap();
		file_config(&format!("[github_app]\nallowed_target_owners = {list}\n"))
			.unwrap()
			.github_app
			.allowed_target_owners
			.unwrap()
	})
}

/// Resolve and store policy through the actual campaign owner, then read Db bytes.
pub fn stored_policy(
	policy: &loupe_server::review::policy::ReviewPolicy,
) -> loupe_core::text::BoundedJson<loupe_core::text::policy::Payload, loupe_provenance::Db> {
	use loupe_server::review::campaign::{self, KindHint, OpenCampaign, Opened, RequestedRef};
	let db =
		loupe_storage::Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests()).unwrap();
	let repo_id = register_repo(&db, &new_repo(), None);
	with_repo(&db, repo_id, |scope| {
		let reference = marked::operator::text("main");
		let opened = campaign::open(
			scope,
			&OpenCampaign {
				trigger: loupe_storage::campaigns::Trigger::Manual,
				requested_ref: RequestedRef::Branch(&reference),
				base_sha: None,
				kind_hint: KindHint::Incremental,
			},
			policy,
			0,
		)?;
		let Opened::Created { campaign_id, .. } = opened else { panic!("new campaign") };
		// Independent SQL/canonical/digest agreement is asserted inside storage
		// by stored_policy_sql_bytes_and_digest_match_the_actual_typed_readback.
		Ok(loupe_storage::campaigns::get(scope, campaign_id)?.unwrap().effective_policy)
	})
	.unwrap()
}

/// Assert the recipe's typed readback; storage also checks raw SQL.
pub fn assert_survey_recipe(job: &loupe_storage::jobs::JobRow, recipe: &str) {
	let expected = format!(
		r#"{{"assignment_key":"ordinary","phase":"survey","recipe":"{recipe}","version":1}}"#
	);
	let stored = job.recipe.as_ref().expect("survey recipe");
	assert_eq!(stored.expose(), expected);
	assert_eq!(*stored.digest(), loupe_core::canonical::digest(expected.as_bytes()));
}

/// Wrap a CA-cert PEM in the form `reqwest::Client::builder()
/// .add_root_certificate` expects.
pub fn pem_to_certificate(pem: &str) -> reqwest::Certificate {
	reqwest::Certificate::from_pem(pem.as_bytes()).expect("parse cert PEM")
}

/// Combine an mTLS client cert + key into the single-PEM-blob form
/// `reqwest::Identity::from_pem` expects. Forces a separator newline
/// so back-to-back PEMs without trailing newlines still parse.
pub fn pem_to_identity(cert_pem: &str, key_pem: &str) -> reqwest::Identity {
	let mut combined = String::with_capacity(cert_pem.len() + key_pem.len() + 1);
	combined.push_str(cert_pem);
	if !cert_pem.ends_with('\n') {
		combined.push('\n');
	}
	combined.push_str(key_pem);
	reqwest::Identity::from_pem(combined.as_bytes()).expect("parse client identity PEM")
}
