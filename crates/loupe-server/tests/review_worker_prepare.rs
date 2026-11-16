//! Survey preparation on the worker against the actual router: a git
//! fixture repository, real checkout, inventory upload and seal, and the
//! server's own digest check.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use git2::{ObjectType, Oid, Repository, RepositoryInitOptions, Signature};
use loupe_proto::review_api::PublishProfileRequestDecoder;
use loupe_proto::review_lease::{BootstrapTarget, OrdinarySurveyRecipe, ReviewSurveyContext};
use loupe_proto::review_lifecycle::PhaseFailureRequestDecoder;
use loupe_proto::review_terminal::FinalizeSurveyRequestDecoder;
use loupe_proto::review_units::ReviewUnitRequestDecoder;
use loupe_proto::LeaseResponse;
use loupe_server::review::campaign;
use loupe_server::review::policy::ReviewPolicy;
use loupe_server::{router, AppState, PeerCert};
use loupe_storage::registry;
use loupe_tls::Ca;
use loupe_worker::client::PhaseError;
use loupe_worker::survey_prepare::{
	prepare, Preparation, PrepareError, PreparedSurvey, SurveyRecipe,
};
use loupe_worker::{RepoCache, Runner, ServerClient};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use serde_json::{json, Value};

mod common;

fn now() -> i64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// A non-bare origin whose `main` points at commits built from raw trees.
struct Origin {
	dir: tempfile::TempDir,
	repo: Repository,
}

impl Origin {
	fn new() -> Self {
		let dir = tempfile::tempdir().unwrap();
		let mut options = RepositoryInitOptions::new();
		options.initial_head("main");
		let repo = Repository::init_opts(dir.path().join("origin"), &options).unwrap();
		Self { dir, repo }
	}
	fn url(&self) -> String {
		format!("file://{}", self.dir.path().join("origin").display())
	}
	fn blob(&self, contents: &[u8]) -> Oid {
		self.repo.blob(contents).unwrap()
	}
	/// Raw tree bytes, so odd modes and raw names survive as written.
	fn tree(&self, entries: &[(&str, Vec<u8>, Oid)]) -> Oid {
		let mut bytes = Vec::new();
		for (mode, name, oid) in entries {
			bytes.extend_from_slice(mode.as_bytes());
			bytes.push(b' ');
			bytes.extend_from_slice(name);
			bytes.push(0);
			bytes.extend_from_slice(oid.as_bytes());
		}
		self.repo.odb().unwrap().write(ObjectType::Tree, &bytes).unwrap()
	}
	fn commit(&self, tree: Oid) -> String {
		let tree = self.repo.find_tree(tree).unwrap();
		let sig = Signature::now("loupe-test", "loupe-test@example.com").unwrap();
		let parent = self.repo.head().ok().and_then(|head| head.peel_to_commit().ok());
		let parents: Vec<_> = parent.iter().collect();
		self.repo
			.commit(Some("refs/heads/main"), &sig, &sig, "fixture", &tree, &parents)
			.unwrap()
			.to_string()
	}
	/// Odd and raw entries: 100664, a symlink, a gitlink, non-UTF-8 names and
	/// a directory whose name sorts differently as a tree than as a path.
	fn odd(&self) -> String {
		let (file, exec) = (self.blob(b"fn main() {}\n"), self.blob(b"#!/bin/sh\n"));
		let nested = self.tree(&[("100755", b"run".to_vec(), exec)]);
		let raw = self.tree(&[("100644", b"x".to_vec(), file)]);
		let root = self.tree(&[
			("100644", b"a.b".to_vec(), file),
			("40000", b"a".to_vec(), nested),
			("40000", b"d\xfe".to_vec(), raw),
			("100664", b"group.rs".to_vec(), file),
			("120000", b"link".to_vec(), self.blob(b"a.b")),
			("160000", b"vendor".to_vec(), Oid::from_str(&"c".repeat(40)).unwrap()),
			("100644", b"z.rs".to_vec(), file),
			("100644", b"\xffraw".to_vec(), file),
		]);
		self.commit(root)
	}
	/// More entries than one inventory batch holds.
	fn wide(&self, count: usize) -> String {
		let blob = self.blob(b"x");
		let entries: Vec<_> =
			(0..count).map(|i| ("100644", format!("f{i:05}").into_bytes(), blob)).collect();
		let root = self.tree(&entries);
		self.commit(root)
	}
}

/// Every phase request the worker sends, with the batch start position.
#[derive(Default)]
struct Log {
	calls: Mutex<Vec<(String, Option<u64>)>>,
	/// Reject the first batch starting at or after this position (0: none).
	reject_from: AtomicU64,
}
impl Log {
	fn take(&self) -> Vec<(String, Option<u64>)> {
		std::mem::take(&mut *self.calls.lock().unwrap())
	}
}

struct Fixture {
	state: AppState,
	offline: common::offline::OfflineDatabase,
	origin: Origin,
	client: Arc<ServerClient>,
	runner: Runner,
	log: Arc<Log>,
	_cache: tempfile::TempDir,
}

async fn observe(log: Arc<Log>, request: Request, next: Next) -> Response {
	let (parts, body) = request.into_parts();
	let bytes = to_bytes(body, 8 << 20).await.unwrap();
	let route = parts.uri.path().rsplit('/').next().unwrap().to_owned();
	let start = serde_json::from_slice::<Value>(&bytes)
		.ok()
		.and_then(|value| value["start_position"].as_u64());
	if route != "lease" {
		log.calls.lock().unwrap().push((route.clone(), start));
	}
	if route == "inventory-batches"
		&& start.is_some_and(|start| {
			let from = log.reject_from.load(Ordering::SeqCst);
			from > 0 && start >= from && log.reject_from.swap(0, Ordering::SeqCst) == from
		}) {
		return StatusCode::FORBIDDEN.into_response();
	}
	next.run(Request::from_parts(parts, Body::from(bytes))).await
}

async fn fixture(origin: Origin) -> Fixture {
	let mut offline = common::offline::OfflineDatabase::new();
	let db = offline.open();
	let ca = Arc::new(Ca::new("worker-prepare").unwrap());
	let bundle = ca.mint_client("worker").unwrap();
	let peer = PeerCert(
		CertificateDer::pem_slice_iter(bundle.cert_pem.as_bytes()).next().unwrap().unwrap(),
	);
	let mut repo = common::new_repo();
	repo.clone_url = common::marked::operator::text(&origin.url());
	assert_eq!(common::register_repo(&db, &repo, None), 1);
	registry::register_worker(
		&db,
		&common::marked::operator_ingress(),
		&common::marked::operator::text("worker"),
		&loupe_tls::cert_fingerprint(peer.0.as_ref()),
		now(),
	)
	.unwrap();
	let policy = ReviewPolicy::default();
	open_campaign(&db, None);
	let state =
		AppState::new(db, ca, Arc::new(loupe_server::reporters::GithubReporter::new().unwrap()))
			.with_review_policy(policy)
			.unwrap();
	let log = Arc::new(Log::default());
	let observed = log.clone();
	let app = router(state.clone())
		.layer(axum::middleware::from_fn(move |request, next| {
			observe(observed.clone(), request, next)
		}))
		.layer(axum::Extension(peer));
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let base = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	let client = Arc::new(ServerClient::from_parts(reqwest::Client::new(), base));
	let cache_dir = tempfile::tempdir().unwrap();
	let cache = Arc::new(RepoCache::new(cache_dir.path().to_owned(), u64::MAX, None).unwrap());
	let runner = Runner::new(client.clone(), cache, Vec::new());
	Fixture { state, offline, origin, client, runner, log, _cache: cache_dir }
}

fn open_campaign(db: &loupe_storage::Db, base_sha: Option<&str>) {
	common::with_repo(db, 1, |scope| {
		let base = base_sha.map(common::marked::operator::text);
		let opened = campaign::open(
			scope,
			&campaign::OpenCampaign {
				trigger: loupe_storage::campaigns::Trigger::Manual,
				requested_ref: campaign::RequestedRef::Branch(&common::marked::operator::text(
					"main",
				)),
				base_sha: base.as_ref(),
				kind_hint: campaign::KindHint::Incremental,
			},
			&ReviewPolicy::default(),
			now(),
		)?;
		assert!(matches!(opened, campaign::Opened::Created { .. }));
		Ok(())
	})
	.unwrap();
}

async fn lease(
	f: &Fixture,
) -> loupe_proto::LeaseEnvelope<loupe_provenance::Agent, loupe_provenance::Server> {
	match f.client.lease_survey_for_tests(0).await.unwrap() {
		LeaseResponse::Lease(env) => *env,
		LeaseResponse::Empty { .. } => panic!("no survey lease"),
	}
}

async fn run(f: &Fixture) -> Result<Preparation, PrepareError> {
	let env = lease(f).await;
	let security = loupe_worker::canary::JobSecurity::new(Default::default(), vec![]).unwrap();
	prepare(&f.runner, env, &security).await
}

fn ready(preparation: Result<Preparation, PrepareError>) -> Box<PreparedSurvey> {
	match preparation.unwrap() {
		Preparation::Ready(prepared) => prepared,
		Preparation::Deferred => panic!("deferred"),
	}
}

fn worker(value: Value) -> Vec<u8> {
	value.to_string().into_bytes()
}

/// Fail the attempt as the handler would, and make the retry claimable now.
async fn requeue(f: &Fixture, prepared_job: (i64, &loupe_proto::JobCapability)) {
	let job = loupe_worker::client::PhaseJob {
		job_id: prepared_job.0,
		capability: prepared_job.1,
		deadline: SystemTime::now() + Duration::from_secs(60),
	};
	let failure = worker(json!({"protocol_version":3,"outcome":"failed","error":null}));
	let failure =
		common::marked::worker_request(&failure).validate(PhaseFailureRequestDecoder).unwrap();
	f.client.phase_failure(&job, &failure).await.unwrap();
	f.offline
		.external_corruption(|conn| {
			conn.execute("UPDATE jobs SET eligible_at=0 WHERE id=?1", [prepared_job.0])?;
			Ok(())
		})
		.unwrap();
}

fn sealed(f: &Fixture) -> i64 {
	f.offline
		.external_corruption(|conn| {
			Ok(conn.query_row(
				"SELECT COUNT(*) FROM generation_manifests WHERE sealed_at IS NOT NULL",
				[],
				|r| r.get(0),
			)?)
		})
		.unwrap()
}

fn routes(calls: &[(String, Option<u64>)]) -> Vec<&str> {
	calls.iter().map(|(route, _)| route.as_str()).collect()
}

#[tokio::test]
async fn fresh_bootstrap_uploads_odd_modes_and_raw_paths_the_server_seals() {
	let origin = Origin::new();
	let head = origin.odd();
	let f = fixture(origin).await;
	let prepared = ready(run(&f).await);
	assert_eq!(prepared.recipe, SurveyRecipe::Bootstrap);
	assert!(matches!(
		prepared.context,
		ReviewSurveyContext::Bootstrap { target: BootstrapTarget::Unresolved {} }
	));
	assert_eq!(prepared.commit.expose(), head);
	assert_eq!(prepared.generation.commit_sha.expose(), head);
	assert!(prepared.needs_profile && prepared.profile.is_none() && prepared.assignments.is_none());
	assert_eq!(prepared.attempt.get(), 1);
	assert_eq!(prepared.phase_limits.new_units.remaining, prepared.limits.new_unit_limit);
	assert!(prepared.worktree.path().join("z.rs").is_file());
	assert_eq!(
		routes(&f.log.take()),
		["pin-target", "inventory-batches", "seal-inventory", "limits"]
	);
	assert_eq!(sealed(&f), 1, "the server recomputed and accepted the digest");
}

#[tokio::test]
async fn retried_bootstrap_resumes_from_the_received_prefix() {
	let origin = Origin::new();
	origin.wide(10_000);
	let f = fixture(origin).await;
	f.log.reject_from.store(8192, Ordering::SeqCst);
	let env = lease(&f).await;
	let (job_id, capability) = (env.job_id, env.job_capability.clone());
	let security = loupe_worker::canary::JobSecurity::new(Default::default(), vec![]).unwrap();
	let error = prepare(&f.runner, env, &security).await.unwrap_err();
	assert!(matches!(error, PrepareError::Phase(PhaseError::Status { status: 403 })), "{error}");
	assert_eq!(
		f.log.take(),
		[
			("pin-target".to_owned(), None),
			("inventory-batches".to_owned(), Some(0)),
			("inventory-batches".to_owned(), Some(4096)),
			("inventory-batches".to_owned(), Some(8192)),
		]
	);
	requeue(&f, (job_id, &capability)).await;
	f.log.take();

	let prepared = ready(run(&f).await);
	assert_eq!(prepared.attempt.get(), 2);
	assert!(matches!(
		prepared.context,
		ReviewSurveyContext::Bootstrap { target: BootstrapTarget::Pinned { .. } }
	));
	assert_eq!(
		f.log.take(),
		[
			("pin-target".to_owned(), None),
			("inventory-batches".to_owned(), Some(0)),
			("inventory-batches".to_owned(), Some(8192)),
			("seal-inventory".to_owned(), None),
			("limits".to_owned(), None),
		],
		"chunk 0 replays and the upload continues after the received prefix"
	);
	assert_eq!(sealed(&f), 1);
}

#[tokio::test]
async fn retried_bootstrap_with_a_sealed_manifest_skips_the_upload() {
	let origin = Origin::new();
	origin.wide(5000);
	let f = fixture(origin).await;
	let first = ready(run(&f).await);
	requeue(&f, (first.job_id, &first.job_capability)).await;
	f.log.take();
	let prepared = ready(run(&f).await);
	assert_eq!(prepared.attempt.get(), 2);
	assert!(prepared.needs_profile);
	assert_eq!(
		routes(&f.log.take()),
		["pin-target", "inventory-batches", "limits"],
		"chunk 0 reports the sealed manifest; nothing else is sent"
	);
}

/// Publish a profile, propose one unit and finalize the bootstrap, which
/// activates its generation.
async fn activate(f: &Fixture, prepared: &PreparedSurvey) -> i64 {
	use common::marked::worker_request;
	let job = prepared.phase_job();
	let profile = worker(json!({"protocol_version":3,"profile":{"scope":"fixture"}}));
	let profile = worker_request(&profile).validate_carrying(PublishProfileRequestDecoder).unwrap();
	f.client.publish_profile(&job, &profile).await.unwrap();
	let unit = worker(json!({"protocol_version":3,"client_review_unit_key":"boundary",
		"title":"Request boundary","objective":"Trace the boundary","priority_band":"normal",
		"source_refs":[{"path":"z.rs"}],"depends_on_review_unit_ids":[],
		"closure_criteria":"Account for callers"}));
	let unit = worker_request(&unit).validate_carrying(ReviewUnitRequestDecoder).unwrap();
	let unit = f.client.review_unit(&job, &unit).await.unwrap();
	let terminal = worker(json!({"protocol_version":3,"payload":{"version":1,
		"terminal_reason":"completed","security_model_notes":"Fixture boundary"}}));
	let terminal =
		worker_request(&terminal).validate_carrying(FinalizeSurveyRequestDecoder).unwrap();
	f.client.finalize_survey(&job, &terminal).await.unwrap();
	i64::from(unit.review_unit_id)
}

#[tokio::test]
async fn ordinary_survey_after_activation_receives_profile_and_assignments() {
	let origin = Origin::new();
	let head = origin.odd();
	let f = fixture(origin).await;
	let bootstrap = ready(run(&f).await);
	let unit = activate(&f, &bootstrap).await;
	f.log.take();

	let prepared = ready(run(&f).await);
	assert_eq!(prepared.recipe, SurveyRecipe::Ordinary(OrdinarySurveyRecipe::Coverage));
	assert_eq!(prepared.commit.expose(), head);
	assert!(!prepared.needs_profile);
	let profile = prepared.profile.as_ref().expect("frozen profile");
	assert_eq!(serde_json::to_value(&profile.profile).unwrap(), json!({"scope":"fixture"}));
	let assigned: Vec<i64> = prepared
		.assignments
		.as_ref()
		.expect("ordinary assignments")
		.as_slice()
		.iter()
		.map(|unit| unit.review_unit_id.into())
		.collect();
	assert_eq!(assigned, [unit]);
	assert_eq!(routes(&f.log.take()), ["pin-target", "limits"], "no inventory upload");
}

#[tokio::test]
async fn deferred_pin_ends_preparation_without_further_calls() {
	let origin = Origin::new();
	let first = origin.odd();
	let f = fixture(origin).await;
	let bootstrap = ready(run(&f).await);
	activate(&f, &bootstrap).await;
	f.offline
		.external_corruption(|conn| {
			conn.execute("UPDATE jobs SET state='cancelled',job_capability_hash=NULL WHERE state!='succeeded'", [])?;
			Ok(())
		})
		.unwrap();
	common::with_repo(&f.state.db, 1, |scope| {
		let campaign = loupe_storage::campaigns::summarize(scope, 1).map(|summary| (1, summary))?;
		loupe_storage::campaigns::finish(
			scope,
			campaign.0,
			&campaign.1,
			&common::marked::operator::text("partial"),
			now(),
		)
	})
	.unwrap();
	let blob = f.origin.blob(b"moved");
	let tree = f.origin.tree(&[("100644", b"z.rs".to_vec(), blob)]);
	f.origin.commit(tree);
	open_campaign(&f.state.db, Some(&first));
	f.log.take();

	let preparation = run(&f).await.unwrap();
	assert!(matches!(preparation, Preparation::Deferred));
	assert_eq!(routes(&f.log.take()), ["pin-target"]);
}

#[tokio::test]
async fn expired_lease_fails_before_repository_access() {
	let origin = Origin::new();
	origin.odd();
	let f = fixture(origin).await;
	let mut env = lease(&f).await;
	let loupe_proto::LeasePayload::ReviewSurvey(lease) = &mut env.payload else { panic!("survey") };
	lease.provenance.limits.hard_deadline_at = now() - 1;
	let security = loupe_worker::canary::JobSecurity::new(Default::default(), vec![]).unwrap();
	let error = prepare(&f.runner, env, &security).await.unwrap_err();
	assert!(matches!(error, PrepareError::HardDeadline));
	assert!(f.log.take().is_empty());
	assert_eq!(std::fs::read_dir(f._cache.path()).unwrap().count(), 0, "no clone");
}
