//! Survey leases end to end: the actual router, a git fixture repository,
//! `Runner` with the scripted MCP agent driving the real broker, catalog,
//! gate, phase client and retry. Requests reach the router through a plain
//! listener with the worker's `PeerCert` injected, as in the other
//! `review_worker_*` suites, so a layer can record and fault responses.
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use git2::{ObjectType, Oid, Repository, RepositoryInitOptions, Signature};
use loupe_server::review::campaign;
use loupe_server::review::policy::ReviewPolicy;
use loupe_server::{router, AppState, PeerCert};
use loupe_storage::registry;
use loupe_tls::Ca;
use loupe_worker::llm::testing::{ScriptedAgent, ScriptedMcpBackend, ToolResult};
use loupe_worker::{RepoCache, Runner, ServerClient};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

mod common;

fn now() -> i64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// Past `submit_by` (deadline − 300 s) but well before the hard deadline.
const PAST_SUBMIT_BY: i64 = 1600;
/// Within the kill margin of the hard deadline.
const PAST_LAUNCH: i64 = 1790;

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
		let origin = Self { dir, repo };
		let lib = origin.blob(b"pub fn parse(input: &[u8]) -> usize { input.len() }\n");
		let main = origin.blob(b"fn main() {}\n");
		let src = origin.tree(&[("100644", b"lib.rs", lib), ("100644", b"main.rs", main)]);
		let readme = origin.blob(b"fixture\n");
		let root = origin.tree(&[("100644", b"README.md", readme), ("40000", b"src", src)]);
		origin.commit(root);
		origin
	}
	fn url(&self) -> String {
		format!("file://{}", self.dir.path().join("origin").display())
	}
	fn blob(&self, contents: &[u8]) -> Oid {
		self.repo.blob(contents).unwrap()
	}
	fn tree(&self, entries: &[(&str, &[u8], Oid)]) -> Oid {
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
}

/// Every non-lease request the worker sends, with the status it received.
#[derive(Default)]
struct Log {
	calls: Mutex<Vec<(String, u16)>>,
	/// Run the next request to this route, then answer 502 instead.
	drop_response: Mutex<Option<&'static str>>,
}
impl Log {
	fn take(&self) -> Vec<(String, u16)> {
		std::mem::take(&mut *self.calls.lock().unwrap())
	}
}

fn routes(calls: &[(String, u16)]) -> Vec<&str> {
	calls.iter().map(|(route, _)| route.as_str()).collect()
}

async fn observe(log: Arc<Log>, request: Request, next: Next) -> Response {
	let route = request.uri().path().rsplit('/').next().unwrap().to_owned();
	if route == "lease" {
		return next.run(request).await;
	}
	let drop = {
		let mut target = log.drop_response.lock().unwrap();
		let hit = target.is_some_and(|target| target == route);
		if hit {
			*target = None;
		}
		hit
	};
	let response = next.run(request).await;
	let response = if drop { StatusCode::BAD_GATEWAY.into_response() } else { response };
	log.calls.lock().unwrap().push((route, response.status().as_u16()));
	response
}

fn policy() -> ReviewPolicy {
	ReviewPolicy { max_units_per_survey: 3, survey_units_per_job: 1, ..ReviewPolicy::default() }
}

struct Fixture {
	state: AppState,
	offline: common::offline::OfflineDatabase,
	origin: Origin,
	client: Arc<ServerClient>,
	log: Arc<Log>,
	/// Seconds the survey clock runs ahead of the wall clock.
	offset: Arc<AtomicI64>,
	cache: tempfile::TempDir,
}

async fn fixture() -> Fixture {
	let origin = Origin::new();
	let mut offline = common::offline::OfflineDatabase::new();
	let db = offline.open();
	let ca = Arc::new(Ca::new("worker-survey").unwrap());
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
	open_campaign(&db, None);
	let state =
		AppState::new(db, ca, Arc::new(loupe_server::reporters::GithubReporter::new().unwrap()))
			.with_review_policy(policy())
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
	Fixture {
		state,
		offline,
		origin,
		client,
		log,
		offset: Arc::new(AtomicI64::new(0)),
		cache: tempfile::tempdir().unwrap(),
	}
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
			&policy(),
			now(),
		)?;
		assert!(matches!(opened, campaign::Opened::Created { .. }));
		Ok(())
	})
	.unwrap();
}

fn cancel_campaign(db: &loupe_storage::Db) {
	common::with_repo(db, 1, |scope| {
		loupe_storage::campaigns::cancel(scope, 1, &common::marked::operator::text("stop"), now())
	})
	.unwrap();
}

impl Fixture {
	/// Claim and run one survey lease with `script` as the agent.
	async fn step<F, Fut>(&self, script: F) -> bool
	where
		F: Fn(ScriptedAgent) -> Fut + Send + Sync + 'static,
		Fut: std::future::Future<Output = anyhow::Result<()>> + Send + 'static,
	{
		let cache = Arc::new(RepoCache::new(self.cache.path().to_owned(), u64::MAX, None).unwrap());
		let offset = self.offset.clone();
		let runner = Runner::new(self.client.clone(), cache, Vec::new())
			.with_phase_backend(Arc::new(ScriptedMcpBackend::new(self.client.clone(), script)))
			.with_survey_clock(Arc::new(move || {
				let ahead = offset.load(Ordering::SeqCst);
				SystemTime::now() + Duration::from_secs(u64::try_from(ahead).unwrap())
			}));
		runner.step(&CancellationToken::new()).await.unwrap()
	}

	fn scalar(&self, sql: &str) -> i64 {
		self.offline.external_corruption(|conn| Ok(conn.query_row(sql, [], |r| r.get(0))?)).unwrap()
	}

	/// `(state, error)` of each survey job, oldest first.
	fn jobs(&self) -> Vec<(String, Option<String>)> {
		self.offline
			.external_corruption(|conn| {
				let mut statement =
					conn.prepare("SELECT state,error FROM jobs WHERE kind='survey' ORDER BY id")?;
				let rows = statement
					.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
					.collect::<Result<Vec<_>, _>>()?;
				Ok(rows)
			})
			.unwrap()
	}

	/// Make a requeued attempt claimable now.
	fn make_eligible(&self) {
		self.offline
			.external_corruption(|conn| {
				conn.execute("UPDATE jobs SET eligible_at=0 WHERE state='queued'", [])?;
				Ok(())
			})
			.unwrap();
	}

	fn unit_ids(&self) -> Vec<i64> {
		self.offline
			.external_corruption(|conn| {
				let mut statement = conn
					.prepare("SELECT review_unit_id FROM review_units ORDER BY review_unit_id")?;
				let rows = statement.query_map([], |r| r.get(0))?.collect::<Result<Vec<_>, _>>()?;
				Ok(rows)
			})
			.unwrap()
	}
}

fn ok(result: &ToolResult) -> &str {
	assert!(!result.is_error, "tool call failed: {}", result.text);
	&result.text
}

/// The id a `propose_review_unit` or `submit_lead` result reports.
fn reported_id(result: &ToolResult, key: &str) -> i64 {
	let text = ok(result);
	let start = text.find(key).unwrap_or_else(|| panic!("{key} in {text}")) + key.len();
	text[start..].split(|c: char| !c.is_ascii_digit()).next().unwrap().parse().unwrap()
}

fn profile() -> Value {
	json!({"profile": {"scope": "fixture", "boundaries": ["parse input"]}})
}

fn unit(key: &str) -> Value {
	json!({"client_review_unit_key": key, "title": "Input parsing",
		"objective": "Trace untrusted input through the parser.", "priority_band": "high",
		"source_refs": [{"path": "src/lib.rs"}], "closure_criteria": "Account for callers."})
}

fn lead(key: &str, unit: i64) -> Value {
	json!({"client_lead_key": key, "identity_family": "memory-safety",
		"identity_anchor": "parse length", "review_unit_id": unit,
		"hypothesis": "The parser trusts the input length.",
		"source_refs": [{"path": "src/lib.rs"}], "next_proof_step": "Write a harness.",
		"counterevidence": "Length is only read.", "proof_gaps": "Reachability."})
}

fn result(key: &str, unit: i64, disposition: &str, leads: &[i64]) -> Value {
	let mut value = json!({"client_result_key": key, "review_unit_id": unit,
		"disposition": disposition, "inspected_refs": [{"path": "src/lib.rs"}],
		"counterevidence": "Checked callers.", "proof_gaps": "None."});
	if !leads.is_empty() {
		value["created_lead_ids"] = json!(leads);
	}
	value
}

fn finalize(reason: &str) -> Value {
	json!({"terminal_reason": reason, "security_model_notes": "Parser is the only boundary."})
}

/// Publish the profile, propose two units, record a lead, results and
/// dispositions, and finalize.
async fn full_bootstrap(mut agent: ScriptedAgent) -> anyhow::Result<()> {
	ok(&agent.call("publish_profile", profile()).await?);
	let first = reported_id(&agent.call("propose_review_unit", unit("parser")).await?, "id=");
	let second = reported_id(&agent.call("propose_review_unit", unit("entry")).await?, "id=");
	let lead_id = reported_id(&agent.call("submit_lead", lead("length", first)).await?, "id=");
	ok(&agent
		.call("submit_review_unit_result", result("r-1", first, "lead_created", &[lead_id]))
		.await?);
	ok(&agent
		.call("submit_review_unit_result", result("r-2", second, "no_lead_found", &[]))
		.await?);
	for (key, path, disposition) in
		[("d-lib", "src/lib.rs", "mapped"), ("d-readme", "README.md", "excluded")]
	{
		let mut arguments = json!({"client_inventory_disposition_key": key, "path": path,
			"disposition": disposition});
		if disposition == "mapped" {
			arguments["mapped_review_unit_ids"] = json!([first]);
		} else {
			arguments["reason"] = json!("Documentation only.");
		}
		ok(&agent.call("submit_inventory_disposition", arguments).await?);
	}
	ok(&agent.call("finalize_survey", finalize("completed")).await?);
	Ok(())
}

/// Publish the profile and propose two units left for coverage jobs.
async fn mapping_bootstrap(mut agent: ScriptedAgent) -> anyhow::Result<()> {
	ok(&agent.call("publish_profile", profile()).await?);
	ok(&agent.call("propose_review_unit", unit("parser")).await?);
	ok(&agent.call("propose_review_unit", unit("entry")).await?);
	ok(&agent.call("finalize_survey", finalize("completed")).await?);
	Ok(())
}

fn assert_no_complete(calls: &[(String, u16)]) {
	assert!(
		!routes(calls).contains(&"complete"),
		"a finalized survey sends no complete: {calls:?}"
	);
}

#[tokio::test]
async fn only_a_worker_with_a_survey_backend_is_leased_a_survey() {
	let f = fixture().await;
	let cache = Arc::new(RepoCache::new(f.cache.path().to_owned(), u64::MAX, None).unwrap());
	let plain = Runner::new(f.client.clone(), cache.clone(), Vec::new());
	let unclaimed =
		tokio::time::timeout(Duration::from_secs(2), plain.step(&CancellationToken::new())).await;
	assert!(matches!(unclaimed, Err(_) | Ok(Ok(false))), "a survey-less worker ran a lease");
	assert_eq!(f.jobs(), [("queued".to_owned(), None)]);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM jobs WHERE worker_id IS NOT NULL"), 0);

	let surveyor = Runner::new(f.client.clone(), cache, Vec::new())
		.with_phase_backend(Arc::new(ScriptedMcpBackend::new(f.client.clone(), full_bootstrap)));
	assert!(surveyor.step(&CancellationToken::new()).await.unwrap());
	assert_eq!(f.jobs(), [("succeeded".to_owned(), None)]);
}

#[tokio::test]
async fn bootstrap_survey_finalizes_and_activates_its_generation() {
	let f = fixture().await;
	let tools = Arc::new(Mutex::new(Vec::new()));
	let seen = tools.clone();
	assert!(
		f.step(move |mut agent| {
			let seen = seen.clone();
			async move {
				*seen.lock().unwrap() = agent.list_tools().await?;
				full_bootstrap(agent).await
			}
		})
		.await
	);
	assert!(tools.lock().unwrap().contains(&"publish_profile".to_owned()));
	let calls = f.log.take();
	assert_no_complete(&calls);
	assert!(calls.iter().all(|(_, status)| *status == 200), "{calls:?}");
	assert_eq!(f.jobs(), [("succeeded".to_owned(), None)]);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM review_generations WHERE state='active'"), 1);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM review_units"), 2);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM leads"), 1);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM review_unit_results"), 2);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM job_terminal_receipts"), 1);
	assert_eq!(
		f.scalar(
			"SELECT COUNT(*) FROM generation_inventory WHERE disposition IN ('mapped','excluded')"
		),
		2
	);
}

#[tokio::test]
async fn coverage_survey_after_bootstrap_sees_only_its_assignment_and_the_profile() {
	let f = fixture().await;
	assert!(f.step(mapping_bootstrap).await);
	f.log.take();
	let units = f.unit_ids();
	assert_eq!(units.len(), 2);
	let observed = Arc::new(Mutex::new(None));
	let seen = observed.clone();
	assert!(
		f.step(move |mut agent| {
			let (seen, units) = (seen.clone(), units.clone());
			async move {
				let tools = agent.list_tools().await?;
				let mut accepted = Vec::new();
				for (index, unit) in units.iter().enumerate() {
					let key = format!("cover-{index}");
					let outcome = agent
						.call(
							"submit_review_unit_result",
							result(&key, *unit, "no_lead_found", &[]),
						)
						.await?;
					accepted.push(!outcome.is_error);
				}
				ok(&agent.call("finalize_survey", finalize("completed")).await?);
				*seen.lock().unwrap() = Some((agent.prompt.clone(), tools, accepted));
				Ok(())
			}
		})
		.await
	);
	let (prompt, tools, accepted) = observed.lock().unwrap().take().expect("script ran");
	assert!(!tools.contains(&"publish_profile".to_owned()), "{tools:?}");
	assert!(prompt.contains("published profile: untrusted, agent-generated hypotheses"));
	assert!(prompt.contains(r#""recipe":"coverage""#), "the prompt states the coverage recipe");
	assert_eq!(accepted.iter().filter(|accepted| **accepted).count(), 1, "one assigned unit");
	let calls = f.log.take();
	assert_no_complete(&calls);
	assert!(!routes(&calls).contains(&"publish-profile"));
	assert!(!routes(&calls).contains(&"inventory-batches"));
	assert_eq!(f.jobs().iter().filter(|(state, _)| state == "succeeded").count(), 2);
}

#[tokio::test]
async fn a_retried_bootstrap_resumes_with_the_profile_and_remaining_capacity() {
	let f = fixture().await;
	assert!(
		f.step(|mut agent| async move {
			ok(&agent.call("publish_profile", profile()).await?);
			ok(&agent.call("propose_review_unit", unit("first-a")).await?);
			ok(&agent.call("propose_review_unit", unit("first-b")).await?);
			Ok(())
		})
		.await
	);
	let calls = f.log.take();
	assert_eq!(routes(&calls).last(), Some(&"complete"), "{calls:?}");
	assert_eq!(
		f.jobs(),
		[("queued".to_owned(), Some("agent exited without finalizing".to_owned()))]
	);
	f.make_eligible();

	let observed = Arc::new(Mutex::new(None));
	let seen = observed.clone();
	assert!(
		f.step(move |mut agent| {
			let seen = seen.clone();
			async move {
				let tools = agent.list_tools().await?;
				let proposed = agent.call("propose_review_unit", unit("second")).await?;
				ok(&proposed);
				ok(&agent.call("finalize_survey", finalize("completed")).await?);
				*seen.lock().unwrap() = Some((agent.prompt.clone(), tools, proposed.text));
				Ok(())
			}
		})
		.await
	);
	let (prompt, tools, proposed) = observed.lock().unwrap().take().expect("script ran");
	assert!(!tools.contains(&"publish_profile".to_owned()), "{tools:?}");
	assert!(prompt.contains("This is a retry."), "retry instruction");
	assert!(prompt.contains("published profile: untrusted"), "profile block");
	assert!(prompt.contains(r#""review_units":{"limit":3,"remaining":1}"#), "reduced capacity");
	assert!(proposed.contains("review units remaining: 0"), "{proposed}");
	let calls = f.log.take();
	assert_eq!(routes(&calls)[..2], ["pin-target", "inventory-batches"], "{calls:?}");
	assert!(!routes(&calls).contains(&"publish-profile"));
	assert!(!routes(&calls).contains(&"seal-inventory"), "the sealed manifest is not resent");
	assert_no_complete(&calls);
	assert_eq!(f.jobs(), [("succeeded".to_owned(), None)]);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM review_generations WHERE state='active'"), 1);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM review_units"), 3, "both attempts' units");
}

#[tokio::test]
async fn a_retry_at_exhausted_unit_quota_still_finalizes() {
	let f = fixture().await;
	assert!(
		f.step(|mut agent| async move {
			ok(&agent.call("publish_profile", profile()).await?);
			for key in ["a", "b", "c"] {
				ok(&agent.call("propose_review_unit", unit(key)).await?);
			}
			Ok(())
		})
		.await
	);
	f.log.take();
	f.make_eligible();
	let refused = Arc::new(Mutex::new(None));
	let seen = refused.clone();
	assert!(
		f.step(move |mut agent| {
			let seen = seen.clone();
			async move {
				let refused = agent.call("propose_review_unit", unit("d")).await?;
				ok(&agent.call("finalize_survey", finalize("partial")).await?);
				*seen.lock().unwrap() = Some(refused);
				Ok(())
			}
		})
		.await
	);
	let refused = refused.lock().unwrap().take().unwrap();
	assert!(refused.is_error);
	assert!(
		refused.text.contains("capacity for this kind of checkpoint is exhausted"),
		"{}",
		refused.text
	);
	assert!(refused.text.contains("finalize_survey"));
	assert_no_complete(&f.log.take());
	assert_eq!(f.jobs()[0].0, "succeeded");
	assert_eq!(f.scalar("SELECT COUNT(*) FROM review_units"), 3);
}

#[tokio::test]
async fn a_lost_response_is_replayed_by_the_host_and_stored_once() {
	let f = fixture().await;
	*f.log.drop_response.lock().unwrap() = Some("review-units");
	assert!(
		f.step(|mut agent| async move {
			ok(&agent.call("publish_profile", profile()).await?);
			ok(&agent.call("propose_review_unit", unit("once")).await?);
			ok(&agent.call("finalize_survey", finalize("completed")).await?);
			Ok(())
		})
		.await
	);
	let calls = f.log.take();
	let units: Vec<_> = calls.iter().filter(|(route, _)| route == "review-units").collect();
	assert_eq!(units, [&("review-units".to_owned(), 502), &("review-units".to_owned(), 200)]);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM review_units"), 1);
	assert_eq!(f.scalar("SELECT COUNT(*) FROM job_checkpoints WHERE client_key LIKE '%once'"), 1);
	assert_eq!(f.jobs()[0].0, "succeeded");
}

#[tokio::test]
async fn the_soft_stop_closes_new_inquiry_but_finalize_is_accepted() {
	let f = fixture().await;
	let offset = f.offset.clone();
	let observed = Arc::new(Mutex::new(None));
	let seen = observed.clone();
	assert!(
		f.step(move |mut agent| {
			let (seen, offset) = (seen.clone(), offset.clone());
			async move {
				ok(&agent.call("publish_profile", profile()).await?);
				let first =
					reported_id(&agent.call("propose_review_unit", unit("early")).await?, "id=");
				offset.store(PAST_SUBMIT_BY, Ordering::SeqCst);
				let late = agent.call("propose_review_unit", unit("late")).await?;
				let query = agent
					.call("query_same_project_lead_candidates", json!({"query": "parse"}))
					.await?;
				ok(&agent.call("submit_lead", lead("after-stop", first)).await?);
				ok(&agent.call("finalize_survey", finalize("partial")).await?);
				*seen.lock().unwrap() = Some((late, query));
				Ok(())
			}
		})
		.await
	);
	let (late, query) = observed.lock().unwrap().take().unwrap();
	for denied in [&late, &query] {
		assert!(denied.is_error && denied.text.contains("soft stop reached"), "{denied:?}");
	}
	let calls = f.log.take();
	assert!(!routes(&calls).contains(&"lead-candidates"));
	assert_eq!(routes(&calls).iter().filter(|r| **r == "review-units").count(), 1);
	assert_eq!(f.jobs()[0].0, "succeeded");
}

#[tokio::test]
async fn a_lease_already_past_submit_by_still_finalizes() {
	let f = fixture().await;
	f.offset.store(PAST_SUBMIT_BY, Ordering::SeqCst);
	let denied = Arc::new(Mutex::new(None));
	let seen = denied.clone();
	assert!(
		f.step(move |mut agent| {
			let seen = seen.clone();
			async move {
				ok(&agent.call("publish_profile", profile()).await?);
				let refused = agent.call("propose_review_unit", unit("late")).await?;
				ok(&agent.call("finalize_survey", finalize("partial")).await?);
				*seen.lock().unwrap() = Some((agent.prompt.clone(), refused));
				Ok(())
			}
		})
		.await
	);
	let (prompt, refused) = denied.lock().unwrap().take().unwrap();
	assert!(prompt.contains(r#""submit_by_remaining_seconds":0"#), "the prompt states the stop");
	assert!(refused.is_error && refused.text.contains("soft stop reached"), "{refused:?}");
	assert_no_complete(&f.log.take());
	assert_eq!(f.jobs()[0].0, "succeeded");
}

#[tokio::test]
async fn a_survey_too_close_to_its_hard_deadline_fails_without_launch() {
	let f = fixture().await;
	f.offset.store(PAST_LAUNCH, Ordering::SeqCst);
	let launched = Arc::new(AtomicBool::new(false));
	let flag = launched.clone();
	assert!(
		f.step(move |_agent| {
			flag.store(true, Ordering::SeqCst);
			async { Ok(()) }
		})
		.await
	);
	assert!(!launched.load(Ordering::SeqCst), "no agent past the launch deadline");
	assert_eq!(routes(&f.log.take()).last(), Some(&"complete"));
	assert_eq!(f.jobs()[0].1.as_deref(), Some("hard deadline reached"));
}

#[tokio::test]
async fn an_agent_that_never_finalizes_fails_the_attempt_with_a_fixed_reason() {
	let f = fixture().await;
	assert!(
		f.step(|mut agent| async move {
			agent.list_tools().await?;
			anyhow::bail!("agent-private-error-sentinel")
		})
		.await
	);
	let calls = f.log.take();
	assert_eq!(calls.last(), Some(&("complete".to_owned(), 200)), "{calls:?}");
	assert_eq!(
		f.jobs(),
		[("queued".to_owned(), Some("agent exited without finalizing".to_owned()))]
	);
}

#[tokio::test]
async fn a_cancelled_campaign_stops_the_agent_and_the_failure_is_accepted() {
	let f = fixture().await;
	let state = f.state.clone();
	let reached_end = Arc::new(AtomicBool::new(false));
	let flag = reached_end.clone();
	assert!(
		f.step(move |mut agent| {
			let (state, flag) = (state.clone(), flag.clone());
			async move {
				ok(&agent.call("publish_profile", profile()).await?);
				cancel_campaign(&state.db);
				let denied = agent.call("propose_review_unit", unit("after-cancel")).await?;
				assert!(denied.is_error && denied.text.contains("no longer has authority"));
				// The handler cancels the agent; a well-behaved script never gets here.
				tokio::time::sleep(Duration::from_secs(30)).await;
				flag.store(true, Ordering::SeqCst);
				Ok(())
			}
		})
		.await
	);
	assert!(!reached_end.load(Ordering::SeqCst), "the agent was stopped");
	let calls = f.log.take();
	assert!(calls.contains(&("review-units".to_owned(), 403)), "{calls:?}");
	assert!(calls.contains(&("limits".to_owned(), 403)), "the refusal was probed: {calls:?}");
	assert_eq!(calls.last(), Some(&("complete".to_owned(), 200)), "{calls:?}");
	let (state, error) = f.jobs().remove(0);
	assert_ne!(state, "leased");
	assert!(error.is_some(), "the server recorded the failure");
}

#[tokio::test]
async fn a_refused_reference_keeps_the_agent_running() {
	let f = fixture().await;
	let observed = Arc::new(Mutex::new(None));
	let seen = observed.clone();
	assert!(
		f.step(move |mut agent| {
			let seen = seen.clone();
			async move {
				ok(&agent.call("publish_profile", profile()).await?);
				let refused = agent
					.call("submit_review_unit_result", result("stray", 9999, "no_lead_found", &[]))
					.await?;
				ok(&agent.call("finalize_survey", finalize("completed")).await?);
				*seen.lock().unwrap() = Some(refused);
				Ok(())
			}
		})
		.await
	);
	let refused = observed.lock().unwrap().take().expect("script ran");
	assert!(refused.is_error, "{refused:?}");
	assert!(refused.text.contains("refused a referenced unit"), "{}", refused.text);
	assert!(!refused.text.contains("no longer has authority"), "{}", refused.text);
	let calls = f.log.take();
	assert!(calls.contains(&("review-unit-results".to_owned(), 403)), "{calls:?}");
	assert!(calls.contains(&("limits".to_owned(), 200)), "{calls:?}");
	assert_no_complete(&calls);
	assert_eq!(f.jobs(), [("succeeded".to_owned(), None)]);
}

#[tokio::test]
async fn a_deferred_pin_ends_the_job_without_further_calls() {
	let f = fixture().await;
	let first = f.origin.repo.head().unwrap().peel_to_commit().unwrap().id().to_string();
	assert!(f.step(full_bootstrap).await);
	f.offline
		.external_corruption(|conn| {
			conn.execute(
				"UPDATE jobs SET state='cancelled',job_capability_hash=NULL WHERE state!='succeeded'",
				[],
			)?;
			Ok(())
		})
		.unwrap();
	common::with_repo(&f.state.db, 1, |scope| {
		let summary = loupe_storage::campaigns::summarize(scope, 1)?;
		loupe_storage::campaigns::finish(
			scope,
			1,
			&summary,
			&common::marked::operator::text("partial"),
			now(),
		)
	})
	.unwrap();
	let blob = f.origin.blob(b"moved");
	let tree = f.origin.tree(&[("100644", b"z.rs", blob)]);
	f.origin.commit(tree);
	open_campaign(&f.state.db, Some(&first));
	f.log.take();

	let launched = Arc::new(AtomicBool::new(false));
	let flag = launched.clone();
	assert!(
		f.step(move |_agent| {
			flag.store(true, Ordering::SeqCst);
			async { Ok(()) }
		})
		.await
	);
	assert!(!launched.load(Ordering::SeqCst));
	assert_eq!(routes(&f.log.take()), ["pin-target"]);
}
