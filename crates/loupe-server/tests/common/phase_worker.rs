//! End-to-end fixture for phase leases (survey, drilldown): the actual
//! router, a git fixture repository and `Runner` with the scripted MCP
//! agent. Requests reach the router through a plain listener with the
//! worker's `PeerCert` injected, so a layer can record and fault responses.
use std::sync::atomic::{AtomicI64, Ordering};
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

pub fn now() -> i64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// Past `submit_by` (deadline − 300 s) but well before the hard deadline.
pub const PAST_SUBMIT_BY: i64 = 1600;
/// Within the kill margin of the hard deadline.
pub const PAST_LAUNCH: i64 = 1790;

/// A non-bare origin whose `main` points at commits built from raw trees.
pub struct Origin {
	pub dir: tempfile::TempDir,
	pub repo: Repository,
}

impl Origin {
	pub fn new() -> Self {
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
	pub fn url(&self) -> String {
		format!("file://{}", self.dir.path().join("origin").display())
	}
	pub fn blob(&self, contents: &[u8]) -> Oid {
		self.repo.blob(contents).unwrap()
	}
	pub fn tree(&self, entries: &[(&str, &[u8], Oid)]) -> Oid {
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
	pub fn commit(&self, tree: Oid) -> String {
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
pub struct Log {
	pub calls: Mutex<Vec<(String, u16)>>,
	/// Run the next request to this route, then answer 502 instead.
	pub drop_response: Mutex<Option<&'static str>>,
}
impl Log {
	pub fn take(&self) -> Vec<(String, u16)> {
		std::mem::take(&mut *self.calls.lock().unwrap())
	}
}

pub fn routes(calls: &[(String, u16)]) -> Vec<&str> {
	calls.iter().map(|(route, _)| route.as_str()).collect()
}

pub async fn observe(log: Arc<Log>, request: Request, next: Next) -> Response {
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

pub fn policy() -> ReviewPolicy {
	ReviewPolicy { max_units_per_survey: 3, survey_units_per_job: 1, ..ReviewPolicy::default() }
}

pub struct Fixture {
	pub state: AppState,
	pub offline: Arc<super::offline::OfflineDatabase>,
	pub origin: Origin,
	pub client: Arc<ServerClient>,
	pub log: Arc<Log>,
	/// Seconds the survey clock runs ahead of the wall clock.
	pub offset: Arc<AtomicI64>,
	pub cache: tempfile::TempDir,
}

pub async fn fixture() -> Fixture {
	fixture_with(async |_, _| {}).await.0
}

/// A fixture whose server state `configure` adjusts before the router is
/// built; whatever it returns is handed back with the fixture.
pub async fn fixture_with<T>(
	configure: impl AsyncFnOnce(&mut AppState, Arc<super::offline::OfflineDatabase>) -> T,
) -> (Fixture, T) {
	let origin = Origin::new();
	let mut offline = super::offline::OfflineDatabase::new();
	let db = offline.open();
	let offline = Arc::new(offline);
	let ca = Arc::new(Ca::new("worker-survey").unwrap());
	let bundle = ca.mint_client("worker").unwrap();
	let peer = PeerCert(
		CertificateDer::pem_slice_iter(bundle.cert_pem.as_bytes()).next().unwrap().unwrap(),
	);
	let mut repo = super::new_repo();
	repo.clone_url = super::marked::operator::text(&origin.url());
	assert_eq!(super::register_repo(&db, &repo, None), 1);
	registry::register_worker(
		&db,
		&super::marked::operator_ingress(),
		&super::marked::operator::text("worker"),
		&loupe_tls::cert_fingerprint(peer.0.as_ref()),
		now(),
	)
	.unwrap();
	open_campaign(&db, None);
	let mut state =
		AppState::new(db, ca, Arc::new(loupe_server::reporters::GithubReporter::new().unwrap()))
			.with_review_policy(policy())
			.unwrap();
	let configured = configure(&mut state, offline.clone()).await;
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
	let fixture = Fixture {
		state,
		offline,
		origin,
		client,
		log,
		offset: Arc::new(AtomicI64::new(0)),
		cache: tempfile::tempdir().unwrap(),
	};
	(fixture, configured)
}

pub fn open_campaign(db: &loupe_storage::Db, base_sha: Option<&str>) {
	super::with_repo(db, 1, |scope| {
		let base = base_sha.map(super::marked::operator::text);
		let opened = campaign::open(
			scope,
			&campaign::OpenCampaign {
				trigger: loupe_storage::campaigns::Trigger::Manual,
				requested_ref: campaign::RequestedRef::Branch(&super::marked::operator::text(
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

pub fn cancel_campaign(db: &loupe_storage::Db) {
	super::with_repo(db, 1, |scope| {
		loupe_storage::campaigns::cancel(scope, 1, &super::marked::operator::text("stop"), now())
	})
	.unwrap();
}

impl Fixture {
	/// Claim and run one phase lease with `script` as the agent.
	pub async fn step<F, Fut>(&self, script: F) -> bool
	where
		F: Fn(ScriptedAgent) -> Fut + Send + Sync + 'static,
		Fut: std::future::Future<Output = anyhow::Result<()>> + Send + 'static,
	{
		let cache = Arc::new(RepoCache::new(self.cache.path().to_owned(), u64::MAX, None).unwrap());
		let offset = self.offset.clone();
		let backend = Arc::new(ScriptedMcpBackend::new(self.client.clone(), script));
		let runner = Runner::new(self.client.clone(), cache, Vec::new())
			.with_survey_backend(backend.clone())
			.with_drilldown_backend(backend)
			.with_phase_clock(Arc::new(move || {
				let ahead = offset.load(Ordering::SeqCst);
				SystemTime::now() + Duration::from_secs(u64::try_from(ahead).unwrap())
			}));
		runner.step(&CancellationToken::new()).await.unwrap()
	}

	pub fn scalar(&self, sql: &str) -> i64 {
		self.offline.external_corruption(|conn| Ok(conn.query_row(sql, [], |r| r.get(0))?)).unwrap()
	}

	/// `(state, error)` of each survey job, oldest first.
	pub fn jobs(&self) -> Vec<(String, Option<String>)> {
		self.jobs_of("survey")
	}

	/// `(state, error)` of each job of `kind`, oldest first.
	pub fn jobs_of(&self, kind: &str) -> Vec<(String, Option<String>)> {
		self.offline
			.external_corruption(|conn| {
				let mut statement =
					conn.prepare("SELECT state,error FROM jobs WHERE kind=?1 ORDER BY id")?;
				let rows = statement
					.query_map([kind], |r| Ok((r.get(0)?, r.get(1)?)))?
					.collect::<Result<Vec<_>, _>>()?;
				Ok(rows)
			})
			.unwrap()
	}

	/// Make a requeued attempt claimable now.
	pub fn make_eligible(&self) {
		self.offline
			.external_corruption(|conn| {
				conn.execute("UPDATE jobs SET eligible_at=0 WHERE state='queued'", [])?;
				Ok(())
			})
			.unwrap();
	}

	pub fn unit_ids(&self) -> Vec<i64> {
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

pub fn ok(result: &ToolResult) -> &str {
	assert!(!result.is_error, "tool call failed: {}", result.text);
	&result.text
}

/// The id a `propose_review_unit` or `submit_lead` result reports.
pub fn reported_id(result: &ToolResult, key: &str) -> i64 {
	let text = ok(result);
	let start = text.find(key).unwrap_or_else(|| panic!("{key} in {text}")) + key.len();
	text[start..].split(|c: char| !c.is_ascii_digit()).next().unwrap().parse().unwrap()
}

pub fn profile() -> Value {
	json!({"profile": {"scope": "fixture", "boundaries": ["parse input"]}})
}

pub fn unit(key: &str) -> Value {
	json!({"client_review_unit_key": key, "title": "Input parsing",
		"objective": "Trace untrusted input through the parser.", "priority_band": "high",
		"source_refs": [{"path": "src/lib.rs"}], "closure_criteria": "Account for callers."})
}

pub fn lead(key: &str, unit: i64) -> Value {
	json!({"client_lead_key": key, "identity_family": "memory-safety",
		"identity_anchor": "parse length", "review_unit_id": unit,
		"hypothesis": "The parser trusts the input length.",
		"source_refs": [{"path": "src/lib.rs"}], "next_proof_step": "Write a harness.",
		"counterevidence": "Length is only read.", "proof_gaps": "Reachability."})
}

pub fn result(key: &str, unit: i64, disposition: &str, leads: &[i64]) -> Value {
	let mut value = json!({"client_result_key": key, "review_unit_id": unit,
		"disposition": disposition, "inspected_refs": [{"path": "src/lib.rs"}],
		"counterevidence": "Checked callers.", "proof_gaps": "None."});
	if !leads.is_empty() {
		value["created_lead_ids"] = json!(leads);
	}
	value
}

pub fn finalize(reason: &str) -> Value {
	json!({"terminal_reason": reason, "security_model_notes": "Parser is the only boundary."})
}

pub fn assert_no_complete(calls: &[(String, u16)]) {
	assert!(
		!routes(calls).contains(&"complete"),
		"a finalized survey sends no complete: {calls:?}"
	);
}
