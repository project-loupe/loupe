//! Synthetic report fixtures admitted by actual Operator and Server owners.
use std::marker::PhantomData;

use loupe_cli::fuzz_support::{observe_response, ResponseCase, ResponseValue};
use loupe_core::text::{BoundedText, TextPolicy};
use loupe_core::{Finding, JobKind, JobState, ReportingDestination};
use loupe_provenance::{Agent, Ingress, Mark, Operator, Secret, Untrusted, Unvalidated, Validate};
use loupe_server::fuzz_support::{operator_value, OperatorRequest, OperatorValue};
use loupe_storage::{findings, jobs, registry, reports, scheduler, scope, Db};
use serde_json::{json, Value};

fn operator() -> Ingress<Operator> {
	// SAFETY: this fixture authors synthetic Operator registration and queue input.
	#[allow(unsafe_code)]
	unsafe {
		Ingress::new()
	}
}

struct FixtureText<P>(PhantomData<P>);
impl<P: TextPolicy> Validate<&str, Operator> for FixtureText<P> {
	type Output = BoundedText<P, Operator>;
	type Error = loupe_core::text::Error;
	fn validate<'a>(
		self, input: Unvalidated<'a, &str>, mark: Mark<'a, Operator>,
	) -> Result<Self::Output, Self::Error> {
		BoundedText::new(&mark, input.get())
	}
}

fn fixture_text<P: TextPolicy>(value: &'static str) -> BoundedText<P, Operator> {
	Untrusted::new(value, operator())
		.validate(FixtureText(PhantomData))
		.unwrap_or_else(|error| panic!("constant report fixture: {error}"))
}

/// Select one original finding through the production registration, queue,
/// lease, submission and report-preparation owners. A fresh database isolates
/// iterations and supplies deterministic IDs without a raw SQL escape hatch.
pub fn prepared_report(
	mut reporting: Value, finding: &Finding<Agent>, app: bool,
) -> Result<(Db, Box<reports::PreparedReport>), String> {
	if reporting.get("kind").and_then(Value::as_str) == Some("github_issue") {
		let fields = reporting.as_object_mut().ok_or("reporting object required")?;
		if fields.remove("pat_secret_id").is_some_and(|value| !value.is_null()) {
			return Err("fixture cannot select an existing secret".into());
		}
		fields.insert("github_pat".into(), if app { Value::Null } else { json!("fake-test-pat") });
	}
	let wire = serde_json::to_vec(&json!({
		"protocol_version": 2, "clone_url": "https://github.com/example/repo.git",
		"reporting": reporting, "scanner_config": null,
		"verification_enabled": false, "require_approval": false
	}))
	.map_err(|error| error.to_string())?;
	let Some(OperatorValue::Register(request)) =
		operator_value(OperatorRequest::RegisterRepo, &wire)
	else {
		return Err("report fixture configuration rejected".into());
	};
	let (destination, pat) = match request.reporting {
		loupe_proto::ReportingSetup::GithubIssue { target_owner, target_repo, github_pat } => (
			ReportingDestination::GithubIssue { target_owner, target_repo, pat_secret_id: None },
			github_pat,
		),
		loupe_proto::ReportingSetup::Email { to, from, subject_prefix } => {
			(ReportingDestination::Email { to, from, subject_prefix }, None)
		},
		loupe_proto::ReportingSetup::Manual => {
			return Err("manual destination has no prepared report".into())
		},
	};
	let db = Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests())
		.map_err(|error| error.to_string())?;
	let operator = operator();
	if app {
		registry::store_github_app(
			&db,
			&operator,
			&loupe_storage::github_app::StoredGithubApp {
				app_id: 1,
				slug: fixture_text("fixture"),
				private_key_pem: Secret::new(
					loupe_server::reporters::github_app::testing::APP_PRIVATE_KEY_PEM.into(),
				),
			},
			0,
		)
		.map_err(|error| error.to_string())?;
	}
	let new = loupe_storage::repos::NewRepo {
		clone_url: request.clone_url,
		host: fixture_text("github.com"),
		owner: fixture_text("example"),
		repo: fixture_text("repo"),
		default_branch: request.branch,
		scan_interval_seconds: None,
		scanner_config: request.scanner_config.ok_or("missing admitted scanner config")?,
		reporting: destination,
		verification_enabled: false,
		require_approval: Some(false),
	};
	let registry::ReportingWrite::Done(repo) =
		registry::register_repository(&db, &operator, &new, pat.as_ref(), 0)
			.map_err(|error| error.to_string())?
	else {
		return Err("fixture app missing".into());
	};
	let Some(OperatorValue::Worker(worker)) = operator_value(
		OperatorRequest::RegisterWorker,
		br#"{"protocol_version":2,"name":"fixture-worker"}"#,
	) else {
		return Err("fixture worker rejected".into());
	};
	let worker = registry::register_worker(&db, &operator, &worker.name, &[9; 32], 0)
		.map_err(|error| error.to_string())?;
	let job = scope::with_operator_repository(
		&db,
		&operator,
		scope::OperatorTarget::Repository(repo),
		|scope| {
			jobs::enqueue(
				scope,
				&jobs::QueuedJob::<Operator> {
					kind: JobKind::Scan,
					incremental: false,
					since_sha: None,
					parent_job_id: None,
					target_finding_id: None,
				},
				0,
			)
		},
	)
	.map_err(|error| error.to_string())?;
	let claimed = scheduler::claim(
		&db,
		&scheduler::ClaimRequest::<Operator> {
			worker_id: worker,
			kinds: &[JobKind::Scan],
			now: 1,
			capability_hash: &[7; 32],
			legacy_lease_seconds: 600,
			policy: &scheduler::ClaimPolicy::default(),
		},
	)
	.map_err(|error| error.to_string())?
	.ok_or("fixture lease missing")?;
	assert_eq!(claimed.claimed.job.id, job);
	assert_eq!(claimed.repository.id, repo);
	let revision = fixture_text("reviewed-sha");
	let prepared = scope::with_active_lease(
		&db,
		jobs::ActiveLease {
			identity: jobs::LeaseIdentity {
				job_id: job,
				worker_id: worker,
				capability_hash: &[7; 32],
			},
			now: 2,
		},
		|scope| {
			assert!(findings::submit(scope, finding)?.is_some(), "fixture finding selected");
			reports::complete_assignment::<_, Operator>(
				scope,
				JobState::Succeeded,
				Some(&revision),
				None,
				false,
				99,
			)
		},
	)
	.map_err(|error| error.to_string())?
	.ok_or("fixture preparation missing")?;
	let reports::Preparation::Ready(batch) = prepared else {
		return Err("fixture report not ready".into());
	};
	batch.check_committed().map_err(|error| error.to_string())?;
	assert_eq!(batch.entries().len(), 1);
	let selected = batch.entries()[0].content().map_err(|error| error.to_string())?;
	assert_eq!(selected.finding(), finding, "original finding survives production selection");
	assert_eq!(
		selected.reviewed_revision().map(|revision| revision.expose()),
		Some("reviewed-sha")
	);
	Ok((db, batch))
}

/// Private finding wire schema, then an actual named Server decoder.
/// The fixture invents a Server envelope around designated Agent content;
/// carried fields retain the decoder's Agent owner into the real reporter.
pub fn finding(raw: &[u8]) -> Option<Finding<Agent>> {
	let old: crate::cli_response_oracle::wire::Finding = serde_json::from_slice(raw).ok()?;
	let mut wire = serde_json::to_value(old).ok()?;
	let envelope = json!({"protocol_version":2,"id":1,"repo_id":1,"job_id":1,
        "state":"confirmed","verification_required":false,"created_at":0});
	wire.as_object_mut()?.extend(envelope.as_object()?.clone());
	let bytes = serde_json::to_vec(&wire).ok()?;
	let expected = crate::cli_response_oracle::legacy(ResponseCase::GetFinding, &bytes)
		.is_ok_and(|v| crate::cli_response_oracle::policies(&v));
	let actual = observe_response(ResponseCase::GetFinding, &bytes).result;
	assert_eq!(actual.is_ok(), expected, "report fixture source admission");
	let Ok(ResponseValue::Finding(f)) = actual else { return None };
	Some(Finding {
		scanner_id: f.scanner_id,
		severity: f.severity,
		title: f.title,
		description: f.description,
		file_path: f.file_path,
		line_start: f.line_start,
		line_end: f.line_end,
		cwe: f.cwe,
		patch_unified: f.patch_unified,
		poc_unified: f.poc_unified,
		fingerprint: f.fingerprint,
	})
}
