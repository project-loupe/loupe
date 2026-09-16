use loupe_server::review::policy::ReviewPolicy;
use loupe_server::FileConfig;

#[test]
fn review_policy_defaults_and_snapshot_are_stable() {
	let policy = ReviewPolicy::default();
	policy.validate().unwrap();
	let snapshot = policy.snapshot().unwrap();
	assert_eq!(
		snapshot.expose(),
		r#"{"campaign_deadline_seconds":21600,"campaign_handoff_reserve":2,"campaign_max_jobs":64,"drilldown_deadline_seconds":2700,"drilldown_submit_margin_seconds":420,"drilldown_token_budget":null,"max_attempts":3,"retry_backoff_base_seconds":60,"retry_backoff_cap_seconds":3600,"survey_deadline_seconds":1800,"survey_submit_margin_seconds":300,"survey_token_budget":null,"survey_units_per_job":4,"verify_deadline_seconds":3600,"verify_submit_margin_seconds":600,"verify_token_budget":null,"version":1}"#
	);
	assert_eq!(*snapshot.digest(), loupe_core::canonical::digest(r#"{"campaign_deadline_seconds":21600,"campaign_handoff_reserve":2,"campaign_max_jobs":64,"drilldown_deadline_seconds":2700,"drilldown_submit_margin_seconds":420,"drilldown_token_budget":null,"max_attempts":3,"retry_backoff_base_seconds":60,"retry_backoff_cap_seconds":3600,"survey_deadline_seconds":1800,"survey_submit_margin_seconds":300,"survey_token_budget":null,"survey_units_per_job":4,"verify_deadline_seconds":3600,"verify_submit_margin_seconds":600,"verify_token_budget":null,"version":1}"#.as_bytes()));
	assert_eq!(policy.claim_policy(), loupe_storage::scheduler::ClaimPolicy::default());
}

#[test]
fn snapshots_freeze_only_campaign_owned_limits() {
	let base = ReviewPolicy::default();
	let mut changed = base.clone();
	changed.active_jobs_per_repo = 9;
	changed.lease_seconds = 500;
	changed.urgency_burst_length = 2;
	assert_eq!(base.snapshot().unwrap(), changed.snapshot().unwrap());
	assert_ne!(base.claim_policy(), changed.claim_policy());
	changed.campaign_max_jobs = 10;
	assert_ne!(base.snapshot().unwrap(), changed.snapshot().unwrap());
}

#[test]
fn policy_reports_all_invalid_fields() {
	let policy = ReviewPolicy {
		active_jobs_per_repo: 0,
		survey_units_per_job: 33,
		survey_token_budget: Some(0),
		..ReviewPolicy::default()
	};
	let error = policy.validate().unwrap_err().to_string();
	for field in ["active_jobs_per_repo", "survey_units_per_job", "survey_token_budget"] {
		assert!(error.contains(field), "missing {field}: {error}");
	}
}

#[test]
fn each_policy_rule_is_enforced() {
	macro_rules! invalid {
		($field:ident, $value:expr) => {{
			let mut policy = ReviewPolicy::default();
			policy.$field = $value;
			let error = policy.validate().expect_err(stringify!($field)).to_string();
			assert!(error.contains(stringify!($field)), "{error}");
			assert!(policy.snapshot().is_err(), "invalid policies must not be frozen");
		}};
	}
	invalid!(active_jobs_per_repo, 0);
	invalid!(active_jobs_total, Some(0));
	invalid!(active_surveys_per_repo, 0);
	invalid!(active_surveys_per_repo, 4);
	invalid!(active_drilldowns_per_repo, 0);
	invalid!(active_drilldowns_per_repo, 4);
	invalid!(active_verifications_per_repo, 0);
	invalid!(active_verifications_per_repo, 4);
	invalid!(verify_reserved_slots, -1);
	invalid!(verify_reserved_slots, 3);
	invalid!(survey_units_per_job, 0);
	invalid!(survey_units_per_job, 33);
	invalid!(survey_deadline_seconds, 600);
	invalid!(drilldown_deadline_seconds, 600);
	invalid!(verify_deadline_seconds, 600);
	invalid!(survey_submit_margin_seconds, -1);
	invalid!(survey_submit_margin_seconds, 1800);
	invalid!(drilldown_submit_margin_seconds, 2700);
	invalid!(verify_submit_margin_seconds, 3600);
	invalid!(lease_seconds, 0);
	invalid!(lease_seconds, 1800);
	invalid!(lease_report_grace_seconds, 0);
	invalid!(lease_report_grace_seconds, 601);
	invalid!(max_attempts, 0);
	invalid!(retry_backoff_base_seconds, 0);
	invalid!(retry_backoff_base_seconds, 3601);
	invalid!(retry_backoff_cap_seconds, 0);
	invalid!(urgency_burst_length, 0);
	invalid!(campaign_handoff_reserve, -1);
	invalid!(campaign_handoff_reserve, 64);
	invalid!(campaign_deadline_seconds, 3599);
	invalid!(campaign_max_jobs, 0);
	invalid!(priority_aging_interval_seconds, 0);
	invalid!(priority_aging_cap, -1);
	invalid!(priority_aging_cap, i64::MAX);
	invalid!(survey_token_budget, Some(0));
	invalid!(drilldown_token_budget, Some(0));
	invalid!(verify_token_budget, Some(0));
	invalid!(verify_token_budget, Some(u64::MAX));
}

#[test]
fn review_toml_is_strict_and_uses_defaults() {
	for raw in [
		"",
		"[review]",
		"[review]\nactive_jobs_total = 8",
		"[review]\nsurvey_token_budget = 900\nverify_reserved_slots = 0",
	] {
		let config: FileConfig = toml::from_str(raw).unwrap();
		let policy = config.review.resolve().unwrap();
		assert_eq!(policy.survey_units_per_job, 4);
	}
	for raw in [
		"[review]\nunknown_limit = 4",
		"[review]\nmax_attempts = -1",
		"[review]\nsurvey_token_budget = -1",
		"[review]\nlease_seconds = '600'",
	] {
		assert!(toml::from_str::<FileConfig>(raw).is_err(), "{raw}");
	}
	for raw in [
		"[review]\nsurvey_units_per_job = 33",
		"[review]\nsurvey_token_budget = 0",
		"[review]\nlease_seconds = 1800",
		"[review]\nverify_reserved_slots = 3",
	] {
		assert!(toml::from_str::<FileConfig>(raw).unwrap().review.resolve().is_err(), "{raw}");
	}
	assert!(FileConfig::default().review.resolve().unwrap().survey_token_budget.is_none());
}

#[test]
fn review_section_accepts_known_policy_keys() {
	let parsed = toml::from_str::<FileConfig>(
		"[review]\nactive_jobs_per_repo = 4\nsurvey_units_per_job = 6\nlease_seconds = 500\n",
	);
	assert!(parsed.is_ok(), "review configuration must be accepted: {parsed:?}");
}

#[test]
fn startup_rejects_zero_token_budget_with_policy_error() {
	let dir = tempfile::tempdir().unwrap();
	let config = dir.path().join("config.toml");
	std::fs::write(&config, "[review]\nsurvey_token_budget = 0\n").unwrap();
	let output = std::process::Command::new(env!("CARGO_BIN_EXE_loupe-server"))
		.args(["serve", "--config"])
		.arg(config)
		.output()
		.unwrap();
	assert!(!output.status.success());
	let error = String::from_utf8_lossy(&output.stderr);
	assert!(
		error.contains("survey_token_budget") && error.contains("must be"),
		"startup must explain the invalid review policy: {error}"
	);
}
