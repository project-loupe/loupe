//! `loupectl` — operator CLI for loupe-server.
//!
//! Authenticates with the admin client cert minted by `loupe-server
//! init`. Every command is one round-trip; the CLI does no caching.

mod render;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use loupe_proto::{
	FindingDetail, JobInfo, ListFindingsResponse, ListReposResponse, RegisterRepoRequest,
	RegisterRepoResponse, RegisterWorkerRequest, RegisterWorkerResponse, ReportingSetup,
	ScanRequest, ScanResponse, UpdateRepoRequest, PROTOCOL_VERSION,
};

#[derive(Debug, Parser)]
#[command(version, about = "loupe operator CLI")]
struct Cli {
	#[command(flatten)]
	conn: ConnArgs,
	#[command(subcommand)]
	cmd: Cmd,
}

#[derive(Debug, Args)]
struct ConnArgs {
	#[arg(long, env = "LOUPE_SERVER_URL")]
	server_url: reqwest::Url,
	#[arg(long, env = "LOUPE_CA_CERT")]
	ca_cert: Option<PathBuf>,
	#[arg(long, env = "LOUPE_CA_CERT_PEM", hide_env_values = true)]
	ca_cert_pem: Option<String>,
	#[arg(long, env = "LOUPE_CA_CERT_PEM_B64", hide_env_values = true)]
	ca_cert_pem_b64: Option<String>,
	#[arg(long, env = "LOUPE_ADMIN_CERT")]
	admin_cert: Option<PathBuf>,
	#[arg(long, env = "LOUPE_ADMIN_CERT_PEM", hide_env_values = true)]
	admin_cert_pem: Option<String>,
	#[arg(long, env = "LOUPE_ADMIN_CERT_PEM_B64", hide_env_values = true)]
	admin_cert_pem_b64: Option<String>,
	#[arg(long, env = "LOUPE_ADMIN_KEY")]
	admin_key: Option<PathBuf>,
	#[arg(long, env = "LOUPE_ADMIN_KEY_PEM", hide_env_values = true)]
	admin_key_pem: Option<String>,
	#[arg(long, env = "LOUPE_ADMIN_KEY_PEM_B64", hide_env_values = true)]
	admin_key_pem_b64: Option<String>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
	#[command(subcommand)]
	Repo(RepoCmd),
	#[command(subcommand)]
	Worker(WorkerCmd),
	#[command(subcommand)]
	Job(JobCmd),
	#[command(subcommand)]
	Finding(FindingCmd),
}

#[derive(Debug, Subcommand)]
enum RepoCmd {
	/// Register a new repo for scanning.
	Add(RepoAddArgs),
	/// List registered repos.
	List,
	/// Deregister a repo (cascades to its jobs and findings).
	Rm { id: i64 },
	/// Patch a repo's scheduling / verification settings. Each flag is
	/// optional and only present fields are applied.
	Update(RepoUpdateArgs),
	/// Trigger a scan now.
	Scan {
		id: i64,
		#[arg(long, default_value_t = false)]
		incremental: bool,
	},
}

#[derive(Debug, Args)]
struct RepoUpdateArgs {
	id: i64,
	/// Stop the scheduler from picking this repo. Triggered scans
	/// (`loupectl repo scan`) still go through.
	#[arg(long, conflicts_with = "enable")]
	disable: bool,
	/// Re-enable a previously disabled repo.
	#[arg(long, conflicts_with = "disable")]
	enable: bool,
	/// Set the scan interval (seconds). Pass 0 to leave it as-is — use
	/// `--disable` if you want to stop scheduled scans.
	#[arg(long)]
	interval: Option<u64>,
	/// Route findings through the verify flow before dispatching.
	#[arg(long, conflicts_with = "no_verification")]
	verification_enabled: bool,
	/// Dispatch findings immediately on insert; skip the verify flow.
	#[arg(long, conflicts_with = "verification_enabled")]
	no_verification: bool,
	/// Pin require_approval = true for this repo. Confirmed findings
	/// park in `awaiting_approval` until a human runs `loupectl
	/// finding approve`.
	#[arg(long, conflicts_with_all = ["no_require_approval", "inherit_approval"])]
	require_approval: bool,
	/// Pin require_approval = false for this repo (immediate dispatch
	/// even if the server default is on).
	#[arg(long, conflicts_with_all = ["require_approval", "inherit_approval"])]
	no_require_approval: bool,
	/// Clear any per-repo override and fall back to the server-level
	/// `require_approval_default`.
	#[arg(long, conflicts_with_all = ["require_approval", "no_require_approval"])]
	inherit_approval: bool,
}

#[derive(Debug, Args)]
struct RepoAddArgs {
	#[arg(long)]
	clone_url: String,
	#[arg(long)]
	branch: Option<String>,
	#[arg(long)]
	scan_interval_seconds: Option<u64>,
	/// Owner of the tracker repo where findings get filed. Required
	/// unless `--no-reporting` is set.
	#[arg(long, required_unless_present = "no_reporting")]
	target_owner: Option<String>,
	/// Tracker repo name where findings get filed. Required unless
	/// `--no-reporting` is set.
	#[arg(long, required_unless_present = "no_reporting")]
	target_repo: Option<String>,
	/// PAT with `repo` scope on the target tracker. Read from the env
	/// var `LOUPE_TRACKER_PAT` if not supplied — never echo it on the
	/// command line in shared shells. Required unless `--no-reporting`
	/// is set.
	#[arg(long, env = "LOUPE_TRACKER_PAT", required_unless_present = "no_reporting")]
	pat: Option<String>,
	/// Skip configuring an automatic reporter. Findings still go
	/// through the full scan + verification + approval pipeline; on
	/// dispatch they go straight to `reported` without poking any
	/// external system. Operators triage via `loupectl finding show /
	/// approve / reject` and act on findings out-of-band. Implies
	/// `--require-approval` unless explicitly overridden — pairing
	/// manual mode with auto-dispatch would silently mark every
	/// finding `reported` before a human ever sees it.
	#[arg(
		long,
		default_value_t = false,
		conflicts_with_all = ["target_owner", "target_repo", "pat"],
	)]
	no_reporting: bool,
	/// Route findings through the verify flow before dispatching. Off
	/// by default; turn on for repos where you want a second-opinion
	/// verifier worker to confirm each finding.
	#[arg(long, default_value_t = false)]
	verification_enabled: bool,
	/// Pin per-repo require_approval = true at registration time.
	#[arg(long, conflicts_with = "no_require_approval")]
	require_approval: bool,
	/// Pin per-repo require_approval = false at registration time.
	/// If neither flag is set, the repo inherits the server-level
	/// `require_approval_default` (or implicit `true` when paired with
	/// `--no-reporting`).
	#[arg(long, conflicts_with = "require_approval")]
	no_require_approval: bool,
}

#[derive(Debug, Subcommand)]
enum WorkerCmd {
	/// Mint a new worker cert. Saves the bundle to `--out` (or stdout).
	Register(WorkerRegisterArgs),
	/// Revoke a worker (next mTLS handshake from that cert will 401).
	Rm { id: i64 },
}

#[derive(Debug, Args)]
struct WorkerRegisterArgs {
	#[arg(long)]
	name: String,
	#[arg(long, conflicts_with = "emit_env")]
	out: Option<PathBuf>,
	/// Print sourceable LOUPE_WORKER_* env assignments instead of JSON.
	#[arg(long, default_value_t = false)]
	emit_env: bool,
}

#[derive(Debug, Subcommand)]
enum JobCmd {
	List,
	Get { id: i64 },
}

#[derive(Debug, Subcommand)]
enum FindingCmd {
	/// List recent findings for a repo (newest first, capped server-side).
	List { repo_id: i64 },
	/// FTS5 keyword search over a repo's findings (title, description,
	/// file path). Free-form keywords are sanitized server-side; the
	/// match is "every term must appear" with BM25 ranking. Useful for
	/// "have we seen something like this before?" lookups.
	Search {
		repo_id: i64,
		/// One or more space-separated keywords. Quote the whole
		/// thing if your shell would split on spaces.
		query: String,
		#[arg(long, default_value_t = 20)]
		limit: i64,
	},
	/// Pretty-print a single finding for human review: title + severity,
	/// location, description, PoC diff, and audit trail. Pass `--json`
	/// to dump the raw FindingDetail DTO instead (for scripting).
	Show {
		id: i64,
		/// Output the raw JSON DTO instead of the pretty rendering.
		#[arg(long, default_value_t = false)]
		json: bool,
	},
	/// Approve a finding parked in `awaiting_approval`. Transitions
	/// it to `confirmed` and immediately runs the dispatcher.
	Approve { id: i64 },
	/// Reject a finding parked in `awaiting_approval`. Transitions
	/// it to terminal `dismissed` with the rejection audit trail
	/// stamped (distinct from a verifier-issued dismiss).
	Reject { id: i64 },
}

#[tokio::main]
async fn main() -> Result<()> {
	let cli = Cli::parse();
	let client = build_client(&cli.conn)?;
	match cli.cmd {
		Cmd::Repo(c) => match c {
			RepoCmd::Add(a) => repo_add(&client, &cli.conn.server_url, a).await,
			RepoCmd::List => repo_list(&client, &cli.conn.server_url).await,
			RepoCmd::Rm { id } => repo_rm(&client, &cli.conn.server_url, id).await,
			RepoCmd::Update(a) => repo_update(&client, &cli.conn.server_url, a).await,
			RepoCmd::Scan { id, incremental } => {
				repo_scan(&client, &cli.conn.server_url, id, incremental).await
			},
		},
		Cmd::Worker(c) => match c {
			WorkerCmd::Register(a) => worker_register(&client, &cli.conn.server_url, a).await,
			WorkerCmd::Rm { id } => worker_rm(&client, &cli.conn.server_url, id).await,
		},
		Cmd::Job(c) => match c {
			JobCmd::List => job_list(&client, &cli.conn.server_url).await,
			JobCmd::Get { id } => job_get(&client, &cli.conn.server_url, id).await,
		},
		Cmd::Finding(c) => match c {
			FindingCmd::List { repo_id } => {
				finding_list(&client, &cli.conn.server_url, repo_id).await
			},
			FindingCmd::Search { repo_id, query, limit } => {
				finding_search(&client, &cli.conn.server_url, repo_id, &query, limit).await
			},
			FindingCmd::Show { id, json } => {
				finding_show(&client, &cli.conn.server_url, id, json).await
			},
			FindingCmd::Approve { id } => finding_approve(&client, &cli.conn.server_url, id).await,
			FindingCmd::Reject { id } => finding_reject(&client, &cli.conn.server_url, id).await,
		},
	}
}

fn build_client(c: &ConnArgs) -> Result<reqwest::Client> {
	let ca = pem_from_env_or_file(
		"CA cert",
		&c.ca_cert_pem,
		&c.ca_cert_pem_b64,
		c.ca_cert.as_ref(),
		"CA cert missing — set LOUPE_CA_CERT_PEM, LOUPE_CA_CERT_PEM_B64, or LOUPE_CA_CERT",
	)?;
	let cert = pem_from_env_or_file(
		"admin cert",
		&c.admin_cert_pem,
		&c.admin_cert_pem_b64,
		c.admin_cert.as_ref(),
		"admin cert missing — set LOUPE_ADMIN_CERT_PEM, LOUPE_ADMIN_CERT_PEM_B64, or LOUPE_ADMIN_CERT",
	)?;
	let key = pem_from_env_or_file(
		"admin key",
		&c.admin_key_pem,
		&c.admin_key_pem_b64,
		c.admin_key.as_ref(),
		"admin key missing — set LOUPE_ADMIN_KEY_PEM, LOUPE_ADMIN_KEY_PEM_B64, or LOUPE_ADMIN_KEY",
	)?;
	let mut combined = String::with_capacity(cert.len() + key.len() + 1);
	combined.push_str(&cert);
	if !cert.ends_with('\n') {
		combined.push('\n');
	}
	combined.push_str(&key);

	let identity =
		reqwest::Identity::from_pem(combined.as_bytes()).context("parsing admin identity")?;
	let root = reqwest::Certificate::from_pem(ca.as_bytes()).context("parsing CA cert")?;
	reqwest::Client::builder()
		.add_root_certificate(root)
		.identity(identity)
		.use_rustls_tls()
		.build()
		.context("building reqwest client")
}

fn pem_from_env_or_file(
	label: &str, pem: &Option<String>, pem_b64: &Option<String>, path: Option<&PathBuf>,
	missing: &'static str,
) -> Result<String> {
	if let Some(pem) = pem.as_deref().filter(|s| !s.is_empty()) {
		return Ok(pem.to_owned());
	}
	if let Some(pem_b64) = pem_b64.as_deref().filter(|s| !s.is_empty()) {
		use base64::Engine as _;
		let bytes = base64::engine::general_purpose::STANDARD
			.decode(pem_b64.trim())
			.with_context(|| format!("decoding base64 {label} PEM"))?;
		return String::from_utf8(bytes).with_context(|| format!("{label} PEM is not valid UTF-8"));
	}
	let path = path.context(missing)?;
	std::fs::read_to_string(path).with_context(|| format!("reading {label} at {}", path.display()))
}

fn url(base: &reqwest::Url, path: &str) -> reqwest::Url {
	base.join(path).expect("path is always valid")
}

async fn repo_add(client: &reqwest::Client, base: &reqwest::Url, a: RepoAddArgs) -> Result<()> {
	// Manual mode implies require_approval = true unless the operator
	// explicitly opts out. Pairing manual mode with auto-dispatch
	// would flip every finding to `reported` before a human ever sees
	// it — almost certainly not what someone passing --no-reporting
	// wants.
	let require_approval = match (a.require_approval, a.no_require_approval) {
		(true, false) => Some(true),
		(false, true) => Some(false),
		_ if a.no_reporting => Some(true),
		_ => None,
	};
	let reporting = if a.no_reporting {
		ReportingSetup::Manual
	} else {
		ReportingSetup::GithubIssue {
			// `clap` enforces these are present unless --no-reporting is set,
			// so the unwrap is structurally safe.
			target_owner: a.target_owner.expect("clap enforces target_owner"),
			target_repo: a.target_repo.expect("clap enforces target_repo"),
			github_pat: a.pat.expect("clap enforces pat"),
		}
	};
	let req = RegisterRepoRequest {
		protocol_version: PROTOCOL_VERSION,
		clone_url: a.clone_url,
		branch: a.branch,
		scan_interval_seconds: a.scan_interval_seconds,
		reporting,
		scanner_config: serde_json::Value::Null,
		verification_enabled: a.verification_enabled,
		require_approval,
	};
	let resp = client.post(url(base, "/v1/repos")).json(&req).send().await?;
	let status = resp.status();
	if !status.is_success() {
		anyhow::bail!("register repo: {} — {}", status, resp.text().await.unwrap_or_default());
	}
	let body: RegisterRepoResponse = resp.json().await?;
	println!("repo_id={}", body.repo_id);
	Ok(())
}

async fn repo_list(client: &reqwest::Client, base: &reqwest::Url) -> Result<()> {
	let resp = client.get(url(base, "/v1/repos")).send().await?;
	let body: ListReposResponse = resp.error_for_status()?.json().await?;
	for r in body.repos {
		let approval = r.require_approval.map_or("inherit".to_owned(), |v| v.to_string());
		let disabled = r.disabled_at.map_or("active".to_owned(), |ts| format!("disabled@{ts}"));
		println!(
			"{:>4}\t{}\t{}/{}\tinterval={:?}\tverify={}\tapproval={}\t{}\tlast_sha={:?}",
			r.id,
			r.host,
			r.owner,
			r.repo,
			r.scan_interval_seconds,
			r.verification_enabled,
			approval,
			disabled,
			r.last_scanned_sha,
		);
	}
	Ok(())
}

async fn repo_rm(client: &reqwest::Client, base: &reqwest::Url, id: i64) -> Result<()> {
	let resp = client.delete(url(base, &format!("/v1/repos/{id}"))).send().await?;
	resp.error_for_status()?;
	Ok(())
}

async fn repo_update(
	client: &reqwest::Client, base: &reqwest::Url, a: RepoUpdateArgs,
) -> Result<()> {
	let disabled = match (a.disable, a.enable) {
		(true, false) => Some(true),
		(false, true) => Some(false),
		_ => None,
	};
	let verification_enabled = match (a.verification_enabled, a.no_verification) {
		(true, false) => Some(true),
		(false, true) => Some(false),
		_ => None,
	};
	let require_approval = match (a.require_approval, a.no_require_approval) {
		(true, false) => Some(true),
		(false, true) => Some(false),
		_ => None,
	};
	let req = UpdateRepoRequest {
		protocol_version: PROTOCOL_VERSION,
		disabled,
		scan_interval_seconds: a.interval,
		verification_enabled,
		require_approval,
		inherit_require_approval: a.inherit_approval,
	};
	let resp = client.patch(url(base, &format!("/v1/repos/{}", a.id))).json(&req).send().await?;
	let status = resp.status();
	if !status.is_success() {
		anyhow::bail!("update repo: {} — {}", status, resp.text().await.unwrap_or_default());
	}
	Ok(())
}

async fn repo_scan(
	client: &reqwest::Client, base: &reqwest::Url, id: i64, incremental: bool,
) -> Result<()> {
	let resp = client
		.post(url(base, &format!("/v1/repos/{id}/scan")))
		.json(&ScanRequest { protocol_version: PROTOCOL_VERSION, incremental })
		.send()
		.await?;
	let status = resp.status();
	if !status.is_success() {
		anyhow::bail!("scan: {} — {}", status, resp.text().await.unwrap_or_default());
	}
	let body: ScanResponse = resp.json().await?;
	println!("job_id={}", body.job_id);
	Ok(())
}

async fn worker_register(
	client: &reqwest::Client, base: &reqwest::Url, a: WorkerRegisterArgs,
) -> Result<()> {
	let resp = client
		.post(url(base, "/v1/workers"))
		.json(&RegisterWorkerRequest { protocol_version: PROTOCOL_VERSION, name: a.name })
		.send()
		.await?;
	let status = resp.status();
	if !status.is_success() {
		anyhow::bail!("register worker: {} — {}", status, resp.text().await.unwrap_or_default());
	}
	let bundle: RegisterWorkerResponse = resp.json().await?;
	if a.emit_env {
		for (name, value) in worker_env_assignments(base, &bundle) {
			println!("{name}={value}");
		}
		return Ok(());
	}
	let serialised = serde_json::to_string_pretty(&bundle)?;
	if let Some(path) = a.out {
		std::fs::write(&path, &serialised)
			.with_context(|| format!("writing bundle to {}", path.display()))?;
		println!("worker_id={} bundle written to {}", bundle.worker_id, path.display());
	} else {
		println!("{serialised}");
	}
	Ok(())
}

fn worker_env_assignments(
	base: &reqwest::Url, bundle: &RegisterWorkerResponse,
) -> Vec<(&'static str, String)> {
	vec![
		("LOUPE_SERVER_URL", base.as_str().to_owned()),
		("LOUPE_WORKER_CA_CERT_PEM_B64", b64(&bundle.ca_cert_pem)),
		("LOUPE_WORKER_CERT_PEM_B64", b64(&bundle.client_cert_pem)),
		("LOUPE_WORKER_KEY_PEM_B64", b64(&bundle.client_key_pem)),
	]
}

fn b64(value: &str) -> String {
	use base64::Engine as _;
	base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
}

async fn worker_rm(client: &reqwest::Client, base: &reqwest::Url, id: i64) -> Result<()> {
	let resp = client.delete(url(base, &format!("/v1/workers/{id}"))).send().await?;
	resp.error_for_status()?;
	Ok(())
}

async fn job_list(client: &reqwest::Client, base: &reqwest::Url) -> Result<()> {
	let resp = client.get(url(base, "/v1/jobs")).send().await?;
	let jobs: Vec<JobInfo> = resp.error_for_status()?.json().await?;
	for j in jobs {
		println!(
			"{:>4}\trepo={}\tkind={:?}\tstate={:?}\tattempts={}\thead={:?}",
			j.job_id, j.repo_id, j.kind, j.state, j.attempts, j.head_sha,
		);
	}
	Ok(())
}

async fn job_get(client: &reqwest::Client, base: &reqwest::Url, id: i64) -> Result<()> {
	let resp = client.get(url(base, &format!("/v1/jobs/{id}"))).send().await?;
	let job: JobInfo = resp.error_for_status()?.json().await?;
	println!("{}", serde_json::to_string_pretty(&job)?);
	Ok(())
}

async fn finding_list(client: &reqwest::Client, base: &reqwest::Url, repo_id: i64) -> Result<()> {
	let resp = client.get(url(base, &format!("/v1/repos/{repo_id}/findings"))).send().await?;
	let body: ListFindingsResponse = resp.error_for_status()?.json().await?;
	for f in body.findings {
		let loc = match (f.file_path.as_deref(), f.line_start) {
			(Some(p), Some(l)) => format!("{p}:{l}"),
			(Some(p), None) => p.to_string(),
			_ => "-".into(),
		};
		println!(
			"{:>5}\tjob={}\t{:?}\t{}\tstate={}\tverify={}\t{}\t{}",
			f.id,
			f.job_id,
			f.severity,
			f.scanner_id,
			f.state,
			f.verification_required,
			loc,
			f.title,
		);
	}
	Ok(())
}

async fn finding_search(
	client: &reqwest::Client, base: &reqwest::Url, repo_id: i64, query: &str, limit: i64,
) -> Result<()> {
	let url = url(base, &format!("/v1/repos/{repo_id}/findings/search"));
	let resp = client.get(url).query(&[("q", query), ("limit", &limit.to_string())]).send().await?;
	let body: ListFindingsResponse = resp.error_for_status()?.json().await?;
	if body.findings.is_empty() {
		println!("(no matches)");
		return Ok(());
	}
	for f in body.findings {
		let loc = match (f.file_path.as_deref(), f.line_start) {
			(Some(p), Some(l)) => format!("{p}:{l}"),
			(Some(p), None) => p.to_string(),
			_ => "-".into(),
		};
		println!(
			"{:>5}\t{:?}\t{}\tstate={}\t{}\t{}",
			f.id, f.severity, f.scanner_id, f.state, loc, f.title,
		);
	}
	Ok(())
}

async fn finding_show(
	client: &reqwest::Client, base: &reqwest::Url, id: i64, as_json: bool,
) -> Result<()> {
	let resp = client.get(url(base, &format!("/v1/findings/{id}"))).send().await?;
	let detail: FindingDetail = resp.error_for_status()?.json().await?;
	if as_json {
		println!("{}", serde_json::to_string_pretty(&detail)?);
	} else {
		print!("{}", render::finding(&detail, render::Style::detect()));
	}
	Ok(())
}

async fn finding_approve(client: &reqwest::Client, base: &reqwest::Url, id: i64) -> Result<()> {
	let resp = client.post(url(base, &format!("/v1/findings/{id}/approve"))).send().await?;
	let status = resp.status();
	if !status.is_success() {
		anyhow::bail!("approve finding: {} — {}", status, resp.text().await.unwrap_or_default());
	}
	Ok(())
}

async fn finding_reject(client: &reqwest::Client, base: &reqwest::Url, id: i64) -> Result<()> {
	let resp = client.post(url(base, &format!("/v1/findings/{id}/reject"))).send().await?;
	let status = resp.status();
	if !status.is_success() {
		anyhow::bail!("reject finding: {} — {}", status, resp.text().await.unwrap_or_default());
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn pem_b64_env_wins_over_file_path() {
		let file = std::env::temp_dir().join("loupectl-test-path-that-should-not-be-read.pem");
		let pem = "-----BEGIN CERTIFICATE-----\nfrom-env\n-----END CERTIFICATE-----\n";
		let pem_b64 = b64(pem);

		let got =
			pem_from_env_or_file("CA cert", &None, &Some(pem_b64), Some(&file), "missing").unwrap();
		assert_eq!(got, pem);
	}

	#[test]
	fn worker_register_out_conflicts_with_emit_env() {
		let err = Cli::try_parse_from([
			"loupectl",
			"--server-url",
			"https://loupe.example:8443",
			"worker",
			"register",
			"--name",
			"worker-1",
			"--out",
			"worker.json",
			"--emit-env",
		])
		.expect_err("clap should reject --out with --emit-env");
		assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
	}

	#[test]
	fn worker_env_assignments_are_single_line_and_decode_to_bundle() {
		let base = reqwest::Url::parse("https://loupe.example:8443/").unwrap();
		let bundle = RegisterWorkerResponse {
			protocol_version: PROTOCOL_VERSION,
			worker_id: 42,
			ca_cert_pem: "ca\ncert\n".into(),
			client_cert_pem: "worker\ncert\n".into(),
			client_key_pem: "worker\nkey\n".into(),
		};

		let assignments = worker_env_assignments(&base, &bundle);
		let names: Vec<_> = assignments.iter().map(|(name, _)| *name).collect();
		assert_eq!(
			names,
			vec![
				"LOUPE_SERVER_URL",
				"LOUPE_WORKER_CA_CERT_PEM_B64",
				"LOUPE_WORKER_CERT_PEM_B64",
				"LOUPE_WORKER_KEY_PEM_B64",
			]
		);
		for (name, value) in &assignments {
			assert!(!value.is_empty(), "{name} value must be present");
			assert!(!value.contains('\n'), "{name} value must fit dotenv/env-file syntax");
		}

		use base64::Engine as _;
		let decoded_ca =
			base64::engine::general_purpose::STANDARD.decode(&assignments[1].1).unwrap();
		assert_eq!(String::from_utf8(decoded_ca).unwrap(), bundle.ca_cert_pem);
	}
}
