//! `loupectl` — operator CLI for loupe-server.
//!
//! Authenticates with the admin client cert minted by `loupe-server
//! init`. Every command is one round-trip; the CLI does no caching.

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
	ca_cert: PathBuf,
	#[arg(long, env = "LOUPE_ADMIN_CERT")]
	cert: PathBuf,
	#[arg(long, env = "LOUPE_ADMIN_KEY")]
	key: PathBuf,
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
}

#[derive(Debug, Args)]
struct RepoAddArgs {
	#[arg(long)]
	clone_url: String,
	#[arg(long)]
	branch: Option<String>,
	#[arg(long)]
	scan_interval_seconds: Option<u64>,
	#[arg(long)]
	target_owner: String,
	#[arg(long)]
	target_repo: String,
	/// PAT with `repo` scope on the target tracker. Read from the env
	/// var `LOUPE_TRACKER_PAT` if not supplied — never echo it on the
	/// command line in shared shells.
	#[arg(long, env = "LOUPE_TRACKER_PAT")]
	pat: String,
	/// Route findings through the verify flow before dispatching. Off
	/// by default; turn on for repos where you want a second-opinion
	/// verifier worker to confirm each finding.
	#[arg(long, default_value_t = false)]
	verification_enabled: bool,
}

#[derive(Debug, Subcommand)]
enum WorkerCmd {
	/// Mint a new worker cert. Saves the bundle to `--out` (or stdout).
	Register {
		#[arg(long)]
		name: String,
		#[arg(long)]
		out: Option<PathBuf>,
	},
	/// Revoke a worker (next mTLS handshake from that cert will 401).
	Rm { id: i64 },
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
	/// Print a single finding in full detail (description + PoC + patch).
	Get { id: i64 },
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
			WorkerCmd::Register { name, out } => {
				worker_register(&client, &cli.conn.server_url, name, out).await
			},
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
			FindingCmd::Get { id } => finding_get(&client, &cli.conn.server_url, id).await,
		},
	}
}

fn build_client(c: &ConnArgs) -> Result<reqwest::Client> {
	let ca = std::fs::read_to_string(&c.ca_cert)
		.with_context(|| format!("reading CA cert at {}", c.ca_cert.display()))?;
	let cert = std::fs::read_to_string(&c.cert)
		.with_context(|| format!("reading admin cert at {}", c.cert.display()))?;
	let key = std::fs::read_to_string(&c.key)
		.with_context(|| format!("reading admin key at {}", c.key.display()))?;
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

fn url(base: &reqwest::Url, path: &str) -> reqwest::Url {
	base.join(path).expect("path is always valid")
}

async fn repo_add(client: &reqwest::Client, base: &reqwest::Url, a: RepoAddArgs) -> Result<()> {
	let req = RegisterRepoRequest {
		protocol_version: PROTOCOL_VERSION,
		clone_url: a.clone_url,
		branch: a.branch,
		scan_interval_seconds: a.scan_interval_seconds,
		reporting: ReportingSetup::GithubIssue {
			target_owner: a.target_owner,
			target_repo: a.target_repo,
			github_pat: a.pat,
		},
		scanner_config: serde_json::Value::Null,
		verification_enabled: a.verification_enabled,
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
		println!(
			"{:>4}\t{}\t{}/{}\tinterval={:?}\tlast_sha={:?}",
			r.id, r.host, r.owner, r.repo, r.scan_interval_seconds, r.last_scanned_sha,
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
	let req = UpdateRepoRequest {
		protocol_version: PROTOCOL_VERSION,
		disabled,
		scan_interval_seconds: a.interval,
		verification_enabled,
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
	client: &reqwest::Client, base: &reqwest::Url, name: String, out: Option<PathBuf>,
) -> Result<()> {
	let resp = client
		.post(url(base, "/v1/workers"))
		.json(&RegisterWorkerRequest { protocol_version: PROTOCOL_VERSION, name })
		.send()
		.await?;
	let status = resp.status();
	if !status.is_success() {
		anyhow::bail!("register worker: {} — {}", status, resp.text().await.unwrap_or_default());
	}
	let bundle: RegisterWorkerResponse = resp.json().await?;
	let serialised = serde_json::to_string_pretty(&bundle)?;
	if let Some(path) = out {
		std::fs::write(&path, &serialised)
			.with_context(|| format!("writing bundle to {}", path.display()))?;
		println!("worker_id={} bundle written to {}", bundle.worker_id, path.display());
	} else {
		println!("{serialised}");
	}
	Ok(())
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

async fn finding_get(client: &reqwest::Client, base: &reqwest::Url, id: i64) -> Result<()> {
	let resp = client.get(url(base, &format!("/v1/findings/{id}"))).send().await?;
	let detail: FindingDetail = resp.error_for_status()?.json().await?;
	println!("{}", serde_json::to_string_pretty(&detail)?);
	Ok(())
}
