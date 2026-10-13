// Keep production safety lints separate from test-only assertions.
#![cfg_attr(
	not(test),
	deny(
		clippy::unwrap_used,
		clippy::expect_used,
		clippy::string_slice,
		clippy::mem_forget,
		clippy::dbg_macro,
		clippy::todo,
		clippy::unimplemented,
		clippy::disallowed_methods
	)
)]
#![deny(unsafe_code)]
//! `loupectl` — operator CLI for loupe-server.
//!
//! Authenticates with the admin client cert minted by `loupe-server
//! init`. Every command is one round-trip; the CLI does no caching.

use std::path::Path;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use loupe_cli::render::{self, TerminalText};
use loupe_core::text::{policy, BoundedText};
use loupe_proto::{
	FindingDetail, GithubAppResponse, GithubReportingAuth, JobInfo, ListFindingsResponse,
	ListReposResponse, RegisterRepoRequest, RegisterRepoResponse, RegisterWorkerRequest,
	RegisterWorkerResponse, ReportingSetup, ReportingSummary, RetryVerifyRequest,
	RetryVerifyResponse, RotateRepoPatRequest, ScanRequest, ScanResponse,
	SetRepoGithubReportingRequest, UpdateRepoRequest, PROTOCOL_VERSION,
};
use loupe_provenance::{Agent, Config, Server};

mod config_input;
mod credential_request;
mod ingress;

// debug-ok: command/configuration children redact text, paths and credentials.
#[derive(Debug, Parser)]
#[command(version, about = "loupe operator CLI")]
struct Cli {
	#[command(flatten)]
	conn: ConnArgs,
	#[command(subcommand)]
	cmd: Cmd,
}

// debug-ok: all connection values delegate to redacted Config owners.
#[derive(Debug, Args)]
struct ConnArgs {
	#[arg(long, env = "LOUPE_SERVER_URL", value_parser = config_input::UrlArgument)]
	server_url: Option<config_input::ConfiguredUrl>,
	#[arg(long, env = "LOUPE_CA_CERT", value_parser = config_input::PathArgument)]
	ca_cert: Option<config_input::ConfiguredPath>,
	#[arg(long, env = "LOUPE_CA_CERT_PEM", hide_env_values = true, value_parser = config_input::PemArgument)]
	ca_cert_pem: Option<config_input::ConfiguredPem>,
	#[arg(long, env = "LOUPE_CA_CERT_PEM_B64", hide_env_values = true, value_parser = config_input::PemArgument)]
	ca_cert_pem_b64: Option<config_input::ConfiguredPem>,
	#[arg(long, env = "LOUPE_ADMIN_CERT", value_parser = config_input::PathArgument)]
	admin_cert: Option<config_input::ConfiguredPath>,
	#[arg(long, env = "LOUPE_ADMIN_CERT_PEM", hide_env_values = true, value_parser = config_input::PemArgument)]
	admin_cert_pem: Option<config_input::ConfiguredPem>,
	#[arg(long, env = "LOUPE_ADMIN_CERT_PEM_B64", hide_env_values = true, value_parser = config_input::PemArgument)]
	admin_cert_pem_b64: Option<config_input::ConfiguredPem>,
	#[arg(long, env = "LOUPE_ADMIN_KEY", value_parser = config_input::PathArgument)]
	admin_key: Option<config_input::ConfiguredPath>,
	#[arg(long, env = "LOUPE_ADMIN_KEY_PEM", hide_env_values = true, value_parser = config_input::PemArgument)]
	admin_key_pem: Option<config_input::ConfiguredPem>,
	#[arg(long, env = "LOUPE_ADMIN_KEY_PEM_B64", hide_env_values = true, value_parser = config_input::PemArgument)]
	admin_key_pem_b64: Option<config_input::ConfiguredPem>,
}

// debug-ok: command variants contain reviewed argument owners and numeric IDs.
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
	#[command(subcommand)]
	Cert(CertCmd),
	/// Manage the server-wide GitHub App used to file issues.
	#[command(subcommand)]
	GithubApp(GithubAppCmd),
}

// debug-ok: app arguments redact credentials; other variants are fieldless.
#[derive(Debug, Subcommand)]
enum GithubAppCmd {
	/// Store (or replace) the GitHub App credential. The server verifies
	/// the key against GitHub before persisting it.
	Set(GithubAppSetArgs),
	/// Show which GitHub App is configured.
	Show,
	/// Remove the stored GitHub App credential.
	Clear,
}

// debug-ok: app ID is numeric; key paths and PEM inputs redact their content.
#[derive(Debug, Args)]
struct GithubAppSetArgs {
	/// Numeric App ID from the app's settings page on GitHub.
	#[arg(long)]
	app_id: u64,
	/// Path to the private key PEM downloaded from the app's settings
	/// page. Read from LOUPE_GITHUB_APP_KEY if omitted. Alternatively
	/// pass the PEM itself via LOUPE_GITHUB_APP_KEY_PEM or, base64
	/// encoded, via LOUPE_GITHUB_APP_KEY_PEM_B64.
	#[arg(long, env = "LOUPE_GITHUB_APP_KEY", value_parser = config_input::PathArgument)]
	private_key_file: Option<config_input::ConfiguredPath>,
	#[arg(long, env = "LOUPE_GITHUB_APP_KEY_PEM", hide_env_values = true, value_parser = config_input::PemArgument)]
	private_key_pem: Option<config_input::ConfiguredPem>,
	#[arg(long, env = "LOUPE_GITHUB_APP_KEY_PEM_B64", hide_env_values = true, value_parser = config_input::PemArgument)]
	private_key_pem_b64: Option<config_input::ConfiguredPem>,
}

// debug-ok: repo arguments redact content; remaining fields are IDs/flags.
#[derive(Debug, Subcommand)]
enum RepoCmd {
	/// Register a new repo for scanning.
	Add(RepoAddArgs),
	/// List registered repos. Pass `--json` to dump the raw
	/// ListReposResponse DTO instead (for scripting).
	List(RepoListArgs),
	/// Deregister a repo (cascades to its jobs and findings).
	Rm { id: i64 },
	/// Patch a repo's scheduling / verification settings. Each flag is
	/// optional and only present fields are applied.
	Update(RepoUpdateArgs),
	/// Replace the GitHub PAT used by this repo's issue reporter.
	RotatePat(RepoRotatePatArgs),
	/// Configure or replace this repo's GitHub issue reporter.
	SetGithubReporting(RepoSetGithubReportingArgs),
	/// Trigger a scan now.
	Scan {
		id: i64,
		#[arg(long, default_value_t = false)]
		incremental: bool,
	},
}

// debug-ok: PAT is redacted; repository ID is numeric.
#[derive(Debug, Args)]
struct RepoRotatePatArgs {
	id: i64,
	/// Replacement PAT for this repo's GitHub issue reporter. Read
	/// from LOUPE_TRACKER_PAT if omitted.
	#[arg(long, env = "LOUPE_TRACKER_PAT", hide_env_values = true, value_parser = config_input::Pat)]
	pat: config_input::PatInput,
}

// debug-ok: target text and optional PAT redact content; ID is numeric.
#[derive(Debug, Args)]
struct RepoSetGithubReportingArgs {
	id: i64,
	#[arg(long, value_parser = config_input::OwnerArgument)]
	target_owner: BoundedText<policy::RepoOwner, Config>,
	#[arg(long, value_parser = config_input::RepoArgument)]
	target_repo: BoundedText<policy::RepoName, Config>,
	/// PAT for the target tracker repo. Read from LOUPE_TRACKER_PAT if
	/// not supplied. Omit both to report through the server's GitHub
	/// App instead; switching an existing PAT-backed repo this way drops
	/// its stored PAT.
	#[arg(long, env = "LOUPE_TRACKER_PAT", hide_env_values = true, value_parser = config_input::Pat)]
	pat: Option<config_input::PatInput>,
}

// debug-ok: update arguments contain only booleans and numeric ID/interval.
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

// debug-ok: all text and PAT values redact; remaining fields are counts/flags.
#[derive(Debug, Args)]
struct RepoAddArgs {
	#[arg(long, value_parser = config_input::CloneUrlArgument)]
	clone_url: BoundedText<policy::CloneUrl, Config>,
	#[arg(long, value_parser = config_input::BranchArgument)]
	branch: Option<BoundedText<policy::GitBranch, Config>>,
	#[arg(long)]
	scan_interval_seconds: Option<u64>,
	/// Owner of the tracker repo where findings get filed. Required
	/// unless `--no-reporting` is set.
	#[arg(long, required_unless_present = "no_reporting", value_parser = config_input::OwnerArgument)]
	target_owner: Option<BoundedText<policy::RepoOwner, Config>>,
	/// Tracker repo name where findings get filed. Required unless
	/// `--no-reporting` is set.
	#[arg(long, required_unless_present = "no_reporting", value_parser = config_input::RepoArgument)]
	target_repo: Option<BoundedText<policy::RepoName, Config>>,
	/// PAT with Issues write access on the target tracker. Read from the
	/// env var `LOUPE_TRACKER_PAT` if not supplied — never echo it on
	/// the command line in shared shells. Omit it (and unset the env
	/// var) to report through the server's GitHub App instead, which is
	/// the default; the server rejects the registration if no app is
	/// configured.
	#[arg(long, env = "LOUPE_TRACKER_PAT", hide_env_values = true, value_parser = config_input::Pat)]
	pat: Option<config_input::PatInput>,
	/// Skip configuring an automatic reporter. Findings still go
	/// through the full scan + verification + approval pipeline.
	/// Confirmed findings remain `confirmed` so operators can configure
	/// reporting later and run `loupectl finding retry-report`, or
	/// triage manually with `loupectl finding show / approve / reject`.
	#[arg(
		long,
		default_value_t = false,
		conflicts_with_all = ["target_owner", "target_repo", "pat"],
	)]
	no_reporting: bool,
	/// Route findings through the verify flow before dispatching.
	#[arg(long, conflicts_with = "no_verification")]
	verification_enabled: bool,
	/// Pin verification off for this repo, even if the server default
	/// is on. If neither flag is set, repo registration inherits the
	/// server-level verification default.
	#[arg(long, conflicts_with = "verification_enabled")]
	no_verification: bool,
	/// Pin per-repo require_approval = true at registration time.
	#[arg(long, conflicts_with = "no_require_approval")]
	require_approval: bool,
	/// Pin per-repo require_approval = false at registration time.
	/// If neither flag is set, the repo inherits the server-level
	/// `require_approval_default`.
	#[arg(long, conflicts_with = "require_approval")]
	no_require_approval: bool,
}

// debug-ok: registration arguments redact content; removal carries an ID.
#[derive(Debug, Subcommand)]
enum WorkerCmd {
	/// Mint a new worker cert. Saves the bundle to `--out` (or stdout).
	Register(WorkerRegisterArgs),
	/// Revoke a worker (next mTLS handshake from that cert will 401).
	Rm { id: i64 },
}

// debug-ok: name and output path redact; output mode is a boolean.
#[derive(Debug, Args)]
struct WorkerRegisterArgs {
	#[arg(long, value_parser = config_input::WorkerNameArgument)]
	name: BoundedText<policy::WorkerName, Config>,
	#[arg(long, conflicts_with = "emit_env", value_parser = config_input::PathArgument)]
	out: Option<config_input::ConfiguredPath>,
	/// Print sourceable LOUPE_WORKER_* env assignments instead of JSON.
	#[arg(long, default_value_t = false)]
	emit_env: bool,
}

// debug-ok: job operations contain only numeric IDs and listing limit.
#[derive(Debug, Subcommand)]
enum JobCmd {
	/// List jobs with the newest row printed last.
	List(ListArgs),
	Get {
		id: i64,
	},
	/// Requeue a failed job.
	Retry {
		id: i64,
	},
	/// Cancel queued or leased work.
	Cancel {
		id: i64,
	},
}

// debug-ok: search query redacts; other arguments are numeric IDs/limits/flags.
#[derive(Debug, Subcommand)]
enum FindingCmd {
	/// List recent findings for a repo (recent page, newest row printed last).
	List(FindingListArgs),
	/// FTS5 keyword search over a repo's findings (title, description,
	/// file path). Free-form keywords are sanitized server-side; the
	/// match is "every term must appear" with BM25 ranking. Useful for
	/// "have we seen something like this before?" lookups.
	Search {
		repo_id: i64,
		/// One or more space-separated keywords. Quote the whole
		/// thing if your shell would split on spaces.
		#[arg(value_parser = config_input::SearchArgument)]
		query: BoundedText<config_input::SearchQuery, Config>,
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
	/// Retry external reporting for a confirmed finding.
	RetryReport { id: i64 },
	/// Recover findings that still need verifier work and requeue or
	/// create their verify jobs.
	RetryVerify(RetryVerifyArgs),
	/// Reject a finding parked in `awaiting_approval`. Transitions
	/// it to terminal `dismissed` with the rejection audit trail
	/// stamped (distinct from a verifier-issued dismiss).
	Reject { id: i64 },
}

// debug-ok: listing argument is only an optional numeric limit.
#[derive(Debug, Args)]
struct ListArgs {
	/// Number of rows to return.
	#[arg(short = 'n', long = "limit", value_parser = parse_positive_i64)]
	limit: Option<i64>,
}

// debug-ok: repository listing contains only numeric limit and output flag.
#[derive(Debug, Args)]
struct RepoListArgs {
	/// Number of rows to return.
	#[arg(short = 'n', long = "limit", value_parser = parse_positive_i64)]
	limit: Option<i64>,
	/// Output the raw JSON DTO instead of the tab-separated listing.
	#[arg(long, default_value_t = false)]
	json: bool,
}

// debug-ok: finding listing contains only numeric repository ID and limit.
#[derive(Debug, Args)]
struct FindingListArgs {
	repo_id: i64,
	/// Number of rows to return.
	#[arg(short = 'n', long = "limit", value_parser = parse_positive_i64)]
	limit: Option<i64>,
}

fn parse_positive_i64(raw: &str) -> Result<i64, String> {
	let value = raw.parse::<i64>().map_err(|_| "limit must be an integer".to_owned())?;
	if value <= 0 {
		return Err("limit must be positive".to_owned());
	}
	Ok(value)
}

// debug-ok: retry arguments contain only booleans and numeric ID/limit.
#[derive(Debug, Args)]
struct RetryVerifyArgs {
	/// Return counts without changing findings or jobs.
	#[arg(long, default_value_t = false)]
	dry_run: bool,
	/// Also retry findings whose verifier-produced history contains an
	/// inconclusive verdict. Deadline-reaper inconclusive rows remain
	/// recoverable without this flag.
	#[arg(long, default_value_t = false)]
	include_inconclusive: bool,
	/// Restrict recovery to one repo.
	#[arg(long)]
	repo_id: Option<i64>,
	/// Optional cap on findings processed in one request.
	#[arg(long)]
	limit: Option<i64>,
}

// debug-ok: certificate argument owner redacts names, paths and PEM inputs.
#[derive(Debug, Subcommand)]
enum CertCmd {
	/// Mint a replacement server certificate signed by the existing CA.
	MintServer(CertMintServerArgs),
}

// debug-ok: certificate names, paths and PEM inputs redact; mode is boolean.
#[derive(Debug, Args)]
struct CertMintServerArgs {
	/// DNS name to include in the server certificate SAN. Repeat for
	/// every hostname clients will use.
	#[arg(long = "hostname", required = true, value_parser = config_input::HostnameArgument)]
	hostnames: Vec<BoundedText<config_input::CertificateName, Config>>,
	#[arg(long, default_value = "loupe-server", value_parser = config_input::CommonNameArgument)]
	common_name: config_input::CertificateCommonName,
	#[arg(long, default_value_t = false)]
	emit_env: bool,
	#[arg(long, env = "LOUPE_CA_CERT", value_parser = config_input::PathArgument)]
	ca_cert: Option<config_input::ConfiguredPath>,
	#[arg(long, env = "LOUPE_CA_CERT_PEM", hide_env_values = true, value_parser = config_input::PemArgument)]
	ca_cert_pem: Option<config_input::ConfiguredPem>,
	#[arg(long, env = "LOUPE_CA_CERT_PEM_B64", hide_env_values = true, value_parser = config_input::PemArgument)]
	ca_cert_pem_b64: Option<config_input::ConfiguredPem>,
	#[arg(long, env = "LOUPE_CA_KEY", value_parser = config_input::PathArgument)]
	ca_key: Option<config_input::ConfiguredPath>,
	#[arg(long, env = "LOUPE_CA_KEY_PEM", hide_env_values = true, value_parser = config_input::PemArgument)]
	ca_key_pem: Option<config_input::ConfiguredPem>,
	#[arg(long, env = "LOUPE_CA_KEY_PEM_B64", hide_env_values = true, value_parser = config_input::PemArgument)]
	ca_key_pem_b64: Option<config_input::ConfiguredPem>,
}

#[tokio::main]
async fn main() -> Result<()> {
	run().await.map_err(|error| anyhow::anyhow!("{}", TerminalText(&format!("{error:#}"))))
}

async fn run() -> Result<()> {
	let Cli { conn, cmd } = Cli::parse();
	match cmd {
		Cmd::Repo(c) => match c {
			RepoCmd::Add(a) => {
				let (client, base) = client_and_url(&conn)?;
				repo_add(&client, base, a).await
			},
			RepoCmd::List(args) => {
				let (client, base) = client_and_url(&conn)?;
				repo_list(&client, base, args.limit, args.json).await
			},
			RepoCmd::Rm { id } => {
				let (client, base) = client_and_url(&conn)?;
				repo_rm(&client, base, id).await
			},
			RepoCmd::Update(a) => {
				let (client, base) = client_and_url(&conn)?;
				repo_update(&client, base, a).await
			},
			RepoCmd::RotatePat(a) => {
				let (client, base) = client_and_url(&conn)?;
				repo_rotate_pat(&client, base, a).await
			},
			RepoCmd::SetGithubReporting(a) => {
				let (client, base) = client_and_url(&conn)?;
				repo_set_github_reporting(&client, base, a).await
			},
			RepoCmd::Scan { id, incremental } => {
				let (client, base) = client_and_url(&conn)?;
				repo_scan(&client, base, id, incremental).await
			},
		},
		Cmd::Worker(c) => match c {
			WorkerCmd::Register(a) => {
				let (client, base) = client_and_url(&conn)?;
				worker_register(&client, base, a).await
			},
			WorkerCmd::Rm { id } => {
				let (client, base) = client_and_url(&conn)?;
				worker_rm(&client, base, id).await
			},
		},
		Cmd::Job(c) => match c {
			JobCmd::List(args) => {
				let (client, base) = client_and_url(&conn)?;
				job_list(&client, base, args.limit).await
			},
			JobCmd::Get { id } => {
				let (client, base) = client_and_url(&conn)?;
				job_get(&client, base, id).await
			},
			JobCmd::Retry { id } => {
				let (client, base) = client_and_url(&conn)?;
				job_retry(&client, base, id).await
			},
			JobCmd::Cancel { id } => {
				let (client, base) = client_and_url(&conn)?;
				job_cancel(&client, base, id).await
			},
		},
		Cmd::Finding(c) => match c {
			FindingCmd::List(args) => {
				let (client, base) = client_and_url(&conn)?;
				finding_list(&client, base, args.repo_id, args.limit).await
			},
			FindingCmd::Search { repo_id, query, limit } => {
				let (client, base) = client_and_url(&conn)?;
				finding_search(&client, base, repo_id, &query, limit).await
			},
			FindingCmd::Show { id, json } => {
				let (client, base) = client_and_url(&conn)?;
				finding_show(&client, base, id, json).await
			},
			FindingCmd::Approve { id } => {
				let (client, base) = client_and_url(&conn)?;
				finding_approve(&client, base, id).await
			},
			FindingCmd::RetryReport { id } => {
				let (client, base) = client_and_url(&conn)?;
				finding_retry_report(&client, base, id).await
			},
			FindingCmd::RetryVerify(a) => {
				let (client, base) = client_and_url(&conn)?;
				finding_retry_verify(&client, base, a).await
			},
			FindingCmd::Reject { id } => {
				let (client, base) = client_and_url(&conn)?;
				finding_reject(&client, base, id).await
			},
		},
		Cmd::Cert(c) => match c {
			CertCmd::MintServer(a) => cert_mint_server(a),
		},
		Cmd::GithubApp(c) => match c {
			GithubAppCmd::Set(a) => {
				let (client, base) = client_and_url(&conn)?;
				github_app_set(&client, base, a).await
			},
			GithubAppCmd::Show => {
				let (client, base) = client_and_url(&conn)?;
				github_app_show(&client, base).await
			},
			GithubAppCmd::Clear => {
				let (client, base) = client_and_url(&conn)?;
				github_app_clear(&client, base).await
			},
		},
	}
}

async fn github_app_set(
	client: &reqwest::Client, base: &reqwest::Url, a: GithubAppSetArgs,
) -> Result<()> {
	let private_key_pem = pem_from_env_or_file(
		"GitHub App private key",
		&a.private_key_pem,
		&a.private_key_pem_b64,
		a.private_key_file.as_ref(),
		"GitHub App private key missing — pass --private-key-file or set LOUPE_GITHUB_APP_KEY_PEM / LOUPE_GITHUB_APP_KEY_PEM_B64",
	)?;
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = credential_request::with_body(
		client.put(url(base, "/v1/github-app")?),
		private_key_pem.app_credential_json(a.app_id)?,
	)
	.send()
	.await?;
	ingress::discard(server_response(resp, "configure GitHub App").await?)?;
	println!("github app {} configured", a.app_id);
	Ok(())
}

async fn github_app_show(client: &reqwest::Client, base: &reqwest::Url) -> Result<()> {
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = client.get(url(base, "/v1/github-app")?).send().await?;
	let body: GithubAppResponse<Server> =
		ingress::show_github_app(server_response(resp, "show GitHub App").await?)?;
	match body.app {
		Some(app) => println!("app_id={} slug={}", app.app_id, TerminalText(app.slug.expose())),
		None => println!("no GitHub App configured"),
	}
	Ok(())
}

async fn github_app_clear(client: &reqwest::Client, base: &reqwest::Url) -> Result<()> {
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = client.delete(url(base, "/v1/github-app")?).send().await?;
	ingress::discard(server_response(resp, "clear GitHub App").await?)?;
	println!("github app cleared");
	Ok(())
}

fn client_and_url(c: &ConnArgs) -> Result<(reqwest::Client, &reqwest::Url)> {
	let base = server_url(c)?;
	let client = build_client(c)?;
	Ok((client, base))
}

fn server_url(c: &ConnArgs) -> Result<&reqwest::Url> {
	c.server_url
		.as_ref()
		.map(config_input::ConfiguredUrl::for_request)
		.context("server URL missing — set LOUPE_SERVER_URL or pass --server-url")
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
	let tls = loupe_tls::reqwest_client_config(cert.for_tls(), key.for_tls(), ca.for_tls())?;
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI transport owns the configured mTLS client for the fixed server API"
	)]
	let client = reqwest::Client::builder()
		.use_preconfigured_tls(tls)
		.build()
		.context("building reqwest client");
	client
}

fn pem_from_env_or_file(
	label: &str, pem: &Option<config_input::ConfiguredPem>,
	pem_b64: &Option<config_input::ConfiguredPem>, path: Option<&config_input::ConfiguredPath>,
	missing: &'static str,
) -> Result<config_input::SelectedPem> {
	if let Some(pem) = pem.as_ref().filter(|s| !s.is_empty()) {
		return Ok(pem.selected_raw());
	}
	if let Some(pem_b64) = pem_b64.as_ref().filter(|s| !s.is_empty()) {
		return pem_b64.selected_base64().with_context(|| format!("decoding base64 {label} PEM"));
	}
	let path = path.context(missing)?.for_filesystem();
	config_input::read_pem(path).with_context(|| format!("reading {label} at {}", path.display()))
}

fn url(base: &reqwest::Url, path: &str) -> Result<reqwest::Url> {
	base.join(path).context("building server request URL")
}

fn register_repo_request(a: RepoAddArgs) -> RegisterRepoRequest<Config> {
	let require_approval = match (a.require_approval, a.no_require_approval) {
		(true, false) => Some(true),
		(false, true) => Some(false),
		_ => None,
	};
	let verification_enabled = match (a.verification_enabled, a.no_verification) {
		(true, false) => Some(true),
		(false, true) => Some(false),
		_ => None,
	};
	let reporting = if a.no_reporting {
		ReportingSetup::Manual
	} else {
		#[expect(
			clippy::expect_used,
			reason = "the only production caller passes clap's validated RepoAddArgs, which requires target_owner unless no_reporting is set"
		)]
		let target_owner = a.target_owner.expect("clap enforces target_owner");
		#[expect(
			clippy::expect_used,
			reason = "the only production caller passes clap's validated RepoAddArgs, which requires target_repo unless no_reporting is set"
		)]
		let target_repo = a.target_repo.expect("clap enforces target_repo");
		ReportingSetup::GithubIssue {
			target_owner,
			target_repo,
			github_pat: a.pat.map(config_input::PatInput::into_pat),
		}
	};
	RegisterRepoRequest {
		protocol_version: PROTOCOL_VERSION,
		clone_url: a.clone_url,
		branch: a.branch,
		scan_interval_seconds: a.scan_interval_seconds,
		reporting,
		scanner_config: None,
		verification_enabled,
		require_approval,
	}
}

async fn repo_add(client: &reqwest::Client, base: &reqwest::Url, a: RepoAddArgs) -> Result<()> {
	let req = register_repo_request(a);
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI repository registration sends the guarded Config credential request to the fixed server endpoint"
	)]
	let resp =
		credential_request::with_body(client.post(url(base, "/v1/repos")?), req.credential_json()?)
			.send()
			.await?;
	let body: RegisterRepoResponse =
		ingress::register_repo(server_response(resp, "register repo").await?)?;
	println!("repo_id={}", body.repo_id);
	Ok(())
}

async fn repo_list(
	client: &reqwest::Client, base: &reqwest::Url, limit: Option<i64>, as_json: bool,
) -> Result<()> {
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let req = client.get(url(base, "/v1/repos")?);
	let req = if let Some(limit) = limit { req.query(&[("limit", limit)]) } else { req };
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = req.send().await?;
	let body: ListReposResponse<Server> =
		ingress::list_repos(server_response(resp, "list repos").await?)?;
	if as_json {
		println!("{}", repo_list_json(&body)?);
		return Ok(());
	}
	for r in body.repos {
		let approval = r.require_approval.map_or("inherit".to_owned(), |v| v.to_string());
		let disabled = r.disabled_at.map_or("active".to_owned(), |ts| format!("disabled@{ts}"));
		println!(
			"{:>4}\t{}\t{}/{}\treporting={}\tinterval={:?}\tverify={}\tapproval={}\t{}\tlast_sha={:?}",
			r.id,
			TerminalText(r.host.expose()),
			TerminalText(r.owner.expose()),
			TerminalText(r.repo.expose()),
			TerminalText(&reporting_label(r.reporting.as_ref())),
			r.scan_interval_seconds,
			r.verification_enabled,
			approval,
			disabled,
			r.last_scanned_sha.as_ref().map(|text| text.expose()),
		);
	}
	Ok(())
}

/// The `--json` rendering of `repo list`: the `ListReposResponse` DTO
/// exactly as the server returned it, pretty-printed. Scripts consume
/// this (e.g. with jq) to find PAT-backed GitHub repos, so nothing is
/// added, dropped, or reshaped on the way out.
fn repo_list_json(body: &ListReposResponse<Server>) -> Result<String> {
	Ok(serde_json::to_string_pretty(body)?)
}

/// Compact reporter description for the human listing: which reporter,
/// and for GitHub which credential it files issues with.
fn reporting_label(reporting: Option<&ReportingSummary<Server>>) -> String {
	match reporting {
		Some(ReportingSummary::GithubIssue { target_owner, target_repo, auth }) => {
			let auth = match auth {
				GithubReportingAuth::App => "app",
				GithubReportingAuth::Pat => "pat",
			};
			format!("github({auth})→{}/{}", target_owner.expose(), target_repo.expose())
		},
		Some(ReportingSummary::Email { to, .. }) => {
			format!("email→{}", to.iter().map(|text| text.expose()).collect::<Vec<_>>().join(","))
		},
		Some(ReportingSummary::Manual) => "manual".to_owned(),
		None => "unknown".to_owned(),
	}
}

async fn repo_rm(client: &reqwest::Client, base: &reqwest::Url, id: i64) -> Result<()> {
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = client.delete(url(base, &format!("/v1/repos/{id}"))?).send().await?;
	ingress::discard(server_response(resp, "remove repo").await?)?;
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
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = client.patch(url(base, &format!("/v1/repos/{}", a.id))?).json(&req).send().await?;
	ingress::discard(server_response(resp, "update repo").await?)?;
	Ok(())
}

async fn repo_rotate_pat(
	client: &reqwest::Client, base: &reqwest::Url, a: RepoRotatePatArgs,
) -> Result<()> {
	let req =
		RotateRepoPatRequest { protocol_version: PROTOCOL_VERSION, github_pat: a.pat.into_pat() };
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = credential_request::with_body(
		client.post(url(base, &format!("/v1/repos/{}/reporting/github-pat", a.id))?),
		req.credential_json()?,
	)
	.send()
	.await?;
	ingress::discard(server_response(resp, "rotate repo PAT").await?)?;
	Ok(())
}

async fn repo_set_github_reporting(
	client: &reqwest::Client, base: &reqwest::Url, a: RepoSetGithubReportingArgs,
) -> Result<()> {
	let id = a.id;
	let req = set_reporting_request(a);
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = credential_request::with_body(
		client.put(url(base, &format!("/v1/repos/{id}/reporting/github"))?),
		req.credential_json()?,
	)
	.send()
	.await?;
	ingress::discard(server_response(resp, "set GitHub reporting").await?)?;
	Ok(())
}

fn set_reporting_request(a: RepoSetGithubReportingArgs) -> SetRepoGithubReportingRequest<Config> {
	SetRepoGithubReportingRequest {
		protocol_version: PROTOCOL_VERSION,
		target_owner: a.target_owner,
		target_repo: a.target_repo,
		github_pat: a.pat.map(config_input::PatInput::into_pat),
	}
}

async fn repo_scan(
	client: &reqwest::Client, base: &reqwest::Url, id: i64, incremental: bool,
) -> Result<()> {
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = client
		.post(url(base, &format!("/v1/repos/{id}/scan"))?)
		.json(&ScanRequest { protocol_version: PROTOCOL_VERSION, incremental })
		.send()
		.await?;
	let body: ScanResponse = ingress::scan_repo(server_response(resp, "scan").await?)?;
	println!("job_id={}", body.job_id);
	Ok(())
}

fn register_worker_request(
	name: BoundedText<policy::WorkerName, Config>,
) -> RegisterWorkerRequest<Config> {
	RegisterWorkerRequest { protocol_version: PROTOCOL_VERSION, name }
}

async fn worker_register(
	client: &reqwest::Client, base: &reqwest::Url, a: WorkerRegisterArgs,
) -> Result<()> {
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = client
		.post(url(base, "/v1/workers")?)
		.json(&register_worker_request(a.name))
		.send()
		.await?;
	let bundle: RegisterWorkerResponse =
		ingress::register_worker_bundle(server_response(resp, "register worker").await?)?;
	if a.emit_env {
		for (name, value) in worker_env_assignments(base, &bundle)? {
			println!("{name}={}", value.expose());
		}
		return Ok(());
	}
	let serialised = bundle.credential_json_pretty()?;
	if let Some(path) = a.out {
		write_secret_file(path.for_filesystem(), serialised.expose())?;
		println!(
			"worker_id={} bundle written to {}",
			bundle.worker_id,
			TerminalText(&path.for_filesystem().to_string_lossy())
		);
	} else {
		print_credential_json(serialised.expose())?;
	}
	Ok(())
}

/// Persist secret material without exposing it to group/other users.
///
/// The worker registration bundle includes an mTLS private key, so we
/// create it atomically with owner-only permissions and refuse to
/// overwrite an existing path that may already have weaker permissions.
fn write_secret_file(path: &Path, contents: &[u8]) -> Result<()> {
	use std::io::Write;

	let mut options = std::fs::OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.mode(0o600);
	}

	#[allow(
		clippy::disallowed_methods,
		reason = "CLI credential export creates the operator-selected file exclusively with restrictive creation mode"
	)]
	let mut file =
		options.open(path).with_context(|| format!("creating secret file {}", path.display()))?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		#[allow(
			clippy::disallowed_methods,
			reason = "CLI credential export enforces owner-only permissions on the newly created file"
		)]
		file.set_permissions(std::fs::Permissions::from_mode(0o600))
			.with_context(|| format!("setting permissions on {}", path.display()))?;
	}
	file.write_all(contents).with_context(|| format!("writing secret file {}", path.display()))?;
	Ok(())
}

fn worker_env_assignments(
	base: &reqwest::Url, bundle: &RegisterWorkerResponse,
) -> Result<Vec<(&'static str, loupe_provenance::Secret<String>)>> {
	Ok(vec![
		("LOUPE_SERVER_URL", loupe_provenance::Secret::new(base.as_str().to_owned())),
		(
			"LOUPE_WORKER_CA_CERT_PEM_B64",
			loupe_tls::encode_pem_base64(bundle.ca_cert_pem.expose())?,
		),
		("LOUPE_WORKER_CERT_PEM_B64", loupe_tls::encode_pem_base64(&bundle.client_cert_pem)?),
		("LOUPE_WORKER_KEY_PEM_B64", loupe_tls::encode_pem_base64(bundle.client_key_pem.expose())?),
	])
}

fn cert_mint_server(a: CertMintServerArgs) -> Result<()> {
	let bundle = mint_server_cert(&a)?;
	if a.emit_env {
		for (name, value) in server_cert_env_assignments(&bundle)? {
			println!("{name}={}", value.expose());
		}
		return Ok(());
	}

	let json = loupe_proto::server_certificate_json_pretty(&bundle.cert_pem, &bundle.key_pem)?;
	print_credential_json(json.expose())?;
	Ok(())
}

fn print_credential_json(bytes: &[u8]) -> Result<()> {
	use std::io::Write;
	let mut stdout = std::io::stdout().lock();
	stdout.write_all(bytes)?;
	stdout.write_all(b"\n")?;
	Ok(())
}

fn mint_server_cert(a: &CertMintServerArgs) -> Result<loupe_tls::CertBundle> {
	let ca_cert = pem_from_env_or_file(
		"CA cert",
		&a.ca_cert_pem,
		&a.ca_cert_pem_b64,
		a.ca_cert.as_ref(),
		"CA cert missing — set LOUPE_CA_CERT_PEM, LOUPE_CA_CERT_PEM_B64, or LOUPE_CA_CERT",
	)?;
	let ca_key = pem_from_env_or_file(
		"CA key",
		&a.ca_key_pem,
		&a.ca_key_pem_b64,
		a.ca_key.as_ref(),
		"CA key missing — set LOUPE_CA_KEY_PEM, LOUPE_CA_KEY_PEM_B64, or LOUPE_CA_KEY",
	)?;
	let ca = loupe_tls::Ca::from_pem(ca_cert.for_tls(), ca_key.for_tls())?;
	ca.mint_server(
		a.common_name.for_certificate(),
		&a.hostnames.iter().map(|name| name.expose().to_owned()).collect::<Vec<_>>(),
	)
}

fn server_cert_env_assignments(
	bundle: &loupe_tls::CertBundle,
) -> Result<Vec<(&'static str, loupe_provenance::Secret<String>)>> {
	Ok(vec![
		("LOUPE_SERVER_CERT_PEM_B64", loupe_tls::encode_pem_base64(&bundle.cert_pem)?),
		("LOUPE_SERVER_KEY_PEM_B64", loupe_tls::encode_pem_base64(bundle.key_pem.expose())?),
	])
}

async fn worker_rm(client: &reqwest::Client, base: &reqwest::Url, id: i64) -> Result<()> {
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = client.delete(url(base, &format!("/v1/workers/{id}"))?).send().await?;
	ingress::discard(server_response(resp, "remove worker").await?)?;
	Ok(())
}

async fn job_list(client: &reqwest::Client, base: &reqwest::Url, limit: Option<i64>) -> Result<()> {
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let req = client.get(url(base, "/v1/jobs")?);
	let req = if let Some(limit) = limit { req.query(&[("limit", limit)]) } else { req };
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = req.send().await?;
	let jobs: Vec<JobInfo<Server>> = ingress::list_jobs(server_response(resp, "list jobs").await?)?;
	for j in jobs.into_iter().rev() {
		println!(
			"{:>4}\trepo={}\tkind={}\tstate={:?}\tattempts={}\thead={:?}",
			j.job_id,
			j.repo_id,
			render::job_kind(&j.kind),
			j.state,
			j.attempts,
			j.head_sha.as_ref().map(|text| text.expose()),
		);
	}
	Ok(())
}

async fn job_get(client: &reqwest::Client, base: &reqwest::Url, id: i64) -> Result<()> {
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = client.get(url(base, &format!("/v1/jobs/{id}"))?).send().await?;
	let job: JobInfo<Server> = ingress::get_job(server_response(resp, "get job").await?)?;
	println!("{}", serde_json::to_string_pretty(&job)?);
	Ok(())
}

async fn job_retry(client: &reqwest::Client, base: &reqwest::Url, id: i64) -> Result<()> {
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = client.post(url(base, &format!("/v1/jobs/{id}/retry"))?).send().await?;
	let job: JobInfo<Server> = ingress::retry_job(server_response(resp, "retry job").await?)?;
	println!("job_id={} state={:?} attempts={}", job.job_id, job.state, job.attempts);
	Ok(())
}

async fn job_cancel(client: &reqwest::Client, base: &reqwest::Url, id: i64) -> Result<()> {
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = client.post(url(base, &format!("/v1/jobs/{id}/cancel"))?).send().await?;
	let job: JobInfo<Server> = ingress::cancel_job(server_response(resp, "cancel job").await?)?;
	println!("job_id={} state={:?} attempts={}", job.job_id, job.state, job.attempts);
	Ok(())
}

async fn finding_list(
	client: &reqwest::Client, base: &reqwest::Url, repo_id: i64, limit: Option<i64>,
) -> Result<()> {
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let req = client.get(url(base, &format!("/v1/repos/{repo_id}/findings"))?);
	let req = if let Some(limit) = limit { req.query(&[("limit", limit)]) } else { req };
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = req.send().await?;
	let body: ListFindingsResponse<Agent, Server> =
		ingress::list_findings(server_response(resp, "list findings").await?)?;
	for f in body.findings.into_iter().rev() {
		println!("{}", render::finding_list_row(&f));
	}
	Ok(())
}

async fn finding_search(
	client: &reqwest::Client, base: &reqwest::Url, repo_id: i64,
	query: &BoundedText<config_input::SearchQuery, Config>, limit: i64,
) -> Result<()> {
	let url = url(base, &format!("/v1/repos/{repo_id}/findings/search"))?;
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = client
		.get(url)
		.query(&[("q", query.expose()), ("limit", &limit.to_string())])
		.send()
		.await?;
	let body: ListFindingsResponse<Agent, Server> =
		ingress::search_findings(server_response(resp, "search findings").await?)?;
	if body.findings.is_empty() {
		println!("(no matches)");
		return Ok(());
	}
	for f in body.findings {
		println!("{}", render::finding_search_row(&f));
	}
	Ok(())
}

async fn finding_show(
	client: &reqwest::Client, base: &reqwest::Url, id: i64, as_json: bool,
) -> Result<()> {
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = client.get(url(base, &format!("/v1/findings/{id}"))?).send().await?;
	let detail: FindingDetail<Agent, Server> =
		ingress::get_finding(server_response(resp, "get finding").await?)?;
	if as_json {
		println!("{}", serde_json::to_string_pretty(&detail)?);
	} else {
		print!("{}", render::finding(&detail, render::Style::detect()));
	}
	Ok(())
}

async fn finding_approve(client: &reqwest::Client, base: &reqwest::Url, id: i64) -> Result<()> {
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = client.post(url(base, &format!("/v1/findings/{id}/approve"))?).send().await?;
	ingress::discard(server_response(resp, "approve finding").await?)?;
	Ok(())
}

async fn finding_retry_report(
	client: &reqwest::Client, base: &reqwest::Url, id: i64,
) -> Result<()> {
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = client.post(url(base, &format!("/v1/findings/{id}/retry-report"))?).send().await?;
	ingress::discard(server_response(resp, "retry report").await?)?;
	Ok(())
}

async fn finding_retry_verify(
	client: &reqwest::Client, base: &reqwest::Url, args: RetryVerifyArgs,
) -> Result<()> {
	let req = RetryVerifyRequest {
		protocol_version: PROTOCOL_VERSION,
		dry_run: args.dry_run,
		include_inconclusive: args.include_inconclusive,
		repo_id: args.repo_id,
		limit: args.limit,
	};
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = client.post(url(base, "/v1/findings/retry-verify")?).json(&req).send().await?;
	let body: RetryVerifyResponse =
		ingress::retry_verification(server_response(resp, "retry verify").await?)?;
	let label = if body.dry_run { "would_revive" } else { "revived" };
	println!(
		"dry_run={} matched={} {}={} requeued_jobs={} created_jobs={} left_queued_or_leased={}",
		body.dry_run,
		body.matched,
		label,
		body.revived,
		body.requeued_jobs,
		body.created_jobs,
		body.left_queued_or_leased,
	);
	Ok(())
}

async fn finding_reject(client: &reqwest::Client, base: &reqwest::Url, id: i64) -> Result<()> {
	#[allow(
		clippy::disallowed_methods,
		reason = "CLI API egress uses the configured server and the operation-specific endpoint and admitted request fields"
	)]
	let resp = client.post(url(base, &format!("/v1/findings/{id}/reject"))?).send().await?;
	ingress::discard(server_response(resp, "reject finding").await?)?;
	Ok(())
}

/// Bound successful and error bodies before decoding or displaying them.
async fn server_response(
	resp: reqwest::Response, action: &'static str,
) -> Result<loupe_provenance::Untrusted<bytes::Bytes, loupe_provenance::Server>> {
	ingress::receive(resp, action).await
}

#[cfg(test)]
mod ingress_tests;
#[cfg(test)]
mod response_tests;

#[cfg(test)]
mod config_fixtures {
	use clap::builder::TypedValueParser;

	use super::config_input::{ConfiguredPath, ConfiguredPem, PathArgument, PemArgument};

	pub(super) fn pem(raw: &str) -> ConfiguredPem {
		PemArgument.parse_ref(&clap::Command::new("test"), None, std::ffi::OsStr::new(raw)).unwrap()
	}

	pub(super) fn path(raw: &std::path::Path) -> ConfiguredPath {
		PathArgument.parse_ref(&clap::Command::new("test"), None, raw.as_os_str()).unwrap()
	}
}

#[cfg(test)]
#[path = "../tests/support/legacy_responses.rs"]
mod legacy_responses;

#[cfg(test)]
mod tests {
	use std::path::PathBuf;

	use base64::Engine as _;

	use super::legacy_responses::{
		GithubReportingAuth, ListReposResponse, RepoSummary, ReportingSummary,
	};
	use super::{config_fixtures, *};

	#[tokio::test]
	async fn non_base_server_url_returns_a_request_error() {
		let cli = Cli::try_parse_from([
			"loupectl",
			"--server-url",
			"mailto:untrusted-url-sentinel@example.test",
			"github-app",
			"show",
		])
		.unwrap();
		let base = cli.conn.server_url.as_ref().unwrap().for_request();
		let error = github_app_show(&reqwest::Client::new(), base).await.unwrap_err();
		assert_eq!(
			error.to_string(),
			"building server request URL",
			"invalid base must fail without a panic"
		);
	}

	#[test]
	fn selected_pem_retains_config_until_concrete_operation() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("selected-key.pem");
		let text = "FAKE_SELECTED_CONFIG_KEY\n\"exact\\bytes";
		std::fs::write(&path, text).unwrap();
		let file: config_input::SelectedPem = config_input::read_pem(&path).unwrap();
		let configured_path = config_fixtures::path(&path);
		let raw = Some(config_fixtures::pem(text));
		let b64 =
			Some(config_fixtures::pem(&base64::engine::general_purpose::STANDARD.encode(text)));
		for (raw, b64, path) in
			[(&raw, &None, None), (&None, &b64, None), (&None, &None, Some(&configured_path))]
		{
			let selected: config_input::SelectedPem =
				pem_from_env_or_file("key", raw, b64, path, "missing").unwrap();
			assert_eq!(selected.for_tls(), text);
			let wire = selected.app_credential_json(73).unwrap();
			let json: serde_json::Value = serde_json::from_slice(wire.expose()).unwrap();
			assert_eq!(json["app_id"], 73);
			assert_eq!(json["private_key_pem"], text);
			assert_eq!(json["protocol_version"], PROTOCOL_VERSION);
		}
		assert_eq!(file.for_tls(), text);
	}

	#[test]
	fn pem_b64_env_wins_over_file_path() {
		let file = std::env::temp_dir().join("loupectl-test-path-that-should-not-be-read.pem");
		let pem = "-----BEGIN CERTIFICATE-----\nfrom-env\n-----END CERTIFICATE-----\n";
		let pem_b64 = config_fixtures::pem(&base64::Engine::encode(
			&base64::engine::general_purpose::STANDARD,
			pem,
		));
		let file = config_fixtures::path(&file);

		let got =
			pem_from_env_or_file("CA cert", &None, &Some(pem_b64), Some(&file), "missing").unwrap();
		assert_eq!(got.for_tls(), pem);
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

	#[cfg(unix)]
	fn unique_temp_dir(prefix: &str) -> PathBuf {
		let suffix =
			std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
		let dir = std::env::temp_dir().join(format!("{prefix}-{}-{suffix}", std::process::id()));
		std::fs::create_dir(&dir).unwrap();
		dir
	}

	#[cfg(unix)]
	#[test]
	fn worker_bundle_file_is_owner_only() {
		use std::os::unix::fs::PermissionsExt;

		let dir = unique_temp_dir("loupectl-worker-bundle-perms");
		let path = dir.join("worker.json");

		write_secret_file(&path, b"{\"client_key_pem\":\"PRIVATE KEY\"}").unwrap();

		let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
		std::fs::remove_dir_all(&dir).unwrap();

		assert_eq!(
			mode, 0o600,
			"worker bundle persisted by --out must be owner-only, got mode {mode:o}",
		);
	}

	#[test]
	fn secret_file_refuses_to_overwrite_existing_path() {
		let suffix =
			std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
		let dir = std::env::temp_dir()
			.join(format!("loupectl-worker-bundle-overwrite-{}-{suffix}", std::process::id()));
		std::fs::create_dir(&dir).unwrap();
		let path = dir.join("worker.json");
		std::fs::write(&path, b"existing").unwrap();

		let err = write_secret_file(&path, b"replacement").expect_err("existing path is refused");
		let contents = std::fs::read(&path).unwrap();
		std::fs::remove_dir_all(&dir).unwrap();

		assert!(err.to_string().contains("creating secret file"), "unexpected error: {err}");
		assert_eq!(contents, b"existing");
	}

	#[test]
	fn repo_rotate_pat_parses_explicit_pat() {
		let cli = Cli::try_parse_from([
			"loupectl",
			"--server-url",
			"https://loupe.example:8443",
			"repo",
			"rotate-pat",
			"7",
			"--pat",
			"ghp_replacement",
		])
		.unwrap();
		let Cmd::Repo(RepoCmd::RotatePat(args)) = cli.cmd else {
			panic!("expected repo rotate-pat command");
		};
		assert_eq!(args.id, 7);
		assert_eq!(args.pat.expose(), "ghp_replacement");
	}

	#[test]
	fn repo_add_inherits_verification_default_unless_pinned() {
		let base = [
			"loupectl",
			"--server-url",
			"https://loupe.example:8443",
			"repo",
			"add",
			"--clone-url",
			"https://github.com/acme/widget.git",
			"--no-reporting",
		];

		let cli = Cli::try_parse_from(base).unwrap();
		let Cmd::Repo(RepoCmd::Add(args)) = cli.cmd else {
			panic!("expected repo add command");
		};
		assert!(!args.verification_enabled);
		assert!(!args.no_verification);

		let mut with_verify = base.to_vec();
		with_verify.push("--verification-enabled");
		let cli = Cli::try_parse_from(with_verify).unwrap();
		let Cmd::Repo(RepoCmd::Add(args)) = cli.cmd else {
			panic!("expected repo add command");
		};
		assert!(args.verification_enabled);
		assert!(!args.no_verification);

		let mut without_verify = base.to_vec();
		without_verify.push("--no-verification");
		let cli = Cli::try_parse_from(without_verify).unwrap();
		let Cmd::Repo(RepoCmd::Add(args)) = cli.cmd else {
			panic!("expected repo add command");
		};
		assert!(!args.verification_enabled);
		assert!(args.no_verification);
	}

	#[test]
	fn repo_set_github_reporting_parses_explicit_pat() {
		let cli = Cli::try_parse_from([
			"loupectl",
			"--server-url",
			"https://loupe.example:8443",
			"repo",
			"set-github-reporting",
			"7",
			"--target-owner",
			"acme",
			"--target-repo",
			"tracker",
			"--pat",
			"ghp_replacement",
		])
		.unwrap();
		let Cmd::Repo(RepoCmd::SetGithubReporting(args)) = cli.cmd else {
			panic!("expected repo set-github-reporting command");
		};
		assert_eq!(args.id, 7);
		assert_eq!(args.target_owner.expose(), "acme");
		assert_eq!(args.target_repo.expose(), "tracker");
		assert_eq!(args.pat.as_ref().map(config_input::PatInput::expose), Some("ghp_replacement"));
	}

	#[test]
	fn repo_set_github_reporting_without_a_pat_selects_the_app() {
		let cli = Cli::try_parse_from([
			"loupectl",
			"--server-url",
			"https://loupe.example:8443",
			"repo",
			"set-github-reporting",
			"7",
			"--target-owner",
			"acme",
			"--target-repo",
			"tracker",
		])
		.unwrap();
		let Cmd::Repo(RepoCmd::SetGithubReporting(args)) = cli.cmd else {
			panic!("expected repo set-github-reporting command");
		};
		assert!(args.pat.is_none(), "no --pat means GitHub App mode");
	}

	#[test]
	fn repo_add_without_a_pat_selects_the_app() {
		let cli = Cli::try_parse_from([
			"loupectl",
			"--server-url",
			"https://loupe.example:8443",
			"repo",
			"add",
			"--clone-url",
			"https://github.com/acme/widget.git",
			"--target-owner",
			"acme",
			"--target-repo",
			"tracker",
		])
		.unwrap();
		let Cmd::Repo(RepoCmd::Add(args)) = cli.cmd else {
			panic!("expected repo add command");
		};
		assert_eq!(args.target_owner.as_ref().map(|value| value.expose()), Some("acme"));
		assert!(args.pat.is_none(), "no --pat means GitHub App mode");
		assert!(!args.no_reporting);
	}

	#[test]
	fn finding_retry_report_parses() {
		let cli = Cli::try_parse_from([
			"loupectl",
			"--server-url",
			"https://loupe.example:8443",
			"finding",
			"retry-report",
			"11",
		])
		.unwrap();
		let Cmd::Finding(FindingCmd::RetryReport { id }) = cli.cmd else {
			panic!("expected finding retry-report command");
		};
		assert_eq!(id, 11);
	}

	#[test]
	fn list_limits_parse() {
		let cli = Cli::try_parse_from([
			"loupectl",
			"--server-url",
			"https://loupe.example:8443",
			"repo",
			"list",
			"-n",
			"25",
		])
		.unwrap();
		let Cmd::Repo(RepoCmd::List(args)) = cli.cmd else {
			panic!("expected repo list command");
		};
		assert_eq!(args.limit, Some(25));

		let cli = Cli::try_parse_from([
			"loupectl",
			"--server-url",
			"https://loupe.example:8443",
			"job",
			"list",
			"-n",
			"25",
		])
		.unwrap();
		let Cmd::Job(JobCmd::List(args)) = cli.cmd else {
			panic!("expected job list command");
		};
		assert_eq!(args.limit, Some(25));

		let cli = Cli::try_parse_from([
			"loupectl",
			"--server-url",
			"https://loupe.example:8443",
			"finding",
			"list",
			"7",
			"-n",
			"250",
		])
		.unwrap();
		let Cmd::Finding(FindingCmd::List(args)) = cli.cmd else {
			panic!("expected finding list command");
		};
		assert_eq!(args.repo_id, 7);
		assert_eq!(args.limit, Some(250));
	}

	#[test]
	fn list_limits_must_be_positive() {
		let err = Cli::try_parse_from([
			"loupectl",
			"--server-url",
			"https://loupe.example:8443",
			"finding",
			"list",
			"7",
			"-n",
			"0",
		])
		.expect_err("zero limit must be rejected");
		assert!(err.to_string().contains("limit must be positive"));
	}

	#[test]
	fn finding_retry_verify_parses() {
		let cli = Cli::try_parse_from([
			"loupectl",
			"--server-url",
			"https://loupe.example:8443",
			"finding",
			"retry-verify",
			"--dry-run",
			"--include-inconclusive",
			"--repo-id",
			"7",
			"--limit",
			"50",
		])
		.unwrap();
		let Cmd::Finding(FindingCmd::RetryVerify(args)) = cli.cmd else {
			panic!("expected finding retry-verify command");
		};
		assert!(args.dry_run);
		assert!(args.include_inconclusive);
		assert_eq!(args.repo_id, Some(7));
		assert_eq!(args.limit, Some(50));
	}

	#[test]
	fn job_retry_parses() {
		let cli = Cli::try_parse_from([
			"loupectl",
			"--server-url",
			"https://loupe.example:8443",
			"job",
			"retry",
			"33",
		])
		.unwrap();
		let Cmd::Job(JobCmd::Retry { id }) = cli.cmd else {
			panic!("expected job retry command");
		};
		assert_eq!(id, 33);
	}

	#[test]
	fn job_cancel_parses() {
		let cli = Cli::try_parse_from([
			"loupectl",
			"--server-url",
			"https://loupe.example:8443",
			"job",
			"cancel",
			"34",
		])
		.unwrap();
		let Cmd::Job(JobCmd::Cancel { id }) = cli.cmd else {
			panic!("expected job cancel command");
		};
		assert_eq!(id, 34);
	}

	#[test]
	fn cert_mint_server_parses_without_server_url() {
		let cli = Cli::try_parse_from([
			"loupectl",
			"cert",
			"mint-server",
			"--hostname",
			"loupe.example.com",
			"--ca-cert-pem",
			"ca-cert",
			"--ca-key-pem",
			"ca-key",
		])
		.unwrap();
		let Cmd::Cert(CertCmd::MintServer(args)) = cli.cmd else {
			panic!("expected cert mint-server command");
		};
		assert_eq!(
			args.hostnames.iter().map(|name| name.expose()).collect::<Vec<_>>(),
			vec!["loupe.example.com"]
		);
		assert!(cli.conn.server_url.is_none());
	}

	#[test]
	fn cert_mint_server_uses_existing_ca() {
		let ca = loupe_tls::Ca::new("loupe-test-ca").unwrap();
		let cert_argument = format!("--ca-cert-pem={}", ca.cert_pem());
		let key_argument = format!("--ca-key-pem={}", ca.key_pem().expose());
		let cli = Cli::try_parse_from([
			"loupectl",
			"cert",
			"mint-server",
			"--hostname",
			"loupe.example.com",
			"--hostname",
			"loupe.internal",
			"--emit-env",
			&cert_argument,
			&key_argument,
		])
		.unwrap();
		let Cmd::Cert(CertCmd::MintServer(args)) = cli.cmd else {
			panic!("expected cert mint-server")
		};
		assert_eq!(
			args.hostnames.iter().map(|name| name.expose()).collect::<Vec<_>>(),
			vec!["loupe.example.com", "loupe.internal"]
		);
		assert_eq!(args.common_name.for_certificate(), "loupe-server");

		let bundle = mint_server_cert(&args).unwrap();
		assert!(bundle.cert_pem.contains("BEGIN CERTIFICATE"));
		assert!(bundle.key_pem.expose().contains("PRIVATE KEY"));
	}

	#[test]
	fn server_cert_env_assignments_are_single_line_and_decode_to_bundle() {
		let bundle = loupe_tls::CertBundle {
			cert_pem: "server\ncert\n".into(),
			key_pem: loupe_provenance::Secret::new("server\nkey\n".into()),
		};

		let assignments = server_cert_env_assignments(&bundle).unwrap();
		let names: Vec<_> = assignments.iter().map(|(name, _)| *name).collect();
		assert_eq!(names, vec!["LOUPE_SERVER_CERT_PEM_B64", "LOUPE_SERVER_KEY_PEM_B64"]);
		for (name, value) in &assignments {
			assert!(!value.expose().is_empty(), "{name} value must be present");
			assert!(!value.expose().contains('\n'), "{name} value must fit dotenv/env-file syntax");
		}

		use base64::Engine as _;
		let decoded_cert =
			base64::engine::general_purpose::STANDARD.decode(assignments[0].1.expose()).unwrap();
		assert_eq!(String::from_utf8(decoded_cert).unwrap(), bundle.cert_pem);
		let decoded_key =
			base64::engine::general_purpose::STANDARD.decode(assignments[1].1.expose()).unwrap();
		assert_eq!(String::from_utf8(decoded_key).unwrap().as_str(), bundle.key_pem.expose());
	}

	#[test]
	fn worker_env_assignments_are_single_line_and_decode_to_bundle() {
		let base = reqwest::Url::parse("https://loupe.example:8443/").unwrap();
		let bundle = RegisterWorkerResponse {
			protocol_version: PROTOCOL_VERSION,
			worker_id: 42,
			ca_cert_pem: loupe_provenance::Secret::new("ca\ncert\n".into()),
			client_cert_pem: "worker\ncert\n".into(),
			client_key_pem: loupe_provenance::Secret::new("worker\nkey\n".into()),
		};

		let assignments = worker_env_assignments(&base, &bundle).unwrap();
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
			assert!(!value.expose().is_empty(), "{name} value must be present");
			assert!(!value.expose().contains('\n'), "{name} value must fit dotenv/env-file syntax");
		}

		use base64::Engine as _;
		let decoded_ca =
			base64::engine::general_purpose::STANDARD.decode(assignments[1].1.expose()).unwrap();
		assert_eq!(String::from_utf8(decoded_ca).unwrap().as_str(), bundle.ca_cert_pem.expose());
		for ((_, encoded), expected) in assignments
			.iter()
			.skip(2)
			.zip([&bundle.client_cert_pem, bundle.client_key_pem.expose()])
		{
			let decoded =
				base64::engine::general_purpose::STANDARD.decode(encoded.expose()).unwrap();
			assert_eq!(
				decoded,
				expected.as_bytes(),
				"every exported worker PEM must retain its bytes"
			);
		}
	}

	#[test]
	fn repo_list_parses_json_with_limit() {
		let cli = Cli::try_parse_from([
			"loupectl",
			"--server-url",
			"https://loupe.example:8443",
			"repo",
			"list",
			"--json",
			"--limit",
			"5",
		])
		.unwrap();
		let Cmd::Repo(RepoCmd::List(args)) = cli.cmd else {
			panic!("expected repo list command");
		};
		assert!(args.json);
		assert_eq!(args.limit, Some(5));
	}

	#[tokio::test]
	async fn repo_list_json_is_the_raw_dto() {
		let body = ListReposResponse {
			protocol_version: PROTOCOL_VERSION,
			repos: vec![
				RepoSummary {
					id: 1,
					clone_url: "https://github.com/acme/widget.git".into(),
					host: "github.com".into(),
					owner: "acme".into(),
					repo: "widget".into(),
					default_branch: Some("main".into()),
					scan_interval_seconds: Some(3600),
					disabled_at: None,
					verification_enabled: true,
					require_approval: None,
					last_scanned_sha: None,
					last_scanned_at: None,
					created_at: 1_700_000_000,
					reporting: Some(ReportingSummary::GithubIssue {
						target_owner: "acme".into(),
						target_repo: "tracker".into(),
						auth: GithubReportingAuth::App,
					}),
				},
				RepoSummary {
					id: 2,
					clone_url: "https://github.com/acme/gadget.git".into(),
					host: "github.com".into(),
					owner: "acme".into(),
					repo: "gadget".into(),
					default_branch: None,
					scan_interval_seconds: None,
					disabled_at: Some(1_700_000_500),
					verification_enabled: false,
					require_approval: Some(true),
					last_scanned_sha: Some("abc123".into()),
					last_scanned_at: Some(1_700_000_400),
					created_at: 1_700_000_001,
					reporting: Some(ReportingSummary::GithubIssue {
						target_owner: "acme".into(),
						target_repo: "tracker".into(),
						auth: GithubReportingAuth::Pat,
					}),
				},
			],
		};

		let original = serde_json::to_vec(&body).unwrap();
		let admitted =
			ingress::list_repos(ingress::test_support::received(&original).await).unwrap();
		let rendered = repo_list_json(&admitted).unwrap();

		let parsed: ListReposResponse = serde_json::from_str(&rendered).unwrap();
		assert_eq!(parsed, body, "JSON output must round-trip to the identical DTO");
		assert!(rendered.contains("\"auth\": \"app\""), "missing app auth marker in:\n{rendered}");
		assert!(rendered.contains("\"auth\": \"pat\""), "missing pat auth marker in:\n{rendered}");
		assert!(rendered.contains("\"kind\": \"github_issue\""), "missing kind in:\n{rendered}");
	}
}

#[cfg(test)]
mod tls_consumer_tests {
	use base64::Engine as _;

	use super::{config_fixtures, *};

	#[test]
	fn tls_consumer_cli_options_debug_redacts_raw_and_encoded_tls_inputs() {
		let sentinel = "FAKE_CLI_TLS_OPTION";
		let encoded = base64::engine::general_purpose::STANDARD.encode(sentinel);
		let mut leaks = Vec::new();
		for flag in [
			"--ca-cert-pem",
			"--admin-cert-pem",
			"--admin-key-pem",
			"--ca-cert-pem-b64",
			"--admin-cert-pem-b64",
			"--admin-key-pem-b64",
		] {
			let value = if flag.ends_with("-b64") { &encoded } else { sentinel };
			let cli = Cli::try_parse_from(["loupectl", flag, value, "repo", "list"]).unwrap();
			if [format!("{cli:?}"), format!("{cli:#?}")].iter().any(|text| text.contains(value)) {
				leaks.push(flag);
			}
		}
		for flag in ["--ca-cert-pem", "--ca-key-pem", "--ca-cert-pem-b64", "--ca-key-pem-b64"] {
			let value = if flag.ends_with("-b64") { &encoded } else { sentinel };
			let cli = Cli::try_parse_from([
				"loupectl",
				"cert",
				"mint-server",
				"--hostname",
				"localhost",
				flag,
				value,
			])
			.unwrap();
			if [format!("{cli:?}"), format!("{cli:#?}")].iter().any(|text| text.contains(value)) {
				leaks.push(flag);
			}
		}
		assert!(leaks.is_empty(), "CLI option Debug disclosed inputs at {leaks:?}");
	}

	#[test]
	fn tls_consumer_cli_loaded_pem_is_redacted() {
		let value = pem_from_env_or_file(
			"key",
			&Some(config_fixtures::pem("FAKE_LOADED_CLI_TLS")),
			&None,
			None,
			"missing",
		)
		.unwrap();
		for rendered in
			[format!("{value:?}"), format!("{value:#?}"), format!("{value}"), format!("{value:#}")]
		{
			assert_eq!(rendered, "[redacted]", "loaded TLS owner must redact every formatter");
		}
	}

	#[test]
	fn tls_consumer_cli_invalid_utf8_error_does_not_retain_private_bytes() {
		let bytes = b"FAKE_INVALID_CLI_TLS\xff";
		let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
		let error = pem_from_env_or_file(
			"key",
			&None,
			&Some(config_fixtures::pem(&encoded)),
			None,
			"missing",
		)
		.unwrap_err();
		let rendered: String = format!("{error:#?}").split_whitespace().collect();
		let reflected: String = format!("bytes:{bytes:?}").split_whitespace().collect();
		assert!(!rendered.contains(&reflected), "invalid UTF-8 error retained private input bytes");
	}

	#[test]
	fn cli_tls_loader_preserves_precedence_empty_fallback_and_errors() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("tls-input");
		std::fs::write(&path, "FILE_TLS").unwrap();
		let configured_path = config_fixtures::path(&path);
		let encoded = base64::engine::general_purpose::STANDARD.encode("B64_TLS");
		assert_eq!(
			pem_from_env_or_file(
				"key",
				&Some(config_fixtures::pem("RAW_TLS")),
				&Some(config_fixtures::pem("invalid%%%")),
				Some(&configured_path),
				"missing"
			)
			.unwrap()
			.for_tls(),
			"RAW_TLS"
		);
		assert_eq!(
			pem_from_env_or_file(
				"key",
				&Some(config_fixtures::pem("")),
				&Some(config_fixtures::pem(&format!(" \n{encoded}\n "))),
				Some(&configured_path),
				"missing"
			)
			.unwrap()
			.for_tls(),
			"B64_TLS"
		);
		assert_eq!(
			pem_from_env_or_file(
				"key",
				&Some(config_fixtures::pem("")),
				&Some(config_fixtures::pem("")),
				Some(&configured_path),
				"missing"
			)
			.unwrap()
			.for_tls(),
			"FILE_TLS"
		);
		assert!(pem_from_env_or_file(
			"key",
			&None,
			&Some(config_fixtures::pem("invalid%%%")),
			Some(&configured_path),
			"missing"
		)
		.is_err());
		std::fs::write(&path, b"invalid\xff").unwrap();
		assert!(
			pem_from_env_or_file("key", &None, &None, Some(&configured_path), "missing").is_err()
		);
		assert!(pem_from_env_or_file("key", &None, &None, None, "missing").is_err());
	}
}

#[cfg(test)]
mod tls_constructor_controls {
	use std::sync::Arc;
	use std::time::Duration;

	use loupe_tls::Ca;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	use super::*;

	fn application_client(ca: &str, cert: &str, key: &str) -> anyhow::Result<reqwest::Client> {
		let cli = Cli::try_parse_from(vec![
			"loupectl".to_owned(),
			"--server-url=https://localhost/".to_owned(),
			format!("--ca-cert-pem={ca}"),
			format!("--admin-cert-pem={cert}"),
			format!("--admin-key-pem={key}"),
			"repo".to_owned(),
			"list".to_owned(),
		])?;
		build_client(&cli.conn)
	}

	async fn exchange(
		http: reqwest::Client, mut config: rustls::ServerConfig,
	) -> (bool, Option<(Vec<u8>, Vec<Vec<u8>>)>) {
		config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let port = listener.local_addr().unwrap().port();
		let mut task = tokio::spawn(async move {
			let (socket, _) = listener.accept().await.unwrap();
			let Ok(mut tls) =
				tokio_rustls::TlsAcceptor::from(Arc::new(config)).accept(socket).await
			else {
				return None;
			};
			let alpn = tls.get_ref().1.alpn_protocol().unwrap_or_default().to_vec();
			let chain = tls
				.get_ref()
				.1
				.peer_certificates()
				.unwrap_or_default()
				.iter()
				.map(|cert| cert.to_vec())
				.collect();
			let mut request = Vec::new();
			while !request.ends_with(b"\r\n\r\n") {
				let mut byte = [0u8; 1];
				if tls.read_exact(&mut byte).await.is_err() || request.len() == 16 * 1024 {
					return None;
				}
				request.push(byte[0]);
			}
			if tls
				.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
				.await
				.is_err()
			{
				return None;
			}
			let _ = tls.shutdown().await;
			Some((alpn, chain))
		});
		let success = tokio::time::timeout(Duration::from_secs(5), async {
			let response = http.get(format!("https://localhost:{port}/")).send().await?;
			let body = response.bytes().await?;
			Ok::<_, reqwest::Error>(body == b"ok".as_slice())
		})
		.await
		.is_ok_and(|result| result.unwrap_or(false));
		let peer = match tokio::time::timeout(Duration::from_secs(5), &mut task).await {
			Ok(result) => result.unwrap(),
			Err(_) => {
				task.abort();
				let _ = task.await;
				None
			},
		};
		(success, peer)
	}

	#[tokio::test]
	async fn actual_constructor_preserves_mtls_http11_chain_and_mixed_roots() {
		let ca = Ca::new("throwaway-application-ca").unwrap();
		let server = ca.mint_server("server", &["localhost".into()]).unwrap();
		let client = ca.mint_client("client").unwrap();
		let unused = ca.mint_client("unused").unwrap();
		let roots = format!("{}{}", unused.key_pem.expose(), ca.cert_pem());
		let chain = format!("{}{}", client.cert_pem, ca.cert_pem());
		let expected: Vec<_> = rustls_pemfile::certs(&mut chain.as_bytes())
			.map(|cert| cert.unwrap().to_vec())
			.collect();
		let http = application_client(&roots, &chain, client.key_pem.expose()).unwrap();
		let config =
			loupe_tls::server_config(&server.cert_pem, server.key_pem.expose(), ca.cert_pem())
				.unwrap();
		let (success, peer) = exchange(http, config).await;
		assert!(success, "actual application client must complete mutual TLS");
		let (alpn, observed) = peer.unwrap();
		assert_eq!(alpn, b"http/1.1");
		assert_eq!(observed, expected);
	}

	#[tokio::test]
	async fn actual_constructor_rejects_wrong_ca_hostname_and_mismatched_key() {
		let ca = Ca::new("throwaway-application-ca").unwrap();
		let foreign = Ca::new("throwaway-foreign-ca").unwrap();
		let client = ca.mint_client("client").unwrap();
		let wrong = ca.mint_client("wrong-key").unwrap();
		assert!(
			application_client(ca.cert_pem(), &client.cert_pem, wrong.key_pem.expose()).is_err()
		);
		for (host, roots) in [("localhost", foreign.cert_pem()), ("wrong-host", ca.cert_pem())] {
			let server = ca.mint_server("server", &[host.into()]).unwrap();
			let http =
				application_client(roots, &client.cert_pem, client.key_pem.expose()).unwrap();
			let config =
				loupe_tls::server_config(&server.cert_pem, server.key_pem.expose(), ca.cert_pem())
					.unwrap();
			assert!(
				!exchange(http, config).await.0,
				"verification must reject wrong trust or hostname"
			);
		}
	}
}
