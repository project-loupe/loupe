use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use loupe_server::init::{run_init, DataDirLayout};
use loupe_server::{serve, AppState, Config, FileConfig};
use loupe_storage::secrets::MasterKey;
use loupe_storage::Db;
use loupe_tls::Ca;

#[derive(Debug, Parser)]
#[command(version, about = "loupe security-scanning daemon")]
struct Cli {
	#[command(subcommand)]
	cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
	/// Bootstrap a fresh data dir: mint the internal CA, server cert,
	/// and admin client cert; persist them under the data dir;
	/// register the admin in the workers table; print the admin bundle
	/// once. Refuses to run against an already-initialised data dir.
	Init(InitArgs),
	/// Run the loupe daemon against an already-initialised data dir.
	Serve(ServeArgs),
}

#[derive(Debug, Parser)]
struct InitArgs {
	#[arg(long, env = "LOUPE_DATA_DIR")]
	data_dir: PathBuf,
	/// SubjectAltName entries for the server cert. Pass at least one.
	/// Defaults cover both `localhost` and `127.0.0.1` so a fresh
	/// bootstrap works for clients that prefer either form (rcgen
	/// auto-classifies entries that parse as IPs into IP SANs and the
	/// rest into DNS SANs). Override with `--hostname` for production
	/// SAN lists.
	#[arg(long = "hostname", value_name = "HOSTNAME", default_values_t = vec!["localhost".to_owned(), "127.0.0.1".to_owned()])]
	hostnames: Vec<String>,
}

#[derive(Debug, Parser)]
struct ServeArgs {
	/// Optional path to a TOML config file. Settings the file
	/// supplies act as defaults; matching env vars or CLI flags
	/// override them. See `contrib/config.toml` for a sample.
	#[arg(long, env = "LOUPE_CONFIG")]
	config: Option<PathBuf>,
	#[arg(long, env = "LOUPE_BIND")]
	bind: Option<SocketAddr>,
	#[arg(long, env = "LOUPE_DB")]
	db: Option<PathBuf>,
	#[arg(long, env = "LOUPE_SERVER_CERT")]
	server_cert: Option<PathBuf>,
	#[arg(long, env = "LOUPE_SERVER_KEY")]
	server_key: Option<PathBuf>,
	#[arg(long, env = "LOUPE_CA_CERT")]
	ca_cert: Option<PathBuf>,
	#[arg(long, env = "LOUPE_CA_KEY")]
	ca_key: Option<PathBuf>,
	/// Path to a file containing the database master key (64 hex
	/// characters, optionally trailing newline — the shape
	/// `loupe-server init` writes). Used only when `LOUPE_MASTER_KEY`
	/// is not set; the env var still wins so operators who manage
	/// the key in a secret store don't need to drop it on disk.
	#[arg(long, env = "LOUPE_MASTER_KEY_FILE")]
	master_key_file: Option<PathBuf>,
	/// Server-level default for the human-in-the-loop approval gate.
	/// Per-repo `require_approval` overrides this. When unset both
	/// here and in the config file, the default is `false`
	/// (immediate dispatch).
	#[arg(long, env = "LOUPE_REQUIRE_APPROVAL_DEFAULT")]
	require_approval_default: Option<bool>,
}

#[tokio::main]
async fn main() -> Result<()> {
	init_tracing();
	let cli = Cli::parse();
	match cli.cmd {
		Cmd::Init(args) => run_init_cmd(args),
		Cmd::Serve(args) => run_serve(args).await,
	}
}

fn run_init_cmd(args: InitArgs) -> Result<()> {
	// LOUPE_MASTER_KEY (64 hex chars) takes precedence: when set,
	// init uses it as-is and does not write a master.key file.
	// Operators who manage the key in a secret store / systemd cred /
	// vault stay in control of where it lives.
	let caller_key = read_master_key_from_env()?;
	let out = run_init(&args.data_dir, &args.hostnames, caller_key)
		.with_context(|| format!("initialising data dir {}", args.data_dir.display()))?;
	let layout = DataDirLayout::at(&args.data_dir);
	println!("loupe data dir initialised at {}", out.layout.root.display());
	println!();
	println!("server cert: {}", layout.server_cert.display());
	println!("server key:  {}", layout.server_key.display());
	println!("ca cert:     {}", layout.ca_cert.display());
	println!();
	if out.minted_master_key {
		println!("master key:  {}", layout.master_key.display());
		println!(
			"  (32 random bytes, hex-encoded; database is sealed under this key.\n\
			   Set `LOUPE_MASTER_KEY=$(cat {})` for `loupe-server serve`,\n\
			   or pass --master-key {}.)",
			layout.master_key.display(),
			layout.master_key.display(),
		);
	} else {
		println!("master key:  loaded from LOUPE_MASTER_KEY env (not persisted to disk)");
	}
	println!();
	println!("admin client cert (saved to {}):", layout.admin_cert.display());
	println!("{}", out.admin_bundle.cert_pem.trim_end());
	println!();
	println!("admin client key (saved to {}):", layout.admin_key.display());
	println!("KEEP THIS SECRET — written once, never re-derivable.");
	println!("{}", out.admin_bundle.key_pem.trim_end());
	Ok(())
}

async fn run_serve(args: ServeArgs) -> Result<()> {
	let file_cfg = match &args.config {
		Some(path) => FileConfig::load(path)?,
		None => FileConfig::default(),
	};

	let bind_addr = args
		.bind
		.or(file_cfg.server.bind)
		.unwrap_or_else(|| "127.0.0.1:8443".parse().expect("hardcoded socket addr is valid"));
	let db_path = args
		.db
		.or(file_cfg.paths.db)
		.context("db path missing — pass --db, set LOUPE_DB, or [paths].db in config.toml")?;
	let server_cert_path = args.server_cert.or(file_cfg.paths.server_cert).context(
		"server cert path missing — pass --server-cert, set LOUPE_SERVER_CERT, or [paths].server_cert",
	)?;
	let server_key_path = args.server_key.or(file_cfg.paths.server_key).context(
		"server key path missing — pass --server-key, set LOUPE_SERVER_KEY, or [paths].server_key",
	)?;
	let ca_cert_path = args
		.ca_cert
		.or(file_cfg.paths.ca_cert)
		.context("CA cert path missing — pass --ca-cert, set LOUPE_CA_CERT, or [paths].ca_cert")?;
	let ca_key_path = args
		.ca_key
		.or(file_cfg.paths.ca_key)
		.context("CA key path missing — pass --ca-key, set LOUPE_CA_KEY, or [paths].ca_key")?;
	let require_approval_default =
		args.require_approval_default.or(file_cfg.policy.require_approval_default).unwrap_or(false);

	// Master key resolution: env > --master-key-file flag > [paths]
	// master_key in config.toml. The env-var path is the highest
	// priority so operators who keep the key out of the filesystem
	// (systemd creds, secret managers, etc.) don't need to drop it
	// on disk just to start the server.
	let master_key = if let Some(key) = read_master_key_from_env()? {
		tracing::info!("loupe-server: master key loaded from LOUPE_MASTER_KEY");
		key
	} else if let Some(path) = args.master_key_file.or(file_cfg.paths.master_key) {
		tracing::info!(path = %path.display(), "loupe-server: master key loaded from file");
		read_master_key_from_file(&path)?
	} else {
		bail!(
			"master key missing — set LOUPE_MASTER_KEY, pass --master-key-file <path>,\n\
			 or add `[paths] master_key = \"...\"` to config.toml.\n\
			 (run `loupe-server init` to mint one.)"
		);
	};

	let server_cert_pem = std::fs::read_to_string(&server_cert_path)
		.with_context(|| format!("reading server cert at {}", server_cert_path.display()))?;
	let server_key_pem = std::fs::read_to_string(&server_key_path)
		.with_context(|| format!("reading server key at {}", server_key_path.display()))?;
	let ca_cert_pem = std::fs::read_to_string(&ca_cert_path)
		.with_context(|| format!("reading CA cert at {}", ca_cert_path.display()))?;
	let ca_key_pem = std::fs::read_to_string(&ca_key_path)
		.with_context(|| format!("reading CA key at {}", ca_key_path.display()))?;

	let ca = Ca::from_pem(&ca_cert_pem, &ca_key_pem).context("rebuilding CA from PEM")?;

	let cfg = Config {
		bind_addr,
		db_path: db_path.clone(),
		server_cert_pem,
		server_key_pem,
		ca_cert_pem,
		ca_key_pem,
	};
	let db = Db::open(&db_path, &master_key)
		.with_context(|| format!("opening db at {}", db_path.display()))?;
	let github = Arc::new(loupe_server::reporters::GithubReporter::new()?);
	let state = AppState::new(Arc::new(db), Arc::new(ca), github)
		.with_require_approval_default(require_approval_default);
	if require_approval_default {
		tracing::info!(
			"loupe-server: require_approval_default = true (per-repo overrides may opt out)"
		);
	}

	let handle = serve(cfg, state).await?;
	tracing::info!(addr = %handle.local_addr, "loupe-server listening");

	tokio::signal::ctrl_c().await.context("waiting for SIGINT")?;
	tracing::info!("loupe-server shutting down");
	handle.shutdown().await;
	Ok(())
}

/// Initialise tracing. Defaults to the human-readable formatter; set
/// `LOUPE_LOG_JSON=1` (or any non-empty value) to switch to structured
/// JSON output for log aggregators. Filter level is taken from
/// `RUST_LOG` as usual.
fn init_tracing() {
	let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
		.unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
	let json = std::env::var_os("LOUPE_LOG_JSON").map(|v| !v.is_empty()).unwrap_or(false);
	if json {
		tracing_subscriber::fmt().json().with_env_filter(env_filter).init();
	} else {
		tracing_subscriber::fmt().with_env_filter(env_filter).init();
	}
}

/// Parse a 32-byte master key from `LOUPE_MASTER_KEY`. The variable
/// holds the key as 64 hex characters (the same shape `loupe-server
/// init` writes to `master.key`). `Ok(None)` if the variable is unset.
fn read_master_key_from_env() -> Result<Option<MasterKey>> {
	let Ok(raw) = std::env::var("LOUPE_MASTER_KEY") else { return Ok(None) };
	Ok(Some(parse_master_key_hex(raw.trim()).context("LOUPE_MASTER_KEY")?))
}

fn read_master_key_from_file(path: &Path) -> Result<MasterKey> {
	let raw = std::fs::read_to_string(path)
		.with_context(|| format!("reading master key file at {}", path.display()))?;
	parse_master_key_hex(raw.trim())
		.with_context(|| format!("master key file at {}", path.display()))
}

fn parse_master_key_hex(s: &str) -> Result<MasterKey> {
	if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
		bail!("expected 64 hex characters, got {} chars", s.len());
	}
	let mut bytes = [0u8; 32];
	for (i, byte) in bytes.iter_mut().enumerate() {
		// Indexing is safe: we just confirmed the string is 64 ASCII chars.
		let hi = u8::from_str_radix(&s[i * 2..i * 2 + 1], 16).expect("ascii hex digit");
		let lo = u8::from_str_radix(&s[i * 2 + 1..i * 2 + 2], 16).expect("ascii hex digit");
		*byte = (hi << 4) | lo;
	}
	Ok(MasterKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn init_default_hostnames_cover_localhost_and_loopback_ip() {
		// Regression guard: a fresh `loupe-server init` (no
		// --hostname flag) must mint a cert valid for BOTH
		// `localhost` AND `127.0.0.1`. Clients connecting via the
		// loopback IP otherwise hit
		//   `invalid peer certificate: certificate not valid for
		//    name "127.0.0.1"`
		// at handshake time, because the cert SAN list lacks the IP.
		// Pinning the default catches anyone shrinking it back to
		// just `localhost` for "tidiness."
		let cli = Cli::try_parse_from(["loupe-server", "init", "--data-dir", "/tmp/x"]).unwrap();
		let Cmd::Init(args) = cli.cmd else {
			panic!("expected init subcommand, got {:?}", cli.cmd);
		};
		assert!(
			args.hostnames.contains(&"localhost".to_owned()),
			"default SAN list must include `localhost`: {:?}",
			args.hostnames,
		);
		assert!(
			args.hostnames.contains(&"127.0.0.1".to_owned()),
			"default SAN list must include `127.0.0.1`: {:?}",
			args.hostnames,
		);
	}
}
