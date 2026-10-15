#![deny(unsafe_code)]
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
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use loupe_provenance::{Config as ConfigSource, Ingress, Mark, Untrusted, Unvalidated, Validate};
use loupe_server::config::{
	select_tls_pem, ConfiguredHostname, ConfiguredPath, ConfiguredPemArgument, HostnameParser,
	PathParser, PemParser,
};
use loupe_server::init::{run_init_with_options, DataDirLayout, InitOptions};
use loupe_server::{serve, AppState, Config, FileConfig};
use loupe_storage::secrets::MasterKey;
use loupe_storage::Db;

// debug-ok: parsed Config wrappers redact all paths, hostnames and credential arguments; other options are scalars.
#[derive(Debug, Parser)]
#[command(version, about = "loupe security-scanning daemon")]
struct Cli {
	#[command(subcommand)]
	cmd: Cmd,
}

// debug-ok: parsed Config wrappers redact content; remaining options are booleans, counts and socket addresses.
#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Cmd {
	/// Bootstrap a fresh data dir: mint the internal CA, server cert,
	/// and admin client cert; persist them under the data dir;
	/// register the admin in the workers table; print the admin bundle
	/// once. Refuses to run against an already-initialised data dir.
	Init(InitArgs),
	/// Run the loupe daemon against an already-initialised data dir.
	Serve(ServeArgs),
}

// debug-ok: parsed Config wrappers redact content; remaining options are booleans, counts and socket addresses.
#[derive(Debug, Parser)]
struct InitArgs {
	#[arg(long, env = "LOUPE_DATA_DIR", value_parser = PathParser)]
	data_dir: ConfiguredPath,
	/// SubjectAltName entries for the server cert. Pass at least one.
	/// Defaults cover both `localhost` and `127.0.0.1` so a fresh
	/// bootstrap works for clients that prefer either form (rcgen
	/// auto-classifies entries that parse as IPs into IP SANs and the
	/// rest into DNS SANs). Override with `--hostname` for production
	/// SAN lists.
	#[arg(long = "hostname", value_name = "HOSTNAME", default_values = ["localhost", "127.0.0.1"], value_parser = HostnameParser)]
	hostnames: Vec<ConfiguredHostname>,
	/// Print sourceable LOUPE_* env assignments carrying the generated
	/// server/admin PEMs and master key. Useful for Docker bootstrap.
	#[arg(long, default_value_t = false)]
	emit_env: bool,
	/// Do not persist generated PEM/key files under the data dir. Must
	/// be paired with --emit-env so the caller can capture the secrets.
	#[arg(long, default_value_t = false, requires = "emit_env")]
	no_persist_secrets: bool,
}

// debug-ok: parsed Config wrappers redact content; remaining options are booleans, counts and socket addresses.
#[derive(Debug, Parser)]
struct ServeArgs {
	/// Optional path to a TOML config file. Settings the file
	/// supplies act as defaults; matching env vars or CLI flags
	/// override them. See `contrib/config.toml` for a sample.
	#[arg(long, env = "LOUPE_CONFIG", value_parser = PathParser)]
	config: Option<ConfiguredPath>,
	#[arg(long, env = "LOUPE_BIND")]
	bind: Option<SocketAddr>,
	#[arg(long, env = "LOUPE_DB", value_parser = PathParser)]
	db: Option<ConfiguredPath>,
	#[arg(long, env = "LOUPE_SERVER_CERT", value_parser = PathParser)]
	server_cert: Option<ConfiguredPath>,
	#[arg(long, env = "LOUPE_SERVER_KEY", value_parser = PathParser)]
	server_key: Option<ConfiguredPath>,
	#[arg(long, env = "LOUPE_CA_CERT", value_parser = PathParser)]
	ca_cert: Option<ConfiguredPath>,
	#[arg(long, env = "LOUPE_CA_KEY", value_parser = PathParser)]
	ca_key: Option<ConfiguredPath>,
	/// Server certificate PEM content. When set, this takes precedence
	/// over --server-cert / LOUPE_SERVER_CERT.
	#[arg(long, env = "LOUPE_SERVER_CERT_PEM", hide_env_values = true, value_parser = PemParser)]
	server_cert_pem: Option<ConfiguredPemArgument>,
	/// Base64-encoded server certificate PEM content. Used when
	/// LOUPE_SERVER_CERT_PEM is unset.
	#[arg(long, env = "LOUPE_SERVER_CERT_PEM_B64", hide_env_values = true, value_parser = PemParser)]
	server_cert_pem_b64: Option<ConfiguredPemArgument>,
	/// Server private-key PEM content. When set, this takes precedence
	/// over --server-key / LOUPE_SERVER_KEY.
	#[arg(long, env = "LOUPE_SERVER_KEY_PEM", hide_env_values = true, value_parser = PemParser)]
	server_key_pem: Option<ConfiguredPemArgument>,
	/// Base64-encoded server private-key PEM content. Used when
	/// LOUPE_SERVER_KEY_PEM is unset.
	#[arg(long, env = "LOUPE_SERVER_KEY_PEM_B64", hide_env_values = true, value_parser = PemParser)]
	server_key_pem_b64: Option<ConfiguredPemArgument>,
	/// Internal CA certificate PEM content. When set, this takes
	/// precedence over --ca-cert / LOUPE_CA_CERT.
	#[arg(long, env = "LOUPE_CA_CERT_PEM", hide_env_values = true, value_parser = PemParser)]
	ca_cert_pem: Option<ConfiguredPemArgument>,
	/// Base64-encoded internal CA certificate PEM content. Used when
	/// LOUPE_CA_CERT_PEM is unset.
	#[arg(long, env = "LOUPE_CA_CERT_PEM_B64", hide_env_values = true, value_parser = PemParser)]
	ca_cert_pem_b64: Option<ConfiguredPemArgument>,
	/// Internal CA private-key PEM content. When set, this takes
	/// precedence over --ca-key / LOUPE_CA_KEY.
	#[arg(long, env = "LOUPE_CA_KEY_PEM", hide_env_values = true, value_parser = PemParser)]
	ca_key_pem: Option<ConfiguredPemArgument>,
	/// Base64-encoded internal CA private-key PEM content. Used when
	/// LOUPE_CA_KEY_PEM is unset.
	#[arg(long, env = "LOUPE_CA_KEY_PEM_B64", hide_env_values = true, value_parser = PemParser)]
	ca_key_pem_b64: Option<ConfiguredPemArgument>,
	/// Path to a file containing the database master key (64 hex
	/// characters, optionally trailing newline — the shape
	/// `loupe-server init` writes). Used only when `LOUPE_MASTER_KEY`
	/// is not set; the env var still wins so operators who manage
	/// the key in a secret store don't need to drop it on disk.
	#[arg(long, env = "LOUPE_MASTER_KEY_FILE", value_parser = PathParser)]
	master_key_file: Option<ConfiguredPath>,
	/// Server-level default for the human-in-the-loop approval gate.
	/// Per-repo `require_approval` overrides this. When unset both
	/// here and in the config file, the default is `false`
	/// (immediate dispatch).
	#[arg(long, env = "LOUPE_REQUIRE_APPROVAL_DEFAULT")]
	require_approval_default: Option<bool>,
	/// Server-level default for the verify flow. Repo registration can
	/// explicitly opt in or out. When unset here and in the config file,
	/// the default is `false` (dispatch without verifier jobs).
	#[arg(long, env = "LOUPE_VERIFICATION_DEFAULT")]
	verification_default: Option<bool>,
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
	let out = run_init_with_options(
		&args.data_dir,
		&args.hostnames,
		caller_key,
		InitOptions { persist_secrets: !args.no_persist_secrets },
	)
	.with_context(|| format!("initialising data dir {}", args.data_dir.as_path().display()))?;
	if args.emit_env {
		print_init_env(&out)?;
		return Ok(());
	}
	let layout = DataDirLayout::at(&args.data_dir);
	println!("loupe data dir initialised at {}", out.layout.root.as_path().display());
	println!();
	println!("server cert: {}", layout.server_cert.as_path().display());
	println!("server key:  {}", layout.server_key.as_path().display());
	println!("ca cert:     {}", layout.ca_cert.as_path().display());
	println!();
	if out.minted_master_key {
		println!("master key:  {}", layout.master_key.as_path().display());
		println!(
			"  (32 random bytes, hex-encoded; database is sealed under this key.\n\
			   Set `LOUPE_MASTER_KEY=$(cat {})` for `loupe-server serve`,\n\
			   or pass --master-key {}.)",
			layout.master_key.as_path().display(),
			layout.master_key.as_path().display(),
		);
	} else {
		println!("master key:  loaded from LOUPE_MASTER_KEY env (not persisted to disk)");
	}
	println!();
	println!("admin client cert (saved to {}):", layout.admin_cert.as_path().display());
	println!("{}", out.admin_bundle.cert_pem.trim_end());
	println!();
	println!("admin client key (saved to {}):", layout.admin_key.as_path().display());
	println!("KEEP THIS SECRET — written once, never re-derivable.");
	println!("{}", out.admin_bundle.key_pem.expose().trim_end());
	Ok(())
}

fn print_init_env(out: &loupe_server::init::InitOutput) -> Result<()> {
	for (name, value) in init_env_assignments(out)? {
		println!("{name}={}", value.expose());
	}
	Ok(())
}

fn init_env_assignments(
	out: &loupe_server::init::InitOutput,
) -> Result<Vec<(&'static str, loupe_provenance::Secret<String>)>> {
	let mut assignments = vec![("LOUPE_MASTER_KEY", out.master_key.to_hex())];
	for (name, value) in [
		("LOUPE_SERVER_CERT_PEM_B64", &out.server_bundle.cert_pem),
		("LOUPE_SERVER_KEY_PEM_B64", out.server_bundle.key_pem.expose()),
		("LOUPE_CA_CERT_PEM_B64", out.ca_cert_pem.expose()),
		("LOUPE_CA_KEY_PEM_B64", out.ca_key_pem.expose()),
		("LOUPE_ADMIN_CERT_PEM_B64", &out.admin_bundle.cert_pem),
		("LOUPE_ADMIN_KEY_PEM_B64", out.admin_bundle.key_pem.expose()),
	] {
		assignments.push((name, loupe_tls::encode_pem_base64(value)?));
	}
	Ok(assignments)
}

async fn run_serve(args: ServeArgs) -> Result<()> {
	let file_cfg = match &args.config {
		Some(path) => FileConfig::load(path.as_path())?,
		None => FileConfig::default(),
	};
	let review_policy = file_cfg.review.resolve()?;
	file_cfg.worker_budgets.validate()?;

	let bind_addr =
		args.bind.or(file_cfg.server.bind).unwrap_or(SocketAddr::from(([127, 0, 0, 1], 8443)));
	let db_path = args
		.db
		.or(file_cfg.paths.db)
		.context("db path missing — pass --db, set LOUPE_DB, or [paths].db in config.toml")?;
	let require_approval_default =
		args.require_approval_default.or(file_cfg.policy.require_approval_default).unwrap_or(false);
	let verification_default =
		args.verification_default.or(file_cfg.policy.verification_default).unwrap_or(false);

	// Master key resolution: env > --master-key-file flag > [paths]
	// master_key in config.toml. The env-var path is the highest
	// priority so operators who keep the key out of the filesystem
	// (systemd creds, secret managers, etc.) don't need to drop it
	// on disk just to start the server.
	let master_key = if let Some(key) = read_master_key_from_env()? {
		tracing::info!("loupe-server: master key loaded from LOUPE_MASTER_KEY");
		key
	} else if let Some(path) = args.master_key_file.or(file_cfg.paths.master_key) {
		tracing::info!(path = %path.as_path().display(), "loupe-server: master key loaded from file");
		read_master_key_from_file(path.as_path())?
	} else {
		bail!(
			"master key missing — set LOUPE_MASTER_KEY, pass --master-key-file <path>,\n\
			 or add `[paths] master_key = \"...\"` to config.toml.\n\
			 (run `loupe-server init` to mint one.)"
		);
	};

	let server_cert_pem = select_tls_pem(
		"server cert",
		args.server_cert_pem,
		args.server_cert_pem_b64,
		args.server_cert.or(file_cfg.paths.server_cert),
		"server cert missing — set LOUPE_SERVER_CERT_PEM, LOUPE_SERVER_CERT_PEM_B64, pass --server-cert, set LOUPE_SERVER_CERT, or [paths].server_cert",
	)?;
	let server_key_pem = select_tls_pem(
		"server key",
		args.server_key_pem,
		args.server_key_pem_b64,
		args.server_key.or(file_cfg.paths.server_key),
		"server key missing — set LOUPE_SERVER_KEY_PEM, LOUPE_SERVER_KEY_PEM_B64, pass --server-key, set LOUPE_SERVER_KEY, or [paths].server_key",
	)?;
	let ca_cert_pem = select_tls_pem(
		"CA cert",
		args.ca_cert_pem,
		args.ca_cert_pem_b64,
		args.ca_cert.or(file_cfg.paths.ca_cert),
		"CA cert missing — set LOUPE_CA_CERT_PEM, LOUPE_CA_CERT_PEM_B64, pass --ca-cert, set LOUPE_CA_CERT, or [paths].ca_cert",
	)?;
	let ca_key_pem = select_tls_pem(
		"CA key",
		args.ca_key_pem,
		args.ca_key_pem_b64,
		args.ca_key.or(file_cfg.paths.ca_key),
		"CA key missing — set LOUPE_CA_KEY_PEM, LOUPE_CA_KEY_PEM_B64, pass --ca-key, set LOUPE_CA_KEY, or [paths].ca_key",
	)?;

	let ca = ca_cert_pem.import_ca(&ca_key_pem)?;

	let cfg = Config {
		bind_addr,
		db_path: db_path.clone(),
		server_cert_pem,
		server_key_pem,
		ca_cert_pem,
		ca_key_pem,
	};
	let db = Db::open(db_path.as_path(), &master_key)
		.inspect_err(|error| {
			if let loupe_storage::Error::Migration(failure) = error {
				tracing::error!(error = %failure, "loupe-server: database upgrade failed");
			}
		})
		.with_context(|| format!("opening db at {}", db_path.as_path().display()))?;
	tracing::info!(
		schema_version = db.schema_version()?,
		build = %std::env::var("LOUPE_BUILD_REVISION").unwrap_or_else(|_| "unknown".into()),
		"loupe-server: database ready"
	);
	let github = Arc::new(loupe_server::reporters::GithubReporter::new()?);
	if let Some(owners) = &file_cfg.github_app.allowed_target_owners {
		tracing::info!(
			owners = ?owners,
			"loupe-server: GitHub App reporting restricted to the listed tracker owners"
		);
	}
	let state = AppState::new(Arc::new(db), Arc::new(ca), github)
		.with_require_approval_default(require_approval_default)
		.with_verification_default(verification_default)
		.with_github_app_allowed_owners(file_cfg.github_app.allowed_target_owners);
	let state = state.with_review_policy(review_policy)?;
	let state = state.with_worker_budgets(file_cfg.worker_budgets)?;
	if require_approval_default {
		tracing::info!(
			"loupe-server: require_approval_default = true (per-repo overrides may opt out)"
		);
	}
	if verification_default {
		tracing::info!(
			"loupe-server: verification_default = true (repo registrations may opt out)"
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
	let raw = loupe_provenance::Secret::new(raw);
	// SAFETY: raw is the actual environment read, already guarded, before hex decoding.
	#[allow(unsafe_code)]
	let input = unsafe { Ingress::<ConfigSource>::new() };
	Ok(Some(
		Untrusted::new(raw.expose().as_str(), input)
			.validate(ServerMasterKeyDecoder)
			.context("LOUPE_MASTER_KEY")?,
	))
}

fn read_master_key_from_file(path: &Path) -> Result<MasterKey> {
	#[allow(
		clippy::disallowed_methods,
		reason = "configuration credential ingress reads the selected master-key file directly into its guarded owner before decoding"
	)]
	let raw = loupe_provenance::Secret::new(
		std::fs::read_to_string(path)
			.with_context(|| format!("reading master key file at {}", path.display()))?,
	);
	// SAFETY: raw is this actual configuration-file read before hex decoding.
	#[allow(unsafe_code)]
	let input = unsafe { Ingress::<ConfigSource>::new() };
	Untrusted::new(raw.expose().as_str(), input)
		.validate(ServerMasterKeyDecoder)
		.with_context(|| format!("master key file at {}", path.display()))
}

// debug-ok: the credential error retains only the supplied character count.
#[derive(Debug, thiserror::Error)]
enum CredentialInputError {
	#[error("expected 64 hex characters, got {0} chars")]
	MasterKey(usize),
}
struct ServerMasterKeyDecoder;
impl Validate<&str, ConfigSource> for ServerMasterKeyDecoder {
	type Output = MasterKey;
	type Error = CredentialInputError;
	fn validate<'view>(
		self, input: Unvalidated<'view, &str>, _: Mark<'view, ConfigSource>,
	) -> Result<Self::Output, Self::Error> {
		let raw = input.get().trim();
		parse_master_key_hex(raw).map_err(|_| CredentialInputError::MasterKey(raw.len()))
	}
}

fn parse_master_key_hex(s: &str) -> Result<MasterKey> {
	if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
		bail!("expected 64 hex characters, got {} chars", s.len());
	}
	let mut bytes = [0u8; 32];
	for (i, byte) in bytes.iter_mut().enumerate() {
		// Indexing is safe: we just confirmed the string is 64 ASCII chars.
		#[expect(
			clippy::expect_used,
			clippy::string_slice,
			reason = "the unchanged string was checked for exactly 64 ASCII hex bytes before these bounded single-digit slices"
		)]
		let hi = u8::from_str_radix(&s[i * 2..i * 2 + 1], 16).expect("ascii hex digit");
		#[expect(
			clippy::expect_used,
			clippy::string_slice,
			reason = "the unchanged string was checked for exactly 64 ASCII hex bytes before these bounded single-digit slices"
		)]
		let lo = u8::from_str_radix(&s[i * 2 + 1..i * 2 + 2], 16).expect("ascii hex digit");
		*byte = (hi << 4) | lo;
	}
	let key = MasterKey::from_bytes(bytes);
	loupe_provenance::Zeroise::zeroise(&mut bytes);
	Ok(key)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn init_default_hostnames_cover_localhost_and_loopback_ip() {
		// DNS and IP loopback connections require distinct SAN entries.
		let tmp = tempfile::tempdir().unwrap();
		let cli = Cli::try_parse_from([
			std::ffi::OsStr::new("loupe-server"),
			std::ffi::OsStr::new("init"),
			std::ffi::OsStr::new("--data-dir"),
			tmp.path().as_os_str(),
		])
		.unwrap();
		let Cmd::Init(args) = cli.cmd else {
			panic!("expected init subcommand, got {:?}", cli.cmd);
		};
		let out = run_init_with_options(
			&args.data_dir,
			&args.hostnames,
			None,
			InitOptions { persist_secrets: false },
		)
		.unwrap();
		let leaf = rustls_pemfile::certs(&mut out.server_bundle.cert_pem.as_bytes())
			.next()
			.unwrap()
			.unwrap();
		let mut roots = rustls::RootCertStore::empty();
		let ca = rustls_pemfile::certs(&mut out.ca_cert_pem.expose().as_bytes())
			.next()
			.unwrap()
			.unwrap();
		roots.add(ca).unwrap();
		let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
			Arc::new(roots),
			Arc::new(rustls::crypto::ring::default_provider()),
		)
		.build()
		.unwrap();
		use rustls::client::danger::ServerCertVerifier;
		for name in ["localhost", "127.0.0.1"] {
			assert!(
				verifier
					.verify_server_cert(
						&leaf,
						&[],
						&name.try_into().unwrap(),
						&[],
						rustls::pki_types::UnixTime::now()
					)
					.is_ok(),
				"default SAN list must include `{name}`"
			);
		}
		assert!(verifier
			.verify_server_cert(
				&leaf,
				&[],
				&"unlisted.invalid".try_into().unwrap(),
				&[],
				rustls::pki_types::UnixTime::now()
			)
			.is_err());
	}

	#[test]
	fn init_env_assignments_are_complete_single_line_values() {
		let tmp = tempfile::tempdir().unwrap();
		let cli = Cli::try_parse_from([
			std::ffi::OsStr::new("loupe-server"),
			std::ffi::OsStr::new("init"),
			std::ffi::OsStr::new("--data-dir"),
			tmp.path().as_os_str(),
			std::ffi::OsStr::new("--hostname=localhost"),
		])
		.unwrap();
		let Cmd::Init(args) = cli.cmd else { panic!("init command") };
		let out = loupe_server::init::run_init_with_options(
			&args.data_dir,
			&args.hostnames,
			None,
			InitOptions { persist_secrets: false },
		)
		.unwrap();

		let assignments: Vec<_> = init_env_assignments(&out).unwrap();
		let names: Vec<_> = assignments.iter().map(|(name, _)| *name).collect();
		assert_eq!(
			names,
			vec![
				"LOUPE_MASTER_KEY",
				"LOUPE_SERVER_CERT_PEM_B64",
				"LOUPE_SERVER_KEY_PEM_B64",
				"LOUPE_CA_CERT_PEM_B64",
				"LOUPE_CA_KEY_PEM_B64",
				"LOUPE_ADMIN_CERT_PEM_B64",
				"LOUPE_ADMIN_KEY_PEM_B64",
			]
		);
		for (name, value) in &assignments {
			assert!(!value.expose().is_empty(), "{name} value must be present");
			assert!(!value.expose().contains('\n'), "{name} value must fit dotenv/env-file syntax");
		}
		assert_eq!(assignments[0].1.expose(), out.master_key.to_hex().expose());
		let exported_key = parse_master_key_hex(assignments[0].1.expose()).unwrap();
		let reopened =
			loupe_storage::Db::open(out.layout.db_path.as_path(), &exported_key).unwrap();
		// Retain the independent SQL count on this test-owned initialization file.
		// Close the production handle before opening the offline observer.
		drop(reopened);
		let offline = rusqlite::Connection::open(out.layout.db_path.as_path()).unwrap();
		offline
			.pragma_update(None, "key", format!("x'{}'", exported_key.to_hex().expose()))
			.unwrap();
		let admin_count = offline
			.query_row("SELECT COUNT(*) FROM workers WHERE kind = 'admin'", [], |row| {
				row.get::<_, i64>(0)
			})
			.unwrap();
		offline.close().unwrap();
		assert_eq!(admin_count, 1, "exported master key must recover the initialized database");

		use base64::Engine as _;
		let server_cert =
			base64::engine::general_purpose::STANDARD.decode(assignments[1].1.expose()).unwrap();
		assert_eq!(String::from_utf8(server_cert).unwrap(), out.server_bundle.cert_pem);
		for ((_, encoded), expected) in assignments.iter().skip(2).zip([
			out.server_bundle.key_pem.expose(),
			out.ca_cert_pem.expose(),
			out.ca_key_pem.expose(),
			&out.admin_bundle.cert_pem,
			out.admin_bundle.key_pem.expose(),
		]) {
			let decoded =
				base64::engine::general_purpose::STANDARD.decode(encoded.expose()).unwrap();
			assert_eq!(decoded, expected.as_bytes(), "export bytes must be preserved");
		}
	}
}

#[cfg(test)]
mod tls_consumer_tests {
	use base64::Engine as _;

	use super::*;

	#[test]
	fn config_master_key_file_preserves_trim_view_and_fixed_error() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("master.key");
		let hex = "aB".repeat(32);
		std::fs::write(&path, format!(" \n{hex}\r\n")).unwrap();
		let key = read_master_key_from_file(path.as_path()).unwrap();
		assert_eq!(key.to_hex().expose(), &"ab".repeat(32));
		std::fs::write(&path, "FAKE_BAD_CONFIG_MASTER_KEY").unwrap();
		let error = read_master_key_from_file(path.as_path()).unwrap_err();
		assert!(format!("{error:#}").contains("expected 64 hex characters"));
		assert!(!format!("{error:#?}").contains("FAKE_BAD_CONFIG_MASTER_KEY"));
	}

	#[test]
	fn tls_consumer_server_options_debug_redacts_raw_and_encoded_tls_inputs() {
		let sentinel = "FAKE_SERVER_TLS_OPTION";
		let encoded = base64::engine::general_purpose::STANDARD.encode(sentinel);
		let mut leaks = Vec::new();
		for flag in [
			"--server-cert-pem",
			"--server-key-pem",
			"--ca-cert-pem",
			"--ca-key-pem",
			"--server-cert-pem-b64",
			"--server-key-pem-b64",
			"--ca-cert-pem-b64",
			"--ca-key-pem-b64",
		] {
			let value = if flag.ends_with("-b64") { &encoded } else { sentinel };
			let cli = Cli::try_parse_from(["loupe-server", "serve", flag, value]).unwrap();
			if [format!("{cli:?}"), format!("{cli:#?}")].iter().any(|text| text.contains(value)) {
				leaks.push(flag);
			}
		}
		assert!(leaks.is_empty(), "server option Debug disclosed inputs at {leaks:?}");
	}
}
