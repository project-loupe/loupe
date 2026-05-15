//! `loupe-server init` — bootstrap a fresh data dir.
//!
//! Mints the internal CA, the server cert, and the admin client cert,
//! writes the PEM bundle under the data dir with restrictive perms, and
//! registers the admin in the workers table. The admin bundle is
//! returned to the caller (the binary then prints it once and only once
//! — re-running init against an existing data dir errors).
//!
//! Database master key handling: the SQLCipher-sealed `loupe.sqlite`
//! needs a 32-byte master key. If the operator already has one in
//! `LOUPE_MASTER_KEY`, init uses it as-is and **does not** persist a
//! key file (the env var is the source of truth, presumably backed by
//! a secret manager / systemd credentials / etc.). Otherwise init
//! mints a fresh 32 bytes, writes them to `data_dir/master.key` (0600,
//! same shape as the cert files), and prints a hint pointing operators
//! at the file.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use loupe_storage::secrets::MasterKey;
use loupe_storage::workers::{self, WorkerKind};
use loupe_storage::Db;
use loupe_tls::{cert_fingerprint, Ca, CertBundle};

#[derive(Debug, Clone, Copy)]
pub struct InitOptions {
	/// Persist generated PEM/key files under the data dir. Production
	/// non-container installs want this; env-only Docker bootstrap does
	/// not.
	pub persist_secrets: bool,
}

impl Default for InitOptions {
	fn default() -> Self {
		Self { persist_secrets: true }
	}
}

/// Layout of files written under the data dir.
pub struct DataDirLayout {
	pub root: PathBuf,
	pub db_path: PathBuf,
	pub ca_cert: PathBuf,
	pub ca_key: PathBuf,
	pub server_cert: PathBuf,
	pub server_key: PathBuf,
	pub admin_cert: PathBuf,
	pub admin_key: PathBuf,
	pub master_key: PathBuf,
}

impl DataDirLayout {
	pub fn at(root: impl Into<PathBuf>) -> Self {
		let root = root.into();
		Self {
			db_path: root.join("loupe.sqlite"),
			ca_cert: root.join("ca.pem"),
			ca_key: root.join("ca.key"),
			server_cert: root.join("server.pem"),
			server_key: root.join("server.key"),
			admin_cert: root.join("admin.pem"),
			admin_key: root.join("admin.key"),
			master_key: root.join("master.key"),
			root,
		}
	}

	/// True if any of the bundle files already exist — used to refuse to
	/// overwrite an initialised data dir.
	pub fn any_exists(&self) -> bool {
		[
			&self.ca_cert,
			&self.ca_key,
			&self.server_cert,
			&self.server_key,
			&self.admin_cert,
			&self.master_key,
			&self.db_path,
		]
		.iter()
		.any(|p| p.exists())
	}
}

/// What `init` returns to its caller. The admin bundle is intended to be
/// printed once and then erased from process memory.
pub struct InitOutput {
	pub layout: DataDirLayout,
	pub server_bundle: CertBundle,
	pub admin_bundle: CertBundle,
	pub ca_cert_pem: String,
	pub ca_key_pem: String,
	/// The master key the SQLCipher database is sealed under.
	/// Either the caller-supplied one (from `LOUPE_MASTER_KEY`) or
	/// the one init just minted. Useful for integration tests that
	/// want to reopen the freshly-bootstrapped DB without round-
	/// tripping through the on-disk hex file.
	pub master_key: MasterKey,
	/// `true` when init minted a fresh key. `false` when init used a
	/// caller-supplied key (typically from `LOUPE_MASTER_KEY`).
	pub minted_master_key: bool,
	/// `true` when generated PEM/key files were written under the data
	/// dir. `false` for env-only bootstrap.
	pub persisted_secrets: bool,
}

/// Bootstrap `data_dir`.
///
/// `server_hostnames` populates the SubjectAltName of the server cert
/// (callers usually pass the public DNS name plus `localhost` for
/// development).
///
/// `caller_key` is the master key to use for SQLCipher. `Some(_)` means
/// the operator already has one (e.g. via `LOUPE_MASTER_KEY`); init
/// will use it as-is and skip writing a key file. `None` means init
/// mints fresh randomness and persists it to `data_dir/master.key` so
/// the next `serve` can read it.
pub fn run_init(
	data_dir: &Path, server_hostnames: &[String], caller_key: Option<MasterKey>,
) -> Result<InitOutput> {
	run_init_with_options(data_dir, server_hostnames, caller_key, InitOptions::default())
}

pub fn run_init_with_options(
	data_dir: &Path, server_hostnames: &[String], caller_key: Option<MasterKey>,
	options: InitOptions,
) -> Result<InitOutput> {
	let layout = DataDirLayout::at(data_dir);

	std::fs::create_dir_all(&layout.root)
		.with_context(|| format!("creating data dir {}", layout.root.display()))?;
	if layout.any_exists() {
		bail!("data dir {} already initialised — refusing to overwrite", layout.root.display());
	}

	let ca = Ca::new("loupe").context("minting internal CA")?;
	let server = ca.mint_server("loupe-server", server_hostnames).context("minting server cert")?;
	let admin = ca.mint_client("admin").context("minting admin client cert")?;

	if options.persist_secrets {
		write_secret(&layout.ca_cert, ca.cert_pem().as_bytes())?;
		write_secret(&layout.ca_key, ca.key_pem().as_bytes())?;
		write_secret(&layout.server_cert, server.cert_pem.as_bytes())?;
		write_secret(&layout.server_key, server.key_pem.as_bytes())?;
		write_secret(&layout.admin_cert, admin.cert_pem.as_bytes())?;
		write_secret(&layout.admin_key, admin.key_pem.as_bytes())?;
	}

	let (master_key, minted_master_key) = match caller_key {
		Some(k) => (k, false),
		None => {
			let k = MasterKey::generate();
			// Persist as 64-char lowercase hex — same shape `serve` expects
			// on disk and what an operator would paste into `PRAGMA key`.
			if options.persist_secrets {
				let mut bytes = k.to_hex().into_bytes();
				bytes.push(b'\n');
				write_secret(&layout.master_key, &bytes)?;
			}
			(k, true)
		},
	};

	let db = Db::open(&layout.db_path, &master_key)
		.with_context(|| format!("opening db at {}", layout.db_path.display()))?;
	let admin_der = pem_first_cert_der(&admin.cert_pem)?;
	let fingerprint = cert_fingerprint(&admin_der);
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
	db.with_conn(|c| Ok(workers::insert(c, "admin", WorkerKind::Admin, &fingerprint, now)?))
		.context("recording admin in workers table")?;

	Ok(InitOutput {
		layout,
		server_bundle: server,
		admin_bundle: admin,
		ca_cert_pem: ca.cert_pem().to_owned(),
		ca_key_pem: ca.key_pem().to_owned(),
		master_key,
		minted_master_key,
		persisted_secrets: options.persist_secrets,
	})
}

fn write_secret(path: &Path, contents: &[u8]) -> Result<()> {
	#[cfg(unix)]
	{
		use std::io::Write;
		use std::os::unix::fs::OpenOptionsExt;
		let mut f = std::fs::OpenOptions::new()
			.write(true)
			.create_new(true)
			.mode(0o600)
			.open(path)
			.with_context(|| format!("creating {}", path.display()))?;
		f.write_all(contents).with_context(|| format!("writing {}", path.display()))?;
	}
	#[cfg(not(unix))]
	{
		std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
	}
	Ok(())
}

/// Strip a single CERTIFICATE PEM block back to its DER bytes.
fn pem_first_cert_der(pem: &str) -> Result<Vec<u8>> {
	let mut reader = pem.as_bytes();
	let mut iter = rustls_pemfile::certs(&mut reader);
	let der = iter
		.next()
		.context("PEM contained no CERTIFICATE block")?
		.context("rustls-pemfile failed to parse certificate")?;
	Ok(der.to_vec())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn bootstraps_a_fresh_data_dir_and_persists_the_master_key() {
		let tmp = tempfile::tempdir().unwrap();
		let out = run_init(tmp.path(), &["localhost".to_owned()], None).unwrap();
		assert!(out.layout.ca_cert.exists());
		assert!(out.layout.server_cert.exists());
		assert!(out.layout.admin_cert.exists());
		assert!(out.layout.master_key.exists(), "init must persist the freshly-minted key");
		assert!(out.layout.db_path.exists());
		assert!(out.minted_master_key, "minted_master_key must be true when no caller_key");

		// master.key must be 64 hex chars + newline.
		let raw = std::fs::read_to_string(&out.layout.master_key).unwrap();
		let trimmed = raw.trim_end();
		assert_eq!(trimmed.len(), 64);
		assert!(trimmed.chars().all(|c| c.is_ascii_hexdigit()));

		// Admin bundle must be parseable as a real cert.
		assert!(out.admin_bundle.cert_pem.contains("BEGIN CERTIFICATE"));
		assert!(out.admin_bundle.key_pem.contains("PRIVATE KEY"));

		// Admin must be in the workers table — re-open the DB with the
		// same key to read it back.
		let key_bytes = decode_hex(trimmed);
		let key = MasterKey::from_bytes(key_bytes);
		let db = Db::open(&out.layout.db_path, &key).unwrap();
		let admin_der = pem_first_cert_der(&out.admin_bundle.cert_pem).unwrap();
		let fp = cert_fingerprint(&admin_der);
		let row = db
			.with_conn(|c| Ok(workers::find_active_by_fingerprint(c, &fp)?))
			.unwrap()
			.expect("admin must be registered after init");
		assert_eq!(row.kind, WorkerKind::Admin);
		assert_eq!(row.name, "admin");
	}

	#[test]
	fn caller_supplied_key_is_used_and_not_persisted() {
		let tmp = tempfile::tempdir().unwrap();
		let key = MasterKey::from_bytes([0x42u8; 32]);
		let out = run_init(tmp.path(), &["localhost".to_owned()], Some(key)).unwrap();
		assert!(
			!out.layout.master_key.exists(),
			"caller-supplied key must not be persisted to disk"
		);
		assert!(!out.minted_master_key);
		// DB only opens with the same key — proves init actually used it.
		let same = MasterKey::from_bytes([0x42u8; 32]);
		assert!(Db::open(&out.layout.db_path, &same).is_ok());
	}

	#[test]
	fn can_bootstrap_without_persisting_secret_files() {
		let tmp = tempfile::tempdir().unwrap();
		let out = run_init_with_options(
			tmp.path(),
			&["localhost".to_owned()],
			None,
			InitOptions { persist_secrets: false },
		)
		.unwrap();
		assert!(!out.layout.ca_cert.exists());
		assert!(!out.layout.ca_key.exists());
		assert!(!out.layout.server_cert.exists());
		assert!(!out.layout.server_key.exists());
		assert!(!out.layout.admin_cert.exists());
		assert!(!out.layout.admin_key.exists());
		assert!(!out.layout.master_key.exists());
		assert!(out.layout.db_path.exists());
		assert!(out.minted_master_key);
		assert!(!out.persisted_secrets);

		let db = Db::open(&out.layout.db_path, &out.master_key).unwrap();
		let admin_der = pem_first_cert_der(&out.admin_bundle.cert_pem).unwrap();
		let fp = cert_fingerprint(&admin_der);
		let row = db
			.with_conn(|c| Ok(workers::find_active_by_fingerprint(c, &fp)?))
			.unwrap()
			.expect("admin must be registered after env-only init");
		assert_eq!(row.kind, WorkerKind::Admin);
		assert_eq!(row.name, "admin");
	}

	#[test]
	fn second_init_refuses_existing_data_dir() {
		let tmp = tempfile::tempdir().unwrap();
		run_init(tmp.path(), &["localhost".to_owned()], None).unwrap();
		let err = match run_init(tmp.path(), &["localhost".to_owned()], None) {
			Err(e) => e,
			Ok(_) => panic!("second init must fail against an existing data dir"),
		};
		assert!(err.to_string().contains("already initialised"), "got: {err}");
	}

	fn decode_hex(s: &str) -> [u8; 32] {
		let mut out = [0u8; 32];
		for (i, byte) in out.iter_mut().enumerate() {
			let hi = u8::from_str_radix(&s[i * 2..i * 2 + 1], 16).unwrap();
			let lo = u8::from_str_radix(&s[i * 2 + 1..i * 2 + 2], 16).unwrap();
			*byte = (hi << 4) | lo;
		}
		out
	}
}
