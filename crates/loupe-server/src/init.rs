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

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use loupe_storage::secrets::MasterKey;
#[cfg(test)]
use loupe_storage::workers::WorkerKind;
use loupe_storage::Db;
use loupe_tls::{cert_fingerprint, Ca, CertBundle};

use crate::config::{ConfiguredHostname, ConfiguredPath};

// debug-ok: initialization options contain only the persist-secrets boolean, never secret bytes.
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
	pub root: ConfiguredPath,
	pub db_path: ConfiguredPath,
	pub ca_cert: ConfiguredPath,
	pub ca_key: ConfiguredPath,
	pub server_cert: ConfiguredPath,
	pub server_key: ConfiguredPath,
	pub admin_cert: ConfiguredPath,
	pub admin_key: ConfiguredPath,
	pub master_key: ConfiguredPath,
}

impl DataDirLayout {
	pub fn at(root: &ConfiguredPath) -> Self {
		let root = root.clone();
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
		.any(|p| {
			#[allow(
				clippy::disallowed_methods,
				reason = "initialization refuses existing files in its Config-selected bundle layout"
			)]
			let exists = p.as_path().exists();
			exists
		})
	}
}

/// What `init` returns to its caller. The admin bundle is intended to be
/// printed once and then erased from process memory.
pub struct InitOutput {
	pub layout: DataDirLayout,
	pub server_bundle: CertBundle,
	pub admin_bundle: CertBundle,
	pub ca_cert_pem: loupe_provenance::Secret<String>,
	pub ca_key_pem: loupe_provenance::Secret<String>,
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
	data_dir: &ConfiguredPath, server_hostnames: &[ConfiguredHostname],
	caller_key: Option<MasterKey>,
) -> Result<InitOutput> {
	run_init_with_options(data_dir, server_hostnames, caller_key, InitOptions::default())
}

pub fn run_init_with_options(
	data_dir: &ConfiguredPath, server_hostnames: &[ConfiguredHostname],
	caller_key: Option<MasterKey>, options: InitOptions,
) -> Result<InitOutput> {
	let layout = DataDirLayout::at(data_dir);

	#[allow(
		clippy::disallowed_methods,
		reason = "initialization creates its Config-selected data directory before exclusive bundle writes"
	)]
	std::fs::create_dir_all(layout.root.as_path())
		.with_context(|| format!("creating data dir {}", layout.root.as_path().display()))?;
	if layout.any_exists() {
		bail!(
			"data dir {} already initialised — refusing to overwrite",
			layout.root.as_path().display()
		);
	}

	let ca = Ca::new("loupe").context("minting internal CA")?;
	let server = ConfiguredHostname::mint_server(&ca, server_hostnames)?;
	let admin = ca.mint_client("admin").context("minting admin client cert")?;

	if options.persist_secrets {
		write_secret(layout.ca_cert.as_path(), ca.cert_pem().as_bytes())?;
		write_secret(layout.ca_key.as_path(), ca.key_pem().expose().as_bytes())?;
		write_secret(layout.server_cert.as_path(), server.cert_pem.as_bytes())?;
		write_secret(layout.server_key.as_path(), server.key_pem.expose().as_bytes())?;
		write_secret(layout.admin_cert.as_path(), admin.cert_pem.as_bytes())?;
		write_secret(layout.admin_key.as_path(), admin.key_pem.expose().as_bytes())?;
	}

	let (master_key, minted_master_key) = match caller_key {
		Some(k) => (k, false),
		None => {
			let k = MasterKey::generate();
			// Persist as 64-char lowercase hex — same shape `serve` expects
			// on disk and what an operator would paste into `PRAGMA key`.
			if options.persist_secrets {
				let hex = k.to_hex();
				write_secret_parts(layout.master_key.as_path(), &[hex.expose().as_bytes(), b"\n"])?;
			}
			(k, true)
		},
	};

	let db = Db::open(layout.db_path.as_path(), &master_key)
		.with_context(|| format!("opening db at {}", layout.db_path.as_path().display()))?;
	let admin_der = pem_first_cert_der(&admin.cert_pem)?;
	let fingerprint = cert_fingerprint(&admin_der);
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
	loupe_storage::registry::bootstrap_admin(&db, &fingerprint, now)
		.context("recording admin in workers table")?;

	let (ca_cert_pem, ca_key_pem) = ca.into_pem();
	Ok(InitOutput {
		layout,
		server_bundle: server,
		admin_bundle: admin,
		ca_cert_pem,
		ca_key_pem,
		master_key,
		minted_master_key,
		persisted_secrets: options.persist_secrets,
	})
}

fn write_secret(path: &Path, contents: &[u8]) -> Result<()> {
	write_secret_parts(path, &[contents])
}

fn write_secret_parts(path: &Path, parts: &[&[u8]]) -> Result<()> {
	use std::io::Write;
	#[cfg(unix)]
	let mut file = {
		use std::os::unix::fs::OpenOptionsExt;
		#[allow(
			clippy::disallowed_methods,
			reason = "initialization exports generated secret bytes only by exclusive creation with mode 0600 in its selected layout"
		)]
		let file = std::fs::OpenOptions::new()
			.write(true)
			.create_new(true)
			.mode(0o600)
			.open(path)
			.with_context(|| format!("creating {}", path.display()))?;
		file
	};
	#[cfg(not(unix))]
	#[allow(
		clippy::disallowed_methods,
		reason = "initialization writes generated bundle material to its Config-selected layout on non-Unix hosts"
	)]
	let mut file =
		std::fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
	for part in parts {
		file.write_all(part).with_context(|| format!("writing {}", path.display()))?;
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
		let out = run_init(
			&crate::test_support::path(tmp.path()),
			&crate::test_support::hostnames(&["localhost"]),
			None,
		)
		.unwrap();
		assert!(out.layout.ca_cert.as_path().exists());
		assert!(out.layout.server_cert.as_path().exists());
		assert!(out.layout.admin_cert.as_path().exists());
		assert!(
			out.layout.master_key.as_path().exists(),
			"init must persist the freshly-minted key"
		);
		assert!(out.layout.db_path.as_path().exists());
		assert!(out.minted_master_key, "minted_master_key must be true when no caller_key");

		// master.key must be 64 hex chars + newline.
		let raw = std::fs::read_to_string(out.layout.master_key.as_path()).unwrap();
		let trimmed = raw.trim_end();
		assert_eq!(raw.len(), 65);
		assert_eq!(raw.as_bytes().last(), Some(&b'\n'));
		assert_eq!(trimmed.len(), 64);
		assert!(trimmed.chars().all(|c| c.is_ascii_hexdigit()));
		assert_eq!(trimmed, out.master_key.to_hex().expose());
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			let mode =
				std::fs::metadata(out.layout.master_key.as_path()).unwrap().permissions().mode();
			assert_eq!(mode & 0o777, 0o600);
		}

		// Admin bundle must be parseable as a real cert.
		assert!(out.admin_bundle.cert_pem.contains("BEGIN CERTIFICATE"));
		assert!(out.admin_bundle.key_pem.expose().contains("PRIVATE KEY"));

		// Admin must be in the workers table — re-open the DB with the
		// same key to read it back.
		let key_bytes = decode_hex(trimmed);
		let key = MasterKey::from_bytes(key_bytes);
		let db = Db::open(out.layout.db_path.as_path(), &key).unwrap();
		let admin_der = pem_first_cert_der(&out.admin_bundle.cert_pem).unwrap();
		let fp = cert_fingerprint(&admin_der);
		let row = loupe_storage::registry::authenticate(&db, &fp)
			.unwrap()
			.expect("admin must be registered after init");
		assert_eq!(row.kind, WorkerKind::Admin);
		assert_eq!(row.name.expose(), "admin");
	}

	#[test]
	fn caller_supplied_key_is_used_and_not_persisted() {
		let tmp = tempfile::tempdir().unwrap();
		let key = MasterKey::from_bytes([0x42u8; 32]);
		let out = run_init(
			&crate::test_support::path(tmp.path()),
			&crate::test_support::hostnames(&["localhost"]),
			Some(key),
		)
		.unwrap();
		assert!(
			!out.layout.master_key.as_path().exists(),
			"caller-supplied key must not be persisted to disk"
		);
		assert!(!out.minted_master_key);
		// DB only opens with the same key — proves init actually used it.
		let same = MasterKey::from_bytes([0x42u8; 32]);
		assert!(Db::open(out.layout.db_path.as_path(), &same).is_ok());
		assert!(Db::open(out.layout.db_path.as_path(), &MasterKey::from_bytes([0x43; 32])).is_err());
	}

	#[test]
	fn can_bootstrap_without_persisting_secret_files() {
		let tmp = tempfile::tempdir().unwrap();
		let out = run_init_with_options(
			&crate::test_support::path(tmp.path()),
			&crate::test_support::hostnames(&["localhost"]),
			None,
			InitOptions { persist_secrets: false },
		)
		.unwrap();
		assert!(!out.layout.ca_cert.as_path().exists());
		assert!(!out.layout.ca_key.as_path().exists());
		assert!(!out.layout.server_cert.as_path().exists());
		assert!(!out.layout.server_key.as_path().exists());
		assert!(!out.layout.admin_cert.as_path().exists());
		assert!(!out.layout.admin_key.as_path().exists());
		assert!(!out.layout.master_key.as_path().exists());
		assert!(out.layout.db_path.as_path().exists());
		assert!(out.minted_master_key);
		assert!(!out.persisted_secrets);

		let db = Db::open(out.layout.db_path.as_path(), &out.master_key).unwrap();
		let admin_der = pem_first_cert_der(&out.admin_bundle.cert_pem).unwrap();
		let fp = cert_fingerprint(&admin_der);
		let row = loupe_storage::registry::authenticate(&db, &fp)
			.unwrap()
			.expect("admin must be registered after env-only init");
		assert_eq!(row.kind, WorkerKind::Admin);
		assert_eq!(row.name.expose(), "admin");
	}

	#[test]
	fn second_init_refuses_existing_data_dir() {
		let tmp = tempfile::tempdir().unwrap();
		run_init(
			&crate::test_support::path(tmp.path()),
			&crate::test_support::hostnames(&["localhost"]),
			None,
		)
		.unwrap();
		let err = match run_init(
			&crate::test_support::path(tmp.path()),
			&crate::test_support::hostnames(&["localhost"]),
			None,
		) {
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
