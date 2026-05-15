use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

/// Server configuration. Populated by `loupe-server`'s clap parser; lives
/// here so integration tests can construct one directly without going
/// through env / CLI.
#[derive(Debug, Clone)]
pub struct Config {
	pub bind_addr: SocketAddr,
	pub db_path: PathBuf,
	pub server_cert_pem: String,
	pub server_key_pem: String,
	pub ca_cert_pem: String,
	pub ca_key_pem: String,
}

/// Wire shape of `config.toml`. All fields are optional so an operator
/// can ship a minimal file and let CLI / env supply the rest. Concrete
/// runtime use is in `main.rs::run_serve`, which layers
/// `defaults → file → env → flags` (later wins) before constructing
/// the final `Config` and `AppState`.
///
/// Path-typed fields under `[paths]` (db, server cert/key, CA
/// cert/key) are interpreted relative to the directory containing the
/// config file, so a single `config.toml` can ship next to the data
/// directory without forcing absolute paths on operators.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
	#[serde(default)]
	pub server: ServerSection,
	#[serde(default)]
	pub paths: PathsSection,
	#[serde(default)]
	pub policy: PolicySection,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
	#[serde(default)]
	pub bind: Option<SocketAddr>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathsSection {
	#[serde(default)]
	pub db: Option<PathBuf>,
	#[serde(default)]
	pub server_cert: Option<PathBuf>,
	#[serde(default)]
	pub server_key: Option<PathBuf>,
	#[serde(default)]
	pub ca_cert: Option<PathBuf>,
	#[serde(default)]
	pub ca_key: Option<PathBuf>,
	/// Path to a file holding the database master key as 64 hex
	/// characters (the shape `loupe-server init` writes). Loaded once
	/// at server startup and used for SQLCipher's `PRAGMA key`. Lower
	/// priority than the `LOUPE_MASTER_KEY` env var.
	#[serde(default)]
	pub master_key: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySection {
	/// Server-level default for the human-in-the-loop approval gate.
	/// Per-repo `require_approval` overrides this on a row-by-row
	/// basis. Defaults to `false` (immediate dispatch) when unset
	/// here AND unset on the repo.
	#[serde(default)]
	pub require_approval_default: Option<bool>,
	/// Server-level default for routing scan findings through verifier
	/// jobs before dispatch. Repo registrations can override this
	/// explicitly; existing repos keep the value resolved at
	/// registration time.
	#[serde(default)]
	#[serde(alias = "verification_enabled_default")]
	pub verification_default: Option<bool>,
}

impl FileConfig {
	/// Read and parse a TOML config from disk. Path-typed fields are
	/// resolved relative to the file's parent directory, then returned
	/// in absolute form so callers don't need to remember the base.
	pub fn load(path: &Path) -> Result<Self> {
		let raw = std::fs::read_to_string(path)
			.with_context(|| format!("reading config file {}", path.display()))?;
		let mut cfg: FileConfig = toml::from_str(&raw)
			.with_context(|| format!("parsing config file {}", path.display()))?;
		let base = path.parent().unwrap_or_else(|| Path::new("."));
		cfg.paths.db = cfg.paths.db.map(|p| resolve(base, p));
		cfg.paths.server_cert = cfg.paths.server_cert.map(|p| resolve(base, p));
		cfg.paths.server_key = cfg.paths.server_key.map(|p| resolve(base, p));
		cfg.paths.ca_cert = cfg.paths.ca_cert.map(|p| resolve(base, p));
		cfg.paths.ca_key = cfg.paths.ca_key.map(|p| resolve(base, p));
		cfg.paths.master_key = cfg.paths.master_key.map(|p| resolve(base, p));
		Ok(cfg)
	}
}

fn resolve(base: &Path, p: PathBuf) -> PathBuf {
	if p.is_absolute() {
		p
	} else {
		base.join(p)
	}
}

#[cfg(test)]
mod tests {
	use std::io::Write;

	use super::*;

	#[test]
	fn empty_file_parses_to_default() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("config.toml");
		std::fs::File::create(&path).unwrap().write_all(b"").unwrap();
		let cfg = FileConfig::load(&path).unwrap();
		assert!(cfg.server.bind.is_none());
		assert!(cfg.policy.require_approval_default.is_none());
		assert!(cfg.policy.verification_default.is_none());
	}

	#[test]
	fn relative_paths_resolve_against_file_dir() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("config.toml");
		std::fs::write(
			&path,
			b"[paths]\ndb = \"data/loupe.db\"\nserver_cert = \"certs/server.pem\"\n",
		)
		.unwrap();
		let cfg = FileConfig::load(&path).unwrap();
		assert_eq!(cfg.paths.db.unwrap(), dir.path().join("data/loupe.db"));
		assert_eq!(cfg.paths.server_cert.unwrap(), dir.path().join("certs/server.pem"));
	}

	#[test]
	fn unknown_field_is_an_error() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("config.toml");
		std::fs::write(&path, b"[server]\nunexpected = 42\n").unwrap();
		let err = FileConfig::load(&path).unwrap_err();
		let msg = format!("{err:#}");
		assert!(
			msg.contains("unknown field") || msg.contains("unexpected"),
			"expected unknown-field error, got: {msg}"
		);
	}

	#[test]
	fn policy_section_round_trips() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("config.toml");
		std::fs::write(
			&path,
			b"[policy]\nrequire_approval_default = true\nverification_default = true\n",
		)
		.unwrap();
		let cfg = FileConfig::load(&path).unwrap();
		assert_eq!(cfg.policy.require_approval_default, Some(true));
		assert_eq!(cfg.policy.verification_default, Some(true));
	}
}
