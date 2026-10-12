use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use loupe_core::source_migration::text::BoundedText;
use loupe_core::text::policy::RepoOwner;
use loupe_provenance::{Config as ConfigSource, Ingress, Mark, Untrusted, Unvalidated, Validate};
use serde::Deserialize;

/// Server configuration. Populated by `loupe-server`'s clap parser; lives
/// here so integration tests can construct one directly without going
/// through env / CLI.
///
/// ```compile_fail,E0599
/// fn duplicate(config: loupe_server::Config) {
///     let _copy = config.clone();
/// }
/// ```
///
/// ```
/// let metadata: fn(&loupe_server::Config) -> std::net::SocketAddr = |config| config.bind_addr;
/// ```
#[derive(Debug)]
pub struct Config {
	pub bind_addr: SocketAddr,
	pub db_path: PathBuf,
	pub server_cert_pem: loupe_provenance::Secret<String>,
	pub server_key_pem: loupe_provenance::Secret<String>,
	pub ca_cert_pem: loupe_provenance::Secret<String>,
	pub ca_key_pem: loupe_provenance::Secret<String>,
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
	#[serde(default)]
	pub review: ReviewSection,
	#[serde(default)]
	pub github_app: GithubAppSection,
	#[serde(default)]
	pub worker_budgets: crate::request_budget::WorkerBudgetConfig,
}

/// Limits on reporting through the server-wide GitHub App. The app's
/// installation on GitHub already decides which trackers it can write
/// to; this section lets the server refuse destinations outside an
/// expected owner set before an issue is ever filed.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubAppSection {
	/// Tracker owners (users or organizations) that app-mode GitHub
	/// destinations may point at, compared case-insensitively. Unset
	/// means no server-side restriction.
	#[serde(default)]
	pub allowed_target_owners: Option<Vec<String>>,
}

/// Review-harness overrides. Environment and CLI overrides arrive at cutover.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewSection {
	pub active_jobs_per_repo: Option<i64>,
	pub active_jobs_total: Option<i64>,
	pub active_surveys_per_repo: Option<i64>,
	pub active_drilldowns_per_repo: Option<i64>,
	pub active_verifications_per_repo: Option<i64>,
	pub verify_reserved_slots: Option<i64>,
	pub survey_units_per_job: Option<i64>,
	pub survey_deadline_seconds: Option<i64>,
	pub survey_submit_margin_seconds: Option<i64>,
	pub drilldown_deadline_seconds: Option<i64>,
	pub drilldown_submit_margin_seconds: Option<i64>,
	pub verify_deadline_seconds: Option<i64>,
	pub verify_submit_margin_seconds: Option<i64>,
	pub lease_seconds: Option<i64>,
	pub lease_report_grace_seconds: Option<i64>,
	pub max_attempts: Option<u32>,
	pub retry_backoff_base_seconds: Option<i64>,
	pub retry_backoff_cap_seconds: Option<i64>,
	pub urgency_burst_length: Option<i64>,
	pub campaign_handoff_reserve: Option<i64>,
	pub campaign_deadline_seconds: Option<i64>,
	pub campaign_max_jobs: Option<i64>,
	pub priority_aging_interval_seconds: Option<i64>,
	pub priority_aging_cap: Option<i64>,
	pub survey_token_budget: Option<u64>,
	pub drilldown_token_budget: Option<u64>,
	pub verify_token_budget: Option<u64>,
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
		let base = path.parent().unwrap_or_else(|| Path::new("."));
		// SAFETY: raw is this actual configuration-file read, before TOML parsing.
		#[allow(unsafe_code)]
		let ingress = unsafe { Ingress::<ConfigSource>::new() };
		let cfg = ServerFileConfigDecoder { base }.decode_legacy(Untrusted::new(raw, ingress))?;
		cfg.github_app
			.validate()
			.with_context(|| format!("validating config file {}", path.display()))?;
		cfg.worker_budgets.validate()?;
		Ok(cfg)
	}
}

// Host paths retain their native representation and relative resolution. They
// are not RepoPath and have no lossy UTF-8 conversion or repository-path cap.
struct ConfiguredPath(PathBuf);
impl ConfiguredPath {
	fn new(_: &Mark<'_, ConfigSource>, base: &Path, path: PathBuf) -> Self {
		Self(resolve(base, path))
	}
}
struct ConfiguredPaths {
	db: Option<ConfiguredPath>,
	server_cert: Option<ConfiguredPath>,
	server_key: Option<ConfiguredPath>,
	ca_cert: Option<ConfiguredPath>,
	ca_key: Option<ConfiguredPath>,
	master_key: Option<ConfiguredPath>,
}
struct ServerFileInput {
	// Text/path fields are removed before this closed-scalar remainder is stored.
	scalars: FileConfig,
	paths: ConfiguredPaths,
	owners: Option<Vec<BoundedText<RepoOwner, ConfigSource>>>,
}
#[derive(Debug, thiserror::Error)]
enum ConfigDecodeError {
	#[error("parsing config file: {0}")]
	Toml(&'static str),
	#[error(transparent)]
	Text(#[from] loupe_core::text::Error),
}
struct ServerFileConfigDecoder<'a> {
	base: &'a Path,
}
impl Validate<&[u8], ConfigSource> for ServerFileConfigDecoder<'_> {
	type Output = ServerFileInput;
	type Error = ConfigDecodeError;
	fn validate<'view>(
		self, input: Unvalidated<'view, &[u8]>, mark: Mark<'view, ConfigSource>,
	) -> Result<Self::Output, Self::Error> {
		let raw = std::str::from_utf8(input.get())
			.map_err(|_| ConfigDecodeError::Toml("invalid UTF-8"))?;
		// TOML parser scratch belongs to the pinned dependency. No whole-file
		// ceiling is invented; admitted free text receives its exact field cap.
		let mut cfg: FileConfig = toml::from_str(raw).map_err(|error: toml::de::Error| {
			ConfigDecodeError::Toml(crate::ingress::error::category(&error.message()))
		})?;
		let paths = std::mem::take(&mut cfg.paths);
		let paths = ConfiguredPaths {
			db: paths.db.map(|path| ConfiguredPath::new(&mark, self.base, path)),
			server_cert: paths.server_cert.map(|path| ConfiguredPath::new(&mark, self.base, path)),
			server_key: paths.server_key.map(|path| ConfiguredPath::new(&mark, self.base, path)),
			ca_cert: paths.ca_cert.map(|path| ConfiguredPath::new(&mark, self.base, path)),
			ca_key: paths.ca_key.map(|path| ConfiguredPath::new(&mark, self.base, path)),
			master_key: paths.master_key.map(|path| ConfiguredPath::new(&mark, self.base, path)),
		};
		let owners = cfg
			.github_app
			.allowed_target_owners
			.take()
			.map(|owners| {
				owners
					.iter()
					.map(|owner| BoundedText::new(&mark, owner))
					.collect::<Result<Vec<_>, _>>()
			})
			.transpose()?;
		Ok(ServerFileInput { scalars: cfg, paths, owners })
	}
}
impl ServerFileConfigDecoder<'_> {
	/// Temporary I exit for the existing defaults→file→env→flags process owner.
	fn decode_legacy(self, input: Untrusted<String, ConfigSource>) -> Result<FileConfig> {
		let input = input.as_bytes().validate(self)?;
		let mut cfg = input.scalars;
		cfg.paths = PathsSection {
			db: input.paths.db.map(|path| path.0),
			server_cert: input.paths.server_cert.map(|path| path.0),
			server_key: input.paths.server_key.map(|path| path.0),
			ca_cert: input.paths.ca_cert.map(|path| path.0),
			ca_key: input.paths.ca_key.map(|path| path.0),
			master_key: input.paths.master_key.map(|path| path.0),
		};
		cfg.github_app.allowed_target_owners = input
			.owners
			.map(|owners| owners.iter().map(|owner| owner.expose().to_owned()).collect());
		Ok(cfg)
	}
}

impl GithubAppSection {
	/// An empty allowlist would silently refuse every app-mode
	/// destination; make the operator say what they mean instead.
	pub fn validate(&self) -> Result<()> {
		if matches!(&self.allowed_target_owners, Some(owners) if owners.is_empty()) {
			anyhow::bail!(
				"[github_app] allowed_target_owners must list at least one owner or be omitted"
			);
		}
		Ok(())
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

	#[test]
	fn github_app_section_lists_allowed_owners() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("config.toml");
		std::fs::write(&path, b"[github_app]\nallowed_target_owners = [\"acme\", \"Acme-Labs\"]\n")
			.unwrap();
		let cfg = FileConfig::load(&path).unwrap();
		assert_eq!(
			cfg.github_app.allowed_target_owners,
			Some(vec!["acme".to_owned(), "Acme-Labs".to_owned()])
		);

		let empty = dir.path().join("empty.toml");
		std::fs::write(&empty, b"").unwrap();
		assert_eq!(FileConfig::load(&empty).unwrap().github_app.allowed_target_owners, None);
	}

	#[test]
	fn empty_allowed_owner_list_is_rejected_at_load() {
		// `[]` would silently refuse every app-mode destination; an
		// operator who wants that should see it at startup, not per repo.
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("config.toml");
		std::fs::write(&path, b"[github_app]\nallowed_target_owners = []\n").unwrap();
		let err = FileConfig::load(&path).unwrap_err();
		let msg = format!("{err:#}");
		assert!(
			msg.contains("allowed_target_owners must list at least one owner or be omitted"),
			"got: {msg}"
		);
	}
}

#[cfg(test)]
mod tls_consumer_tests {
	use super::*;

	#[test]
	fn server_config_accepts_mixed_certificate_and_ca_inputs() {
		let ca = loupe_tls::Ca::new("throwaway-config-ca").unwrap();
		let server = ca.mint_server("server", &["localhost".into()]).unwrap();
		let unused = ca.mint_client("unused").unwrap();
		let cfg = Config {
			bind_addr: "127.0.0.1:0".parse().unwrap(),
			db_path: "unused".into(),
			server_cert_pem: loupe_provenance::Secret::new(format!(
				"{}{}",
				unused.key_pem.expose(),
				server.cert_pem
			)),
			server_key_pem: server.key_pem,
			ca_cert_pem: loupe_provenance::Secret::new(format!(
				"{}{}",
				ca.cert_pem(),
				unused.key_pem.expose()
			)),
			ca_key_pem: loupe_provenance::Secret::new(ca.key_pem().expose().to_owned()),
		};
		assert!(crate::tls::build(&cfg).is_ok());
	}

	#[test]
	fn tls_consumer_config_debug_redacts_keys_and_mixed_certificate_inputs() {
		let cfg = Config {
			bind_addr: "127.0.0.1:8443".parse().unwrap(),
			db_path: "public-database-path".into(),
			server_cert_pem: loupe_provenance::Secret::new(
				"public-cert\nFAKE_MIXED_SERVER_PRIVATE".into(),
			),
			server_key_pem: loupe_provenance::Secret::new("FAKE_SERVER_PRIVATE".into()),
			ca_cert_pem: loupe_provenance::Secret::new("public-ca\nFAKE_MIXED_CA_PRIVATE".into()),
			ca_key_pem: loupe_provenance::Secret::new("FAKE_CA_PRIVATE".into()),
		};
		for rendered in [format!("{cfg:?}"), format!("{cfg:#?}")] {
			assert!(rendered.contains("public-database-path"));
			assert!(!rendered.contains("FAKE_"), "Config Debug disclosed private TLS input");
		}
	}
}
