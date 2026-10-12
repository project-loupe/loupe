use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
mod input;
pub use input::{
	select_tls_pem, ConfiguredHostname, ConfiguredPath, ConfiguredPem, ConfiguredPemArgument,
	HostnameParser, PathParser, PemParser,
};
use loupe_core::text::policy::RepoOwner;
use loupe_core::text::BoundedText;
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
pub struct Config {
	pub bind_addr: SocketAddr,
	pub db_path: ConfiguredPath,
	pub server_cert_pem: ConfiguredPem,
	pub server_key_pem: ConfiguredPem,
	pub ca_cert_pem: ConfiguredPem,
	pub ca_key_pem: ConfiguredPem,
}
impl std::fmt::Debug for Config {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		// Preserve the existing public-path diagnostic; PEM owners redact.
		f.debug_struct("Config")
			.field("bind_addr", &self.bind_addr)
			.field("db_path", &self.db_path.as_path())
			.field("server_cert_pem", &self.server_cert_pem)
			.field("server_key_pem", &self.server_key_pem)
			.field("ca_cert_pem", &self.ca_cert_pem)
			.field("ca_key_pem", &self.ca_key_pem)
			.finish()
	}
}
impl Config {
	pub(crate) fn build_tls(&self) -> Result<rustls::ServerConfig> {
		loupe_tls::server_config(
			self.server_cert_pem.0.expose(),
			self.server_key_pem.0.expose(),
			self.ca_cert_pem.0.expose(),
		)
		.context("building loupe-server rustls config")
	}
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
#[derive(Debug, Clone, Default)]
pub struct FileConfig {
	pub server: ServerSection,
	pub paths: PathsSection,
	pub policy: PolicySection,
	pub review: ReviewSection,
	pub github_app: GithubAppSection,
	pub worker_budgets: crate::request_budget::WorkerBudgetConfig,
}

/// Limits on reporting through the server-wide GitHub App. The app's
/// installation on GitHub already decides which trackers it can write
/// to; this section lets the server refuse destinations outside an
/// expected owner set before an issue is ever filed.
#[derive(Debug, Clone, Default)]
pub struct GithubAppSection {
	/// Tracker owners (users or organizations) that app-mode GitHub
	/// destinations may point at, compared case-insensitively. Unset
	/// means no server-side restriction.
	pub allowed_target_owners: Option<Vec<BoundedText<RepoOwner, ConfigSource>>>,
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

#[derive(Debug, Clone, Default)]
pub struct PathsSection {
	pub db: Option<ConfiguredPath>,
	pub server_cert: Option<ConfiguredPath>,
	pub server_key: Option<ConfiguredPath>,
	pub ca_cert: Option<ConfiguredPath>,
	pub ca_key: Option<ConfiguredPath>,
	/// Path to a file holding the database master key as 64 hex
	/// characters (the shape `loupe-server init` writes). Loaded once
	/// at server startup and used for SQLCipher's `PRAGMA key`. Lower
	/// priority than the `LOUPE_MASTER_KEY` env var.
	pub master_key: Option<ConfiguredPath>,
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
		let cfg =
			Untrusted::new(raw, ingress).as_bytes().validate(ServerFileConfigDecoder { base })?;
		cfg.github_app
			.validate()
			.with_context(|| format!("validating config file {}", path.display()))?;
		cfg.worker_budgets.validate()?;
		Ok(cfg)
	}
}

// Private wire schema: only the actual TOML decoder constructs retained Config owners.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFileConfig {
	#[serde(default)]
	server: ServerSection,
	#[serde(default)]
	paths: RawPaths,
	#[serde(default)]
	policy: PolicySection,
	#[serde(default)]
	review: ReviewSection,
	#[serde(default)]
	github_app: RawGithubApp,
	#[serde(default)]
	worker_budgets: crate::request_budget::WorkerBudgetConfig,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPaths {
	db: Option<PathBuf>,
	server_cert: Option<PathBuf>,
	server_key: Option<PathBuf>,
	ca_cert: Option<PathBuf>,
	ca_key: Option<PathBuf>,
	master_key: Option<PathBuf>,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGithubApp {
	allowed_target_owners: Option<Vec<String>>,
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
	type Output = FileConfig;
	type Error = ConfigDecodeError;
	fn validate<'view>(
		self, input: Unvalidated<'view, &[u8]>, mark: Mark<'view, ConfigSource>,
	) -> Result<Self::Output, Self::Error> {
		let raw = std::str::from_utf8(input.get())
			.map_err(|_| ConfigDecodeError::Toml("invalid UTF-8"))?;
		// TOML parser scratch belongs to the pinned dependency. No whole-file
		// ceiling is invented; admitted free text receives its exact field cap.
		let mut cfg: RawFileConfig = toml::from_str(raw).map_err(|error: toml::de::Error| {
			ConfigDecodeError::Toml(crate::ingress::error::category(&error.message()))
		})?;
		let paths = std::mem::take(&mut cfg.paths);
		let paths = PathsSection {
			db: paths.db.map(|path| ConfiguredPath::from_file(&mark, self.base, path)),
			server_cert: paths
				.server_cert
				.map(|path| ConfiguredPath::from_file(&mark, self.base, path)),
			server_key: paths
				.server_key
				.map(|path| ConfiguredPath::from_file(&mark, self.base, path)),
			ca_cert: paths.ca_cert.map(|path| ConfiguredPath::from_file(&mark, self.base, path)),
			ca_key: paths.ca_key.map(|path| ConfiguredPath::from_file(&mark, self.base, path)),
			master_key: paths
				.master_key
				.map(|path| ConfiguredPath::from_file(&mark, self.base, path)),
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
		Ok(FileConfig {
			server: cfg.server,
			paths,
			policy: cfg.policy,
			review: cfg.review,
			github_app: GithubAppSection { allowed_target_owners: owners },
			worker_budgets: cfg.worker_budgets,
		})
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
		assert_eq!(cfg.paths.db.unwrap().as_path(), dir.path().join("data/loupe.db"));
		assert_eq!(cfg.paths.server_cert.unwrap().as_path(), dir.path().join("certs/server.pem"));
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
			cfg.github_app
				.allowed_target_owners
				.as_ref()
				.map(|owners| owners.iter().map(BoundedText::expose).collect::<Vec<_>>()),
			Some(vec!["acme", "Acme-Labs"])
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
			db_path: crate::test_support::path(Path::new("unused")),
			server_cert_pem: crate::test_support::pem(&format!(
				"{}{}",
				unused.key_pem.expose(),
				server.cert_pem
			)),
			server_key_pem: crate::test_support::pem(server.key_pem.expose()),
			ca_cert_pem: crate::test_support::pem(&format!(
				"{}{}",
				ca.cert_pem(),
				unused.key_pem.expose()
			)),
			ca_key_pem: crate::test_support::pem(ca.key_pem().expose()),
		};
		assert!(crate::tls::build(&cfg).is_ok());
	}

	#[test]
	fn tls_consumer_config_debug_redacts_keys_and_mixed_certificate_inputs() {
		let cfg = Config {
			bind_addr: "127.0.0.1:8443".parse().unwrap(),
			db_path: crate::test_support::path(Path::new("public-database-path")),
			server_cert_pem: crate::test_support::pem("public-cert\nFAKE_MIXED_SERVER_PRIVATE"),
			server_key_pem: crate::test_support::pem("FAKE_SERVER_PRIVATE"),
			ca_cert_pem: crate::test_support::pem("public-ca\nFAKE_MIXED_CA_PRIVATE"),
			ca_key_pem: crate::test_support::pem("FAKE_CA_PRIVATE"),
		};
		for rendered in [format!("{cfg:?}"), format!("{cfg:#?}")] {
			assert!(rendered.contains("public-database-path"));
			assert!(!rendered.contains("FAKE_"), "Config Debug disclosed private TLS input");
		}
	}
}
