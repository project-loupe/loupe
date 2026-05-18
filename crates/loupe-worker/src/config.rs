use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::llm::claude_cli::{DEFAULT_CLAUDE_EFFORT, DEFAULT_CLAUDE_MODEL};
use crate::llm::codex_cli::{DEFAULT_CODEX_EFFORT, DEFAULT_CODEX_MODEL};
use crate::llm::mcp::DEFAULT_BKB_API_URL;
use crate::llm::{CliModelConfig, DEFAULT_REQUEST_TIMEOUT};
use crate::runner::DEFAULT_MAX_WORKDIR_BYTES;
use crate::scanners::LlmScannerConfig;

const DEFAULT_CACHE_DIR: &str = "/var/cache/loupe-worker";
const DEFAULT_MAX_CACHE_GB: u64 = 40;
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_MAX_CONCURRENT_FILES: usize = 8;
const DEFAULT_MAX_FILE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone)]
pub struct WorkerConfig {
	pub server_url: Option<reqwest::Url>,
	pub tls: TlsConfig,
	pub cache: CacheConfig,
	pub runtime: RuntimeConfig,
	pub logging: LoggingConfig,
	pub agents: AgentsConfig,
	pub scanner_defaults: LlmScannerConfig,
	pub bkb: BkbConfig,
}

#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
	pub ca_cert: Option<PathBuf>,
	pub cert: Option<PathBuf>,
	pub key: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct CacheConfig {
	pub dir: PathBuf,
	pub max_gb: u64,
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
	pub max_workdir_bytes: u64,
	pub disable_sandbox: bool,
}

#[derive(Debug, Clone)]
pub struct LoggingConfig {
	pub level: String,
	pub json: bool,
	pub agent_output: bool,
}

#[derive(Debug, Clone)]
pub struct AgentsConfig {
	pub claude: CliModelConfig,
	pub codex: CliModelConfig,
}

#[derive(Debug, Clone)]
pub struct BkbConfig {
	pub api_url: String,
}

#[derive(Debug, Clone, Default)]
pub struct WorkerConfigOverrides {
	pub server_url: Option<reqwest::Url>,
	pub ca_cert: Option<PathBuf>,
	pub cert: Option<PathBuf>,
	pub key: Option<PathBuf>,
	pub cache_dir: Option<PathBuf>,
	pub max_cache_gb: Option<u64>,
	pub max_workdir_gb: Option<u64>,
	pub disable_sandbox: Option<bool>,
	pub log_level: Option<String>,
	pub log_json: Option<bool>,
	pub log_agent_output: Option<bool>,
	pub claude_model: Option<String>,
	pub claude_effort: Option<String>,
	pub codex_model: Option<String>,
	pub codex_effort: Option<String>,
	pub max_concurrent_files: Option<usize>,
	pub max_file_bytes: Option<u64>,
	pub per_request_timeout_seconds: Option<u64>,
	pub bkb_api_url: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
	#[serde(default)]
	pub server: ServerSection,
	#[serde(default)]
	pub tls: TlsSection,
	#[serde(default)]
	pub cache: CacheSection,
	#[serde(default)]
	pub runtime: RuntimeSection,
	#[serde(default)]
	pub logging: LoggingSection,
	#[serde(default)]
	pub agents: AgentsSection,
	#[serde(default)]
	pub scanner_defaults: ScannerDefaultsSection,
	#[serde(default)]
	pub bkb: BkbSection,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
	#[serde(default)]
	pub url: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSection {
	#[serde(default)]
	pub ca_cert: Option<PathBuf>,
	#[serde(default)]
	pub cert: Option<PathBuf>,
	#[serde(default)]
	pub key: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheSection {
	#[serde(default)]
	pub dir: Option<PathBuf>,
	#[serde(default)]
	pub max_gb: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSection {
	#[serde(default)]
	pub max_workdir_gb: Option<u64>,
	#[serde(default)]
	pub disable_sandbox: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingSection {
	#[serde(default)]
	pub level: Option<String>,
	#[serde(default)]
	pub json: Option<bool>,
	#[serde(default)]
	pub agent_output: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentsSection {
	#[serde(default)]
	pub claude: AgentSection,
	#[serde(default)]
	pub codex: AgentSection,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSection {
	#[serde(default)]
	pub model: Option<String>,
	#[serde(default)]
	pub effort: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScannerDefaultsSection {
	#[serde(default)]
	pub max_concurrent_files: Option<usize>,
	#[serde(default)]
	pub max_file_bytes: Option<u64>,
	#[serde(default)]
	pub per_request_timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BkbSection {
	#[serde(default)]
	pub api_url: Option<String>,
}

impl WorkerConfig {
	pub fn load(path: Option<&Path>, overrides: WorkerConfigOverrides) -> Result<Self> {
		let mut cfg = WorkerConfig::default();
		if let Some(path) = path {
			cfg.apply_file(FileConfig::load(path)?)?;
		}
		cfg.apply_overrides(overrides);
		cfg.validate()?;
		Ok(cfg)
	}

	fn apply_file(&mut self, file: FileConfig) -> Result<()> {
		if let Some(v) = file.server.url {
			self.server_url = Some(
				v.parse::<reqwest::Url>().with_context(|| format!("parsing [server].url `{v}`"))?,
			);
		}
		if let Some(v) = file.tls.ca_cert {
			self.tls.ca_cert = Some(v);
		}
		if let Some(v) = file.tls.cert {
			self.tls.cert = Some(v);
		}
		if let Some(v) = file.tls.key {
			self.tls.key = Some(v);
		}
		if let Some(v) = file.cache.dir {
			self.cache.dir = v;
		}
		if let Some(v) = file.cache.max_gb {
			self.cache.max_gb = v;
		}
		if let Some(v) = file.runtime.max_workdir_gb {
			self.runtime.max_workdir_bytes = gb_to_bytes(v);
		}
		if let Some(v) = file.runtime.disable_sandbox {
			self.runtime.disable_sandbox = v;
		}
		if let Some(v) = file.logging.level {
			self.logging.level = v;
		}
		if let Some(v) = file.logging.json {
			self.logging.json = v;
		}
		if let Some(v) = file.logging.agent_output {
			self.logging.agent_output = v;
		}
		if let Some(v) = file.agents.claude.model {
			self.agents.claude.model = v;
		}
		if let Some(v) = file.agents.claude.effort {
			self.agents.claude.effort = v;
		}
		if let Some(v) = file.agents.codex.model {
			self.agents.codex.model = v;
		}
		if let Some(v) = file.agents.codex.effort {
			self.agents.codex.effort = v;
		}
		if let Some(v) = file.scanner_defaults.max_concurrent_files {
			self.scanner_defaults.max_concurrent_files = v;
		}
		if let Some(v) = file.scanner_defaults.max_file_bytes {
			self.scanner_defaults.max_file_bytes = v;
		}
		if let Some(v) = file.scanner_defaults.per_request_timeout_seconds {
			self.scanner_defaults.per_request_timeout = Duration::from_secs(v);
		}
		if let Some(v) = file.bkb.api_url {
			self.bkb.api_url = v;
		}
		Ok(())
	}

	fn apply_overrides(&mut self, overrides: WorkerConfigOverrides) {
		if let Some(v) = overrides.server_url {
			self.server_url = Some(v);
		}
		if let Some(v) = overrides.ca_cert {
			self.tls.ca_cert = Some(v);
		}
		if let Some(v) = overrides.cert {
			self.tls.cert = Some(v);
		}
		if let Some(v) = overrides.key {
			self.tls.key = Some(v);
		}
		if let Some(v) = overrides.cache_dir {
			self.cache.dir = v;
		}
		if let Some(v) = overrides.max_cache_gb {
			self.cache.max_gb = v;
		}
		if let Some(v) = overrides.max_workdir_gb {
			self.runtime.max_workdir_bytes = gb_to_bytes(v);
		}
		if let Some(v) = overrides.disable_sandbox {
			self.runtime.disable_sandbox = v;
		}
		if let Some(v) = overrides.log_level {
			self.logging.level = v;
		}
		if let Some(v) = overrides.log_json {
			self.logging.json = v;
		}
		if let Some(v) = overrides.log_agent_output {
			self.logging.agent_output = v;
		}
		if let Some(v) = overrides.claude_model {
			self.agents.claude.model = v;
		}
		if let Some(v) = overrides.claude_effort {
			self.agents.claude.effort = v;
		}
		if let Some(v) = overrides.codex_model {
			self.agents.codex.model = v;
		}
		if let Some(v) = overrides.codex_effort {
			self.agents.codex.effort = v;
		}
		if let Some(v) = overrides.max_concurrent_files {
			self.scanner_defaults.max_concurrent_files = v;
		}
		if let Some(v) = overrides.max_file_bytes {
			self.scanner_defaults.max_file_bytes = v;
		}
		if let Some(v) = overrides.per_request_timeout_seconds {
			self.scanner_defaults.per_request_timeout = Duration::from_secs(v);
		}
		if let Some(v) = overrides.bkb_api_url {
			self.bkb.api_url = v;
		}
	}

	fn validate(&self) -> Result<()> {
		validate_nonempty("agents.claude.model", &self.agents.claude.model)?;
		validate_nonempty("agents.codex.model", &self.agents.codex.model)?;
		validate_effort(
			"agents.claude.effort",
			&self.agents.claude.effort,
			&["low", "medium", "high", "xhigh", "max"],
		)?;
		validate_effort(
			"agents.codex.effort",
			&self.agents.codex.effort,
			&["none", "low", "medium", "high", "xhigh"],
		)?;
		validate_effort(
			"logging.level",
			&self.logging.level,
			&["trace", "debug", "info", "warn", "error"],
		)?;
		validate_nonzero("cache.max_gb", self.cache.max_gb)?;
		validate_nonzero(
			"scanner_defaults.max_concurrent_files",
			self.scanner_defaults.max_concurrent_files as u64,
		)?;
		validate_nonzero("scanner_defaults.max_file_bytes", self.scanner_defaults.max_file_bytes)?;
		validate_nonzero(
			"scanner_defaults.per_request_timeout_seconds",
			self.scanner_defaults.per_request_timeout.as_secs(),
		)?;
		validate_nonempty("bkb.api_url", &self.bkb.api_url)?;
		self.bkb.api_url.parse::<reqwest::Url>().context("bkb.api_url must be a valid URL")?;
		Ok(())
	}
}

impl Default for WorkerConfig {
	fn default() -> Self {
		let scanner_defaults = LlmScannerConfig::default();
		Self {
			server_url: None,
			tls: TlsConfig::default(),
			cache: CacheConfig {
				dir: PathBuf::from(DEFAULT_CACHE_DIR),
				max_gb: DEFAULT_MAX_CACHE_GB,
			},
			runtime: RuntimeConfig {
				max_workdir_bytes: DEFAULT_MAX_WORKDIR_BYTES,
				disable_sandbox: false,
			},
			logging: LoggingConfig {
				level: DEFAULT_LOG_LEVEL.to_owned(),
				json: false,
				agent_output: false,
			},
			agents: AgentsConfig {
				claude: CliModelConfig {
					model: DEFAULT_CLAUDE_MODEL.to_owned(),
					effort: DEFAULT_CLAUDE_EFFORT.to_owned(),
				},
				codex: CliModelConfig {
					model: DEFAULT_CODEX_MODEL.to_owned(),
					effort: DEFAULT_CODEX_EFFORT.to_owned(),
				},
			},
			scanner_defaults: LlmScannerConfig {
				max_concurrent_files: DEFAULT_MAX_CONCURRENT_FILES,
				max_file_bytes: DEFAULT_MAX_FILE_BYTES,
				per_request_timeout: DEFAULT_REQUEST_TIMEOUT,
				include_extensions: scanner_defaults.include_extensions,
				exclude_path_substrings: scanner_defaults.exclude_path_substrings,
			},
			bkb: BkbConfig { api_url: DEFAULT_BKB_API_URL.to_owned() },
		}
	}
}

impl FileConfig {
	pub fn load(path: &Path) -> Result<Self> {
		let raw = std::fs::read_to_string(path)
			.with_context(|| format!("reading worker config file {}", path.display()))?;
		let mut cfg: FileConfig = toml::from_str(&raw)
			.with_context(|| format!("parsing worker config file {}", path.display()))?;
		let base = path.parent().unwrap_or_else(|| Path::new("."));
		cfg.tls.ca_cert = cfg.tls.ca_cert.map(|p| resolve(base, p));
		cfg.tls.cert = cfg.tls.cert.map(|p| resolve(base, p));
		cfg.tls.key = cfg.tls.key.map(|p| resolve(base, p));
		cfg.cache.dir = cfg.cache.dir.map(|p| resolve(base, p));
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

fn gb_to_bytes(gb: u64) -> u64 {
	gb.saturating_mul(1_073_741_824)
}

fn validate_nonempty(name: &str, value: &str) -> Result<()> {
	if value.trim().is_empty() {
		anyhow::bail!("{name} must not be empty");
	}
	Ok(())
}

fn validate_effort(name: &str, value: &str, allowed: &[&str]) -> Result<()> {
	validate_nonempty(name, value)?;
	if !allowed.contains(&value) {
		anyhow::bail!("{name} must be one of {}; got `{value}`", allowed.join("|"));
	}
	Ok(())
}

fn validate_nonzero(name: &str, value: u64) -> Result<()> {
	if value == 0 {
		anyhow::bail!("{name} must be greater than zero");
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn defaults_match_expected_agent_and_cache_settings() {
		let cfg = WorkerConfig::load(None, WorkerConfigOverrides::default()).unwrap();
		assert_eq!(cfg.cache.dir, PathBuf::from(DEFAULT_CACHE_DIR));
		assert_eq!(cfg.cache.max_gb, 40);
		assert_eq!(cfg.logging.level, "info");
		assert_eq!(cfg.agents.claude.model, "claude-opus-4-7");
		assert_eq!(cfg.agents.claude.effort, "max");
		assert_eq!(cfg.agents.codex.model, "gpt-5.5");
		assert_eq!(cfg.agents.codex.effort, "xhigh");
		assert_eq!(cfg.bkb.api_url, "https://bitcoinknowledge.dev");
	}

	#[test]
	fn file_config_overrides_defaults_and_resolves_paths() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("worker.toml");
		std::fs::write(
			&path,
			r#"
[server]
url = "https://loupe.example.com:8443"

[tls]
ca_cert = "ca.pem"
cert = "worker.pem"
key = "worker.key"

[cache]
dir = "cache"
max_gb = 7

[runtime]
max_workdir_gb = 3
disable_sandbox = true

[logging]
level = "debug"
json = true
agent_output = true

[agents.claude]
model = "claude-custom"
effort = "xhigh"

[agents.codex]
model = "gpt-custom"
effort = "high"

[scanner_defaults]
max_concurrent_files = 2
max_file_bytes = 1234
per_request_timeout_seconds = 99

[bkb]
api_url = "https://bkb.example.test"
"#,
		)
		.unwrap();

		let cfg = WorkerConfig::load(Some(&path), WorkerConfigOverrides::default()).unwrap();

		assert_eq!(cfg.server_url.unwrap().as_str(), "https://loupe.example.com:8443/");
		assert_eq!(cfg.tls.ca_cert.unwrap(), dir.path().join("ca.pem"));
		assert_eq!(cfg.tls.cert.unwrap(), dir.path().join("worker.pem"));
		assert_eq!(cfg.tls.key.unwrap(), dir.path().join("worker.key"));
		assert_eq!(cfg.cache.dir, dir.path().join("cache"));
		assert_eq!(cfg.cache.max_gb, 7);
		assert_eq!(cfg.runtime.max_workdir_bytes, 3 * 1_073_741_824);
		assert!(cfg.runtime.disable_sandbox);
		assert_eq!(cfg.logging.level, "debug");
		assert!(cfg.logging.json);
		assert!(cfg.logging.agent_output);
		assert_eq!(cfg.agents.claude.model, "claude-custom");
		assert_eq!(cfg.agents.claude.effort, "xhigh");
		assert_eq!(cfg.agents.codex.model, "gpt-custom");
		assert_eq!(cfg.agents.codex.effort, "high");
		assert_eq!(cfg.scanner_defaults.max_concurrent_files, 2);
		assert_eq!(cfg.scanner_defaults.max_file_bytes, 1234);
		assert_eq!(cfg.scanner_defaults.per_request_timeout, Duration::from_secs(99));
		assert_eq!(cfg.bkb.api_url, "https://bkb.example.test");
	}

	#[test]
	fn overrides_win_over_file_config() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("worker.toml");
		std::fs::write(
			&path,
			r#"
[agents.codex]
model = "from-file"
effort = "low"
"#,
		)
		.unwrap();

		let cfg = WorkerConfig::load(
			Some(&path),
			WorkerConfigOverrides {
				codex_model: Some("from-env".to_owned()),
				codex_effort: Some("xhigh".to_owned()),
				..WorkerConfigOverrides::default()
			},
		)
		.unwrap();

		assert_eq!(cfg.agents.codex.model, "from-env");
		assert_eq!(cfg.agents.codex.effort, "xhigh");
	}

	#[test]
	fn unknown_fields_are_rejected() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("worker.toml");
		std::fs::write(&path, "[logging]\nverbose = true\n").unwrap();
		let err = WorkerConfig::load(Some(&path), WorkerConfigOverrides::default()).unwrap_err();
		let msg = format!("{err:#}");
		assert!(msg.contains("unknown field") || msg.contains("verbose"), "got: {msg}");
	}

	#[test]
	fn invalid_effort_is_rejected() {
		let err = WorkerConfig::load(
			None,
			WorkerConfigOverrides { codex_effort: Some("max".to_owned()), ..Default::default() },
		)
		.unwrap_err();
		assert!(err.to_string().contains("agents.codex.effort"), "got: {err}");
	}
}
