//! Independent configuration wire schema; these values have no source labels.
// Every field participates in serde admission and the full Debug oracle, even
// where no separate field comparison reads it.
#![allow(dead_code)]
use std::path::PathBuf;

use loupe_worker::llm::JobAgent;
use loupe_worker::sandbox::SandboxNetworkMode;
use serde::Deserialize;
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
	pub sandbox: SandboxSection,
	#[serde(default)]
	pub logging: LoggingSection,
	#[serde(default)]
	pub agents: AgentsSection,
	#[serde(default)]
	pub scanner_defaults: ScannerDefaultsSection,
	#[serde(default)]
	pub bkb: BkbSection,
	#[serde(default)]
	pub broker: BrokerSection,
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
pub struct SandboxSection {
	#[serde(default)]
	pub network: Option<SandboxNetworkMode>,
	#[serde(default)]
	pub allowlist: Option<Vec<String>>,
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
	pub scan: Option<JobAgent>,
	#[serde(default)]
	pub verify: Option<JobAgent>,
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

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerSection {
	#[serde(default)]
	pub request_ceiling: Option<u64>,
	#[serde(default)]
	pub output_ceiling_bytes: Option<u64>,
	#[serde(default)]
	pub token_ceiling: Option<u64>,
}
