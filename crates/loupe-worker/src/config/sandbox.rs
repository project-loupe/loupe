//! Closed declarations of worker configuration deliberately published inside
//! a sandbox. Only this config finalizer constructs these values, after all
//! file/argument merging and the complete WorkerConfig validation.
use loupe_provenance::{Config, Mark, Untrusted, Unvalidated, Validate};

use super::{ConfiguredText, WorkerConfig};

/// An explicit public-to-the-sandbox configuration declaration, retaining its
/// Config source. This is not a conversion available to arbitrary text owners.
#[derive(Clone)]
pub struct ConfigNonSecret(Value);
#[derive(Clone)]
enum Value {
	Configured(ConfiguredText),
	LaunchPath(String, std::marker::PhantomData<Config>),
}
impl std::fmt::Debug for ConfigNonSecret {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("ConfigNonSecret<Config>([redacted])")
	}
}
impl ConfigNonSecret {
	#[cfg(kani)]
	pub(crate) fn proof_launch_path() -> Self {
		Self(Value::Configured(ConfiguredText::Builtin("/bin")))
	}
	pub(crate) fn model_policy(&self) -> anyhow::Result<ConfiguredText> {
		match &self.0 {
			Value::Configured(value) => Ok(value.clone()),
			Value::LaunchPath(..) => anyhow::bail!("invalid model policy declaration"),
		}
	}
	pub(crate) fn for_sandbox(&self) -> &str {
		match &self.0 {
			Value::Configured(text) => text.for_operation(),
			Value::LaunchPath(text, _) => text,
		}
	}
}

// debug-ok: All dynamic fields use redacted ConfigNonSecret; other fields are closed modes and booleans.
#[derive(Clone, Debug)]
// debug-ok: fields use the redacted ConfigNonSecret formatter.
pub struct SandboxAgentConfig {
	model: ConfigNonSecret,
	effort: ConfigNonSecret,
}
impl SandboxAgentConfig {
	pub fn model(&self) -> &ConfigNonSecret {
		&self.model
	}
	pub fn effort(&self) -> &ConfigNonSecret {
		&self.effort
	}
}

// debug-ok: All dynamic fields use redacted ConfigNonSecret; other fields are closed modes and booleans.
#[derive(Clone, Debug, Default)]
// debug-ok: closed mode and redacted declared configuration.
pub struct SandboxNetworkPolicy {
	mode: crate::sandbox::SandboxNetworkMode,
	allowlist: Vec<ConfigNonSecret>,
}
impl SandboxNetworkPolicy {
	pub fn mode(&self) -> crate::sandbox::SandboxNetworkMode {
		self.mode
	}
	pub fn allowlist(&self) -> &[ConfigNonSecret] {
		&self.allowlist
	}
}

#[derive(Clone, Default)]
pub struct SandboxRequiredHosts(Vec<String>);
impl std::fmt::Debug for SandboxRequiredHosts {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("SandboxRequiredHosts<Config>([redacted])")
	}
}
impl SandboxRequiredHosts {
	pub(crate) fn for_bkb(endpoint: Option<&ConfigNonSecret>) -> anyhow::Result<Self> {
		let mut hosts = Vec::new();
		if let Some(endpoint) = endpoint {
			let url = reqwest::Url::parse(endpoint.for_sandbox())
				.map_err(|_| anyhow::anyhow!("invalid configured BKB API URL"))?;
			let host = url
				.host_str()
				.ok_or_else(|| anyhow::anyhow!("configured BKB API URL has no host"))?;
			hosts.push(host.to_owned());
		}
		Ok(Self(hosts))
	}
	pub(crate) fn for_supervisor(&self) -> &[String] {
		&self.0
	}
	pub(crate) fn is_empty(&self) -> bool {
		self.0.is_empty()
	}
	#[cfg(any(test, kani, fuzzing))]
	pub(crate) fn fixture(hosts: Vec<String>) -> Self {
		Self(hosts)
	}
}

// debug-ok: All dynamic fields use redacted ConfigNonSecret; other fields are closed modes and booleans.
#[derive(Clone, Debug)]
// debug-ok: every content field has an explicit redacted formatter.
pub struct SandboxLaunchConfig {
	claude: SandboxAgentConfig,
	codex: SandboxAgentConfig,
	bkb_api_url: ConfigNonSecret,
	network: SandboxNetworkPolicy,
	path: ConfigNonSecret,
}
impl SandboxLaunchConfig {
	pub fn claude(&self) -> &SandboxAgentConfig {
		&self.claude
	}
	pub fn codex(&self) -> &SandboxAgentConfig {
		&self.codex
	}
	pub fn bkb_api_url(&self) -> &ConfigNonSecret {
		&self.bkb_api_url
	}
	pub fn network(&self) -> &SandboxNetworkPolicy {
		&self.network
	}
	pub fn path(&self) -> &ConfigNonSecret {
		&self.path
	}
}

impl Default for SandboxLaunchConfig {
	fn default() -> Self {
		// Defaults are the same fixed fields as WorkerConfig::default; no
		// caller-provided text reaches this infallible path.
		let config = WorkerConfig::default();
		finalize(&config, config.launch_path.clone())
	}
}

pub(super) fn finalize(config: &WorkerConfig, path: ConfigNonSecret) -> SandboxLaunchConfig {
	// Exact allowlist: do not turn this into a public text/field-name constructor.
	SandboxLaunchConfig {
		claude: SandboxAgentConfig {
			model: ConfigNonSecret(Value::Configured(config.agents.claude.model.clone())),
			effort: ConfigNonSecret(Value::Configured(config.agents.claude.effort.clone())),
		},
		codex: SandboxAgentConfig {
			model: ConfigNonSecret(Value::Configured(config.agents.codex.model.clone())),
			effort: ConfigNonSecret(Value::Configured(config.agents.codex.effort.clone())),
		},
		bkb_api_url: ConfigNonSecret(Value::Configured(config.bkb.api_url.clone())),
		network: SandboxNetworkPolicy {
			mode: config.sandbox.mode,
			allowlist: config
				.sandbox
				.allowlist
				.iter()
				.cloned()
				.map(|host| ConfigNonSecret(Value::Configured(host)))
				.collect(),
		},
		path,
	}
}

pub(super) fn launch_path(original: Untrusted<String, Config>) -> ConfigNonSecret {
	struct LaunchPath;
	impl Validate<String, Config> for LaunchPath {
		type Output = ConfigNonSecret;
		type Error = std::convert::Infallible;
		fn validate<'view>(
			self, value: Unvalidated<'view, String>, _: Mark<'view, Config>,
		) -> Result<Self::Output, Self::Error> {
			Ok(ConfigNonSecret(Value::LaunchPath(value.get().clone(), std::marker::PhantomData)))
		}
	}
	match original.validate(LaunchPath) {
		Ok(value) => value,
		Err(never) => match never {},
	}
}
