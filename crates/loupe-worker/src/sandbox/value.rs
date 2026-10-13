//! Closed sandbox operands. Native paths never pass through UTF-8 formatting.
use std::ffi::OsString;

use super::SandboxPath;
use crate::config::ConfigNonSecret;
use crate::llm::codex_cli::{toml_string_array, toml_string_literal};

#[derive(Clone)]
pub struct SandboxValue(Value);
#[derive(Clone)]
enum Value {
	Static(&'static str),
	Path(SandboxPath),
	Port(u16),
	NonSecret(ConfigNonSecret),
	Rendered(String),
	#[cfg(any(test, fuzzing))]
	Fixture(OsString),
}
impl std::fmt::Debug for SandboxValue {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("SandboxValue([redacted])")
	}
}
impl SandboxValue {
	pub const fn r#static(value: &'static str) -> Self {
		Self(Value::Static(value))
	}
	pub fn path(value: SandboxPath) -> Self {
		Self(Value::Path(value))
	}
	pub fn port(value: u16) -> Self {
		Self(Value::Port(value))
	}
	pub fn non_secret(value: ConfigNonSecret) -> Self {
		Self(Value::NonSecret(value))
	}
	pub(super) fn operand(&self) -> OsString {
		match &self.0 {
			Value::Static(value) => OsString::from(value),
			Value::Path(value) => value.native().as_os_str().to_owned(),
			Value::Port(value) => OsString::from(value.to_string()),
			Value::NonSecret(value) => OsString::from(value.for_sandbox()),
			Value::Rendered(value) => OsString::from(value),
			#[cfg(any(test, fuzzing))]
			Value::Fixture(value) => value.clone(),
		}
	}
	pub(super) fn owner(&self) -> Option<std::sync::Arc<dyn Send + Sync>> {
		match &self.0 {
			Value::Path(path) => path.owner(),
			_ => None,
		}
	}
	#[cfg(any(test, fuzzing))]
	pub(crate) fn fixture(value: impl Into<OsString>) -> Self {
		Self(Value::Fixture(value.into()))
	}
	#[cfg(test)]
	pub(crate) fn test_text(values: Vec<Self>) -> Vec<String> {
		values
			.iter()
			.map(|value| value.operand().into_string().expect("UTF-8 fixture operand"))
			.collect()
	}
	pub(crate) fn codex_effort(value: &ConfigNonSecret) -> Self {
		Self(Value::Rendered(format!(
			"model_reasoning_effort={}",
			toml_string_literal(value.for_sandbox())
		)))
	}
	pub(crate) fn codex_permissions() -> anyhow::Result<Vec<Self>> {
		let policy: toml::Table = toml::from_str(include_str!("../llm/codex-permissions.toml"))
			.map_err(|_| anyhow::anyhow!("embedded Codex permissions are invalid"))?;
		Ok(policy
			.into_iter()
			.map(|(key, value)| Self(Value::Rendered(format!("{key}={value}"))))
			.collect())
	}
	pub(crate) fn codex_mcp(bkb: Option<&ConfigNonSecret>) -> Vec<Self> {
		use crate::llm::mcp::{SANDBOX_BKB_MCP_BIN, SANDBOX_LOUPE_BIN, SANDBOX_MCP_SOCKET};
		let mut values = vec![
			Self(Value::Rendered(format!(
				"mcp_servers.loupe.command={}",
				toml_string_literal(SANDBOX_LOUPE_BIN)
			))),
			Self(Value::Rendered(format!(
				"mcp_servers.loupe.args={}",
				toml_string_array(&[
					"mcp-proxy".into(),
					"--socket".into(),
					SANDBOX_MCP_SOCKET.into()
				])
			))),
			Self::r#static("mcp_servers.loupe.env={}"),
			Self::r#static("mcp_servers.loupe.default_tools_approval_mode=\"approve\""),
		];
		if let Some(bkb) = bkb {
			values.extend([
				Self(Value::Rendered(format!(
					"mcp_servers.bkb.command={}",
					toml_string_literal(SANDBOX_BKB_MCP_BIN)
				))),
				Self::r#static("mcp_servers.bkb.args=[]"),
				Self::r#static("mcp_servers.bkb.default_tools_approval_mode=\"approve\""),
				Self(Value::Rendered(format!(
					"mcp_servers.bkb.env={{ BKB_API_URL = {} }}",
					toml_string_literal(bkb.for_sandbox())
				))),
			]);
		}
		values
	}
}
