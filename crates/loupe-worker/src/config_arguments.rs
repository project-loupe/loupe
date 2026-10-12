//! Binary-only projection from the actual shared Config value parsers.
use super::config_value_parsers::{ConfiguredPath, ConfiguredText, ConfiguredUrl};

/// The temporary, named Config-to-legacy override exit. All textual/path
/// inputs were admitted by their actual Clap owner; this never mints a token.
pub(super) struct WorkerOverridesDecoder;
impl WorkerOverridesDecoder {
	pub(super) fn into_legacy(
		args: &super::RunArgs,
	) -> loupe_worker::config::WorkerConfigOverrides {
		loupe_worker::config::WorkerConfigOverrides {
			server_url: args.server_url.as_ref().map(ConfiguredUrl::legacy_override),
			ca_cert: args.ca_cert.as_ref().map(ConfiguredPath::legacy_override),
			cert: args.cert.as_ref().map(ConfiguredPath::legacy_override),
			key: args.key.as_ref().map(ConfiguredPath::legacy_override),
			cache_dir: args.cache_dir.as_ref().map(ConfiguredPath::legacy_override),
			max_cache_gb: args.max_cache_gb,
			max_workdir_gb: args.max_workdir_gb,
			disable_sandbox: args.disable_sandbox,
			sandbox_network: args.sandbox_network,
			sandbox_allowlist: args
				.sandbox_allowlist
				.as_ref()
				.map(|v| v.iter().map(ConfiguredText::legacy_override).collect()),
			log_level: args.log_level.as_ref().map(ConfiguredText::legacy_override),
			log_json: args.log_json,
			log_agent_output: args.log_agent_output,
			scan_agent: args.scan_agent,
			verify_agent: args.verify_agent,
			claude_model: args.claude_model.as_ref().map(ConfiguredText::legacy_override),
			claude_effort: args.claude_effort.as_ref().map(ConfiguredText::legacy_override),
			codex_model: args.codex_model.as_ref().map(ConfiguredText::legacy_override),
			codex_effort: args.codex_effort.as_ref().map(ConfiguredText::legacy_override),
			max_concurrent_files: args.max_concurrent_files,
			max_file_bytes: args.max_file_bytes,
			per_request_timeout_seconds: args.per_request_timeout_seconds,
			bkb_api_url: args.bkb_api_url.as_ref().map(ConfiguredText::legacy_override),
			broker_request_ceiling: args.broker_request_ceiling,
			broker_output_ceiling_bytes: args.broker_output_ceiling_bytes,
			broker_token_ceiling: args.broker_token_ceiling,
		}
	}
}
