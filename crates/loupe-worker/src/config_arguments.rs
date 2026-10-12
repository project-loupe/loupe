//! Binary-only projection from the actual shared Config value parsers.

/// Move Config owners admitted by the actual Clap callbacks into the final
/// override set, retaining them through precedence and operational use.
pub(super) struct WorkerOverridesDecoder;
impl WorkerOverridesDecoder {
	pub(super) fn decode(args: &super::RunArgs) -> loupe_worker::config::WorkerConfigOverrides {
		loupe_worker::config::WorkerConfigOverrides {
			server_url: args.server_url.clone(),
			ca_cert: args.ca_cert.clone(),
			cert: args.cert.clone(),
			key: args.key.clone(),
			cache_dir: args.cache_dir.clone(),
			max_cache_gb: args.max_cache_gb,
			max_workdir_gb: args.max_workdir_gb,
			disable_sandbox: args.disable_sandbox,
			sandbox_network: args.sandbox_network,
			sandbox_allowlist: args.sandbox_allowlist.clone(),
			log_level: args.log_level.clone(),
			log_json: args.log_json,
			log_agent_output: args.log_agent_output,
			scan_agent: args.scan_agent,
			verify_agent: args.verify_agent,
			claude_model: args.claude_model.clone(),
			claude_effort: args.claude_effort.clone(),
			codex_model: args.codex_model.clone(),
			codex_effort: args.codex_effort.clone(),
			max_concurrent_files: args.max_concurrent_files,
			max_file_bytes: args.max_file_bytes,
			per_request_timeout_seconds: args.per_request_timeout_seconds,
			bkb_api_url: args.bkb_api_url.clone(),
			broker_request_ceiling: args.broker_request_ceiling,
			broker_output_ceiling_bytes: args.broker_output_ceiling_bytes,
			broker_token_ceiling: args.broker_token_ceiling,
		}
	}
}
