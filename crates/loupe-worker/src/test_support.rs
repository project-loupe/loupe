//! Synthetic original wire fixtures admitted by the concrete production
//! decoders. These helpers do not assert that a network read occurred.
use std::path::Path;

#[derive(Clone, Default)]
pub(crate) struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for LogCapture {
	fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
		self.0.lock().unwrap().extend_from_slice(bytes);
		Ok(bytes.len())
	}
	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}
impl LogCapture {
	pub(crate) fn install(&self) {
		let writer = self.clone();
		tracing::subscriber::set_global_default(
			tracing_subscriber::fmt()
				.with_max_level(tracing::Level::DEBUG)
				.without_time()
				.with_ansi(false)
				.with_writer(move || writer.clone())
				.finish(),
		)
		.unwrap();
	}
	pub(crate) fn text(&self) -> String {
		String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
	}
}

pub(crate) fn config_text(value: &str) -> crate::config::ConfiguredText {
	use clap::builder::TypedValueParser;
	crate::config_value_parsers::ConfiguredTextParser
		.parse_ref(&clap::Command::new("worker-test"), None, std::ffi::OsStr::new(value))
		.unwrap()
}

pub(crate) fn scan_context(workdir: &Path, head: &str) -> crate::ScanContext {
	let wire = br#"{"kind":"lease","protocol_version":1,"job_id":1,"repo_id":1,"job_capability":"test-capability","repo":{"host":"github.com","owner":"a","repo":"b","clone_url":"https://github.com/a/b.git"},"scanner_config":null,"lease_expires_at":300,"payload":{"kind":"scan"}}"#;
	let loupe_proto::LeaseResponse::Lease(env) = crate::client::test_lease(wire).response else {
		panic!("lease fixture")
	};
	// The head comes from the actual persisted Repo cursor reader, not a mark
	// applied to a caller string or a Server revision converted to Repo.
	let tmp = tempfile::tempdir().unwrap();
	let cache = crate::RepoCache::new(tmp.path().to_owned(), 1024, None).unwrap();
	let key = crate::RepoKey::new("github.com", "a", "b");
	std::fs::create_dir_all(cache.repo_path(&key)).unwrap();
	cache.write_cursor(&key, head).unwrap();
	crate::ScanContext {
		security: crate::canary::JobSecurity::new(Default::default(), Vec::new()).unwrap(),
		tool_boundary: crate::llm::prompt::JobToolBoundary::new().unwrap(),
		workdir: workdir.to_owned(),
		sandbox_workdir: crate::sandbox::SandboxPath::fixture(workdir.to_owned()),
		repo: env.repo,
		repo_id: env.repo_id,
		job_id: env.job_id,
		job_capability: env.job_capability,
		head_sha: cache.read_cursor(&key).unwrap(),
		base_sha: None,
		config: None,
		cancel: tokio_util::sync::CancellationToken::new(),
	}
}

pub(crate) fn sandbox_network(
	network: crate::sandbox::SandboxNetworkConfig,
) -> crate::config::SandboxNetworkPolicy {
	let mut config = crate::config::WorkerConfig::default();
	config.sandbox = network;
	config.sandbox_launch_config().unwrap().network().clone()
}

pub(crate) fn sandbox_agent(
	codex: bool, agent: crate::llm::CliModelConfig,
) -> crate::config::SandboxAgentConfig {
	let mut config = crate::config::WorkerConfig::default();
	if codex {
		config.agents.codex = agent;
	} else {
		config.agents.claude = agent;
	}
	let launch = config.sandbox_launch_config().unwrap();
	if codex {
		launch.codex().clone()
	} else {
		launch.claude().clone()
	}
}

pub(crate) fn patch(raw: &str) -> crate::source_discovery::ScannerConfigPatch {
	crate::client::test_scanner_patch(raw)
		.expect("scanner text admitted")
		.expect("valid scanner patch")
}
