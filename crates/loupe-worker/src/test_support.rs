//! Synthetic original wire fixtures admitted by the concrete production
//! decoders. These helpers do not assert that a network read occurred.
use std::path::Path;

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
		workdir: workdir.to_owned(),
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

pub(crate) fn patch(raw: &str) -> crate::source_discovery::ScannerConfigPatch {
	crate::client::test_scanner_patch(raw)
		.expect("scanner text admitted")
		.expect("valid scanner patch")
}
