//! Mount authority comes from concrete checkout, binary and temporary owners.
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone)]
pub struct SandboxPath {
	native: PathBuf,
	owner: Option<Arc<dyn Send + Sync>>,
}
impl std::fmt::Debug for SandboxPath {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("SandboxPath([redacted])")
	}
}
impl SandboxPath {
	pub(super) fn smoke_test(directory: Arc<tempfile::TempDir>) -> Self {
		Self { native: directory.path().to_owned(), owner: Some(directory) }
	}
	pub(crate) fn checkout(source: &crate::runner::CheckedOutWorktree) -> Self {
		Self { native: source.path().to_owned(), owner: Some(Arc::new(source.clone())) }
	}
	pub(crate) fn mcp_broker(source: &crate::llm::mcp::McpBroker) -> Self {
		Self { native: source.host_dir().to_owned(), owner: Some(source.mount_owner()) }
	}
	pub(crate) fn model_broker(source: &crate::llm::model_broker::ModelBrokerSession) -> Self {
		Self { native: source.host_dir().to_owned(), owner: Some(source.mount_owner()) }
	}
	pub(crate) fn claude_config(source: &crate::llm::claude_cli::McpScratch) -> Self {
		Self { native: source.config_path().to_owned(), owner: Some(source.mount_owner()) }
	}
	pub(crate) fn canary(source: &Arc<crate::canary::JobSecurity>) -> Self {
		Self { native: source.canary_mount_path(), owner: Some(source.clone()) }
	}
	pub(super) fn binary(native: PathBuf) -> Self {
		// Called only by this module's validated binary/install resolver.
		Self { native, owner: None }
	}
	pub(super) fn native(&self) -> &Path {
		&self.native
	}
	pub(super) fn owner(&self) -> Option<Arc<dyn Send + Sync>> {
		self.owner.clone()
	}

	/// Explicit synthetic path authority for fixtures, absent in normal builds.
	#[cfg(any(test, feature = "test-support", fuzzing, kani))]
	pub fn fixture(path: PathBuf) -> Self {
		Self { native: path, owner: None }
	}
}
