//! The actual host binary/install discovery owner, using captured launch PATH.
use std::ffi::OsStr;

use super::{entrypoint_bind_source, npm_node_modules_root, SandboxPath};
use crate::config::ConfigNonSecret;

#[derive(Clone)]
pub struct SandboxBinary {
	entrypoint: SandboxPath,
	binds: Vec<SandboxPath>,
}
impl SandboxBinary {
	pub fn current_worker() -> anyhow::Result<SandboxPath> {
		let path = std::env::current_exe()
			.map_err(|_| anyhow::anyhow!("worker executable unavailable"))?;
		#[allow(
			clippy::disallowed_methods,
			reason = "The binary owner resolves the selected worker executable before typed sandbox admission."
		)]
		let path = std::fs::canonicalize(path)
			.map_err(|_| anyhow::anyhow!("worker executable unavailable"))?;
		Ok(SandboxPath::binary(path))
	}
	pub(crate) fn discover(name: &OsStr, launch_path: &ConfigNonSecret) -> anyhow::Result<Self> {
		let original = std::env::split_paths(launch_path.for_sandbox())
			.map(|dir| dir.join(name))
			.find(|candidate| candidate.is_file())
			.ok_or_else(|| anyhow::anyhow!("agent executable not found"))?;
		#[allow(
			clippy::disallowed_methods,
			reason = "The binary owner resolves a selected Config CLI path before typed sandbox admission."
		)]
		let canonical = std::fs::canonicalize(&original)
			.map_err(|_| anyhow::anyhow!("agent executable canonicalization failed"))?;
		let entrypoint_bind = entrypoint_bind_source(&original)
			.map_err(|_| anyhow::anyhow!("agent executable mount unavailable"))?;
		let install_dir = if canonical.is_dir() {
			canonical
		} else if let Some(root) = npm_node_modules_root(&canonical) {
			root
		} else {
			canonical
				.parent()
				.ok_or_else(|| anyhow::anyhow!("agent install directory unavailable"))?
				.to_owned()
		};
		Ok(Self {
			entrypoint: SandboxPath::binary(original),
			binds: vec![SandboxPath::binary(entrypoint_bind), SandboxPath::binary(install_dir)],
		})
	}
	pub fn sandbox_path(&self) -> SandboxPath {
		self.entrypoint.clone()
	}
	pub(crate) fn bkb_mcp(launch_path: &ConfigNonSecret) -> Option<SandboxPath> {
		for dir in std::env::split_paths(launch_path.for_sandbox()) {
			let candidate = dir.join("bkb-mcp");
			#[allow(
				clippy::disallowed_methods,
				reason = "Optional BKB discovery resolves only the selected Config PATH candidate."
			)]
			if candidate.is_file() && std::fs::canonicalize(&candidate).is_ok() {
				#[allow(
					clippy::disallowed_methods,
					reason = "Optional BKB discovery probes the selected candidate with the fixed version argument and discarded output."
				)]
				let healthy = std::process::Command::new(&candidate)
					.arg("--help")
					.stdout(std::process::Stdio::null())
					.stderr(std::process::Stdio::null())
					.status()
					.is_ok_and(|status| status.success());
				if healthy {
					return Some(SandboxPath::binary(candidate));
				}
			}
		}
		None
	}
	pub(super) fn binds(&self) -> &[SandboxPath] {
		&self.binds
	}
}
