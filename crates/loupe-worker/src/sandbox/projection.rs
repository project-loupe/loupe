//! Fuzz-only observation driver. It returns plain snapshots, never a command,
//! a declared configuration value, or a mount capability. Config host fields
//! enter through the actual argument parser and complete config finalizer.
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use clap::builder::TypedValueParser;

use super::{
	BindDestination, SandboxBinary, SandboxBuilder, SandboxNetworkMode, SandboxPath, SandboxValue,
};

pub struct ProjectionInput<'a> {
	pub workdir: &'a OsStr,
	pub program: &'a OsStr,
	pub args: &'a [OsString],
	pub env: &'a [(&'static str, OsString)],
	pub binds: &'a [(PathBuf, OsString)],
	pub network: Option<SandboxNetworkMode>,
	pub hosts: &'a [String],
	/// Synthetic positional operands, matching the Kani projection
	/// domain. Production required hosts come only from the declared BKB URL.
	pub required: &'a [String],
	pub binary: Option<&'a OsStr>,
}

pub struct ProjectionObservation {
	pub argv: Vec<OsString>,
	pub env: Vec<(OsString, Option<OsString>)>,
}

// debug-ok: a closed rejection stage and numeric host index only.
#[derive(Debug, PartialEq, Eq)]
pub enum ProjectionRejection {
	HostText(usize),
	ConfigPolicy,
	Binary,
}

pub fn observe(input: ProjectionInput<'_>) -> Result<ProjectionObservation, ProjectionRejection> {
	let mut config = crate::config::WorkerConfig::default();
	if let Some(mode) = input.network {
		config.sandbox.mode = mode;
		for (index, host) in input.hosts.iter().enumerate() {
			let host = crate::config_value_parsers::ConfiguredTextParser
				.parse_ref(
					&clap::Command::new("sandbox-projection-fixture"),
					None,
					OsStr::new(host),
				)
				.map_err(|_| ProjectionRejection::HostText(index))?;
			config.sandbox.allowlist.push(host);
		}
	}
	let launch = config.sandbox_launch_config().map_err(|_| ProjectionRejection::ConfigPolicy)?;
	let mut builder = SandboxBuilder::new(SandboxPath::fixture(input.workdir.into()), &launch);
	if input.network.is_some() {
		builder = builder
			.with_network(
				launch.network().clone(),
				crate::config::SandboxRequiredHosts::fixture(input.required.to_vec()),
			)
			.with_network_supervisor(SandboxPath::fixture("/trusted/worker".into()));
	}
	for (source, destination) in input.binds {
		builder.extra_ro_binds.push((
			SandboxPath::fixture(source.clone()),
			BindDestination::Fixture(destination.clone()),
		));
	}
	if let Some(binary) = input.binary {
		let binary = SandboxBinary::discover(binary, launch.path())
			.map_err(|_| ProjectionRejection::Binary)?;
		builder = builder.allow_binary(&binary);
	}
	for (name, value) in input.env {
		builder = builder.set_env(name, SandboxValue::fixture(value.clone()));
	}
	let arguments: Vec<_> = input.args.iter().cloned().map(SandboxValue::fixture).collect();
	Ok(builder.build(SandboxValue::fixture(input.program), &arguments).observation())
}
