//! Exercise the actual filesystem loader and its documented path/owner rules.
use std::path::Path;

use loupe_server::config::FileConfig;

use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("config fixture: {error}"));
	let file = dir.path().join("config.toml");
	std::fs::write(&file, data).unwrap_or_else(|error| panic!("config fixture write: {error}"));
	let result = FileConfig::load(&file);
	let Ok(text) = std::str::from_utf8(data) else {
		assert!(result.is_err(), "non-UTF8 config accepted");
		return;
	};
	let parsed = toml::from_str::<toml::Value>(text);
	if let Ok(config) = result {
		let raw = parsed.unwrap_or_else(|_| panic!("invalid TOML config accepted"));
		assert!(
			config
				.github_app
				.allowed_target_owners
				.as_ref()
				.is_none_or(|owners| !owners.is_empty()),
			"empty GitHub owner allowlist accepted"
		);
		assert!(config.github_app.validate().is_ok());
		for (name, value) in [
			("db", config.paths.db),
			("server_cert", config.paths.server_cert),
			("server_key", config.paths.server_key),
			("ca_cert", config.paths.ca_cert),
			("ca_key", config.paths.ca_key),
			("master_key", config.paths.master_key),
		] {
			if let Some(value) = value {
				assert!(value.is_absolute(), "config path was not resolved to an absolute path");
				let original = raw
					.get("paths")
					.and_then(|p| p.get(name))
					.and_then(toml::Value::as_str)
					.unwrap_or_else(|| panic!("accepted path is not a TOML string"));
				let expected = if Path::new(original).is_absolute() {
					Path::new(original).to_owned()
				} else {
					dir.path().join(original)
				};
				assert_eq!(value, expected, "config path changed beyond relative resolution");
			}
		}
		let Some(table) = raw.as_table() else { panic!("non-table configuration accepted") };
		assert!(
			table.keys().all(|key| [
				"server",
				"paths",
				"policy",
				"review",
				"github_app",
				"worker_budgets"
			]
			.contains(&key.as_str())),
			"unknown root config key accepted"
		);
	}
}

pub fn server_config_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn server_config_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller guarantees a valid readable input buffer.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	fn assert_loader(data: &[u8], accepted: bool) {
		let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("config fixture: {error}"));
		let file = dir.path().join("config.toml");
		std::fs::write(&file, data).unwrap_or_else(|error| panic!("config fixture: {error}"));
		let result = FileConfig::load(&file);
		assert_eq!(result.is_ok(), accepted, "actual loader admission must match the control");
		if let Ok(config) = result {
			assert_eq!(config.worker_budgets.max_workers, 4096);
			assert_eq!(config.worker_budgets.idle_seconds, 120);
		}
	}

	#[test]
	fn worker_budget_section_is_a_known_root() {
		let data = include_bytes!("../test_cases/server_config/worker-budgets-empty");
		assert_loader(data, true);
		do_test(data);
	}

	#[test]
	fn empty_config_keeps_its_defaults() {
		assert_loader(b"", true);
		do_test(b"");
	}

	#[test]
	fn unrelated_root_sections_remain_rejected() {
		let data = b"[not_a_config_section]\n";
		assert_loader(data, false);
		do_test(data);
	}
}
