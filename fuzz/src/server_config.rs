//! Exercise the actual filesystem loader and its documented path/owner rules.
use std::path::Path;

use loupe_server::config::FileConfig;
use unicode_general_category::{get_general_category, GeneralCategory};

use crate::utils::test_logger;

const OWNER_CAP: usize = 2 * 1024 * 1024;

fn owner_error(owner: &str) -> Option<String> {
	if owner.len() > OWNER_CAP {
		return Some("repo_owner: Bytes".into());
	}
	owner.chars().find_map(|character| {
		let point = u32::from(character);
		(matches!(
			get_general_category(character),
			GeneralCategory::Control
				| GeneralCategory::Format
				| GeneralCategory::Unassigned
				| GeneralCategory::PrivateUse
				| GeneralCategory::LineSeparator
				| GeneralCategory::ParagraphSeparator
		) || (0xfdd0..=0xfdef).contains(&point)
			|| matches!(point % 0x1_0000, 0xfffe | 0xffff))
		.then(|| format!("repo_owner: Character (U+{point:04X})"))
	})
}

pub fn do_test(data: &[u8]) {
	// Compact boundary controls exercise the real field policy without storing
	// multi-megabyte corpus files. Ordinary TOML retains its existing uncapped I/O.
	let expanded;
	let data = if let [255, edge] = data {
		let count = [OWNER_CAP - 1, OWNER_CAP, OWNER_CAP + 1][usize::from(edge % 3)];
		expanded = format!("[github_app]\nallowed_target_owners = [\"{}\"]\n", "a".repeat(count));
		expanded.as_bytes()
	} else {
		data
	};
	let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("config fixture: {error}"));
	let file = dir.path().join("config.toml");
	std::fs::write(&file, data).unwrap_or_else(|error| panic!("config fixture write: {error}"));
	let result = FileConfig::load(&file);
	if let Err(error) = &result {
		assert!(
			!format!("{error:#} {error:?}").contains("private_config_sentinel"),
			"config error retained input"
		);
	}
	let Ok(text) = std::str::from_utf8(data) else {
		assert!(result.is_err(), "non-UTF8 config accepted");
		return;
	};
	let parsed = toml::from_str::<toml::Value>(text);
	// Deserialize the existing wire schema only as a compatibility oracle.
	// Independently evaluate every post-parse admission rule; do not call its
	// production validators or labelled constructors on this side.
	let wire = toml::from_str::<FileConfig>(text);
	let expected_error = wire.as_ref().ok().and_then(|config| {
		if let Some(owners) = &config.github_app.allowed_target_owners {
			if let Some(error) = owners.iter().find_map(|owner| owner_error(owner)) {
				return Some(error);
			}
			if owners.is_empty() {
				return Some(
					"[github_app] allowed_target_owners must list at least one owner or be omitted"
						.into(),
				);
			}
		}
		let budgets = &config.worker_budgets;
		if budgets.max_workers == 0 {
			return Some("worker_budgets.max_workers must be positive".into());
		}
		if budgets.idle_seconds == 0 {
			return Some("worker_budgets.idle_seconds must be positive".into());
		}
		[("requests", &budgets.requests), ("bytes", &budgets.bytes), ("leases", &budgets.leases)]
			.into_iter()
			.find_map(|(name, bucket)| {
				(bucket.capacity == 0 || bucket.refill_per_second == 0).then(|| {
					format!("worker_budgets.{name} capacity and refill_per_second must be positive")
				})
			})
	});
	assert_eq!(
		result.is_ok(),
		wire.is_ok() && expected_error.is_none(),
		"actual Config owner admission"
	);
	if let Err(error) = &result {
		let chain = error.chain().map(ToString::to_string).collect::<Vec<_>>();
		if let Some(expected) = expected_error {
			let expected = if expected.starts_with("[github_app]") {
				vec![format!("validating config file {}", file.display()), expected]
			} else {
				vec![expected]
			};
			assert_eq!(chain, expected, "Config error chain must contain only fixed metadata");
		} else {
			assert_eq!(chain.len(), 1, "TOML error retained a parser cause");
			assert!(
				[
					"missing field",
					"duplicate field",
					"invalid type",
					"unknown field",
					"unknown variant",
					"invalid data"
				]
				.into_iter()
				.any(|category| chain[0] == format!("parsing config file: {category}")),
				"unbounded TOML error: {chain:?}"
			);
		}
	}
	if let Ok(config) = result {
		assert_eq!(
			config.github_app.allowed_target_owners,
			wire.as_ref().ok().and_then(|wire| wire.github_app.allowed_target_owners.clone()),
			"Config owner spelling changed"
		);
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

	#[test]
	fn actual_owner_policy_preserves_spelling_and_rejects_controls() {
		for owner in [
			"",
			"  e\u{301}  ",
			"É",
			"org/repo",
			"x\t",
			"x\r",
			"x\n",
			"\u{202e}",
			"\u{e000}",
			"\u{fdd0}",
			"\u{10ffff}",
		] {
			let text = format!(
				"[github_app]\nallowed_target_owners = [{}]\n",
				serde_json::to_string(owner)
					.unwrap_or_else(|error| panic!("owner fixture: {error}"))
			);
			do_test(text.as_bytes());
		}
		for edge in 0..3 {
			do_test(&[255, edge]);
		}
	}

	#[test]
	fn actual_config_errors_and_native_relative_paths() {
		for input in [
			"[github_app]\nallowed_target_owners = []\n",
			"[worker_budgets]\nmax_workers = 0\n",
			"[worker_budgets]\nidle_seconds = 0\n",
			"[worker_budgets.bytes]\ncapacity = 0\nrefill_per_second = 1\n",
			"[worker_budgets.requests]\ncapacity = 1\nrefill_per_second = 0\n",
			"[worker_budgets.leases]\ncapacity = 1\nrefill_per_second = 0\n",
			"[server]\nprivate_config_sentinel = 3\n",
			"[paths]\ndb = { private_config_sentinel = 3 }\n",
			"[private_config_sentinel\n",
			"[paths]\ndb = '../a/./é.db'\nserver_cert = 'cert.pem'\nserver_key = 'key.pem'\nca_cert = 'ca.pem'\nca_key = 'ca-key.pem'\nmaster_key = 'master.key'\n",
		] {
			do_test(input.as_bytes());
		}
	}
}
