//! Raw TOML bytes pass through the actual path-based loader and validation.
//! The fixture parent is absolute; relative TLS/cache paths must resolve there.

use loupe_worker::config::{fuzzing, WorkerConfig, WorkerConfigOverrides};
mod wire;
use loupe_worker::sandbox::SandboxNetworkMode;
use wire::FileConfig;

use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	if data.len() > 128 * 1024 {
		return;
	}
	let recipe = data.strip_prefix(b"\xffLOUPECFG").map(|control| {
		let choice = control.first().copied().unwrap_or(0);
		let length = [0, 1, 2 * 1024 * 1024 - 1, 2 * 1024 * 1024, 2 * 1024 * 1024 + 1]
			[usize::from(choice % 5)];
		format!("[logging]\nlevel=\"{}\"\n", "a".repeat(length)).into_bytes()
	});
	let data = recipe.as_deref().unwrap_or(data);
	check_arguments(data);
	let expected = std::str::from_utf8(data)
		.ok()
		.and_then(|text| toml::from_str::<toml::Value>(text).ok())
		.filter(legacy_shape)
		.filter(file_text_policy);
	let observed =
		crate::worker_client_ingress::oracle::without_logs(|| fuzzing::file_document(data));
	assert_eq!(
		observed.is_ok(),
		expected.is_some(),
		"Config original document schema/field admission differs"
	);
	if let Ok(actual) = &observed {
		let expected: FileConfig = toml::from_str(std::str::from_utf8(data).unwrap_or_default())
			.unwrap_or_else(|error| panic!("legacy admitted Config shape: {error}"));
		assert_eq!(
			format!("{actual:?}"),
			format!("{expected:?}"),
			"Config admitted original fields changed"
		);
	} else if let Err(error) = &observed {
		check_file_error(data, error);
	}
	let fixture = tempfile::tempdir().unwrap_or_else(|_| panic!("create config fixture"));
	let path = fixture.path().join("worker.toml");
	std::fs::write(&path, data).unwrap_or_else(|_| panic!("write config fixture"));
	let loaded = WorkerConfig::load(Some(&path), WorkerConfigOverrides::default());
	let parsed = fuzzing::load_document(&path);
	let Ok(file) = parsed else {
		assert!(loaded.is_err());
		return;
	};
	for value in file.resolved_paths() {
		assert!(value.is_absolute(), "config path was not resolved against its absolute parent");
	}
	let Ok(config) = fuzzing::merge(file) else {
		assert!(loaded.is_err());
		return;
	};
	let expected = allowed(&config);
	assert_eq!(
		fuzzing::validate(&config).is_ok(),
		expected,
		"worker config validation differs from oracle"
	);
	assert_eq!(loaded.is_ok(), expected, "config load skipped or changed validation");
	if let Ok(loaded) = loaded {
		assert!(allowed(&loaded));
		assert!(loaded.cache.dir.for_filesystem().is_absolute());
		for value in [&loaded.tls.ca_cert, &loaded.tls.cert, &loaded.tls.key].into_iter().flatten()
		{
			assert!(value.for_filesystem().is_absolute());
		}
	}
}

fn legacy_shape(value: &toml::Value) -> bool {
	let Some(sections) = value.as_table() else { return false };
	sections.iter().all(|(section, value)| {
		let Some(fields) = value.as_table() else { return false };
		match section.as_str() {
			"server" => fields.iter().all(|(key, v)| key == "url" && v.is_str()),
			"tls" => fields
				.iter()
				.all(|(key, v)| ["ca_cert", "cert", "key"].contains(&key.as_str()) && v.is_str()),
			"cache" => fields.iter().all(|(key, v)| match key.as_str() {
				"dir" => v.is_str(),
				"max_gb" => unsigned(v),
				_ => false,
			}),
			"runtime" => fields.iter().all(|(key, v)| match key.as_str() {
				"max_workdir_gb" => unsigned(v),
				"disable_sandbox" => v.is_bool(),
				_ => false,
			}),
			"sandbox" => fields.iter().all(|(key, v)| match key.as_str() {
				"network" => v.as_str().is_some_and(|s| ["allowlist", "public"].contains(&s)),
				"allowlist" => {
					v.as_array().is_some_and(|items| items.iter().all(toml::Value::is_str))
				},
				_ => false,
			}),
			"logging" => fields.iter().all(|(key, v)| match key.as_str() {
				"level" => v.is_str(),
				"json" | "agent_output" => v.is_bool(),
				_ => false,
			}),
			"agents" => fields.iter().all(|(key, v)| match key.as_str() {
				"scan" | "verify" => {
					v.as_str().is_some_and(|s| ["auto", "claude", "codex"].contains(&s))
				},
				"claude" | "codex" => v.as_table().is_some_and(|items| {
					items
						.iter()
						.all(|(key, v)| ["model", "effort"].contains(&key.as_str()) && v.is_str())
				}),
				_ => false,
			}),
			"scanner_defaults" => fields.iter().all(|(key, v)| {
				["max_concurrent_files", "max_file_bytes", "per_request_timeout_seconds"]
					.contains(&key.as_str())
					&& unsigned(v)
			}),
			"bkb" => fields.iter().all(|(key, v)| key == "api_url" && v.is_str()),
			"broker" => fields.iter().all(|(key, v)| {
				["request_ceiling", "output_ceiling_bytes", "token_ceiling"].contains(&key.as_str())
					&& unsigned(v)
			}),
			_ => false,
		}
	})
}
fn unsigned(value: &toml::Value) -> bool {
	value.as_integer().is_some_and(|v| v >= 0)
}
fn file_text_policy(value: &toml::Value) -> bool {
	let mut strings = Vec::new();
	for (section, key) in [("server", "url"), ("logging", "level"), ("bkb", "api_url")] {
		if let Some(text) =
			value.get(section).and_then(|v| v.get(key)).and_then(toml::Value::as_str)
		{
			strings.push(text);
		}
	}
	for agent in ["claude", "codex"] {
		for key in ["model", "effort"] {
			if let Some(text) = value
				.get("agents")
				.and_then(|v| v.get(agent))
				.and_then(|v| v.get(key))
				.and_then(toml::Value::as_str)
			{
				strings.push(text);
			}
		}
	}
	strings.extend(
		value
			.get("sandbox")
			.and_then(|v| v.get("allowlist"))
			.and_then(toml::Value::as_array)
			.into_iter()
			.flatten()
			.filter_map(toml::Value::as_str),
	);
	strings.into_iter().all(|text| crate::worker_client_ingress::oracle::text(text, false))
}
fn check_file_error(data: &[u8], actual: &str) {
	let text = match std::str::from_utf8(data) {
		Ok(text) => text,
		Err(error) => {
			assert_eq!(actual, error.to_string());
			return;
		},
	};
	if let Err(error) = toml::from_str::<FileConfig>(text) {
		let reason =
			["unknown field", "unknown variant", "invalid type", "invalid value", "missing field"]
				.into_iter()
				.find(|reason| error.message().starts_with(reason))
				.unwrap_or("invalid TOML");
		let span = error.span().unwrap_or(0..0);
		assert_eq!(
			actual,
			format!("worker_config: {reason} at bytes {}..{}", span.start, span.end),
			"Config parser error retained source payload or lost fixed metadata"
		);
	} else {
		let Some(rest) = actual.strip_prefix("worker_config: ") else {
			panic!("unknown Config policy error: {actual}")
		};
		assert!(
			rest == "Bytes"
				|| rest == "Chars"
				|| rest
					.strip_prefix("Character (U+")
					.and_then(|s| s.strip_suffix(')'))
					.is_some_and(|s| u32::from_str_radix(s, 16).is_ok()),
			"Config policy error is not closed"
		);
	}
}
#[cfg(unix)]
fn check_arguments(data: &[u8]) {
	crate::worker_client_ingress::oracle::without_logs(|| check_argument_callbacks(data));
}
#[cfg(unix)]
fn check_argument_callbacks(data: &[u8]) {
	use std::os::unix::ffi::OsStrExt;

	use fuzzing::{ArgumentCase, ArgumentValue};
	let original = std::ffi::OsStr::from_bytes(data);
	let text = std::str::from_utf8(data)
		.ok()
		.filter(|value| crate::worker_client_ingress::oracle::text(value, false));
	let observed = fuzzing::argument(ArgumentCase::Text, original);
	assert_eq!(
		observed.as_ref().ok(),
		text.map(|text| ArgumentValue::Text(text.to_owned())).as_ref(),
		"actual Config text callback differs"
	);
	let url = text
		.and_then(|text| url::Url::parse(text).ok())
		.map(|url| ArgumentValue::Url(url.to_string()));
	assert_eq!(
		fuzzing::argument(ArgumentCase::Url, original).ok(),
		url,
		"actual Config URL callback differs"
	);
	assert_eq!(
		fuzzing::argument(ArgumentCase::Path, original),
		Ok(ArgumentValue::Path(original.to_owned())),
		"native Config callback changed bytes or invented a path policy"
	);
}
#[cfg(not(unix))]
fn check_arguments(_: &[u8]) {}

fn allowed(config: &WorkerConfig) -> bool {
	let url = url::Url::parse(config.bkb.api_url.for_operation()).ok();
	let bkb = url.as_ref().is_some_and(|url| {
		["http", "https"].contains(&url.scheme())
			&& url.host_str().is_some_and(crate::worker_network_host::allowed)
			&& url.username().is_empty()
			&& url.password().is_none()
	});
	!config.agents.claude.model.for_operation().trim().is_empty()
		&& !config.agents.codex.model.for_operation().trim().is_empty()
		&& ["low", "medium", "high", "xhigh", "max"]
			.contains(&config.agents.claude.effort.for_operation())
		&& ["none", "low", "medium", "high", "xhigh"]
			.contains(&config.agents.codex.effort.for_operation())
		&& ["trace", "debug", "info", "warn", "error"]
			.contains(&config.logging.level.for_operation())
		&& config.cache.max_gb > 0
		&& config.scanner_defaults.max_concurrent_files > 0
		&& config.scanner_defaults.max_file_bytes > 0
		&& config.scanner_defaults.per_request_timeout.as_secs() > 0
		&& (config.sandbox.mode == SandboxNetworkMode::Allowlist
			|| config.sandbox.allowlist.is_empty())
		&& config
			.sandbox
			.allowlist
			.iter()
			.all(|host| crate::worker_network_host::allowed(host.for_operation()))
		&& bkb
		&& config.broker.request_ceiling > 0
		&& config.broker.output_ceiling_bytes > 0
		&& config.broker.token_ceiling != Some(0)
}

pub fn worker_config_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_config_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	#[test]
	fn bkb_urls_reject_credentials_but_allow_public_paths() {
		for (url, admitted) in [
			("https:[::@i", false),
			("https://user@example.com/api", false),
			("https://user:password@example.com/api", false),
			("https://:password@example.com/api", false),
			("https://user:@example.com/api", false),
			("https://%75ser@example.com/api", false),
			("https://example.com/api/v2?format=json", true),
			("https://example.com/@public?contact=user@example.com", true),
			("https://@example.com/api", true),
		] {
			let mut config = super::WorkerConfig::default();
			config.bkb.api_url = loupe_worker::config::ConfiguredText::Builtin(url);
			assert_eq!(
				super::fuzzing::validate(&config).is_ok(),
				admitted,
				"BKB URL policy: {url}"
			);
			assert_eq!(super::allowed(&config), admitted, "BKB URL oracle: {url}");
			super::do_test(format!("[bkb]\napi_url={url:?}\n").as_bytes());
		}
	}

	#[test]
	fn config_file_schema_fields_and_closed_errors_are_independent() {
		for document in [b"".as_slice(),b"[unknown]\nvalue='DO_NOT_ECHO_SENTINEL'",b"[logging]\nlevel='DO_NOT_ECHO_SENTINEL",b"[logging]\nlevel=17",b"[logging]\nlevel=\"bad\\u0001text\"",b"[server]\nurl='https://user:pat-sentinel@example.invalid/'\n[agents.claude]\nmodel='model'\neffort='high'",b"[tls]\nkey='native\tpath'",b"[sandbox]\nallowlist=['example.invalid']\nnetwork='allowlist'",b"\xff"] { super::do_test(document); }
		for length in 0..5 {
			let mut input = b"\xffLOUPECFG".to_vec();
			input.push(length);
			super::do_test(&input);
		}
	}
	#[test]
	fn original_argv_bytes_caps_and_native_path_spelling_survive_actual_callbacks() {
		for input in [
			b"ordinary".as_slice(),
			b"https://user:pat-sentinel@example.invalid/",
			b"a\0b",
			b"a\tb",
			b"\xff",
			b"e\xcc\x81",
			b"\xc3\xa9",
		] {
			super::check_arguments(input);
		}
		for length in [2 * 1024 * 1024 - 1, 2 * 1024 * 1024, 2 * 1024 * 1024 + 1] {
			super::check_arguments(&vec![b'a'; length]);
		}
	}
}
