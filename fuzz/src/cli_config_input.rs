//! Actual native Config parser callbacks. Header: selector, source, recipe.
//! Recipe 0 is raw (64 KiB bound); others construct one 2 MiB edge field.
//! No process argv/environment/file/HTTP/TLS integration is claimed here.
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use loupe_cli::fuzz_support::{self, CommonNameSource, ConfigCase, ConfigValue};

use crate::cli_common as oracle;
use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	let data = &data[..data.len().min(oracle::INPUT_LIMIT)];
	let Some(&selector) = data.first() else { return };
	let case = ConfigCase::ALL[usize::from(selector) % ConfigCase::ALL.len()];
	let source = match data.get(1).copied().unwrap_or(0) % 3 {
		0 => CommonNameSource::CommandLine,
		1 => CommonNameSource::Environment,
		_ => CommonNameSource::Default,
	};
	let recipe = data.get(2).copied().unwrap_or(0);
	let payload = data.get(3..).unwrap_or_default();
	let constructed;
	let raw = if recipe == 0 {
		payload
	} else {
		constructed = oracle::boundary(recipe - 1).into_bytes();
		&constructed
	};
	check(case, source, raw, payload);
}
pub fn check(case: ConfigCase, source: CommonNameSource, raw: &[u8], actions: &[u8]) -> bool {
	let value = std::ffi::OsStr::from_bytes(raw);
	let observed = fuzz_support::observe_config(case, value, source, actions);
	assert_eq!(observed.case, case);
	let default = case == ConfigCase::CommonName && source == CommonNameSource::Default;
	assert_eq!(observed.mints, usize::from(!default), "actual Config mint count");
	let utf8 = std::str::from_utf8(raw);
	let admitted = if default || case == ConfigCase::Path {
		true
	} else {
		utf8.as_ref().is_ok_and(|s| match case {
			ConfigCase::Pat | ConfigCase::Pem => true,
			ConfigCase::Url => reqwest::Url::parse(s).is_ok(),
			_ => oracle::exact(s, case == ConfigCase::Search),
		})
	};
	assert_eq!(observed.result.is_ok(), admitted, "Config {case:?} admission");
	let expected_callback = match case {
		ConfigCase::CloneUrl => "CloneUrlLegacy",
		ConfigCase::Branch => "BranchLegacy",
		ConfigCase::Owner => "OwnerLegacy",
		ConfigCase::Repo => "RepoLegacy",
		ConfigCase::WorkerName => "WorkerNameLegacy",
		ConfigCase::Search => "SearchLegacy",
		ConfigCase::Hostname => "HostnameLegacy",
		ConfigCase::CommonName => "CommonNameLegacy",
		ConfigCase::Path => "PathLegacy",
		ConfigCase::Url => "UrlLegacy",
		ConfigCase::Pem => "PemLegacy",
		ConfigCase::Pat => "Pat",
	};
	let mut expected_callbacks = vec![expected_callback];
	if case == ConfigCase::CommonName && !default {
		expected_callbacks.push("HostnameLegacy");
	}
	assert_eq!(observed.callbacks, expected_callbacks, "actual callback entered");
	let text_owner =
		!matches!(case, ConfigCase::Path | ConfigCase::Url | ConfigCase::Pem | ConfigCase::Pat);
	let expected_typed = if admitted && text_owner && !default {
		vec![utf8.unwrap_or_else(|_| unreachable!("admitted text is UTF-8")).to_owned()]
	} else {
		Vec::new()
	};
	assert_eq!(observed.typed_text, expected_typed, "typed Config text before legacy exit");
	if let Ok(result) = observed.result {
		match result {
			ConfigValue::Text(text) => {
				assert_eq!(text.as_bytes(), if default { b"loupe-server".as_slice() } else { raw })
			},
			ConfigValue::Path(path) => assert_eq!(path.into_os_string().into_vec(), raw),
			ConfigValue::Url(url) => {
				assert_eq!(Some(url), utf8.ok().and_then(|s| reqwest::Url::parse(s).ok()))
			},
			ConfigValue::Pem(text) => assert_eq!(text.as_bytes(), raw),
			ConfigValue::Pat(pat) => {
				assert!(
					pat.shared && pat.redacted && pat.unique_moves && pat.shared_copy,
					"PAT ownership/formatter observation"
				);
				assert_eq!(pat.survived.as_bytes(), raw);
				assert!(pat.exports.len() >= 2);
				for text in pat.exports {
					assert_eq!(text.as_bytes(), raw)
				}
			},
		}
	}
	admitted
}
pub fn cli_config_input_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data)
}
/// # Safety
/// The caller provides `datalen` readable bytes for this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cli_config_input_run(data: *const u8, datalen: usize) {
	// SAFETY: the C runner supplies a readable input slice for this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn every_callback_has_positive_negative_and_exact_controls() {
		for case in ConfigCase::ALL {
			let good = if case == ConfigCase::Url {
				b"http://host/ e%CC%81".as_slice()
			} else {
				b" exact e\xcc\x81 *markup* "
			};
			assert!(check(case, CommonNameSource::CommandLine, good, &[0, 0, 2, 1, 3, 1]));
			let rejected = check(case, CommonNameSource::CommandLine, b"\xff", &[]);
			assert_eq!(rejected, case == ConfigCase::Path);
			if !matches!(
				case,
				ConfigCase::Url | ConfigCase::Path | ConfigCase::Pem | ConfigCase::Pat
			) {
				assert!(!check(case, CommonNameSource::Environment, b"\x1b", &[]));
			}
		}
	}
	#[test]
	fn defaults_secrets_native_paths_and_text_edges_are_distinct() {
		assert!(check(ConfigCase::CommonName, CommonNameSource::Default, b"\xff", &[]));
		assert!(check(ConfigCase::CommonName, CommonNameSource::Environment, b"loupe-server", &[]));
		for case in [ConfigCase::Pat, ConfigCase::Pem, ConfigCase::Path] {
			for raw in [b"".as_slice(), b"\0\r\n\t\x1b", b"e\xcc\x81\\\""] {
				assert!(check(case, CommonNameSource::CommandLine, raw, &[0, 2, 0, 1, 3]));
			}
			// The harness expansion limit is not a PAT/PEM/native-path policy cap.
			assert!(check(
				case,
				CommonNameSource::CommandLine,
				&oracle::boundary(2).into_bytes(),
				&[]
			));
		}
		for recipe in 0..7 {
			let field = oracle::boundary(recipe);
			assert_eq!(
				check(ConfigCase::Search, CommonNameSource::CommandLine, field.as_bytes(), &[]),
				field.len() <= oracle::TEXT_LIMIT
			);
		}
		assert!(check(
			ConfigCase::Search,
			CommonNameSource::CommandLine,
			b"\r\n\t e\xcc\x81 ",
			&[]
		));
		assert!(!check(ConfigCase::WorkerName, CommonNameSource::CommandLine, b"a\n", &[]));
	}
}
