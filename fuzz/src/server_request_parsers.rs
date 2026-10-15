//! Independent shape checks for protocol, query, clone URL and FTS ingress.
use http::HeaderValue;
use loupe_proto::PROTOCOL_VERSION;
use loupe_server::router::request_protocol_error;
use loupe_server::routes::jobs;

use crate::utils::test_logger;

fn decimal_u16(bytes: &[u8]) -> Option<u16> {
	let digits = bytes.strip_prefix(b"+").unwrap_or(bytes);
	if digits.is_empty() {
		return None;
	}
	let mut value = 0u16;
	for byte in digits {
		if !byte.is_ascii_digit() {
			return None;
		}
		value = value.checked_mul(10)?.checked_add(u16::from(byte - b'0'))?;
	}
	Some(value)
}

pub(super) fn clone_url_shape(text: &str) -> Option<(String, String, String)> {
	let (scheme, rest) = text.split_once("://")?;
	let segments: Vec<_> = rest.split('/').collect();
	let (host, owner, raw_repo) = match scheme {
		"file" => ("local", "local", *segments.iter().rev().find(|part| !part.is_empty())?),
		"https" => {
			let names: Vec<_> = segments.iter().skip(1).filter(|part| !part.is_empty()).collect();
			(*segments.first()?, **names.first()?, **names.get(1)?)
		},
		_ => return None,
	};
	let repo = raw_repo.strip_suffix(".git").unwrap_or(raw_repo);
	(!repo.is_empty()).then(|| (host.to_owned(), owner.to_owned(), repo.to_owned()))
}

pub fn do_test(data: &[u8]) {
	let Some((&selector, bytes)) = data.split_first() else { return };
	let text = String::from_utf8_lossy(bytes);
	let optional = (selector & 128 == 0).then_some(text.as_ref());
	match selector % 5 {
		0 => {
			let value =
				if selector & 128 == 0 { HeaderValue::from_bytes(bytes).ok() } else { None };
			let admitted = value.is_none() || decimal_u16(bytes) == Some(PROTOCOL_VERSION);
			assert_eq!(
				request_protocol_error(value.as_ref()).is_none(),
				admitted,
				"protocol header admission differs"
			);
		},
		1 => {
			let result = jobs::parse_states(optional);
			let mut expected = Vec::new();
			if let Some(raw) = optional {
				for state in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
					if !expected.contains(&state) {
						expected.push(state);
					}
				}
			}
			let valid = optional.is_none()
				|| (!expected.is_empty()
					&& expected.iter().all(|state| {
						["queued", "leased", "succeeded", "failed", "cancelled"].contains(state)
					}));
			assert_eq!(result.is_ok(), valid, "job state filter admission differs");
			if let Ok(states) = result {
				assert_eq!(states.iter().map(|state| state.as_str()).collect::<Vec<_>>(), expected);
			}
		},
		2 => {
			let expected = optional
				.is_none_or(|kind| ["scan", "verify", "survey", "drilldown"].contains(&kind));
			let result = jobs::parse_kind(optional);
			assert_eq!(result.is_ok(), expected, "job kind filter admission differs");
			if let Ok(kind) = result {
				assert_eq!(kind.as_ref().map(|kind| kind.as_str()), optional);
			}
		},
		3 => {
			let parsed = loupe_server::fuzz_support::legacy_clone_url(&text);
			assert_eq!(parsed, clone_url_shape(&text), "clone URL grammar differs");
			if let Some((host, owner, repo)) = parsed {
				assert!(!owner.is_empty() && !repo.is_empty());
				if text.starts_with("file://") {
					assert_eq!((&*host, &*owner), ("local", "local"));
				} else {
					assert!(text.starts_with(&format!("https://{host}/")));
				}
				let canonical = format!("https://{host}/{owner}/{repo}.git");
				assert_eq!(
					loupe_server::fuzz_support::legacy_clone_url(&canonical),
					Some((host, owner, repo))
				);
			}
		},
		_ => {
			let output = loupe_storage::findings::sanitize_fts_query(&text);
			let expected = text
				.split_whitespace()
				.filter_map(|token| {
					let cleaned: String = token
						.chars()
						.filter(|ch| !['"', '*', ':', '(', ')', '\''].contains(ch))
						.collect();
					(cleaned.len() >= 2).then(|| format!("\"{cleaned}\""))
				})
				.collect::<Vec<_>>()
				.join(" ");
			assert_eq!(output, expected, "FTS stripping or token admission differs");
			assert!(!output.contains(['*', ':', '(', ')', '\'']));
		},
	}
}

pub fn server_request_parsers_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn server_request_parsers_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller guarantees a valid readable input buffer.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
