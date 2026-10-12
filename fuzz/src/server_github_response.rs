//! Parse every provider response through the same pure cores as HTTP dispatch.
//! Diagnostics have an exact metadata-only vocabulary; token Debug is constant.
use http::StatusCode;
use loupe_server::reporters::{github, github_app, ReporterCredential};
use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserializer;
use serde_json::Value;

use crate::utils::input::ByteSource;
use crate::utils::redact::{assert_redacted, Redaction};
use crate::utils::test_logger;

/// Independent schema oracle: required fields occur once, or in declaration
/// order in an exact-length sequence. Unknown object values use Serde's ignored
/// value grammar, which admits invalid UTF-8, lone surrogates, huge numbers and
/// deep containers that a whole-body Value decoder rejects. Syntax still matters.
struct Fields(&'static [&'static str]);

impl Fields {
	fn decode(self, body: &[u8]) -> Option<Vec<Value>> {
		let mut decoder = serde_json::Deserializer::from_slice(body);
		let values = (&mut decoder).deserialize_any(self).ok()?;
		decoder.end().ok()?;
		Some(values)
	}

	fn validate<E: de::Error>(name: &str, value: Value) -> Result<Value, E> {
		if (name == "id" && value.as_u64().is_some()) || (name != "id" && value.is_string()) {
			Ok(value)
		} else {
			Err(E::custom("wrong field type"))
		}
	}
}

impl<'de> Visitor<'de> for Fields {
	type Value = Vec<Value>;

	fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str("response fields in an object or sequence")
	}

	fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
		let mut values = vec![None; self.0.len()];
		while let Some(name) = map.next_key::<String>()? {
			if let Some(index) = self.0.iter().position(|field| *field == name) {
				if values[index].is_some() {
					return Err(de::Error::custom("duplicate field"));
				}
				values[index] = Some(Self::validate(&name, map.next_value()?)?);
			} else {
				map.next_value::<IgnoredAny>()?;
			}
		}
		values.into_iter().collect::<Option<_>>().ok_or_else(|| de::Error::custom("missing field"))
	}

	fn visit_seq<S: SeqAccess<'de>>(self, mut sequence: S) -> Result<Self::Value, S::Error> {
		let mut values = Vec::with_capacity(self.0.len());
		for name in self.0 {
			let value =
				sequence.next_element()?.ok_or_else(|| de::Error::custom("missing field"))?;
			values.push(Self::validate(name, value)?);
		}
		if sequence.next_element::<IgnoredAny>()?.is_some() {
			return Err(de::Error::custom("extra field"));
		}
		Ok(values)
	}
}

pub fn do_test(data: &[u8]) {
	let mut input = ByteSource::new(data);
	let kind = input.u8().unwrap_or(0) % 5;
	let Ok(status) = StatusCode::from_u16(input.u16().unwrap_or(200)) else { return };
	let body = input.rest();
	match kind {
		0 => {
			let expected = Fields(&["id", "slug"]).decode(body);
			let result = github_app::parse_app_response(status, body, 7);
			assert_eq!(
				result.is_ok(),
				status.is_success() && expected.is_some(),
				"app admission differs"
			);
			match result {
				Ok(app) => {
					assert!(status.is_success(), "app error status admitted");
					assert_eq!(
						expected.as_ref().and_then(|fields| fields.first()).and_then(Value::as_u64),
						Some(app.id)
					);
					assert_eq!(
						expected.as_ref().and_then(|fields| fields.get(1)).and_then(Value::as_str),
						Some(app.slug.as_str())
					);
				},
				Err(error) => {
					let expected = if status.is_success() {
						"parsing GitHub App metadata: invalid response body".into()
					} else {
						format!("github returned {status} when fetching app 7")
					};
					assert_eq!(
						format!("{error:#}"),
						expected,
						"app error disclosed response content"
					);
				},
			}
		},
		1 => {
			let expected = Fields(&["id"]).decode(body);
			let result = github_app::parse_installation_response(status, body, "example", "repo");
			assert_eq!(
				result.is_ok(),
				status.is_success() && expected.is_some(),
				"installation admission differs"
			);
			match result {
				Ok(id) => {
					assert!(status.is_success(), "installation error status admitted");
					assert_eq!(
						expected.as_ref().and_then(|fields| fields.first()).and_then(Value::as_u64),
						Some(id)
					);
				},
				Err(error) => {
					let expected = if status == StatusCode::NOT_FOUND {
						"the GitHub App is not installed on example/repo; add the repository to the app's installation or report with a PAT instead".into()
					} else if status.is_success() {
						"parsing installation response: invalid response body".into()
					} else {
						format!("github returned {status} when looking up the installation for example/repo")
					};
					assert_eq!(
						format!("{error:#}"),
						expected,
						"installation error disclosed response content"
					);
				},
			}
		},
		2 => {
			let expected = Fields(&["token"]).decode(body);
			let result = github_app::parse_access_token_response(status, body, 7);
			assert_eq!(
				result.is_ok(),
				status.is_success() && expected.is_some(),
				"token admission differs"
			);
			match result {
				Ok(token) => {
					assert!(status.is_success(), "token error status admitted");
					assert_eq!(
						expected.as_ref().and_then(|fields| fields.first()).and_then(Value::as_str),
						Some(token.expose().as_str())
					);
					let credential = ReporterCredential::GithubPat(loupe_provenance::Secret::new(
						token.expose().as_bytes().to_vec(),
					));
					assert_redacted(
						&format!("{credential:?}"),
						token.expose().as_bytes(),
						&Redaction::baseline("GithubPat(redacted)"),
					);
					assert_eq!(format!("{token:?}"), "[redacted]");
					assert_eq!(format!("{token}"), "[redacted]");
				},
				Err(error) => {
					let expected = if status.is_success() {
						"parsing installation token: invalid response body".into()
					} else {
						format!("github returned {status} when minting an installation token for installation 7")
					};
					assert_eq!(
						format!("{error:#}"),
						expected,
						"token error disclosed response content"
					);
				},
			}
		},
		3 => {
			let json = serde_json::from_slice::<Value>(body).ok();
			match github::parse_issue_response(status, body) {
				Ok(number) => {
					assert!(status.is_success(), "issue error status admitted");
					assert!(json.is_some());
					assert_eq!(
						number,
						json.as_ref()
							.and_then(|json| json.get("number"))
							.and_then(Value::as_i64)
							.map(|value| value.to_string())
					);
				},
				Err(error) => {
					if status.is_success() {
						assert!(json.is_none());
					}
					let expected = if status.is_success() {
						"parsing issue response: invalid response body".into()
					} else {
						format!("github returned {status} when opening issue")
					};
					assert_eq!(
						format!("{error:#}"),
						expected,
						"issue error disclosed response content"
					);
				},
			}
		},
		_ => {
			let text = String::from_utf8_lossy(body);
			let result = github::check_label_response(status, &text, "severity:high");
			assert_eq!(
				result.is_ok(),
				status.is_success()
					|| (status == StatusCode::UNPROCESSABLE_ENTITY
						&& text.contains("already_exists"))
			);
			if let Err(error) = result {
				assert_eq!(
					format!("{error:#}"),
					format!("github returned {status} when creating label severity:high"),
					"label error disclosed response content"
				);
			}
		},
	}
}

pub fn server_github_response_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn server_github_response_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller guarantees a valid readable input buffer.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	fn check(kind: u8, body: &[u8]) {
		for status in [200u16, 201, 204, 400, 404, 422, 500] {
			let mut input = vec![kind];
			input.extend_from_slice(&status.to_le_bytes());
			input.extend_from_slice(body);
			do_test(&input);
		}
	}

	#[test]
	fn ignored_invalid_utf8_regression() {
		do_test(include_bytes!("../test_cases/server_github_response/ignored-utf8-original"));
		do_test(include_bytes!("../test_cases/server_github_response/ignored-utf8-minimal"));
	}

	#[test]
	fn typed_fields_and_exact_sequences() {
		for (kind, schema, object, sequence, expected) in [
			(
				0,
				&["id", "slug"][..],
				&b"{\"slug\":\"app\",\"id\":7}"[..],
				&b"[7,\"app\"]"[..],
				vec![Value::from(7), Value::from("app")],
			),
			(1, &["id"][..], &b"{\"id\":7}"[..], &b"[7]"[..], vec![Value::from(7)]),
			(
				2,
				&["token"][..],
				&b"{\"token\":\"secret\"}"[..],
				&b"[\"secret\"]"[..],
				vec![Value::from("secret")],
			),
		] {
			for body in [object, sequence] {
				assert_eq!(Fields(schema).decode(body), Some(expected.clone()));
				check(kind, body);
			}
			for body in [&b"{}"[..], b"[]", b"null", b"true", b"7", b"\"text\""] {
				assert!(Fields(schema).decode(body).is_none());
				check(kind, body);
			}
		}
		for (kind, schema, bodies) in [
			(
				0,
				&["id", "slug"][..],
				&[
					&b"{\"id\":7}"[..],
					&b"{\"slug\":\"app\"}"[..],
					&b"[7]"[..],
					&b"[7,\"app\",null]"[..],
					&b"[\"app\",7]"[..],
					&b"{\"id\":7,\"slug\":\"app\",\"slug\":\"other\"}"[..],
				][..],
			),
			(
				1,
				&["id"][..],
				&[
					&b"{\"id\":7,\"id\":8}"[..],
					&b"{\"id\":7,\"i\\u0064\":8}"[..],
					&b"[7,8]"[..],
					&b"{\"id\":null}"[..],
					&b"{\"id\":1.0}"[..],
					&b"{\"id\":-0}"[..],
					&b"{\"id\":18446744073709551616}"[..],
				][..],
			),
			(
				2,
				&["token"][..],
				&[
					&b"{\"token\":\"secret\",\"token\":\"other\"}"[..],
					&b"[\"secret\",null]"[..],
					&b"{\"token\":null}"[..],
					&b"{\"token\":7}"[..],
					&b"{\"token\":\"\xff\"}"[..],
					&b"{\"token\":\"\\uD800\"}"[..],
				][..],
			),
		] {
			for body in bodies {
				assert!(Fields(schema).decode(body).is_none(), "admitted {body:?}");
				check(kind, body);
			}
		}
	}

	#[test]
	fn ignored_values_still_require_valid_syntax() {
		for (kind, schema, fields) in [
			(0, &["id", "slug"][..], &b"\"id\":7,\"slug\":\"app\""[..]),
			(1, &["id"][..], &b"\"id\":7"[..]),
			(2, &["token"][..], &b"\"token\":\"secret\""[..]),
		] {
			let deep = format!("{}null{}", "[".repeat(140), "]".repeat(140));
			for (ignored, accepted) in [
				(&b"\"\xff\""[..], true),
				(&b"\"\\uD800\""[..], true),
				(&b"1e9999"[..], true),
				(&b"{\"\xff\":[\"\xff\",1e9999]}"[..], true),
				(deep.as_bytes(), true),
				(&b"[1,]"[..], false),
				(&b"{\"x\":}"[..], false),
				(&b"01"[..], false),
				(&b"\"\\uZZZZ\""[..], false),
				(&b"\"\n\""[..], false),
			] {
				let mut body = b"{".to_vec();
				body.extend_from_slice(fields);
				body.extend_from_slice(b",\"unused\":");
				body.extend_from_slice(ignored);
				body.extend_from_slice(b",\"unused\":null}");
				assert_eq!(Fields(schema).decode(&body).is_some(), accepted, "{body:?}");
				check(kind, &body);
				// Issue receipts use Value and must reject invalid ignored strings,
				// extreme numbers and deep objects instead of skipping them.
				check(3, &body);
				check(4, &body);
			}
			let mut body = b"{".to_vec();
			body.extend_from_slice(fields);
			body.extend_from_slice(b"} null");
			assert!(Fields(schema).decode(&body).is_none(), "trailing data admitted");
			check(kind, &body);
		}
	}

	#[test]
	fn issue_numbers_and_label_statuses() {
		for body in [
			&b"{\"number\":7,\"number\":8}"[..],
			b"{\"number\":-7}",
			b"{\"number\":9223372036854775808}",
			b"{\"number\":\"7\"}",
			b"[7]",
			b"null",
			b"{\"number\":7,\"unused\":\"\xff\"}",
			b"{\"number\":7} null",
			b"already_exists",
			b"already_exist",
			b"already_exists\xff",
		] {
			check(3, body);
			check(4, body);
		}
	}
}
