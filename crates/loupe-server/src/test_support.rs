//! Private synthetic SQL-domain inputs and actual Config parser fixtures.
#![allow(dead_code)]
use std::ffi::OsStr;
use std::path::Path;

use clap::Parser;
use loupe_core::text::{BoundedText, TextPolicy};
use loupe_provenance::{Db, Ingress, Mark, Untrusted, Unvalidated, Validate};

use crate::config::{
	ConfiguredHostname, ConfiguredPath, ConfiguredPem, ConfiguredPemArgument, HostnameParser,
	PathParser, PemParser,
};

#[path = "../tests/common/offline.rs"]
pub(crate) mod offline;

#[allow(unsafe_code)]
pub(crate) fn operator() -> Ingress<loupe_provenance::Operator> {
	// SAFETY: synthetic authority confined to this private test fixture module.
	unsafe { Ingress::new() }
}

pub(crate) type Events =
	std::sync::Arc<std::sync::Mutex<Vec<std::collections::BTreeMap<String, String>>>>;
pub(crate) fn capture_security_events() -> (tracing::subscriber::DefaultGuard, Events) {
	use tracing_subscriber::prelude::*;
	struct Capture(Events);
	impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
		fn on_event(
			&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>,
		) {
			if event.metadata().target() != "loupe::security_event" {
				return;
			}
			struct Fields(std::collections::BTreeMap<String, String>);
			impl tracing::field::Visit for Fields {
				fn record_debug(
					&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug,
				) {
					self.0.insert(field.name().into(), format!("{value:?}"));
				}
				fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
					self.0.insert(field.name().into(), value.into());
				}
			}
			let mut fields = Fields(Default::default());
			event.record(&mut fields);
			self.0.lock().unwrap().push(fields.0);
		}
	}
	let events: Events = Default::default();
	let guard = tracing::subscriber::set_default(
		tracing_subscriber::registry().with(Capture(events.clone())),
	);
	(guard, events)
}

struct Fixture<F>(F);
impl<F, T> Validate<&str, Db> for Fixture<F>
where
	F: for<'a> FnOnce(&'a str, &Mark<'a, Db>) -> T,
{
	type Output = T;
	type Error = std::convert::Infallible;
	fn validate<'a>(
		self, input: Unvalidated<'a, &str>, mark: Mark<'a, Db>,
	) -> Result<T, Self::Error> {
		Ok((self.0)(input.get(), &mark))
	}
}
#[allow(unsafe_code)]
fn database<T>(raw: &str, f: impl for<'a> FnOnce(&'a str, &Mark<'a, Db>) -> T) -> T {
	// SAFETY: synthetic data in this private cfg(test) fixture, never a runtime row reader.
	Untrusted::new(raw, unsafe { Ingress::<Db>::new() }).validate(Fixture(f)).unwrap()
}
pub(crate) fn text<P: TextPolicy>(raw: &str) -> BoundedText<P, Db> {
	database(raw, |raw, mark| BoundedText::new(mark, raw).unwrap())
}
pub(crate) fn scanner(value: serde_json::Value) -> loupe_core::ScannerDocument<Db> {
	database("", |_, mark| loupe_core::ScannerDocument::stored(mark, value))
}
#[derive(Parser)]
struct ConfigArgs {
	#[arg(long, value_parser=PathParser)]
	path: Option<ConfiguredPath>,
	#[arg(long, value_parser=PemParser)]
	pem: Option<ConfiguredPemArgument>,
	#[arg(long, value_parser=HostnameParser)]
	hostname: Vec<ConfiguredHostname>,
}
pub(crate) fn path(value: &Path) -> ConfiguredPath {
	ConfigArgs::try_parse_from([OsStr::new("fixture"), OsStr::new("--path"), value.as_os_str()])
		.unwrap()
		.path
		.unwrap()
}
pub(crate) fn pem(value: &str) -> ConfiguredPem {
	let args = ConfigArgs::try_parse_from(["fixture", &format!("--pem={value}")]).unwrap();
	crate::config::select_tls_pem("fixture", args.pem, None, None, "missing fixture").unwrap()
}
pub(crate) fn hostnames(values: &[&str]) -> Vec<ConfiguredHostname> {
	let args: Vec<_> = std::iter::once("fixture".to_owned())
		.chain(values.iter().map(|value| format!("--hostname={value}")))
		.collect();
	ConfigArgs::try_parse_from(args).unwrap().hostname
}
#[test]
fn content_debug_omits_raw_receipt() {
	let receipt = crate::reporters::DispatchReceipt {
		kind: "github",
		external_id: Some("https://example.invalid/AGENT_DEBUG_SENTINEL".into()),
	};
	assert!(
		!format!("{receipt:?}").contains("AGENT_DEBUG_SENTINEL"),
		"receipt Debug exposes external content"
	);
}
#[test]
fn content_debug_omits_raw_query() {
	let query = crate::routes::jobs::ListQuery {
		limit: Some(3),
		state: Some("AGENT_DEBUG_SENTINEL".into()),
		kind: None,
	};
	assert!(
		!format!("{query:?}").contains("AGENT_DEBUG_SENTINEL"),
		"query Debug exposes raw input"
	);
}
#[test]
fn content_debug_omits_raw_certificate_bytes() {
	let certificate = crate::PeerCert(rustls::pki_types::CertificateDer::from(vec![77; 32]));
	let debug = format!("{certificate:?}");
	assert!(
		!debug.contains("4d4d") && !debug.contains("77, 77"),
		"peer certificate Debug exposes bytes: {debug}"
	);
}
