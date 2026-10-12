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
