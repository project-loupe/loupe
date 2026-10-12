//! Fixed observations of actual web boundaries, available only to fuzz builds.
//! No source token, marked owner, arbitrary decoder or normal-build API escapes.
use std::cell::RefCell;
use std::ffi::OsStr;
use std::path::Path;

use loupe_core::text::{BoundedText, TextPolicy};
use loupe_provenance::Browser;

/// Named implementation entries, recorded inside the real validators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
	Guard,
	Token,
	Path,
	Limit,
	Jobs,
	Search,
	CreateRepo,
	UpdateRepo,
	RotatePat,
	SetGithubReporting,
	EnqueueScan,
	RetryVerify,
	ServerHeader,
	ServerCollect,
	ServerJson,
	ServerDiagnostic,
	ConfigUrl,
	ConfigPath,
	ConfigPem,
	ConfigRaw,
	ConfigBase64,
	ConfigFile,
	ConfigSelected,
}
/// A fixed source-bearing query field observed before its temporary I exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserField {
	Search,
	State,
	Kind,
}
/// Only fake fixture data is copied by these cfg-only observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
	BufferAllocation(usize),
	BrowserText(BrowserField, String),
	Body {
		owner: Entry,
		absent: bool,
		original_len: usize,
		shared_pointer: bool,
		debug: String,
	},
	ServerText {
		original_len: usize,
		original_hash: [u8; 32],
		shared_pointer: bool,
		replacement_len: Option<usize>,
		text_len: usize,
	},
	ServerJsonDebug(String),
	ConfigValue {
		owner: Entry,
		bytes: Vec<u8>,
		pointer: usize,
		debug: Option<String>,
	},
}
#[derive(Debug, Default)]
pub struct Trace {
	pub entries: Vec<Entry>,
	pub values: Vec<Observation>,
}
thread_local! { static TRACE: RefCell<Option<Trace>> = const { RefCell::new(None) }; }
pub(crate) fn hit(entry: Entry) {
	TRACE.with(|slot| {
		if let Some(trace) = slot.borrow_mut().as_mut() {
			trace.entries.push(entry);
		}
	});
}
pub(crate) fn record(value: Observation) {
	TRACE.with(|slot| {
		if let Some(trace) = slot.borrow_mut().as_mut() {
			trace.values.push(value);
		}
	});
}
pub(crate) fn browser_text<P: TextPolicy>(field: BrowserField, text: &BoundedText<P, Browser>) {
	record(Observation::BrowserText(field, text.expose().to_owned()));
}
/// RAII scopes make observations iteration-local, including cancellation.
pub struct Session {
	audit: crate::ingress::json::audit::Audit,
}
impl Session {
	pub fn start() -> Self {
		TRACE.with(|slot| {
			assert!(slot.borrow().is_none(), "overlapping web fixture");
			*slot.borrow_mut() = Some(Trace::default());
		});
		Self { audit: crate::ingress::json::audit::start() }
	}
	pub fn finish(self) -> (Trace, Vec<(usize, usize, bool)>) {
		let trace = TRACE
			.with(|slot| slot.borrow_mut().take())
			.unwrap_or_else(|| panic!("web observation scope missing"));
		let drops = self.audit.lock().unwrap_or_else(|_| panic!("web drop audit poisoned")).clone();
		assert_eq!(
			trace
				.values
				.iter()
				.filter(|value| matches!(value, Observation::BufferAllocation(_)))
				.count(),
			drops.len(),
			"web guarded allocation still live at fixture completion"
		);
		(trace, drops)
	}
}
impl Drop for Session {
	fn drop(&mut self) {
		TRACE.with(|slot| {
			slot.borrow_mut().take();
		});
		crate::ingress::json::audit::stop();
	}
}
/// Concrete callbacks only; they mint Config at their existing native boundary.
#[derive(Debug, Clone, Copy)]
pub enum ConfigParser {
	Url,
	Path,
	Pem,
}
pub fn config_parse(parser: ConfigParser, value: &OsStr) -> Result<Vec<u8>, String> {
	crate::config::fuzz_parse(parser, value)
}
/// Actual selected read, including the existing raw/base64/file priority.
pub fn config_selected(
	raw: Option<&str>, base64: Option<&str>, path: Option<&Path>,
) -> Result<Vec<u8>, String> {
	crate::config::fuzz_selected(raw, base64, path)
}
/// The pure pre-allocation budget seam is separate from URI transport limits.
pub fn query_decoded_budget(encoded: &str) -> bool {
	crate::ingress::queries::fuzz_budget(encoded)
}
