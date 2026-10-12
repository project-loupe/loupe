//! Fixed-source fixtures for actual private server validators.
//! These entries exist only in fuzz builds and grant no runtime authority.

pub use crate::ingress::transport_fuzz::{collect_operator, Collection};
#[path = "ingress/router_fuzz.rs"]
mod router_fixture;
pub use router_fixture::{leased_heartbeat, request_route, RequestCase, RequestObservation};

pub use crate::ingress::jobs::fuzz::{worker_request, WorkerRequest};
pub use crate::ingress::query::fuzz::{job_query, operator_search, worker_search};
pub use crate::ingress::registry::fuzz::{operator_request, OperatorRequest};

pub type Decoded = Result<serde_json::Value, (u16, String)>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CarriedSpan {
	pub field: &'static str,
	pub start: usize,
	pub end: usize,
}

thread_local! {
	static CARRIED: std::cell::RefCell<Option<Vec<CarriedSpan>>> = const { std::cell::RefCell::new(None) };
}

pub(crate) fn observe_carry(field: &'static str, start: usize, end: usize) {
	CARRIED.with_borrow_mut(|active| {
		if let Some(spans) = active {
			spans.push(CarriedSpan { field, start, end });
		}
	});
}

pub(crate) fn observe(body: impl FnOnce() -> Decoded) -> (Decoded, Vec<CarriedSpan>) {
	struct Restore(Option<Vec<CarriedSpan>>);
	impl Drop for Restore {
		fn drop(&mut self) {
			CARRIED.with_borrow_mut(|active| *active = self.0.take());
		}
	}
	let _restore = Restore(CARRIED.replace(Some(Vec::new())));
	let result = body();
	let spans = CARRIED.with_borrow_mut(|active| active.take().unwrap_or_default());
	(result, spans)
}

pub(crate) fn error(error: crate::ingress::DecodeError) -> (u16, String) {
	let (status, text) = error.response();
	(status.as_u16(), text)
}

pub use crate::reporters::github_app::fuzz_access_token as reporter_token;
pub use crate::reporters::ingress_fuzz::{
	app as reporter_app, installation as reporter_installation, issue as reporter_issue,
	label as reporter_label,
};
