//! Raw broker message ceilings, enforced before parsing or text allocation.

#[derive(Clone, Copy)]
pub(crate) struct Limits {
	pub(crate) mcp_record_bytes: usize,
	pub(crate) model_request_bytes: usize,
}

impl Default for Limits {
	fn default() -> Self {
		Self { mcp_record_bytes: 16 * 1024 * 1024, model_request_bytes: 16 * 1024 * 1024 }
	}
}
