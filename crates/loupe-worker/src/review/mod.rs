//! Review-phase work on the worker.

#[cfg_attr(
	not(any(test, kani)),
	expect(dead_code, reason = "no survey session consults the gate yet")
)]
pub(crate) mod gate;
#[allow(dead_code, reason = "the survey handler runs prepared attempts")]
pub(crate) mod inventory;
#[allow(dead_code, reason = "the survey handler runs prepared attempts")]
pub mod prepare;
pub(crate) mod retry;
