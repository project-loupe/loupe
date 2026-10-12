//! Compile-time schema controls. These do not establish runtime producer coverage.
//!
//! The concrete emitter accepts an event made only from closed/scalar fields:
//! ```
//! use loupe_core::security_event::*;
//! emit(SecurityEvent::BudgetExhausted {
//! 	context: EventContext::default(),
//! 	resource: BudgetResource::WorkerRequests,
//! 	used: None,
//! 	limit: None,
//! });
//! ```
//! Neither owned nor borrowed text is an event:
//! ```compile_fail,E0308
//! use loupe_core::security_event::emit;
//! emit(String::from("untrusted"));
//! ```
//! ```compile_fail,E0308
//! use loupe_core::security_event::emit;
//! fn wrong(raw: &str) { emit(raw); }
//! ```
//! A static string still cannot become a reason:
//! ```compile_fail,E0308
//! use loupe_core::security_event::*;
//! let _ = SecurityEvent::CapabilityDenied {
//!     context: EventContext::default(), operation: Operation::Heartbeat,
//!     requested: RequestedTarget::None, reason: "missing_capability",
//! };
//! ```
//! IDs are integers, not content or a context map:
//! ```compile_fail,E0308
//! use loupe_core::security_event::EventContext;
//! let _ = EventContext { job_id: Some("1"), ..EventContext::default() };
//! ```
//! ```compile_fail,E0308
//! use loupe_core::security_event::emit;
//! emit(serde_json::json!({"job_id": 1}));
//! ```
//! A redacted secret is still authority material, never event context:
//! ```compile_fail,E0308
//! use loupe_core::security_event::emit;
//! use loupe_provenance::Secret;
//! emit(Secret::new(String::from("fixture-secret")));
//! ```
//! A fixed-size hash is not an admitted correlation identifier:
//! ```compile_fail,E0308
//! use loupe_core::security_event::emit;
//! emit([0_u8; 32]);
//! ```
//! The domain JobKind enum is text-bearing through Unknown:
//! ```compile_fail,E0308
//! use loupe_core::{JobKind, security_event::emit};
//! emit(JobKind::Unknown(String::from("untrusted-kind")));
//! ```
//! Arbitrary errors and callbacks are not a logging interface:
//! ```compile_fail,E0308
//! use loupe_core::security_event::emit;
//! emit(std::io::Error::other("untrusted-error"));
//! ```
//! ```compile_fail,E0308
//! use loupe_core::security_event::emit;
//! emit(|| "untrusted-callback");
//! ```
