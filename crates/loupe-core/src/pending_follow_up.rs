//! The specific mixed-source coalescing document stored on a generation.
use loupe_provenance::{Db, Source};

use crate::text::json::CheckedJson;
use crate::text::policy::{Payload, RevisionText};
use crate::text::{BoundedJson, BoundedText, Error};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowUpTrigger {
	Manual,
	Scheduled,
	CompatScanApi,
	Reconciliation,
	Operator,
}
impl FollowUpTrigger {
	fn as_str(self) -> &'static str {
		match self {
			Self::Manual => "manual",
			Self::Scheduled => "scheduled",
			Self::CompatScanApi => "compat_scan_api",
			Self::Reconciliation => "reconciliation",
			Self::Operator => "operator",
		}
	}
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewIntent {
	FullReview,
	Incremental,
}
impl ReviewIntent {
	fn as_str(self) -> &'static str {
		match self {
			Self::FullReview => "full_review",
			Self::Incremental => "incremental",
		}
	}
}

/// Prior database content and the current request remain distinct owners.
/// Canonicalization preserves the historical Payload policy, including its
/// semantic string normalization, limits, and unknown trigger entries.
pub struct PendingFollowUp<'a, S: Source> {
	_previous: Option<&'a BoundedJson<Payload, Db>>,
	_requested_ref: &'a BoundedText<RevisionText, S>,
	canonical: CheckedJson,
}
impl<'a, S: Source> PendingFollowUp<'a, S> {
	pub fn new(
		previous: Option<&'a BoundedJson<Payload, Db>>,
		requested_ref: &'a BoundedText<RevisionText, S>, trigger: FollowUpTrigger,
		intent: ReviewIntent, at: i64,
	) -> Result<Self, Error> {
		let prior =
			previous.and_then(|p| serde_json::from_str::<serde_json::Value>(p.expose()).ok());
		let retained_intent = if prior.as_ref().is_some_and(|p| p["kind_hint"] == "full_review") {
			ReviewIntent::FullReview
		} else {
			intent
		};
		let mut triggers =
			prior.and_then(|p| p["triggers"].as_array().cloned()).unwrap_or_default();
		triggers.push(serde_json::json!({
			"trigger": trigger.as_str(), "ref": requested_ref, "at": at,
			"kind_hint": intent.as_str()
		}));
		if triggers.len() > 16 {
			triggers.drain(..triggers.len() - 16);
		}
		let value = serde_json::json!({
			"version": 1, "triggers": triggers, "newest_ref": requested_ref,
			"kind_hint": retained_intent.as_str()
		});
		let canonical = CheckedJson::parse::<Payload>(&value.to_string())?;
		Ok(Self { _previous: previous, _requested_ref: requested_ref, canonical })
	}

	/// Fixed generation pending-follow-up persistence view; no source cast.
	pub fn canonical(&self) -> &str {
		self.canonical.expose()
	}
}
impl<S: Source> std::fmt::Debug for PendingFollowUp<'_, S> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "PendingFollowUp<Db, {}>([redacted])", S::NAME)
	}
}
