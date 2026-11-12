//! Typed pre-proof evidence. These types validate structure, not source truth,
//! inventory membership, job authority or HTTP body sizes.
//!
//! Canonical bytes retain every nested `RepoPath` exactly. Do not convert these
//! payloads through generic `BoundedJson`, whose prose leaves normalize NFC.
//!
//! Admission requires a source mark or a named validator, never public serde
//! deserialization into an already labelled value.
//! ```compile_fail,E0277
//! use loupe_core::review_payload::FindingEvidenceV1;
//! use loupe_provenance::Agent;
//! let _: FindingEvidenceV1<Agent> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::review_payload::LeadEvidenceV1;
//! use loupe_provenance::Agent;
//! let _: LeadEvidenceV1<Agent> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::review_payload::UnitResultPayloadV1;
//! use loupe_provenance::Agent;
//! let _: UnitResultPayloadV1<Agent> = serde_json::from_str("{}").unwrap();
//! ```

use loupe_provenance::{Mark, Source, Unvalidated, Validate};
use serde::{Deserialize, Serialize};

mod decode;

use crate::text::{policy, Anchor, BoundedJson, BoundedText, Identifier, RepoPath, SourceRef};
use crate::{canonical, Severity};

pub type GeneratedProfile<S> = BoundedJson<policy::GeneratedProfile, S>;
pub const SURVEY_TERMINAL_MAX_BYTES: usize = 32 * 1024;
pub const EVIDENCE_MAX_BYTES: usize = 128 * 1024;
pub const AWAITING_PROOF_INFRASTRUCTURE: &str = "awaiting proof infrastructure";

// debug-ok: errors contain only static policy fields and closed failure categories.
#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("{field}: {rule}")]
	Invalid { field: &'static str, rule: &'static str },
	#[error("{field}: canonical payload exceeds {max_bytes} bytes")]
	Bytes { field: &'static str, max_bytes: usize },
	#[error("invalid review payload JSON")]
	Json,
	#[error(transparent)]
	Text(#[from] crate::text::Error),
}

impl From<serde_json::Error> for Error {
	fn from(_: serde_json::Error) -> Self {
		Self::Json
	}
}

fn invalid(field: &'static str, rule: &'static str) -> Error {
	Error::Invalid { field, rule }
}

/// A version that cannot represent a future or unversioned payload.
// debug-ok: closed scalar protocol value contains no untrusted text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct Version1;

impl TryFrom<u32> for Version1 {
	type Error = Error;
	fn try_from(value: u32) -> Result<Self, Error> {
		if value == 1 {
			Ok(Self)
		} else {
			Err(invalid("version", "expected 1"))
		}
	}
}
impl From<Version1> for u32 {
	fn from(_: Version1) -> Self {
		1
	}
}

// debug-ok: closed scalar protocol value contains no untrusted text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationRole {
	RootControl,
	EntryPoint,
	Wrapper,
	Sink,
	Implementation,
}
crate::closed_string_enum!(LocationRole { RootControl, EntryPoint, Wrapper, Sink, Implementation });

// debug-ok: closed scalar protocol value contains no untrusted text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
	Low,
	Medium,
	High,
}
crate::closed_string_enum!(Confidence { Low, Medium, High });

// Private wire schemas retain original JSON tokens; labelled values have no
// Deserialize implementation. Each field is constructed under the caller's
// actual source mark, and every public serialization rechecks its invariants.
macro_rules! checked_serde {
	($name:ident $(, $canonical:ident)?) => {
		impl<S: Source> Serialize for $name<S> {
			fn serialize<T: serde::Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
				self.validate().map_err(serde::ser::Error::custom)?;
				$(self.$canonical().map_err(serde::ser::Error::custom)?;)?
				self.serialize_fields(serializer)
			}
		}
		impl<S: Source> $name<S> {
			pub fn from_json(mark: &Mark<'_, S>, raw: &str) -> Result<Self, Error> {
				let raw: &serde_json::value::RawValue = serde_json::from_str(raw)?;
				<Self as decode::Field<S>>::decode(mark, Some(raw))
			}
		}
	};
}
macro_rules! checked_struct {
	($name:ident, $remote:literal $(, $canonical:ident)? {
		$($(#[$attribute:meta])* $field:ident: $ty:ty),* $(,)?
	}) => {
		pub struct $name<S: Source> { $(pub $field: $ty),* }
		record_impls!($name { $($field),* });
		impl<S: Source> $name<S> {
			fn serialize_fields<T: serde::Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
				#[derive(Serialize)]
				#[serde(bound(serialize = ""))]
				struct Wire<'a, S: Source> { $($(#[$attribute])* $field: &'a $ty),* }
				Wire { $($field: &self.$field),* }.serialize(serializer)
			}
		}
		impl<S: Source> decode::Field<S> for $name<S> {
			fn decode(mark: &Mark<'_, S>, raw: Option<&serde_json::value::RawValue>) -> Result<Self, Error> {
				#[derive(Deserialize)]
				#[serde(deny_unknown_fields)]
				struct Wire<'a> {
					$(#[serde(borrow, default)] $field: Option<&'a serde_json::value::RawValue>),*
				}
				let raw: Wire<'_> = serde_json::from_str(decode::required(raw)?.get())?;
				let value = Self { $($field: decode::field(mark, raw.$field)?),* };
				value.validate()?;
				$(value.$canonical()?;)?
				Ok(value)
			}
		}
		checked_serde!($name $(, $canonical)?);
	};
}
macro_rules! checked_enum {
	($name:ident, $remote:literal, $tag:literal $(, $canonical:ident)? {
		$($variant:ident { $($(#[$attribute:meta])* $field:ident: $ty:ty),* $(,)? }),* $(,)?
	}) => {
		pub enum $name<S: Source> { $($variant { $($field: $ty),* }),* }
		impl<S: Source> Clone for $name<S> {
			fn clone(&self) -> Self {
				match self { $(Self::$variant { $($field),* } => Self::$variant { $($field: $field.clone()),* }),* }
			}
		}
		impl<S: Source> PartialEq for $name<S> {
			fn eq(&self, other: &Self) -> bool {
				match self { $(Self::$variant { $($field),* } => {
					let left = ($($field),*);
					match other { Self::$variant { $($field),* } => left == ($($field),*), _ => false }
				}),* }
			}
		}
		impl<S: Source> Eq for $name<S> {}
		impl<S: Source> std::fmt::Debug for $name<S> {
			fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				write!(f, "{}<{}>([redacted])", stringify!($name), S::NAME)
			}
		}
		impl<S: Source> $name<S> {
			fn serialize_fields<T: serde::Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
				#[derive(Serialize)]
				#[serde(tag = $tag, rename_all = "snake_case", bound(serialize = ""))]
				enum Wire<'a, S: Source> { $($variant { $($(#[$attribute])* $field: &'a $ty),* }),* }
				let wire = match self { $(Self::$variant { $($field),* } => Wire::$variant { $($field),* }),* };
				wire.serialize(serializer)
			}
		}
		impl<S: Source> decode::Field<S> for $name<S> {
			fn decode(mark: &Mark<'_, S>, raw: Option<&serde_json::value::RawValue>) -> Result<Self, Error> {
				#[derive(Deserialize)]
				#[serde(rename_all = "snake_case")]
				enum Tag { $($variant),* }
				#[derive(Deserialize)]
				struct Tagged { #[serde(rename = $tag)] tag: Tag }
				let raw = decode::required(raw)?.get();
				let tagged: Tagged = serde_json::from_str(raw)?;
				let value = match tagged.tag { $(Tag::$variant => {
					#[derive(Deserialize)]
					#[serde(deny_unknown_fields)]
					struct Wire<'a> {
						#[serde(rename = $tag)] _tag: Tag,
						$(#[serde(borrow, default)] $field: Option<&'a serde_json::value::RawValue>),*
					}
					let raw: Wire<'_> = serde_json::from_str(raw)?;
					Self::$variant { $($field: decode::field(mark, raw.$field)?),* }
				}),* };
				value.validate()?;
				$(value.$canonical()?;)?
				Ok(value)
			}
		}
		checked_serde!($name $(, $canonical)?);
	};
}

checked_struct!(L2Argument, "L2Argument" {
	attacker_source: BoundedText<policy::AttackerSource, S>,
	control: BoundedText<policy::AttackerControl, S>,
	sink: BoundedText<policy::EvidenceSink, S>,
	reachable_path: BoundedText<policy::ReachablePath, S>,
	trust_boundary: BoundedText<policy::TrustBoundary, S>,
});
impl<S: Source> L2Argument<S> {
	fn validate(&self) -> Result<(), Error> {
		Ok(())
	}
}

checked_struct!(MaterialLocation, "MaterialLocation" {
	role: LocationRole,
	file: RepoPath<S>,
	#[serde(skip_serializing_if = "Option::is_none")]
	symbol: Option<BoundedText<policy::MaterialSymbol, S>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	line_start: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	line_end: Option<u32>,
});
impl<S: Source> MaterialLocation<S> {
	fn validate(&self) -> Result<(), Error> {
		if self.line_start == Some(0) || self.line_end == Some(0) {
			return Err(invalid("material_locations", "line numbers must be positive"));
		}
		if let Some(end) = self.line_end {
			let start =
				self.line_start.ok_or_else(|| invalid("line_end", "requires line_start"))?;
			if end < start {
				return Err(invalid("line_end", "precedes line_start"));
			}
		}
		Ok(())
	}
}

fn reference_count(field: &'static str, count: usize) -> Result<(), Error> {
	if (1..=16).contains(&count) {
		Ok(())
	} else {
		Err(invalid(field, "expected 1 to 16 entries"))
	}
}

checked_struct!(Revalidation, "Revalidation" {
	current_source_refs: Vec<SourceRef<S>>,
	rationale: BoundedText<policy::RevalidationRationale, S>,
});
impl<S: Source> Revalidation<S> {
	fn validate(&self) -> Result<(), Error> {
		reference_count("current_source_refs", self.current_source_refs.len())
	}
}
checked_struct!(SourceCounterargument, "SourceCounterargument" {
	argument: BoundedText<policy::RejectionArgument, S>,
	source_refs: Vec<SourceRef<S>>,
});
impl<S: Source> SourceCounterargument<S> {
	fn validate(&self) -> Result<(), Error> {
		reference_count("source_refs", self.source_refs.len())
	}
}
checked_struct!(SourceHardening, "SourceHardening" {
	argument: BoundedText<policy::HardeningArgument, S>,
	source_refs: Vec<SourceRef<S>>,
});
impl<S: Source> SourceHardening<S> {
	fn validate(&self) -> Result<(), Error> {
		reference_count("source_refs", self.source_refs.len())
	}
}
checked_struct!(PartialSourceEvidence, "PartialSourceEvidence" {
	argument: BoundedText<policy::Argument, S>,
	source_refs: Vec<SourceRef<S>>,
});
impl<S: Source> PartialSourceEvidence<S> {
	fn validate(&self) -> Result<(), Error> {
		reference_count("source_refs", self.source_refs.len())
	}
}
checked_struct!(FindingEvidenceV1, "FindingEvidenceV1", canonical_bytes {
	version: Version1,
	l2_argument: L2Argument<S>,
	material_locations: Vec<MaterialLocation<S>>,
	counterevidence: BoundedText<policy::EvidenceCounterevidence, S>,
	assumptions_gaps: BoundedText<policy::AssumptionsGaps, S>,
	confidence: Confidence,
});
impl<S: Source> FindingEvidenceV1<S> {
	fn validate(&self) -> Result<(), Error> {
		reference_count("material_locations", self.material_locations.len())?;
		for location in &self.material_locations {
			location.validate()?;
		}
		Ok(())
	}
}
checked_struct!(PromotionV1, "PromotionV1", canonical_bytes {
	version: Version1,
	severity: Severity,
	title: BoundedText<policy::ReviewFindingTitle, S>,
	description: BoundedText<policy::ReviewFindingDescription, S>,
	identity_family: Identifier<policy::Family, S>,
	identity_anchor: Anchor<policy::AnchorText, S>,
	#[serde(skip_serializing_if = "Option::is_none")]
	identity_instance_key: Option<Anchor<policy::InstanceKey, S>>,
	evidence: FindingEvidenceV1<S>,
	#[serde(skip_serializing_if = "Option::is_none")]
	cwe: Option<Identifier<policy::Cwe, S>>,
});
impl<S: Source> PromotionV1<S> {
	fn validate(&self) -> Result<(), Error> {
		self.evidence.validate()
	}
}
// debug-ok: closed scalar protocol value contains no untrusted text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SurveyTerminalReason {
	Completed,
	Partial,
	Deferred,
}
crate::closed_string_enum!(SurveyTerminalReason { Completed, Partial, Deferred });

checked_struct!(SurveyTerminalV1, "SurveyTerminalV1", canonical_bytes {
	version: Version1,
	terminal_reason: SurveyTerminalReason,
	#[serde(skip_serializing_if = "Option::is_none")]
	continuation: Option<BoundedText<policy::SurveyContinuation, S>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	security_model_notes: Option<BoundedText<policy::SecurityModelNotes, S>>,
});
impl<S: Source> SurveyTerminalV1<S> {
	fn validate(&self) -> Result<(), Error> {
		Ok(())
	}
}
/// A classification for later server policy, never a scheduling command.
// debug-ok: closed scalar protocol value contains no untrusted text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuationClass {
	SourceAnalysisRemaining,
	AwaitingProofInfrastructure,
	ExternalDependency,
	RequiresSuccessor,
}
crate::closed_string_enum!(ContinuationClass {
	SourceAnalysisRemaining,
	AwaitingProofInfrastructure,
	ExternalDependency,
	RequiresSuccessor
});

// debug-ok: duplicate target has only a closed kind and numeric ID.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(
	tag = "kind",
	rename_all = "snake_case",
	deny_unknown_fields,
	try_from = "DuplicateTargetWire"
)]
pub enum DuplicateTarget {
	Lead { id: i64 },
	Finding { id: i64 },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum DuplicateTargetWire {
	Lead { id: i64 },
	Finding { id: i64 },
}
impl Serialize for DuplicateTarget {
	fn serialize<T: serde::Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
		self.validate().map_err(serde::ser::Error::custom)?;
		let wire = match self {
			Self::Lead { id } => DuplicateTargetWire::Lead { id: *id },
			Self::Finding { id } => DuplicateTargetWire::Finding { id: *id },
		};
		wire.serialize(serializer)
	}
}
impl TryFrom<DuplicateTargetWire> for DuplicateTarget {
	type Error = Error;
	fn try_from(value: DuplicateTargetWire) -> Result<Self, Error> {
		let value = match value {
			DuplicateTargetWire::Lead { id } => Self::Lead { id },
			DuplicateTargetWire::Finding { id } => Self::Finding { id },
		};
		value.validate()?;
		Ok(value)
	}
}
impl DuplicateTarget {
	fn validate(&self) -> Result<(), Error> {
		let (Self::Lead { id } | Self::Finding { id }) = self;
		if *id > 0 {
			Ok(())
		} else {
			Err(invalid("target.id", "must be positive"))
		}
	}
}
checked_enum!(DrilldownTerminalV1, "DrilldownTerminalV1", "disposition", canonical_bytes {
	Promote {
		version: Version1,
		promotion: Box<PromotionV1<S>>,
		#[serde(skip_serializing_if = "Option::is_none")]
		revalidation: Option<Revalidation<S>>,
	},
	Reject {
		version: Version1,
		counterargument: SourceCounterargument<S>,
		#[serde(skip_serializing_if = "Option::is_none")]
		revalidation: Option<Revalidation<S>>,
	},
	Duplicate {
		version: Version1,
		target: DuplicateTarget,
		rationale: BoundedText<policy::DuplicateRationale, S>,
		#[serde(skip_serializing_if = "Option::is_none")]
		revalidation: Option<Revalidation<S>>,
	},
	Hardening {
		version: Version1,
		explanation: SourceHardening<S>,
		#[serde(skip_serializing_if = "Option::is_none")]
		revalidation: Option<Revalidation<S>>,
	},
	Defer {
		version: Version1,
		reason: BoundedText<policy::DeferReason, S>,
		continuation: ContinuationClass,
		#[serde(skip_serializing_if = "Option::is_none")]
		retry_explanation: Option<BoundedText<policy::RetryExplanation, S>>,
		#[serde(skip_serializing_if = "Option::is_none")]
		revalidation: Option<Revalidation<S>>,
	},
});
impl<S: Source> DrilldownTerminalV1<S> {
	fn validate(&self) -> Result<(), Error> {
		let revalidation = match self {
			Self::Promote { promotion, revalidation, .. } => {
				promotion.validate()?;
				revalidation
			},
			Self::Reject { counterargument, revalidation, .. } => {
				counterargument.validate()?;
				revalidation
			},
			Self::Duplicate { target, revalidation, .. } => {
				target.validate()?;
				revalidation
			},
			Self::Hardening { explanation, revalidation, .. } => {
				explanation.validate()?;
				revalidation
			},
			Self::Defer { revalidation, .. } => revalidation,
		};
		if let Some(value) = revalidation {
			value.validate()?;
		}
		Ok(())
	}
}
// debug-ok: closed scalar protocol value contains no untrusted text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PreProofRung {
	L2,
}
crate::closed_string_enum!(PreProofRung { L2 });
// debug-ok: closed scalar protocol value contains no untrusted text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreProofApplicability {
	NotApplicable,
}
crate::closed_string_enum!(PreProofApplicability { NotApplicable });

checked_enum!(VerificationTerminalV1, "VerificationTerminalV1", "verdict", canonical_bytes {
	Verified {
		version: Version1,
		established_rung: PreProofRung,
		e2e_applicability: PreProofApplicability,
		e2e_rationale: BoundedText<policy::ApplicabilityRationale, S>,
		evidence: Box<FindingEvidenceV1<S>>,
		#[serde(skip_serializing_if = "Option::is_none")]
		revalidation: Option<Revalidation<S>>,
		#[serde(skip_serializing_if = "Option::is_none")]
		notes: Option<BoundedText<policy::ReviewNotes, S>>,
	},
	Rejected {
		version: Version1,
		counterargument: SourceCounterargument<S>,
		#[serde(skip_serializing_if = "Option::is_none")]
		revalidation: Option<Revalidation<S>>,
		#[serde(skip_serializing_if = "Option::is_none")]
		notes: Option<BoundedText<policy::ReviewNotes, S>>,
	},
	Inconclusive {
		version: Version1,
		blocker: BoundedText<policy::VerificationBlocker, S>,
		continuation: ContinuationClass,
		#[serde(skip_serializing_if = "Option::is_none")]
		partial_evidence: Option<PartialSourceEvidence<S>>,
		#[serde(skip_serializing_if = "Option::is_none")]
		retry_explanation: Option<BoundedText<policy::RetryExplanation, S>>,
		#[serde(skip_serializing_if = "Option::is_none")]
		revalidation: Option<Revalidation<S>>,
		#[serde(skip_serializing_if = "Option::is_none")]
		notes: Option<BoundedText<policy::ReviewNotes, S>>,
	},
});
impl<S: Source> VerificationTerminalV1<S> {
	fn validate(&self) -> Result<(), Error> {
		let revalidation = match self {
			Self::Verified { evidence, revalidation, .. } => {
				evidence.validate()?;
				revalidation
			},
			Self::Rejected { counterargument, revalidation, .. } => {
				counterargument.validate()?;
				revalidation
			},
			Self::Inconclusive {
				blocker, continuation, partial_evidence, revalidation, ..
			} => {
				if *continuation == ContinuationClass::AwaitingProofInfrastructure
					&& blocker.expose() != AWAITING_PROOF_INFRASTRUCTURE
				{
					return Err(invalid("blocker", "expected awaiting proof infrastructure"));
				}
				if let Some(value) = partial_evidence {
					value.validate()?;
				}
				revalidation
			},
		};
		if let Some(value) = revalidation {
			value.validate()?;
		}
		Ok(())
	}
}
// Concrete payload methods share only rendering. No open-ended validation
// registry or generic JSON policy can reinterpret their field semantics.
macro_rules! canonical_payload {
	($name:ident, $field:literal, $limit:expr) => {
		impl<S: Source> $name<S> {
			pub const MAX_BYTES: usize = $limit;
			pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
				self.validate()?;
				// Call the derived field serializer directly to avoid recursing
				// through this type's aggregate-checking Serialize implementation.
				let value = self.serialize_fields(serde_json::value::Serializer)?;
				let bytes = canonical::canonical_bytes(&value);
				if bytes.len() > Self::MAX_BYTES {
					return Err(Error::Bytes { field: $field, max_bytes: Self::MAX_BYTES });
				}
				Ok(bytes)
			}
			pub fn digest(&self) -> Result<[u8; 32], Error> {
				Ok(canonical::digest(&self.canonical_bytes()?))
			}
		}
	};
}
canonical_payload!(FindingEvidenceV1, "finding_evidence", EVIDENCE_MAX_BYTES);
canonical_payload!(PromotionV1, "promotion", EVIDENCE_MAX_BYTES);
canonical_payload!(SurveyTerminalV1, "survey_terminal", SURVEY_TERMINAL_MAX_BYTES);
canonical_payload!(DrilldownTerminalV1, "drilldown_terminal", EVIDENCE_MAX_BYTES);
canonical_payload!(VerificationTerminalV1, "verification_terminal", EVIDENCE_MAX_BYTES);

/// Named schema validators require an already captured source; they never mint
/// or change one. A carrying ingress must select Agent spans before using them.
macro_rules! payload_decoder {
	($decoder:ident, $payload:ident) => {
		pub struct $decoder;
		impl<S: Source> Validate<&[u8], S> for $decoder {
			type Output = $payload<S>;
			type Error = Error;
			fn validate<'view>(
				self, input: Unvalidated<'view, &[u8]>, mark: Mark<'view, S>,
			) -> Result<Self::Output, Error> {
				let raw = std::str::from_utf8(input.get()).map_err(|_| Error::Json)?;
				$payload::from_json(&mark, raw)
			}
		}
	};
}
payload_decoder!(FindingEvidenceV1Decoder, FindingEvidenceV1);
payload_decoder!(PromotionV1Decoder, PromotionV1);
payload_decoder!(SurveyTerminalV1Decoder, SurveyTerminalV1);
payload_decoder!(DrilldownTerminalV1Decoder, DrilldownTerminalV1);
payload_decoder!(VerificationTerminalV1Decoder, VerificationTerminalV1);

mod checkpoint;
pub use checkpoint::*;
