//! Inert, narrowly scoped review leases. Representation is not authorization:
//! the server must check preparation, assignment ownership and runtime gates.
//!
//! Phase prose retains its Agent source; metadata retains the actual source of
//! the response or stored row. Deserialization cannot invent either label.
//! ```compile_fail,E0277
//! use loupe_proto::review_lease::ReviewSurveyLease;
//! use loupe_provenance::{Agent, Server};
//! let _: ReviewSurveyLease<Agent, Server> = serde_json::from_str("{}").unwrap();
//! ```

use std::num::{NonZeroU32, NonZeroU64};

pub use loupe_core::review_metadata::{CommitPolicy, DigestPolicy, ReviewCommit, ReviewDigest};
use loupe_core::review_payload::{FindingEvidenceV1, GeneratedProfile, Version1};
use loupe_core::text::policy::{
	AnchorText, Argument, Family, InstanceKey, Objective, Reason, ReviewFindingDescription,
	ReviewFindingTitle, Title,
};
use loupe_core::text::{Anchor, BoundedText, IdentPolicy, Identifier, SourceRef};
use loupe_core::Severity;
use loupe_provenance::Source;

mod decode;
pub use decode::{
	ReviewDrilldownLeaseDecoder, ReviewLeaseDecodeError, ReviewSurveyLeaseDecoder,
	ReviewVerifyLeaseDecoder,
};
use serde::{Deserialize, Serialize};

/// Phase advertisement is deliberately independent of legacy `verify:*` tags.
// debug-ok: closed protocol scalars or collections delegate to redacted values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ReviewCapability {
	#[serde(rename = "review:survey:v1")]
	Survey,
	#[serde(rename = "review:drilldown:v1")]
	Drilldown,
	#[serde(rename = "review:verify:v1")]
	Verify,
}
loupe_core::closed_string_enum!(ReviewCapability { Survey, Drilldown, Verify });

/// Positive SQLite identifiers, not opaque agent-selected ownership fields.
// debug-ok: closed protocol scalars or collections delegate to redacted values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "i64", into = "i64")]
pub struct ReviewId(i64);
impl TryFrom<i64> for ReviewId {
	type Error = &'static str;
	fn try_from(value: i64) -> Result<Self, Self::Error> {
		if value > 0 {
			Ok(Self(value))
		} else {
			Err("review id must be positive")
		}
	}
}
impl From<ReviewId> for i64 {
	fn from(value: ReviewId) -> Self {
		value.0
	}
}

/// Bounded collections reject the first excess element while decoding.
// debug-ok: closed protocol scalars or collections delegate to redacted values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct LeaseList<T, const MAX: usize, const MIN: usize = 0>(Vec<T>);
impl<T, const MAX: usize, const MIN: usize> LeaseList<T, MAX, MIN> {
	pub fn new(values: Vec<T>) -> Result<Self, &'static str> {
		if !(MIN..=MAX).contains(&values.len()) {
			Err("review collection outside its bounds")
		} else {
			Ok(Self(values))
		}
	}
	pub fn as_slice(&self) -> &[T] {
		&self.0
	}
}
impl<T, const MAX: usize> Default for LeaseList<T, MAX> {
	fn default() -> Self {
		Self(Vec::new())
	}
}
impl<'de, T: Deserialize<'de>, const MAX: usize, const MIN: usize> Deserialize<'de>
	for LeaseList<T, MAX, MIN>
{
	fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		struct Visitor<T, const MAX: usize, const MIN: usize>(std::marker::PhantomData<T>);
		impl<'de, T: Deserialize<'de>, const MAX: usize, const MIN: usize> serde::de::Visitor<'de>
			for Visitor<T, MAX, MIN>
		{
			type Value = LeaseList<T, MAX, MIN>;
			fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				write!(formatter, "at most {MAX} review items")
			}
			fn visit_seq<A: serde::de::SeqAccess<'de>>(
				self, mut seq: A,
			) -> Result<Self::Value, A::Error> {
				let mut values = Vec::new();
				while let Some(value) = seq.next_element()? {
					if values.len() == MAX {
						return Err(serde::de::Error::custom(
							"review collection exceeds its bound",
						));
					}
					values.push(value);
				}
				LeaseList::new(values).map_err(serde::de::Error::custom)
			}
		}
		deserializer.deserialize_seq(Visitor::<T, MAX, MIN>(std::marker::PhantomData))
	}
}

// debug-ok: closed protocol scalars or collections delegate to redacted values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewLimits {
	pub soft_deadline_at: i64,
	pub submit_by: i64,
	pub hard_deadline_at: i64,
	pub token_budget: Option<NonZeroU64>,
	pub new_unit_limit: u32,
	pub lead_limit: u32,
	pub sibling_limit: u32,
}

// debug-ok: closed protocol scalars or collections delegate to redacted values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewProvenance {
	pub workflow_contract_version: Version1,
	pub campaign_id: ReviewId,
	pub attempt: NonZeroU32,
	pub limits: ReviewLimits,
}

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
#[serde(deny_unknown_fields)]
pub struct ReviewGeneration<MetaS: Source> {
	pub generation_id: ReviewId,
	pub commit_sha: ReviewCommit<MetaS>,
}

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
#[serde(deny_unknown_fields)]
pub struct FrozenReviewProfile<ContentS: Source, MetaS: Source> {
	pub profile_version: NonZeroU32,
	pub profile_digest: ReviewDigest<MetaS>,
	pub profile: GeneratedProfile<ContentS>,
}

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
#[serde(deny_unknown_fields)]
pub struct AssignedReviewUnit<ContentS: Source> {
	pub review_unit_id: ReviewId,
	pub assignment_epoch: NonZeroU64,
	pub title: BoundedText<Title, ContentS>,
	pub objective: BoundedText<Objective, ContentS>,
	pub source_refs: LeaseList<SourceRef<ContentS>, 32>,
	pub depends_on: LeaseList<ReviewId, 8>,
	pub closure_criteria: Option<BoundedText<Reason, ContentS>>,
}

/// Array order is assignment order; a unit can occur only once in a batch.
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
#[serde(transparent)]
pub struct ReviewAssignments<ContentS: Source>(LeaseList<AssignedReviewUnit<ContentS>, 32>);
impl<ContentS: Source> TryFrom<LeaseList<AssignedReviewUnit<ContentS>, 32>>
	for ReviewAssignments<ContentS>
{
	type Error = &'static str;
	fn try_from(units: LeaseList<AssignedReviewUnit<ContentS>, 32>) -> Result<Self, Self::Error> {
		for (index, unit) in units.as_slice().iter().enumerate() {
			if units.as_slice()[..index]
				.iter()
				.any(|prior| prior.review_unit_id == unit.review_unit_id)
			{
				return Err("duplicate review unit assignment");
			}
		}
		Ok(Self(units))
	}
}
impl<ContentS: Source> From<ReviewAssignments<ContentS>>
	for LeaseList<AssignedReviewUnit<ContentS>, 32>
{
	fn from(value: ReviewAssignments<ContentS>) -> Self {
		value.0
	}
}
impl<ContentS: Source> ReviewAssignments<ContentS> {
	pub fn as_slice(&self) -> &[AssignedReviewUnit<ContentS>] {
		self.0.as_slice()
	}
}

// debug-ok: closed protocol scalars or collections delegate to redacted values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrdinarySurveyRecipe {
	Coverage,
	SameCommitIncremental,
}

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BootstrapTarget<ContentS: Source, MetaS: Source> {
	/// The original ref remains in the enclosing repo/head-branch fields.
	Unresolved {},
	Pinned {
		generation: ReviewGeneration<MetaS>,
		published_profile: Option<FrozenReviewProfile<ContentS, MetaS>>,
	},
}

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
#[serde(tag = "recipe", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReviewSurveyContext<ContentS: Source, MetaS: Source> {
	Bootstrap {
		target: BootstrapTarget<ContentS, MetaS>,
	},
	/// Preparation only: an unknown target is not an ordinary empty batch.
	ResolveTarget {},
	Ordinary {
		generation: ReviewGeneration<MetaS>,
		profile: FrozenReviewProfile<ContentS, MetaS>,
		ordinary_recipe: OrdinarySurveyRecipe,
		assignments: ReviewAssignments<ContentS>,
	},
	/// The shape cannot carry a generated profile; runtime remains B8-held.
	Corroboration {
		generation: ReviewGeneration<MetaS>,
		assignments: ReviewAssignments<ContentS>,
	},
}

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
#[serde(deny_unknown_fields)]
pub struct ReviewSurveyLease<ContentS: Source, MetaS: Source> {
	pub provenance: ReviewProvenance,
	pub context: ReviewSurveyContext<ContentS, MetaS>,
}

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
#[serde(deny_unknown_fields)]
pub struct AssignedReviewLead<ContentS: Source, MetaS: Source> {
	pub lead_id: ReviewId,
	pub producer_commit_sha: ReviewCommit<MetaS>,
	pub identity_family: Identifier<Family, ContentS>,
	pub identity_anchor: Anchor<AnchorText, ContentS>,
	pub identity_instance_key: Option<Anchor<InstanceKey, ContentS>>,
	pub hypothesis: BoundedText<Argument, ContentS>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub invariant_or_boundary: Option<BoundedText<Reason, ContentS>>,
	pub source_refs: LeaseList<SourceRef<ContentS>, 16, 1>,
	pub next_proof_step: BoundedText<Reason, ContentS>,
	pub counterevidence: BoundedText<Objective, ContentS>,
	pub proof_gaps: BoundedText<Objective, ContentS>,
}

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
#[serde(deny_unknown_fields)]
pub struct ReviewDrilldownLease<ContentS: Source, MetaS: Source> {
	pub provenance: ReviewProvenance,
	pub generation: ReviewGeneration<MetaS>,
	pub profile: FrozenReviewProfile<ContentS, MetaS>,
	pub lead: AssignedReviewLead<ContentS, MetaS>,
}

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
#[serde(deny_unknown_fields)]
pub struct AssignedReviewFinding<ContentS: Source, MetaS: Source> {
	pub finding_id: ReviewId,
	pub reviewed_commit_sha: ReviewCommit<MetaS>,
	pub severity: Severity,
	pub title: BoundedText<ReviewFindingTitle, ContentS>,
	pub description: BoundedText<ReviewFindingDescription, ContentS>,
	pub identity_family: Identifier<Family, ContentS>,
	pub identity_anchor: Anchor<AnchorText, ContentS>,
	pub identity_instance_key: Option<Anchor<InstanceKey, ContentS>>,
	pub evidence: FindingEvidenceV1<ContentS>,
}

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
#[serde(deny_unknown_fields)]
pub struct ReviewVerifyLease<ContentS: Source, MetaS: Source> {
	pub provenance: ReviewProvenance,
	pub generation: ReviewGeneration<MetaS>,
	pub profile: FrozenReviewProfile<ContentS, MetaS>,
	pub finding: AssignedReviewFinding<ContentS, MetaS>,
}

record_impls!(ReviewGeneration<MetaS> { generation_id, commit_sha });
record_impls!(FrozenReviewProfile<ContentS, MetaS> { profile_version, profile_digest, profile });
record_impls!(AssignedReviewUnit<ContentS> { review_unit_id, assignment_epoch, title, objective, source_refs, depends_on, closure_criteria });
record_impls!(ReviewSurveyLease<ContentS, MetaS> { provenance, context });
record_impls!(AssignedReviewLead<ContentS, MetaS> { lead_id, producer_commit_sha, identity_family, identity_anchor, identity_instance_key, source_refs, hypothesis, invariant_or_boundary, next_proof_step, counterevidence, proof_gaps });
record_impls!(ReviewDrilldownLease<ContentS, MetaS> { provenance, generation, profile, lead });
record_impls!(AssignedReviewFinding<ContentS, MetaS> { finding_id, reviewed_commit_sha, severity, title, description, identity_family, identity_anchor, identity_instance_key, evidence });
record_impls!(ReviewVerifyLease<ContentS, MetaS> { provenance, generation, profile, finding });

impl<ContentS: Source> Clone for ReviewAssignments<ContentS> {
	fn clone(&self) -> Self {
		Self(self.0.clone())
	}
}
impl<ContentS: Source> PartialEq for ReviewAssignments<ContentS> {
	fn eq(&self, other: &Self) -> bool {
		self.0 == other.0
	}
}
impl<ContentS: Source> Eq for ReviewAssignments<ContentS> {}
impl<ContentS: Source> std::fmt::Debug for ReviewAssignments<ContentS> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("ReviewAssignments([redacted])")
	}
}
macro_rules! review_enum_impls {
	($name:ident { $($variant:ident { $($field:ident),* }),* $(,)? }) => {
		impl<ContentS: Source, MetaS: Source> Clone for $name<ContentS, MetaS> {
			fn clone(&self) -> Self {
				match self { $(Self::$variant { $($field),* } => Self::$variant { $($field: $field.clone()),* }),* }
			}
		}
		impl<ContentS: Source, MetaS: Source> PartialEq for $name<ContentS, MetaS> {
			fn eq(&self, other: &Self) -> bool {
				match self { $(Self::$variant { $($field),* } => {
					let left = ($($field,)*);
					match other { Self::$variant { $($field),* } => left == ($($field,)*), _ => false }
				}),* }
			}
		}
		impl<ContentS: Source, MetaS: Source> Eq for $name<ContentS, MetaS> {}
		impl<ContentS: Source, MetaS: Source> std::fmt::Debug for $name<ContentS, MetaS> {
			fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				f.write_str(concat!(stringify!($name), "([redacted])"))
			}
		}
	};
}
review_enum_impls!(BootstrapTarget {
	Unresolved {},
	Pinned { generation, published_profile },
});
review_enum_impls!(ReviewSurveyContext {
	Bootstrap { target },
	ResolveTarget {},
	Ordinary { generation, profile, ordinary_recipe, assignments },
	Corroboration { generation, assignments },
});

#[cfg(test)]
mod tests {
	#[test]
	fn worker_closed_values_decode_only_from_json_strings() {
		use crate::review_inventory::Disposition;
		use crate::review_lifecycle::FailedOutcome;
		use crate::review_units::PriorityBand;
		fn strict<T: serde::de::DeserializeOwned>(word: &str) {
			assert!(serde_json::from_value::<T>(json!(word)).is_ok(), "{word} must decode");
			assert!(serde_json::from_value::<T>(json!({ word: null })).is_err(), "{word} map form");
			assert!(serde_json::from_str::<T>(&format!("{{\"{word}\":null}}")).is_err());
		}
		strict::<ReviewCapability>("review:verify:v1");
		strict::<FailedOutcome>("failed");
		strict::<Disposition>("excluded");
		strict::<PriorityBand>("urgent");
	}

	use loupe_provenance::{Agent, Server};
	use serde_json::{json, Value};

	use super::*;
	use crate::{LeaseRequest, PROTOCOL_VERSION};
	type LeasePayload = crate::LeasePayload<Agent, Server>;

	fn decode(raw: &str) -> Result<LeasePayload, ReviewLeaseDecodeError> {
		let value: Value = serde_json::from_str(raw)?;
		let bytes = crate::test_support::server_response(raw.as_bytes());
		match value["kind"].as_str() {
			Some("review_survey") => bytes
				.validate_carrying(ReviewSurveyLeaseDecoder)
				.map(|lease| LeasePayload::ReviewSurvey(Box::new(lease))),
			Some("review_drilldown") => bytes
				.validate_carrying(ReviewDrilldownLeaseDecoder)
				.map(|lease| LeasePayload::ReviewDrilldown(Box::new(lease))),
			Some("review_verify") => bytes
				.validate_carrying(ReviewVerifyLeaseDecoder)
				.map(|lease| LeasePayload::ReviewVerify(Box::new(lease))),
			_ => Err(ReviewLeaseDecodeError::Invalid("not a phase lease")),
		}
	}
	fn decode_value(raw: Value) -> Result<LeasePayload, ReviewLeaseDecodeError> {
		decode(&raw.to_string())
	}

	fn provenance() -> Value {
		json!({"workflow_contract_version":1,"campaign_id":2,"attempt":1,
			"limits":{"soft_deadline_at":100,"submit_by":100,"hard_deadline_at":200,
				"token_budget":null,"new_unit_limit":32,"lead_limit":16,"sibling_limit":4}})
	}
	fn generation() -> Value {
		json!({"generation_id":3,"commit_sha":"a".repeat(40)})
	}
	fn profile() -> Value {
		json!({"profile_version":1,"profile_digest":"b".repeat(64),"profile":{"purpose":"test"}})
	}
	fn unit(id: i64, path: &str) -> Value {
		json!({"review_unit_id":id,"assignment_epoch":2,"title":"Review parser",
			"objective":"Check input bounds","source_refs":[{"path":path}],
			"depends_on":[],"closure_criteria":null})
	}
	fn ordinary() -> Value {
		json!({"kind":"review_survey","provenance":provenance(),
			"context":{"recipe":"ordinary","generation":generation(),"profile":profile(),
				"ordinary_recipe":"coverage","assignments":[unit(5,"src/e\u{301}.rs"),unit(4,"src/é.rs")]}})
	}
	fn evidence() -> Value {
		json!({"version":1,"l2_argument":{"attacker_source":"Remote request","control":"Request length",
			"sink":"Allocation","reachable_path":"Handler calls the allocator","trust_boundary":"Request to memory"},
			"material_locations":[{"role":"sink","file":"src/lib.rs","line_start":3,"line_end":4}],
			"counterevidence":"Authentication precedes allocation","assumptions_gaps":"Authenticated attacker",
			"confidence":"medium"})
	}

	#[test]
	fn source_markers_add_no_clone_or_equality_bounds() {
		fn traits<T: Clone + Eq + Serialize>() {}
		fn check<C: Source, M: Source>() {
			traits::<ReviewGeneration<M>>();
			traits::<FrozenReviewProfile<C, M>>();
			traits::<AssignedReviewUnit<C>>();
			traits::<ReviewAssignments<C>>();
			traits::<BootstrapTarget<C, M>>();
			traits::<ReviewSurveyContext<C, M>>();
			traits::<ReviewSurveyLease<C, M>>();
			traits::<AssignedReviewLead<C, M>>();
			traits::<ReviewDrilldownLease<C, M>>();
			traits::<AssignedReviewFinding<C, M>>();
			traits::<ReviewVerifyLease<C, M>>();
			traits::<crate::LeasePayload<C, M>>();
		}
		check::<Agent, Server>();
	}

	#[test]
	fn nested_decoder_requires_the_original_response_token() {
		use loupe_provenance::{Unvalidated, ValidateCarrying};
		use serde_json::value::RawValue;
		struct Nested;
		impl ValidateCarrying<&[u8], Server> for Nested {
			type Output = ReviewSurveyLease<Agent, Server>;
			type Error = ReviewLeaseDecodeError;
			fn validate(
				self, u: Unvalidated<'_, &[u8], Server>,
			) -> Result<Self::Output, Self::Error> {
				#[derive(Deserialize)]
				struct Wire<'a> {
					#[serde(borrow)]
					payload: &'a RawValue,
				}
				let wire: Wire<'_> = serde_json::from_slice(u.get())?;
				let foreign: Box<RawValue> = serde_json::from_str(wire.payload.get())?;
				assert!(
					ReviewSurveyLeaseDecoder::decode_payload(&u, &foreign).is_err(),
					"separately allocated identical JSON is not part of the server response"
				);
				ReviewSurveyLeaseDecoder::decode_payload(&u, wire.payload)
			}
		}
		// This metadata-only payload cannot rely on an Agent-field carry to
		// detect the foreign token: containment must precede all construction.
		let raw = json!({"payload":{"kind":"review_survey","provenance":provenance(),
			"context":{"recipe":"bootstrap","target":{"kind":"pinned","generation":generation()}}}})
		.to_string();
		let lease =
			crate::test_support::server_response(raw.as_bytes()).validate_carrying(Nested).unwrap();
		let ReviewSurveyContext::Bootstrap {
			target: BootstrapTarget::Pinned { generation, published_profile },
		} = lease.context
		else {
			panic!("pinned bootstrap");
		};
		assert_eq!(generation.commit_sha.expose(), "a".repeat(40));
		assert!(published_profile.is_none());
	}

	#[test]
	fn drilldown_decoder_retains_every_assigned_field_and_source() {
		let raw = json!({"kind":"review_drilldown","provenance":provenance(),
			"generation":generation(),"profile":profile(),"lead":{
				"lead_id":4,"producer_commit_sha":"a".repeat(40),"identity_family":"memory-safety",
				"identity_anchor":"request allocation","identity_instance_key":"allocator",
				"hypothesis":"Unbounded input","invariant_or_boundary":"Only authorized callers","source_refs":[{"path":"src/e\u{301}.rs","symbol":"allocate"}],
				"next_proof_step":"Trace length","counterevidence":"Authentication","proof_gaps":"Caller scope"}});
		let payload = decode_value(raw.clone()).unwrap();
		assert_eq!(serde_json::to_value(&payload).unwrap(), raw);
		let LeasePayload::ReviewDrilldown(lease) = payload else {
			panic!("drilldown");
		};
		let _: &ReviewCommit<Server> = &lease.lead.producer_commit_sha;
		let _: &BoundedText<Argument, Agent> = &lease.lead.hypothesis;
		let _: &Option<BoundedText<Reason, Agent>> = &lease.lead.invariant_or_boundary;
		assert_eq!(
			lease.lead.invariant_or_boundary.as_ref().unwrap().expose(),
			"Only authorized callers"
		);
		let mut without_boundary = raw.clone();
		without_boundary["lead"].as_object_mut().unwrap().remove("invariant_or_boundary");
		assert_eq!(
			serde_json::to_value(decode_value(without_boundary.clone()).unwrap()).unwrap(),
			without_boundary
		);
		assert_eq!(lease.lead.source_refs.as_slice()[0].path.expose(), "src/e\u{301}.rs");
		let mut invalid = raw.clone();
		invalid["lead"]["unexpected"] = json!(true);
		assert!(decode_value(invalid).is_err());
		let mut invalid = raw;
		invalid["lead"]["source_refs"] = json!([]);
		assert!(decode_value(invalid).is_err());
	}

	#[test]
	fn ordinary_assignments_preserve_order_epochs_and_path_bytes() {
		let payload: LeasePayload = decode_value(ordinary()).unwrap();
		let LeasePayload::ReviewSurvey(lease) = &payload else { panic!("review survey") };
		let ReviewSurveyContext::Ordinary { assignments, .. } = &lease.context else {
			panic!("ordinary")
		};
		assert_eq!(i64::from(assignments.as_slice()[0].review_unit_id), 5);
		assert_eq!(assignments.as_slice()[0].assignment_epoch.get(), 2);
		assert_eq!(
			assignments.as_slice()[0].source_refs.as_slice()[0].path.expose(),
			"src/e\u{301}.rs"
		);
		assert_eq!(assignments.as_slice()[1].source_refs.as_slice()[0].path.expose(), "src/é.rs");
		assert_eq!(decode(&serde_json::to_string(&payload).unwrap()).unwrap(), payload);
	}

	#[test]
	fn review_verify_is_distinct_from_legacy_verify() {
		let raw = json!({"kind":"review_verify","provenance":provenance(),"generation":generation(),
			"profile":profile(),"finding":{"finding_id":4,"reviewed_commit_sha":"a".repeat(40),
				"severity":"high","title":"Unbounded allocation","description":"Requests allocate without a limit",
				"identity_family":"memory-safety","identity_anchor":"request allocation","evidence":evidence()}});
		let payload: LeasePayload = decode_value(raw.clone()).unwrap();
		assert!(matches!(payload, LeasePayload::ReviewVerify(_)));
		let mut legacy_tag = raw;
		legacy_tag["kind"] = json!("verify");
		assert!(decode_value(legacy_tag).is_err());
	}

	#[test]
	fn bootstrap_and_corroboration_cannot_inherit_ordinary_scope() {
		let mut bootstrap = json!({"kind":"review_survey","provenance":provenance(),
			"context":{"recipe":"bootstrap","target":{"kind":"unresolved"}}});
		assert!(decode_value(bootstrap.clone()).is_ok());
		bootstrap["context"]["assignments"] = json!([unit(4, "src/lib.rs")]);
		assert!(decode_value(bootstrap).is_err());
		let mut corroboration = json!({"kind":"review_survey","provenance":provenance(),
			"context":{"recipe":"corroboration","generation":generation(),"assignments":[]}});
		assert!(decode_value(corroboration.clone()).is_ok());
		corroboration["context"]["profile"] = profile();
		assert!(decode_value(corroboration).is_err());
	}

	#[test]
	fn review_payload_rejects_unknown_fields_at_each_boundary() {
		for pointer in [
			"",
			"/provenance",
			"/provenance/limits",
			"/context",
			"/context/generation",
			"/context/profile",
			"/context/assignments/0",
			"/context/assignments/0/source_refs/0",
		] {
			let mut raw = ordinary();
			raw.pointer_mut(pointer)
				.unwrap()
				.as_object_mut()
				.unwrap()
				.insert("unexpected".into(), json!(true));
			assert!(decode_value(raw).is_err(), "unknown field accepted at {pointer}");
		}
	}

	#[test]
	fn review_assignment_bounds_and_identity_are_enforced() {
		let mut raw = ordinary();
		raw["context"]["assignments"] = json!([unit(5, "src/lib.rs"), unit(5, "src/other.rs")]);
		assert!(decode_value(raw.clone()).is_err());
		raw["context"]["assignments"] =
			Value::Array((1..=33).map(|id| unit(id, "src/lib.rs")).collect());
		assert!(decode_value(raw).is_err());
		for (pointer, value) in [
			("/provenance/attempt", json!(0)),
			("/provenance/campaign_id", json!(-1)),
			("/context/generation/commit_sha", json!("main")),
			("/context/assignments/0/assignment_epoch", json!(0)),
		] {
			let mut raw = ordinary();
			*raw.pointer_mut(pointer).unwrap() = value;
			assert!(decode_value(raw).is_err(), "invalid {pointer}");
		}
	}

	#[test]
	fn review_provenance_rejects_unknown_versions_and_duplicate_fields() {
		let mut raw = ordinary();
		raw["provenance"]["workflow_contract_version"] = json!(2);
		assert!(decode_value(raw).is_err());
		let raw = ordinary().to_string().replace("\"attempt\":1", "\"attempt\":1,\"attempt\":1");
		assert!(decode(&raw).is_err());
	}

	#[test]
	fn legacy_request_does_not_advertise_phase_verification() {
		let request = LeaseRequest::<Server> {
			protocol_version: PROTOCOL_VERSION,
			capabilities: vec![crate::test_support::text("verify:llm")],
			review_capabilities: LeaseList::default(),
			wait_seconds: 0,
		};
		assert!(request.review_capabilities.as_slice().is_empty());
		let raw = serde_json::to_value(request).unwrap();
		assert_eq!(raw["capabilities"], json!(["verify:llm"]));
		assert_eq!(raw["review_capabilities"], json!([]));
		// The server's concrete request decoder admits this exact scalar list;
		// a legacy tag must not be accepted as a phase advertisement.
		assert!(serde_json::from_value::<LeaseList<ReviewCapability, 3>>(json!(["verify:llm"]))
			.is_err());
	}
}
