//! Admission of the three fixed phase payloads from an actual server response.
//! The concrete validators own the Server -> Agent carry decisions. Borrowed
//! JSON tokens preserve both their original spans and exact repository paths.

use std::marker::PhantomData;

use loupe_core::text::{
	decode_json_string_bounded, policy, AnchorPolicy, Normalization, RepoPath, TextPolicy,
};
use loupe_provenance::{Agent, Mark, Server, Unvalidated, Validate, ValidateCarrying};
use serde_json::value::RawValue;

use super::*;

/// A bounded, content-free admission failure.
// debug-ok: parser errors retain only static classifications and policy errors.
#[derive(Debug, thiserror::Error)]
pub enum ReviewLeaseDecodeError {
	#[error("invalid review lease JSON")]
	Json,
	#[error("invalid review lease: {0}")]
	Invalid(&'static str),
	#[error(transparent)]
	Text(#[from] loupe_core::text::Error),
	#[error(transparent)]
	Payload(#[from] loupe_core::review_payload::Error),
}
impl From<serde_json::Error> for ReviewLeaseDecodeError {
	fn from(_: serde_json::Error) -> Self {
		Self::Json
	}
}
type Error = ReviewLeaseDecodeError;
type View<'v, 'a> = Unvalidated<'v, &'a [u8], Server>;

trait AgentValue: Sized {
	fn admit(mark: &Mark<'_, Agent>, raw: &str) -> Result<Self, Error>;
}
struct AgentField<T>(PhantomData<T>);
impl<T: AgentValue> Validate<&[u8], Agent> for AgentField<T> {
	type Output = T;
	type Error = Error;
	fn validate<'v>(self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Agent>) -> Result<T, Error> {
		T::admit(&mark, std::str::from_utf8(u.get()).map_err(|_| Error::Json)?)
	}
}
impl<P: TextPolicy> AgentValue for BoundedText<P, Agent> {
	fn admit(mark: &Mark<'_, Agent>, raw: &str) -> Result<Self, Error> {
		let factor = if P::NORMALIZATION == Normalization::Semantic { 4 } else { 1 };
		let ceiling = P::MAX_BYTES.saturating_mul(factor);
		let value = decode_json_string_bounded(raw, P::FIELD, ceiling, ceiling)?;
		Ok(Self::new(mark, &value)?)
	}
}
impl<P: IdentPolicy> AgentValue for Identifier<P, Agent> {
	fn admit(mark: &Mark<'_, Agent>, raw: &str) -> Result<Self, Error> {
		let value = decode_json_string_bounded(raw, P::FIELD, P::MAX_LEN, P::MAX_LEN)?;
		Ok(Self::new(mark, &value)?)
	}
}
impl<P: AnchorPolicy> AgentValue for Anchor<P, Agent> {
	fn admit(mark: &Mark<'_, Agent>, raw: &str) -> Result<Self, Error> {
		// Whitespace folding has no fixed input/output ratio. The HTTP ingress
		// bounds the document; preflight still precedes decoded allocation.
		let value = decode_json_string_bounded(raw, P::FIELD, raw.len(), raw.len())?;
		Ok(Self::new(mark, &value)?)
	}
}
impl AgentValue for SourceRef<Agent> {
	fn admit(mark: &Mark<'_, Agent>, raw: &str) -> Result<Self, Error> {
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Wire<'a> {
			#[serde(borrow)]
			path: &'a RawValue,
			#[serde(borrow, default)]
			symbol: Option<&'a RawValue>,
		}
		let wire: Wire<'_> = serde_json::from_str(raw)?;
		let path = decode_json_string_bounded(wire.path.get(), "path", 512, 512)?;
		Ok(Self {
			path: RepoPath::new(mark, &path)?,
			symbol: wire
				.symbol
				.filter(|raw| raw.get() != "null")
				.map(|raw| BoundedText::<policy::Symbol, Agent>::admit(mark, raw.get()))
				.transpose()?,
		})
	}
}
impl AgentValue for GeneratedProfile<Agent> {
	fn admit(mark: &Mark<'_, Agent>, raw: &str) -> Result<Self, Error> {
		Ok(Self::new(mark, raw)?)
	}
}
impl AgentValue for FindingEvidenceV1<Agent> {
	fn admit(mark: &Mark<'_, Agent>, raw: &str) -> Result<Self, Error> {
		Ok(Self::from_json(mark, raw)?)
	}
}

fn span(u: &View<'_, '_>, raw: &RawValue) -> Result<std::ops::Range<usize>, Error> {
	let start = (raw.get().as_ptr() as usize)
		.checked_sub(u.get().as_ptr() as usize)
		.ok_or(Error::Invalid("content span outside response"))?;
	let end = start.checked_add(raw.get().len()).ok_or(Error::Invalid("content span overflow"))?;
	if u.get().get(start..end).is_none() {
		return Err(Error::Invalid("content span outside response"));
	}
	Ok(start..end)
}
fn content<T: AgentValue>(u: &View<'_, '_>, raw: &RawValue) -> Result<T, Error> {
	u.carry::<Agent>(span(u, raw)?)
		.ok_or(Error::Invalid("content span outside response"))?
		.validate(AgentField::<T>(PhantomData))
}
fn optional_content<T: AgentValue>(
	u: &View<'_, '_>, raw: Option<&RawValue>,
) -> Result<Option<T>, Error> {
	raw.filter(|raw| raw.get() != "null").map(|raw| content(u, raw)).transpose()
}
fn metadata<P: IdentPolicy>(
	u: &View<'_, '_>, raw: &RawValue,
) -> Result<Identifier<P, Server>, Error> {
	let value = decode_json_string_bounded(raw.get(), P::FIELD, P::MAX_LEN, P::MAX_LEN)?;
	Ok(Identifier::new(&u.mark(), &value)?)
}
fn content_list<T: AgentValue, const MAX: usize, const MIN: usize>(
	u: &View<'_, '_>, raw: &RawValue,
) -> Result<LeaseList<T, MAX, MIN>, Error> {
	// Bound the borrowed token list before admitting any owned content.
	let tokens: LeaseList<&RawValue, MAX, MIN> = serde_json::from_str(raw.get())?;
	LeaseList::new(tokens.as_slice().iter().map(|raw| content(u, raw)).collect::<Result<_, _>>()?)
		.map_err(Error::Invalid)
}

fn generation(u: &View<'_, '_>, raw: &RawValue) -> Result<ReviewGeneration<Server>, Error> {
	#[derive(Deserialize)]
	#[serde(deny_unknown_fields)]
	struct Wire<'a> {
		generation_id: ReviewId,
		#[serde(borrow)]
		commit_sha: &'a RawValue,
	}
	let wire: Wire<'_> = serde_json::from_str(raw.get())?;
	Ok(ReviewGeneration {
		generation_id: wire.generation_id,
		commit_sha: metadata(u, wire.commit_sha)?,
	})
}
fn profile(u: &View<'_, '_>, raw: &RawValue) -> Result<FrozenReviewProfile<Agent, Server>, Error> {
	#[derive(Deserialize)]
	#[serde(deny_unknown_fields)]
	struct Wire<'a> {
		profile_version: NonZeroU32,
		#[serde(borrow)]
		profile_digest: &'a RawValue,
		#[serde(borrow)]
		profile: &'a RawValue,
	}
	let wire: Wire<'_> = serde_json::from_str(raw.get())?;
	Ok(FrozenReviewProfile {
		profile_version: wire.profile_version,
		profile_digest: metadata(u, wire.profile_digest)?,
		profile: content(u, wire.profile)?,
	})
}
fn unit(u: &View<'_, '_>, raw: &RawValue) -> Result<AssignedReviewUnit<Agent>, Error> {
	#[derive(Deserialize)]
	#[serde(deny_unknown_fields)]
	struct Wire<'a> {
		review_unit_id: ReviewId,
		assignment_epoch: NonZeroU64,
		#[serde(borrow)]
		title: &'a RawValue,
		#[serde(borrow)]
		objective: &'a RawValue,
		#[serde(borrow)]
		source_refs: &'a RawValue,
		depends_on: LeaseList<ReviewId, 8>,
		#[serde(borrow, default)]
		closure_criteria: Option<&'a RawValue>,
	}
	let wire: Wire<'_> = serde_json::from_str(raw.get())?;
	Ok(AssignedReviewUnit {
		review_unit_id: wire.review_unit_id,
		assignment_epoch: wire.assignment_epoch,
		title: content(u, wire.title)?,
		objective: content(u, wire.objective)?,
		source_refs: content_list(u, wire.source_refs)?,
		depends_on: wire.depends_on,
		closure_criteria: optional_content(u, wire.closure_criteria)?,
	})
}
fn assignments(u: &View<'_, '_>, raw: &RawValue) -> Result<ReviewAssignments<Agent>, Error> {
	let tokens: LeaseList<&RawValue, 32> = serde_json::from_str(raw.get())?;
	let units = tokens.as_slice().iter().map(|raw| unit(u, raw)).collect::<Result<_, _>>()?;
	ReviewAssignments::try_from(LeaseList::new(units).map_err(Error::Invalid)?)
		.map_err(Error::Invalid)
}

fn bootstrap(u: &View<'_, '_>, raw: &RawValue) -> Result<BootstrapTarget<Agent, Server>, Error> {
	#[derive(Deserialize)]
	#[serde(rename_all = "snake_case")]
	enum Kind {
		Unresolved,
		Pinned,
	}
	#[derive(Deserialize)]
	struct Tag {
		kind: Kind,
	}
	let tag: Tag = serde_json::from_str(raw.get())?;
	match tag.kind {
		Kind::Unresolved => {
			#[derive(Deserialize)]
			#[serde(deny_unknown_fields)]
			struct Wire {
				#[serde(rename = "kind")]
				_kind: Kind,
			}
			let _: Wire = serde_json::from_str(raw.get())?;
			Ok(BootstrapTarget::Unresolved {})
		},
		Kind::Pinned => {
			#[derive(Deserialize)]
			#[serde(deny_unknown_fields)]
			struct Wire<'a> {
				#[serde(rename = "kind")]
				_kind: Kind,
				#[serde(borrow)]
				generation: &'a RawValue,
				#[serde(borrow, default)]
				published_profile: Option<&'a RawValue>,
			}
			let wire: Wire<'_> = serde_json::from_str(raw.get())?;
			Ok(BootstrapTarget::Pinned {
				generation: generation(u, wire.generation)?,
				published_profile: wire
					.published_profile
					.filter(|raw| raw.get() != "null")
					.map(|raw| profile(u, raw))
					.transpose()?,
			})
		},
	}
}
fn context(u: &View<'_, '_>, raw: &RawValue) -> Result<ReviewSurveyContext<Agent, Server>, Error> {
	#[derive(Deserialize)]
	#[serde(rename_all = "snake_case")]
	enum Recipe {
		Bootstrap,
		ResolveTarget,
		Ordinary,
		Corroboration,
	}
	#[derive(Deserialize)]
	struct Tag {
		recipe: Recipe,
	}
	let tag: Tag = serde_json::from_str(raw.get())?;
	match tag.recipe {
		Recipe::Bootstrap => {
			#[derive(Deserialize)]
			#[serde(deny_unknown_fields)]
			struct Wire<'a> {
				#[serde(rename = "recipe")]
				_recipe: Recipe,
				#[serde(borrow)]
				target: &'a RawValue,
			}
			let wire: Wire<'_> = serde_json::from_str(raw.get())?;
			Ok(ReviewSurveyContext::Bootstrap { target: bootstrap(u, wire.target)? })
		},
		Recipe::ResolveTarget => {
			#[derive(Deserialize)]
			#[serde(deny_unknown_fields)]
			struct Wire {
				#[serde(rename = "recipe")]
				_recipe: Recipe,
			}
			let _: Wire = serde_json::from_str(raw.get())?;
			Ok(ReviewSurveyContext::ResolveTarget {})
		},
		Recipe::Ordinary => {
			#[derive(Deserialize)]
			#[serde(deny_unknown_fields)]
			struct Wire<'a> {
				#[serde(rename = "recipe")]
				_recipe: Recipe,
				#[serde(borrow)]
				generation: &'a RawValue,
				#[serde(borrow)]
				profile: &'a RawValue,
				ordinary_recipe: OrdinarySurveyRecipe,
				#[serde(borrow)]
				assignments: &'a RawValue,
			}
			let wire: Wire<'_> = serde_json::from_str(raw.get())?;
			Ok(ReviewSurveyContext::Ordinary {
				generation: generation(u, wire.generation)?,
				profile: profile(u, wire.profile)?,
				ordinary_recipe: wire.ordinary_recipe,
				assignments: assignments(u, wire.assignments)?,
			})
		},
		Recipe::Corroboration => {
			#[derive(Deserialize)]
			#[serde(deny_unknown_fields)]
			struct Wire<'a> {
				#[serde(rename = "recipe")]
				_recipe: Recipe,
				#[serde(borrow)]
				generation: &'a RawValue,
				#[serde(borrow)]
				assignments: &'a RawValue,
			}
			let wire: Wire<'_> = serde_json::from_str(raw.get())?;
			Ok(ReviewSurveyContext::Corroboration {
				generation: generation(u, wire.generation)?,
				assignments: assignments(u, wire.assignments)?,
			})
		},
	}
}
fn lead(u: &View<'_, '_>, raw: &RawValue) -> Result<AssignedReviewLead<Agent, Server>, Error> {
	#[derive(Deserialize)]
	#[serde(deny_unknown_fields)]
	struct Wire<'a> {
		lead_id: ReviewId,
		#[serde(borrow)]
		producer_commit_sha: &'a RawValue,
		#[serde(borrow)]
		identity_family: &'a RawValue,
		#[serde(borrow)]
		identity_anchor: &'a RawValue,
		#[serde(borrow, default)]
		identity_instance_key: Option<&'a RawValue>,
		#[serde(borrow)]
		hypothesis: &'a RawValue,
		#[serde(borrow, default)]
		invariant_or_boundary: Option<&'a RawValue>,
		#[serde(borrow)]
		source_refs: &'a RawValue,
		#[serde(borrow)]
		next_proof_step: &'a RawValue,
		#[serde(borrow)]
		counterevidence: &'a RawValue,
		#[serde(borrow)]
		proof_gaps: &'a RawValue,
	}
	let wire: Wire<'_> = serde_json::from_str(raw.get())?;
	Ok(AssignedReviewLead {
		lead_id: wire.lead_id,
		producer_commit_sha: metadata(u, wire.producer_commit_sha)?,
		identity_family: content(u, wire.identity_family)?,
		identity_anchor: content(u, wire.identity_anchor)?,
		identity_instance_key: optional_content(u, wire.identity_instance_key)?,
		hypothesis: content(u, wire.hypothesis)?,
		invariant_or_boundary: optional_content(u, wire.invariant_or_boundary)?,
		source_refs: content_list(u, wire.source_refs)?,
		next_proof_step: content(u, wire.next_proof_step)?,
		counterevidence: content(u, wire.counterevidence)?,
		proof_gaps: content(u, wire.proof_gaps)?,
	})
}
fn finding(
	u: &View<'_, '_>, raw: &RawValue,
) -> Result<AssignedReviewFinding<Agent, Server>, Error> {
	#[derive(Deserialize)]
	#[serde(deny_unknown_fields)]
	struct Wire<'a> {
		finding_id: ReviewId,
		#[serde(borrow)]
		reviewed_commit_sha: &'a RawValue,
		severity: Severity,
		#[serde(borrow)]
		title: &'a RawValue,
		#[serde(borrow)]
		description: &'a RawValue,
		#[serde(borrow)]
		identity_family: &'a RawValue,
		#[serde(borrow)]
		identity_anchor: &'a RawValue,
		#[serde(borrow, default)]
		identity_instance_key: Option<&'a RawValue>,
		#[serde(borrow)]
		evidence: &'a RawValue,
	}
	let wire: Wire<'_> = serde_json::from_str(raw.get())?;
	Ok(AssignedReviewFinding {
		finding_id: wire.finding_id,
		reviewed_commit_sha: metadata(u, wire.reviewed_commit_sha)?,
		severity: wire.severity,
		title: content(u, wire.title)?,
		description: content(u, wire.description)?,
		identity_family: content(u, wire.identity_family)?,
		identity_anchor: content(u, wire.identity_anchor)?,
		identity_instance_key: optional_content(u, wire.identity_instance_key)?,
		evidence: content(u, wire.evidence)?,
	})
}

macro_rules! phase_decoder {
	($decoder:ident, $lease:ident, $kind:literal, { $($field:ident : $admit:ident),* $(,)? }) => {
		/// Decode this phase's complete `kind`-tagged payload from server bytes.
		pub struct $decoder;
		impl $decoder {
			/// Decode a borrowed payload token within a server response validator.
			/// The token must belong to the original response, not a reserialized
			/// or separately supplied document. Containment is checked before any
			/// source-bearing metadata or content can be constructed.
			pub fn decode_payload(u: &View<'_, '_>, raw: &RawValue) -> Result<$lease<Agent, Server>, Error> {
				span(u, raw)?;
				#[derive(Deserialize)]
				enum Kind { #[serde(rename = $kind)] Expected }
				#[derive(Deserialize)]
				#[serde(deny_unknown_fields)]
				struct Wire<'a> {
					#[serde(rename = "kind")] _kind: Kind,
					provenance: ReviewProvenance,
					$(#[serde(borrow)] $field: &'a RawValue),*
				}
				let wire: Wire<'_> = serde_json::from_str(raw.get())?;
				let lease = $lease { provenance: wire.provenance, $($field: $admit(u, wire.$field)?),* };
				crate::objects_only(
					raw.get().as_bytes(),
					lease,
					Error::Invalid("lease object in sequence form"),
				)
			}
		}
		impl ValidateCarrying<&[u8], Server> for $decoder {
			type Output = $lease<Agent, Server>;
			type Error = Error;
			fn validate(self, u: View<'_, '_>) -> Result<Self::Output, Error> {
				let raw: &RawValue = serde_json::from_slice(u.get())?;
				Self::decode_payload(&u, raw)
			}
		}
	};
}
phase_decoder!(ReviewSurveyLeaseDecoder, ReviewSurveyLease, "review_survey", { context: context });
phase_decoder!(ReviewDrilldownLeaseDecoder, ReviewDrilldownLease, "review_drilldown", { generation: generation, profile: profile, lead: lead });
phase_decoder!(ReviewVerifyLeaseDecoder, ReviewVerifyLease, "review_verify", { generation: generation, profile: profile, finding: finding });
