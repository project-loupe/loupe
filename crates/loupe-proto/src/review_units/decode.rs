//! The fixed Worker request schema owns each original-span Agent carry.
use std::marker::PhantomData;

use loupe_core::review_payload::Error;
use loupe_core::text::{
	decode_json_string_bounded, policy, IdentPolicy, Normalization, RepoPath, TextPolicy,
};
use loupe_provenance::{Agent, Mark, Unvalidated, Validate, ValidateCarrying, Worker};
use serde_json::value::RawValue;

use super::*;

type View<'v, 'a> = Unvalidated<'v, &'a [u8], Worker>;
trait Content: Sized {
	fn admit(mark: &Mark<'_, Agent>, raw: &str) -> Result<Self, Error>;
}
impl<P: TextPolicy> Content for BoundedText<P, Agent> {
	fn admit(mark: &Mark<'_, Agent>, raw: &str) -> Result<Self, Error> {
		let factor = if P::NORMALIZATION == Normalization::Semantic { 4 } else { 1 };
		let ceiling = P::MAX_BYTES.saturating_mul(factor);
		let value = decode_json_string_bounded(raw, P::FIELD, ceiling, ceiling)?;
		Ok(Self::new(mark, &value)?)
	}
}
impl Content for SourceRef<Agent> {
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
struct AgentField<T>(PhantomData<T>);
impl<T: Content> Validate<&[u8], Agent> for AgentField<T> {
	type Output = T;
	type Error = Error;
	fn validate<'v>(self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Agent>) -> Result<T, Error> {
		T::admit(&mark, std::str::from_utf8(u.get()).map_err(|_| Error::Json)?)
	}
}
fn invalid(rule: &'static str) -> Error {
	Error::Invalid { field: "review_unit_proposal", rule }
}
fn content<T: Content>(u: &View<'_, '_>, raw: &RawValue) -> Result<T, Error> {
	let start = (raw.get().as_ptr() as usize)
		.checked_sub(u.get().as_ptr() as usize)
		.ok_or_else(|| invalid("content span outside request"))?;
	let end = start.checked_add(raw.get().len()).ok_or_else(|| invalid("content span overflow"))?;
	u.carry::<Agent>(start..end)
		.ok_or_else(|| invalid("content span outside request"))?
		.validate(AgentField::<T>(PhantomData))
}
fn optional<T: Content>(u: &View<'_, '_>, raw: Option<&RawValue>) -> Result<Option<T>, Error> {
	raw.filter(|raw| raw.get() != "null").map(|raw| content(u, raw)).transpose()
}

pub struct ReviewUnitRequestDecoder;
impl ValidateCarrying<&[u8], Worker> for ReviewUnitRequestDecoder {
	type Output = ReviewUnitRequest<Agent, Worker>;
	type Error = Error;
	fn validate(self, u: View<'_, '_>) -> Result<Self::Output, Error> {
		if u.get().len() > 256 * 1024 {
			return Err(Error::Bytes { field: "review_unit_proposal", max_bytes: 256 * 1024 });
		}
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Wire<'a> {
			protocol_version: ReviewProtocol,
			#[serde(borrow)]
			client_review_unit_key: &'a RawValue,
			#[serde(borrow)]
			title: &'a RawValue,
			#[serde(borrow)]
			objective: &'a RawValue,
			priority_band: PriorityBand,
			#[serde(borrow, default)]
			priority_rationale: Option<&'a RawValue>,
			#[serde(borrow)]
			source_refs: LeaseList<&'a RawValue, 32, 1>,
			#[serde(default)]
			depends_on_review_unit_ids: LeaseList<ReviewId, 8>,
			#[serde(borrow, default)]
			closure_criteria: Option<&'a RawValue>,
			#[serde(borrow, default)]
			semantic_context: Option<&'a RawValue>,
		}
		let wire: Wire<'_> = serde_json::from_slice(u.get())?;
		let key = decode_json_string_bounded(
			wire.client_review_unit_key.get(),
			ClientKey::FIELD,
			ClientKey::MAX_LEN,
			ClientKey::MAX_LEN,
		)?;
		let request = ReviewUnitRequest {
			protocol_version: wire.protocol_version,
			client_review_unit_key: Identifier::new(&u.mark(), &key)?,
			title: content(&u, wire.title)?,
			objective: content(&u, wire.objective)?,
			priority_band: wire.priority_band,
			priority_rationale: optional(&u, wire.priority_rationale)?,
			source_refs: LeaseList::new(
				wire.source_refs
					.as_slice()
					.iter()
					.map(|raw| content(&u, raw))
					.collect::<Result<_, _>>()?,
			)
			.map_err(invalid)?,
			depends_on_review_unit_ids: wire.depends_on_review_unit_ids,
			closure_criteria: optional(&u, wire.closure_criteria)?,
			semantic_context: optional(&u, wire.semantic_context)?,
		};
		request.validate().map_err(invalid)?;
		crate::objects_only(u.get(), request, invalid("request object in sequence form"))
	}
}
