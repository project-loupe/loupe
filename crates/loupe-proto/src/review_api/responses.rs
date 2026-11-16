//! Worker-side admission of host-preparation responses and the phase error
//! envelope from original Server bytes. Profile and assignment text carries
//! Agent; generation, digest and receipt metadata stay Server.

use loupe_core::review_candidates::{Candidate, CandidateKind};
use loupe_provenance::{Agent, Mark, Server, Unvalidated, Validate, ValidateCarrying};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::{
	CandidatesResponse, ManifestProgress, PhaseLimitsResponse, PinTargetResponse,
	PreparationDeferral, PublishedProfile, ReviewProtocol, UnsupportedRecipe,
};
use crate::review_lease::decode::{self as lease, View};
use crate::review_lease::{LeaseList, ReviewId};
use crate::review_response::{
	closed, exact, metadata, present, ReviewResponseDecodeError as Error,
};
use crate::PROTOCOL_VERSION;

exact_response_decoder!(
	/// Decode a `GET …/limits` response.
	PhaseLimitsResponseDecoder => PhaseLimitsResponse
);

/// Decode an inventory batch or seal response.
pub struct ManifestProgressDecoder;
impl Validate<&[u8], Server> for ManifestProgressDecoder {
	type Output = ManifestProgress<Server>;
	type Error = Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Server>,
	) -> Result<Self::Output, Error> {
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Wire<'a> {
			protocol_version: ReviewProtocol,
			expected_entry_count: u64,
			#[serde(borrow)]
			expected_digest: &'a RawValue,
			received_entry_count: u64,
			received_canonical_bytes: u64,
			sealed: bool,
		}
		let wire: Wire<'_> = serde_json::from_slice(u.get())?;
		let value = ManifestProgress {
			protocol_version: wire.protocol_version,
			expected_entry_count: wire.expected_entry_count,
			expected_digest: metadata(&mark, wire.expected_digest)?,
			received_entry_count: wire.received_entry_count,
			received_canonical_bytes: wire.received_canonical_bytes,
			sealed: wire.sealed,
		};
		exact(u.get(), value)
	}
}

/// Decode a `publish-profile` response.
pub struct PublishedProfileDecoder;
impl Validate<&[u8], Server> for PublishedProfileDecoder {
	type Output = PublishedProfile<Server>;
	type Error = Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Server>,
	) -> Result<Self::Output, Error> {
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Wire<'a> {
			protocol_version: ReviewProtocol,
			profile_version: u32,
			#[serde(borrow)]
			profile_digest: &'a RawValue,
		}
		let wire: Wire<'_> = serde_json::from_slice(u.get())?;
		let value = PublishedProfile {
			protocol_version: wire.protocol_version,
			profile_version: wire.profile_version,
			profile_digest: metadata(&mark, wire.profile_digest)?,
		};
		exact(u.get(), value)
	}
}

/// Decode a `pin-target` response. Generated profile and assignment text is
/// carried to Agent from its original span; everything else stays Server.
pub struct PinTargetResponseDecoder;
impl ValidateCarrying<&[u8], Server> for PinTargetResponseDecoder {
	type Output = PinTargetResponse<Agent, Server>;
	type Error = Error;
	fn validate(self, u: View<'_, '_>) -> Result<Self::Output, Error> {
		#[derive(Deserialize, Serialize)]
		#[serde(rename_all = "snake_case")]
		enum Outcome {
			Prepared,
			Deferred,
		}
		#[derive(Deserialize)]
		struct Tag<'a> {
			#[serde(borrow)]
			outcome: &'a RawValue,
		}
		let tag: Tag<'_> = serde_json::from_slice(u.get())?;
		let value = match closed::<Outcome>(tag.outcome)? {
			Outcome::Prepared => {
				#[derive(Deserialize)]
				#[serde(deny_unknown_fields)]
				struct Wire<'a> {
					#[serde(rename = "outcome")]
					_outcome: Outcome,
					protocol_version: ReviewProtocol,
					#[serde(borrow)]
					generation: &'a RawValue,
					#[serde(borrow, deserialize_with = "present")]
					profile: Option<&'a RawValue>,
					#[serde(borrow, deserialize_with = "present")]
					assignments: Option<&'a RawValue>,
				}
				let wire: Wire<'_> = serde_json::from_slice(u.get())?;
				PinTargetResponse::Prepared {
					protocol_version: wire.protocol_version,
					generation: lease::generation(&u, wire.generation)?,
					profile: wire.profile.map(|raw| lease::profile(&u, raw)).transpose()?,
					assignments: wire
						.assignments
						.map(|raw| lease::assignments(&u, raw))
						.transpose()?,
				}
			},
			Outcome::Deferred => {
				#[derive(Deserialize)]
				#[serde(deny_unknown_fields)]
				struct Wire<'a> {
					#[serde(rename = "outcome")]
					_outcome: Outcome,
					protocol_version: ReviewProtocol,
					#[serde(borrow)]
					receipt: &'a RawValue,
				}
				#[derive(Deserialize)]
				#[serde(deny_unknown_fields)]
				struct Receipt<'a> {
					receipt_id: ReviewId,
					#[serde(borrow)]
					commit_sha: &'a RawValue,
					#[serde(borrow)]
					reason: &'a RawValue,
				}
				let wire: Wire<'_> = serde_json::from_slice(u.get())?;
				let receipt: Receipt<'_> = serde_json::from_str(wire.receipt.get())?;
				PinTargetResponse::Deferred {
					protocol_version: wire.protocol_version,
					receipt: PreparationDeferral {
						receipt_id: receipt.receipt_id,
						commit_sha: metadata(&u.mark(), receipt.commit_sha)?,
						reason: closed::<UnsupportedRecipe>(receipt.reason)?,
					},
				}
			},
		};
		crate::objects_only(u.get(), value, Error::Invalid("response object in sequence form"))
	}
}

/// Decode a `lead-candidates` response. Identity text is carried to Agent;
/// the producing checkout stays Server.
pub struct CandidatesResponseDecoder;
impl ValidateCarrying<&[u8], Server> for CandidatesResponseDecoder {
	type Output = CandidatesResponse<Agent, Server>;
	type Error = Error;
	fn validate(self, u: View<'_, '_>) -> Result<Self::Output, Error> {
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Wire<'a> {
			protocol_version: ReviewProtocol,
			#[serde(borrow)]
			candidates: LeaseList<&'a RawValue, 20>,
		}
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Entry<'a> {
			#[serde(borrow)]
			kind: &'a RawValue,
			id: i64,
			producer_job_id: i64,
			#[serde(borrow)]
			commit_sha: &'a RawValue,
			created_at: i64,
			#[serde(borrow)]
			identity_family: &'a RawValue,
			#[serde(borrow)]
			identity_anchor: &'a RawValue,
			#[serde(borrow, deserialize_with = "present")]
			identity_instance_key: Option<&'a RawValue>,
		}
		let wire: Wire<'_> = serde_json::from_slice(u.get())?;
		let candidates = wire
			.candidates
			.as_slice()
			.iter()
			.map(|raw| {
				let entry: Entry<'_> = serde_json::from_str(raw.get())?;
				let candidate = Candidate {
					kind: closed::<CandidateKind>(entry.kind)?,
					id: entry.id,
					producer_job_id: entry.producer_job_id,
					commit_sha: metadata(&u.mark(), entry.commit_sha)?,
					created_at: entry.created_at,
					identity_family: lease::content(&u, entry.identity_family)?,
					identity_anchor: lease::content(&u, entry.identity_anchor)?,
					identity_instance_key: lease::optional_content(
						&u,
						entry.identity_instance_key,
					)?,
				};
				candidate.validate().map_err(Error::Invalid)?;
				Ok(candidate)
			})
			.collect::<Result<_, Error>>()?;
		let value = CandidatesResponse {
			protocol_version: wire.protocol_version,
			candidates: LeaseList::new(candidates).map_err(Error::Invalid)?,
		};
		crate::objects_only(u.get(), value, Error::Invalid("response object in sequence form"))
	}
}

/// Every error code a phase route sends, including the router's fallback
/// codes for statuses no handler produced (`unauthenticated`,
/// `method_not_allowed`, `request_failed`). A code outside this set is
/// `Other`, so a newer server's code is still classified by its status.
// debug-ok: closed error vocabulary, never response text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewErrorCode {
	InvalidRequest,
	Denied,
	NotFound,
	RequestTooLarge,
	ContentType,
	ContentEncoding,
	CheckoutConflict,
	CheckpointConflict,
	CheckpointLimit,
	CompatibilityKeyConflict,
	CompatibilityPolicy,
	FindingIdentityConflict,
	IncompatibleReviewState,
	InvalidLimits,
	InventoryLimit,
	InventoryRevisionConflict,
	RevalidationRequired,
	StateConflict,
	TerminalConflict,
	UnitResultExists,
	InternalError,
	ResponseTooLarge,
	Unauthenticated,
	MethodNotAllowed,
	RequestFailed,
	Other,
}
impl ReviewErrorCode {
	pub const KNOWN: [Self; 25] = [
		Self::InvalidRequest,
		Self::Denied,
		Self::NotFound,
		Self::RequestTooLarge,
		Self::ContentType,
		Self::ContentEncoding,
		Self::CheckoutConflict,
		Self::CheckpointConflict,
		Self::CheckpointLimit,
		Self::CompatibilityKeyConflict,
		Self::CompatibilityPolicy,
		Self::FindingIdentityConflict,
		Self::IncompatibleReviewState,
		Self::InvalidLimits,
		Self::InventoryLimit,
		Self::InventoryRevisionConflict,
		Self::RevalidationRequired,
		Self::StateConflict,
		Self::TerminalConflict,
		Self::UnitResultExists,
		Self::InternalError,
		Self::ResponseTooLarge,
		Self::Unauthenticated,
		Self::MethodNotAllowed,
		Self::RequestFailed,
	];
	fn classify(raw: &str) -> Self {
		Self::KNOWN
			.into_iter()
			.find(|code| loupe_core::closed_string::spelling(code).as_deref() == Some(raw))
			.unwrap_or(Self::Other)
	}
}

/// The phase error envelope:
/// `{"protocol_version":3,"error":{"code":…,"detail":null[,"current_revision":n]}}`.
// debug-ok: closed error code and a numeric revision only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewErrorResponse {
	pub code: ReviewErrorCode,
	/// Present exactly for `InventoryRevisionConflict`; an `Other` code may
	/// carry it.
	pub current_revision: Option<i64>,
}
impl Serialize for ReviewErrorResponse {
	fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		#[derive(Serialize)]
		struct Body {
			code: ReviewErrorCode,
			detail: (),
			#[serde(skip_serializing_if = "Option::is_none")]
			current_revision: Option<i64>,
		}
		#[derive(Serialize)]
		struct Envelope {
			protocol_version: u16,
			error: Body,
		}
		Envelope {
			protocol_version: PROTOCOL_VERSION,
			error: Body { code: self.code, detail: (), current_revision: self.current_revision },
		}
		.serialize(serializer)
	}
}

/// Decode a phase route's error body. Unknown codes are admitted as `Other`.
pub struct ReviewErrorResponseDecoder;
impl Validate<&[u8], Server> for ReviewErrorResponseDecoder {
	type Output = ReviewErrorResponse;
	type Error = Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, _: Mark<'v, Server>,
	) -> Result<Self::Output, Error> {
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Wire<'a> {
			#[serde(rename = "protocol_version")]
			_protocol_version: ReviewProtocol,
			#[serde(borrow)]
			error: Body<'a>,
		}
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Body<'a> {
			#[serde(borrow)]
			code: &'a RawValue,
			#[serde(rename = "detail")]
			_detail: Null,
			#[serde(default)]
			current_revision: Option<i64>,
		}
		struct Null;
		impl<'de> Deserialize<'de> for Null {
			fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
				<()>::deserialize(deserializer).map(|()| Null)
			}
		}
		let wire: Wire<'_> = serde_json::from_slice(u.get())?;
		if !wire.error.code.get().starts_with('"') {
			return Err(Error::Invalid("error code is not a string"));
		}
		let code =
			loupe_core::text::decode_json_string_bounded(wire.error.code.get(), "code", 64, 64)
				.map(|raw| ReviewErrorCode::classify(&raw))
				.unwrap_or(ReviewErrorCode::Other);
		let revision_allowed =
			matches!(code, ReviewErrorCode::InventoryRevisionConflict | ReviewErrorCode::Other);
		let revision_required = code == ReviewErrorCode::InventoryRevisionConflict;
		match (wire.error.current_revision, revision_allowed, revision_required) {
			(Some(_), false, _) => return Err(Error::Invalid("unexpected current_revision")),
			(None, _, true) => return Err(Error::Invalid("missing current_revision")),
			_ => {},
		}
		let value = ReviewErrorResponse { code, current_revision: wire.error.current_revision };
		crate::objects_only(u.get(), value, Error::Invalid("response object in sequence form"))
	}
}
