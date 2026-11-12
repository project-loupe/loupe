//! Worker-host preparation contracts never accept repository, campaign,
//! generation or worker ownership from callers. The concrete decoders admit
//! actual Worker request bytes; only generated profile content carries Agent.
//!
//! Public records serialize but cannot fabricate a source through serde.
//! ```compile_fail,E0277
//! use loupe_proto::review_api::PinTargetRequest;
//! use loupe_provenance::Worker;
//! let _: PinTargetRequest<Worker> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_proto::review_api::PublishProfileRequest;
//! use loupe_provenance::Agent;
//! let _: PublishProfileRequest<Agent> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_proto::review_api::InventoryBatchRequest;
//! use loupe_provenance::Worker;
//! let _: InventoryBatchRequest<Worker> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_proto::review_api::SealInventoryRequest;
//! let _: SealInventoryRequest = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! let _: loupe_proto::review_api::PinTargetRequest<loupe_provenance::Operator> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! let _: loupe_proto::review_api::InventoryBatchRequest<loupe_provenance::Operator> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! let _: loupe_proto::review_api::PublishProfileRequest<loupe_provenance::Operator> = serde_json::from_str("{}").unwrap();
//! ```

use loupe_core::review_payload::{GeneratedProfile, Version1};
use loupe_core::text::{decode_json_string_bounded, IdentPolicy, Identifier};
use loupe_provenance::{Agent, Mark, Source, Unvalidated, Validate, ValidateCarrying, Worker};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::review_lease::{
	FrozenReviewProfile, LeaseList, ReviewAssignments, ReviewCommit, ReviewDigest,
	ReviewGeneration, ReviewId,
};
use crate::PROTOCOL_VERSION;

// debug-ok: numeric capacity only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capacity {
	pub limit: u32,
	pub remaining: u32,
}

// debug-ok: numeric limits, timestamps and closed availability states only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseLimitsResponse {
	pub protocol_version: ReviewProtocol,
	pub soft_deadline_at: i64,
	pub submit_by: i64,
	pub hard_deadline_at: i64,
	pub remaining_seconds: u64,
	pub new_units: Capacity,
	pub leads: Capacity,
	pub siblings: Capacity,
	pub candidate_queries: Capacity,
	pub campaign_jobs_limit: u64,
	pub campaign_jobs_admitted: u64,
	pub campaign_general_remaining: u64,
	pub campaign_urgent_remaining: u64,
	pub campaign_verification_remaining: u64,
	pub proof_capacity: Unavailable,
	pub artifact_capacity: Unavailable,
	pub output_capacity: Unavailable,
	pub tokens: TokenCapacity,
}
// debug-ok: closed availability state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unavailable {
	Unavailable,
}
// debug-ok: numeric token limit and closed state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum TokenCapacity {
	None,
	HostEnforced { limit: u64, spent: UnknownSpend },
}
// debug-ok: closed unknown-spend state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownSpend {
	Unknown,
}

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct CandidatesResponse<C: Source, M: Source> {
	pub protocol_version: ReviewProtocol,
	pub candidates: LeaseList<loupe_core::review_candidates::Candidate<C, M>, 20>,
}

/// New phase requests require the exact version, in addition to their header.
// debug-ok: exact, closed protocol version with no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct ReviewProtocol;
impl TryFrom<u16> for ReviewProtocol {
	type Error = &'static str;
	fn try_from(value: u16) -> Result<Self, Self::Error> {
		if value == PROTOCOL_VERSION {
			Ok(Self)
		} else {
			Err("unsupported protocol_version")
		}
	}
}
impl From<ReviewProtocol> for u16 {
	fn from(_: ReviewProtocol) -> Self {
		PROTOCOL_VERSION
	}
}

// debug-ok: policy marker with no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawPathHexPolicy;
impl IdentPolicy for RawPathHexPolicy {
	const FIELD: &'static str = "raw_path_hex";
	const MAX_LEN: usize = loupe_core::inventory_manifest::MAX_PATH_BYTES * 2;
	fn accepts(value: &str) -> bool {
		!value.is_empty()
			&& value.len().is_multiple_of(2)
			&& value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
	}
}
/// Lowercase hex retains every raw Git path byte, including non-UTF-8. Git
/// path/mode semantics are checked when the host composes a manifest entry.
pub type RawPathHex<S> = Identifier<RawPathHexPolicy, S>;

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct PinTargetRequest<S: Source> {
	pub protocol_version: ReviewProtocol,
	pub commit_sha: ReviewCommit<S>,
}
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct ManifestEntry<S: Source> {
	pub raw_path_hex: RawPathHex<S>,
	pub git_mode: u32,
	pub object_id: ReviewCommit<S>,
}
impl<S: Source> ManifestEntry<S> {
	pub fn to_manifest(
		&self,
	) -> Result<loupe_core::inventory_manifest::ManifestEntry<S>, &'static str> {
		loupe_core::inventory_manifest::ManifestEntry::from_encoded(
			&self.raw_path_hex,
			self.git_mode,
			&self.object_id,
		)
	}
}
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct InventoryBatchRequest<S: Source> {
	pub protocol_version: ReviewProtocol,
	pub format_version: Version1,
	pub expected_entry_count: u64,
	pub expected_digest: ReviewDigest<S>,
	pub start_position: u64,
	pub entries: LeaseList<ManifestEntry<S>, 4096>,
}
// debug-ok: only the closed protocol version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SealInventoryRequest {
	pub protocol_version: ReviewProtocol,
}
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct PublishProfileRequest<S: Source> {
	pub protocol_version: ReviewProtocol,
	pub profile: GeneratedProfile<S>,
}
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct ManifestProgress<S: Source> {
	pub protocol_version: ReviewProtocol,
	pub expected_entry_count: u64,
	pub expected_digest: ReviewDigest<S>,
	pub received_entry_count: u64,
	pub received_canonical_bytes: u64,
	pub sealed: bool,
}
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct PublishedProfile<S: Source> {
	pub protocol_version: ReviewProtocol,
	pub profile_version: u32,
	pub profile_digest: ReviewDigest<S>,
}
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct PreparationDeferral<S: Source> {
	pub receipt_id: ReviewId,
	pub commit_sha: ReviewCommit<S>,
	pub reason: UnsupportedRecipe,
}
// debug-ok: closed refusal reason with no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedRecipe {
	UnsupportedRecipe,
}

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PinTargetResponse<ContentS: Source, MetaS: Source> {
	Prepared {
		protocol_version: ReviewProtocol,
		generation: ReviewGeneration<MetaS>,
		/// Bootstrap has no profile before publication. Ordinary jobs reuse it.
		profile: Option<FrozenReviewProfile<ContentS, MetaS>>,
		/// Only ordinary surveys receive an assignment batch, including empty.
		assignments: Option<ReviewAssignments<ContentS>>,
	},
	Deferred {
		protocol_version: ReviewProtocol,
		receipt: PreparationDeferral<MetaS>,
	},
}
record_impls!(PinTargetRequest<S> { protocol_version, commit_sha });
record_impls!(ManifestEntry<S> { raw_path_hex, git_mode, object_id });
record_impls!(InventoryBatchRequest<S> { protocol_version, format_version, expected_entry_count, expected_digest, start_position, entries });
record_impls!(PublishProfileRequest<S> { protocol_version, profile });
record_impls!(ManifestProgress<S> { protocol_version, expected_entry_count, expected_digest, received_entry_count, received_canonical_bytes, sealed });
record_impls!(PublishedProfile<S> { protocol_version, profile_version, profile_digest });
record_impls!(PreparationDeferral<S> { receipt_id, commit_sha, reason });

impl<C: Source, M: Source> Clone for PinTargetResponse<C, M> {
	fn clone(&self) -> Self {
		match self {
			Self::Prepared { protocol_version, generation, profile, assignments } => {
				Self::Prepared {
					protocol_version: *protocol_version,
					generation: generation.clone(),
					profile: profile.clone(),
					assignments: assignments.clone(),
				}
			},
			Self::Deferred { protocol_version, receipt } => {
				Self::Deferred { protocol_version: *protocol_version, receipt: receipt.clone() }
			},
		}
	}
}
impl<C: Source, M: Source> PartialEq for PinTargetResponse<C, M> {
	fn eq(&self, other: &Self) -> bool {
		match (self, other) {
			(
				Self::Prepared {
					protocol_version: lv,
					generation: lg,
					profile: lp,
					assignments: la,
				},
				Self::Prepared {
					protocol_version: rv,
					generation: rg,
					profile: rp,
					assignments: ra,
				},
			) => (lv, lg, lp, la) == (rv, rg, rp, ra),
			(
				Self::Deferred { protocol_version: lv, receipt: lr },
				Self::Deferred { protocol_version: rv, receipt: rr },
			) => (lv, lr) == (rv, rr),
			_ => false,
		}
	}
}
impl<C: Source, M: Source> Eq for PinTargetResponse<C, M> {}
impl<C: Source, M: Source> std::fmt::Debug for PinTargetResponse<C, M> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("PinTargetResponse([redacted])")
	}
}

/// A bounded failure classification, never a serde diagnostic containing input.
// debug-ok: static classifications and content-free text policy errors.
#[derive(Debug, thiserror::Error)]
pub enum ReviewApiDecodeError {
	#[error("invalid review preparation JSON")]
	Json,
	#[error("invalid review preparation request: {0}")]
	Invalid(&'static str),
	#[error(transparent)]
	Text(#[from] loupe_core::text::Error),
}
impl From<serde_json::Error> for ReviewApiDecodeError {
	fn from(_: serde_json::Error) -> Self {
		Self::Json
	}
}
type Error = ReviewApiDecodeError;

fn identifier<P: IdentPolicy>(
	mark: &Mark<'_, Worker>, raw: &RawValue,
) -> Result<Identifier<P, Worker>, Error> {
	let text = decode_json_string_bounded(raw.get(), P::FIELD, P::MAX_LEN, P::MAX_LEN)?;
	Ok(Identifier::new(mark, &text)?)
}

pub struct PinTargetRequestDecoder;
impl Validate<&[u8], Worker> for PinTargetRequestDecoder {
	type Output = PinTargetRequest<Worker>;
	type Error = Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Worker>,
	) -> Result<Self::Output, Error> {
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Wire<'a> {
			protocol_version: ReviewProtocol,
			#[serde(borrow)]
			commit_sha: &'a RawValue,
		}
		let wire: Wire<'_> = serde_json::from_slice(u.get())?;
		Ok(PinTargetRequest {
			protocol_version: wire.protocol_version,
			commit_sha: identifier(&mark, wire.commit_sha)?,
		})
	}
}

pub struct InventoryBatchRequestDecoder;
impl Validate<&[u8], Worker> for InventoryBatchRequestDecoder {
	type Output = InventoryBatchRequest<Worker>;
	type Error = Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Worker>,
	) -> Result<Self::Output, Error> {
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Wire<'a> {
			protocol_version: ReviewProtocol,
			format_version: Version1,
			expected_entry_count: u64,
			#[serde(borrow)]
			expected_digest: &'a RawValue,
			start_position: u64,
			#[serde(borrow)]
			entries: LeaseList<&'a RawValue, 4096>,
		}
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Entry<'a> {
			#[serde(borrow)]
			raw_path_hex: &'a RawValue,
			git_mode: u32,
			#[serde(borrow)]
			object_id: &'a RawValue,
		}
		let wire: Wire<'_> = serde_json::from_slice(u.get())?;
		let entries = wire
			.entries
			.as_slice()
			.iter()
			.map(|raw| {
				let entry: Entry<'_> = serde_json::from_str(raw.get())?;
				Ok(ManifestEntry {
					raw_path_hex: identifier(&mark, entry.raw_path_hex)?,
					git_mode: entry.git_mode,
					object_id: identifier(&mark, entry.object_id)?,
				})
			})
			.collect::<Result<_, Error>>()?;
		Ok(InventoryBatchRequest {
			protocol_version: wire.protocol_version,
			format_version: wire.format_version,
			expected_entry_count: wire.expected_entry_count,
			expected_digest: identifier(&mark, wire.expected_digest)?,
			start_position: wire.start_position,
			entries: LeaseList::new(entries).map_err(Error::Invalid)?,
		})
	}
}

pub struct SealInventoryRequestDecoder;
impl Validate<&[u8], Worker> for SealInventoryRequestDecoder {
	type Output = SealInventoryRequest;
	type Error = Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, _: Mark<'v, Worker>,
	) -> Result<Self::Output, Error> {
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Wire {
			protocol_version: ReviewProtocol,
		}
		let wire: Wire = serde_json::from_slice(u.get())?;
		Ok(SealInventoryRequest { protocol_version: wire.protocol_version })
	}
}

struct AgentProfile;
impl Validate<&[u8], Agent> for AgentProfile {
	type Output = GeneratedProfile<Agent>;
	type Error = Error;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Agent>,
	) -> Result<Self::Output, Error> {
		let raw = std::str::from_utf8(u.get()).map_err(|_| Error::Json)?;
		Ok(GeneratedProfile::new(&mark, raw)?)
	}
}

fn profile_content(
	u: &Unvalidated<'_, &[u8], Worker>, raw: &RawValue,
) -> Result<GeneratedProfile<Agent>, Error> {
	let start = (raw.get().as_ptr() as usize)
		.checked_sub(u.get().as_ptr() as usize)
		.ok_or(Error::Invalid("profile span outside request"))?;
	let end = start.checked_add(raw.get().len()).ok_or(Error::Invalid("profile span overflow"))?;
	u.carry::<Agent>(start..end)
		.ok_or(Error::Invalid("profile span outside request"))?
		.validate(AgentProfile)
}

pub struct PublishProfileRequestDecoder;
impl ValidateCarrying<&[u8], Worker> for PublishProfileRequestDecoder {
	type Output = PublishProfileRequest<Agent>;
	type Error = Error;
	fn validate(self, u: Unvalidated<'_, &[u8], Worker>) -> Result<Self::Output, Error> {
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Wire<'a> {
			protocol_version: ReviewProtocol,
			#[serde(borrow)]
			profile: &'a RawValue,
		}
		let wire: Wire<'_> = serde_json::from_slice(u.get())?;
		Ok(PublishProfileRequest {
			protocol_version: wire.protocol_version,
			profile: profile_content(&u, wire.profile)?,
		})
	}
}

#[cfg(test)]
mod tests {
	use loupe_provenance::{Agent, Source, Worker};
	use serde::Serialize;
	use serde_json::json;

	use super::*;
	use crate::test_support::worker_request;

	fn pin(raw: &str) -> Result<PinTargetRequest<Worker>, ReviewApiDecodeError> {
		worker_request(raw.as_bytes()).validate(PinTargetRequestDecoder)
	}
	fn batch(raw: &str) -> Result<InventoryBatchRequest<Worker>, ReviewApiDecodeError> {
		worker_request(raw.as_bytes()).validate(InventoryBatchRequestDecoder)
	}
	fn profile(raw: &str) -> Result<PublishProfileRequest<Agent>, ReviewApiDecodeError> {
		worker_request(raw.as_bytes()).validate_carrying(PublishProfileRequestDecoder)
	}
	fn entry(raw: &str) -> serde_json::Value {
		json!({"raw_path_hex":raw,"git_mode":0o100644,"object_id":"b".repeat(40)})
	}
	fn batch_json(entries: Vec<serde_json::Value>) -> String {
		json!({"protocol_version":PROTOCOL_VERSION,"format_version":1,
			"expected_entry_count":entries.len(),"expected_digest":"c".repeat(64),
			"start_position":0,"entries":entries})
		.to_string()
	}

	#[test]
	fn phase_requests_require_exact_version_and_no_ownership_fields() {
		let valid =
			json!({"protocol_version":PROTOCOL_VERSION,"commit_sha":"a".repeat(40)}).to_string();
		let request = pin(&valid).unwrap();
		assert_eq!(
			serde_json::to_value(&request).unwrap(),
			serde_json::from_str::<serde_json::Value>(&valid).unwrap()
		);
		for invalid in [
			valid.replace(":3", ":2"),
			valid.replace(",\"protocol_version\":3", ""),
			valid
				.replace("\"protocol_version\":3", "\"protocol_version\":3,\"protocol_version\":3"),
			valid.replace('}', ",\"generation_id\":1}"),
			valid.replace('}', ",\"worker_id\":1}"),
			valid.replace('}', ",\"campaign_id\":1}"),
			valid.replace('}', ",\"repo_id\":1}"),
		] {
			assert!(pin(&invalid).is_err(), "accepted invalid pin request");
		}
	}

	#[test]
	fn raw_identity_is_lossless_and_bounded_not_a_display_path() {
		let request = batch(&batch_json(vec![
			entry("61ff"),
			entry("61254646"),
			entry("65cc81"),
			entry("c3a9"),
		]))
		.unwrap();
		let entries = request.entries.as_slice();
		assert_eq!(entries[0].to_manifest().unwrap().raw_path(), b"a\xff");
		assert_eq!(entries[1].to_manifest().unwrap().raw_path(), b"a%FF");
		assert_ne!(entries[0], entries[1]);
		assert_ne!(entries[2].to_manifest().unwrap(), entries[3].to_manifest().unwrap());
		for invalid in ["", "0", "AA", "gg"] {
			assert!(batch(&batch_json(vec![entry(invalid)])).is_err());
		}
		assert!(batch(&batch_json(vec![entry(&"61".repeat(64 * 1024))])).is_ok());
		assert!(batch(&batch_json(vec![entry(&"61".repeat(64 * 1024 + 1))])).is_err());
	}

	#[test]
	fn manifest_semantics_remain_at_the_host_composition_boundary() {
		for raw_path in ["00", "2f61", "612f2e2e2f62"] {
			let request = batch(&batch_json(vec![entry(raw_path)])).unwrap();
			assert!(request.entries.as_slice()[0].to_manifest().is_err());
		}
		let mut bad_mode = entry("61");
		bad_mode["git_mode"] = json!(0o040000);
		let request = batch(&batch_json(vec![bad_mode])).unwrap();
		assert!(request.entries.as_slice()[0].to_manifest().is_err());
	}

	#[test]
	fn inventory_schema_rejects_duplicates_unknowns_and_excess_entries() {
		let valid = batch_json(vec![entry("61")]);
		assert!(batch(&valid).is_ok());
		for invalid in [
			valid.replace("\"format_version\":1", "\"format_version\":2"),
			valid.replace("\"start_position\":0", "\"start_position\":0,\"start_position\":0"),
			valid.replace("\"git_mode\":33188", "\"git_mode\":33188,\"git_mode\":33188"),
			valid.replace("\"git_mode\":33188", "\"git_mode\":33188,\"repo_id\":1"),
			valid.replace(
				"\"raw_path_hex\":\"61\"",
				"\"raw_path_hex\":\"61\",\"raw_path_hex\":\"62\"",
			),
		] {
			assert!(batch(&invalid).is_err(), "accepted invalid inventory schema");
		}
		assert!(batch(&batch_json(vec![entry("61"); 4096])).is_ok());
		assert!(batch(&batch_json(vec![entry("61"); 4097])).is_err());
	}

	#[test]
	fn seal_requires_only_the_exact_protocol_version() {
		let valid = format!(r#"{{"protocol_version":{PROTOCOL_VERSION}}}"#);
		assert!(worker_request(valid.as_bytes()).validate(SealInventoryRequestDecoder).is_ok());
		for raw in [
			"{}",
			r#"{"protocol_version":2}"#,
			r#"{"protocol_version":3,"sealed":true}"#,
			r#"{"protocol_version":3,"protocol_version":3}"#,
		] {
			assert!(worker_request(raw.as_bytes()).validate(SealInventoryRequestDecoder).is_err());
		}
	}

	#[test]
	fn profile_carries_original_token_before_bounded_semantic_admission() {
		let raw = r#"{ "protocol_version":3, "profile":{ "purpose":"e\u0301" } }"#;
		let request = profile(raw).unwrap();
		let _: &GeneratedProfile<Agent> = &request.profile;
		assert_eq!(request.profile.expose(), r#"{"purpose":"é"}"#);
		for invalid in [
			r#"{"protocol_version":3,"profile":{"purpose":"a","purpose":"b"}}"#.to_owned(),
			r#"{"protocol_version":3,"profile":{},"profile":{}}"#.to_owned(),
			r#"{"protocol_version":3,"profile":{},"generation_id":1}"#.to_owned(),
			format!(
				r#"{{"protocol_version":3,"profile":{{"purpose":"{}"}}}}"#,
				"a".repeat(32 * 1024)
			),
		] {
			assert!(profile(&invalid).is_err(), "accepted invalid profile");
		}
	}

	#[test]
	fn request_diagnostics_are_closed_and_content_free() {
		let sentinel = "private-profile-sentinel";
		let request =
			profile(&format!(r#"{{"protocol_version":3,"profile":{{"purpose":"{sentinel}"}}}}"#))
				.unwrap();
		assert!(!format!("{request:?}").contains(sentinel));
		let invalid = format!(r#"{{"protocol_version":3,"profile":{{}},"{sentinel}":1}}"#);
		let error = profile(&invalid).unwrap_err();
		assert!(!format!("{error:?} {error}").contains(sentinel));
		let invalid = format!(r#"{{"protocol_version":3,"commit_sha":"{sentinel}"}}"#);
		let error = pin(&invalid).unwrap_err();
		assert!(!format!("{error:?} {error}").contains(sentinel));
	}

	#[test]
	fn profile_carry_rejects_a_copied_token_outside_the_original_request() {
		struct CheckSpan;
		impl ValidateCarrying<&[u8], Worker> for CheckSpan {
			type Output = ();
			type Error = Error;
			fn validate(self, u: Unvalidated<'_, &[u8], Worker>) -> Result<(), Error> {
				let original: &RawValue = serde_json::from_slice(u.get())?;
				let copied = RawValue::from_string(original.get().to_owned())?;
				assert!(profile_content(&u, original).is_ok());
				assert!(matches!(
					profile_content(&u, &copied),
					Err(Error::Invalid("profile span outside request"))
				));
				Ok(())
			}
		}
		worker_request(br#"{ "purpose": "e\u0301" }"#).validate_carrying(CheckSpan).unwrap();
	}

	#[test]
	fn source_markers_add_no_incidental_trait_bounds() {
		fn traits<T: Clone + Eq + std::fmt::Debug + Serialize>() {}
		fn check<C: Source, M: Source>() {
			traits::<PinTargetRequest<M>>();
			traits::<ManifestEntry<M>>();
			traits::<InventoryBatchRequest<M>>();
			traits::<SealInventoryRequest>();
			traits::<PublishProfileRequest<C>>();
			traits::<ManifestProgress<M>>();
			traits::<PublishedProfile<M>>();
			traits::<PreparationDeferral<M>>();
			traits::<PinTargetResponse<C, M>>();
		}
		check::<Agent, Worker>();
	}
}
