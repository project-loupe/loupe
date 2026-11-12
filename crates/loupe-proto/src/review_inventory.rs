//! Independent, byte-exact inventory disposition checkpoints.
use loupe_core::canonical;
use loupe_core::text::policy::ClientKey;
pub use loupe_core::text::policy::InventoryReason;
use loupe_core::text::{decode_json_string_bounded, BoundedText, Identifier, RepoPath};
use loupe_provenance::{Mark, Source, Unvalidated, Validate, Worker};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::review_api::ReviewProtocol;
use crate::review_lease::{LeaseList, ReviewId};

// debug-ok: closed inventory disposition, never content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
	Mapped,
	Context,
	Excluded,
	Unresolved,
}
loupe_core::closed_string_enum!(Disposition { Mapped, Context, Excluded, Unresolved });

// debug-ok: numeric unit identity and assignment epoch only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitMapping {
	pub review_unit_id: ReviewId,
	pub assignment_epoch: u64,
}

/// Original Worker input, not authority and not publicly deserializable.
/// ```compile_fail,E0277
/// use loupe_proto::review_inventory::InventoryDispositionRequest;
/// use loupe_provenance::Worker;
/// let _: InventoryDispositionRequest<Worker> = serde_json::from_str("{}").unwrap();
/// ```
/// ```compile_fail,E0277
/// use loupe_proto::review_inventory::InventoryDispositionRequest;
/// use loupe_provenance::Operator;
/// let _: InventoryDispositionRequest<Operator> = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct InventoryDispositionRequest<S: Source> {
	pub protocol_version: ReviewProtocol,
	pub client_inventory_disposition_key: Identifier<ClientKey, S>,
	pub source_path: RepoPath<S>,
	pub expected_revision: i64,
	pub disposition: Disposition,
	pub reason: Option<BoundedText<InventoryReason, S>>,
	pub mappings: LeaseList<UnitMapping, 8>,
}

record_impls!(InventoryDispositionRequest<S> { protocol_version, client_inventory_disposition_key, source_path, expected_revision, disposition, reason, mappings });
impl<S: Source> InventoryDispositionRequest<S> {
	pub fn validate(&self) -> Result<(), &'static str> {
		if self.expected_revision < 0 {
			return Err("expected_revision must be nonnegative");
		}
		if (self.disposition == Disposition::Mapped) == self.mappings.as_slice().is_empty() {
			return Err("mapped requires mappings; other dispositions forbid them");
		}
		if matches!(self.disposition, Disposition::Context | Disposition::Excluded)
			&& self.reason.is_none()
		{
			return Err("context and excluded require reason");
		}
		let mut ids = std::collections::HashSet::new();
		for mapping in self.mappings.as_slice() {
			if mapping.assignment_epoch > i64::MAX as u64
				|| !ids.insert(i64::from(mapping.review_unit_id))
			{
				return Err("mappings require distinct units and SQLite-range epochs");
			}
		}
		Ok(())
	}
	/// Canonicalize the complete typed request, never generic JSON prose leaves:
	/// RepoPath deliberately preserves NFC-distinct Git identities.
	pub fn digest(&self) -> Result<[u8; 32], serde_json::Error> {
		Ok(canonical::digest(&canonical::canonical_bytes(&serde_json::to_value(self)?)))
	}
}

// debug-ok: protocol and positive numeric receipt fields only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryDispositionResponse {
	pub protocol_version: ReviewProtocol,
	pub inventory_entry_id: ReviewId,
	pub revision: u64,
}

pub const MAX_REQUEST_BYTES: usize = 8192;
pub struct InventoryDispositionRequestDecoder;
impl Validate<&[u8], Worker> for InventoryDispositionRequestDecoder {
	type Output = InventoryDispositionRequest<Worker>;
	type Error = crate::review_api::ReviewApiDecodeError;
	fn validate<'v>(
		self, u: Unvalidated<'v, &[u8]>, mark: Mark<'v, Worker>,
	) -> Result<Self::Output, Self::Error> {
		use crate::review_api::ReviewApiDecodeError as Error;
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Wire<'a> {
			protocol_version: ReviewProtocol,
			#[serde(borrow)]
			client_inventory_disposition_key: &'a RawValue,
			#[serde(borrow)]
			source_path: &'a RawValue,
			expected_revision: i64,
			disposition: Disposition,
			#[serde(borrow)]
			reason: Option<&'a RawValue>,
			#[serde(default)]
			mappings: LeaseList<UnitMapping, 8>,
		}
		if u.get().len() > MAX_REQUEST_BYTES {
			return Err(Error::Invalid("inventory request exceeds byte limit"));
		}
		let wire: Wire<'_> = serde_json::from_slice(u.get())?;
		// Decode within the enclosing raw cap, then apply each field's existing
		// normalization and exact-path policies to the same Worker-owned input.
		let text = |raw: &RawValue, field| {
			decode_json_string_bounded(raw.get(), field, MAX_REQUEST_BYTES, MAX_REQUEST_BYTES)
				.map(|value| value.into_owned())
		};
		let value = InventoryDispositionRequest {
			protocol_version: wire.protocol_version,
			client_inventory_disposition_key: Identifier::new(
				&mark,
				&text(wire.client_inventory_disposition_key, "client_key")?,
			)?,
			source_path: RepoPath::new(&mark, &text(wire.source_path, "source_path")?)?,
			expected_revision: wire.expected_revision,
			disposition: wire.disposition,
			reason: wire
				.reason
				.map(|raw| text(raw, "reason").and_then(|value| BoundedText::new(&mark, &value)))
				.transpose()?,
			mappings: wire.mappings,
		};
		value.validate().map_err(Error::Invalid)?;
		crate::objects_only(u.get(), value, crate::review_api::NOT_OBJECT)
	}
}
#[cfg(test)]
mod tests {
	use serde_json::json;

	use super::*;
	fn decode(
		value: serde_json::Value,
	) -> Result<InventoryDispositionRequest<Worker>, crate::review_api::ReviewApiDecodeError> {
		decode_raw(&value.to_string())
	}
	fn decode_raw(
		raw: &str,
	) -> Result<InventoryDispositionRequest<Worker>, crate::review_api::ReviewApiDecodeError> {
		crate::test_support::worker_request(raw.as_bytes())
			.validate(InventoryDispositionRequestDecoder)
	}
	fn reason(
		raw: &str,
	) -> Result<InventoryDispositionRequest<Worker>, crate::review_api::ReviewApiDecodeError> {
		let mut value = request();
		value["reason"] = json!(raw);
		decode(value)
	}
	fn request() -> serde_json::Value {
		json!({"protocol_version":3,"client_inventory_disposition_key":"entry-a","source_path":"a.rs","expected_revision":0,"disposition":"mapped","mappings":[{"review_unit_id":1,"assignment_epoch":0}]})
	}
	#[test]
	fn strict_bounds_and_variant_requirements() {
		let valid = request();
		assert!(decode(valid.clone()).is_ok());
		for (field, value) in [
			("unexpected", json!(1)),
			("protocol_version", json!(2)),
			("expected_revision", json!(-1)),
			("source_path", json!("../a")),
			("mappings", json!([])),
			(
				"mappings",
				json!([{"review_unit_id":1,"assignment_epoch":0},{"review_unit_id":1,"assignment_epoch":1}]),
			),
		] {
			let mut invalid = valid.clone();
			invalid[field] = value;
			assert!(decode(invalid).is_err(), "{field}");
		}
		for disposition in ["context", "excluded", "unresolved"] {
			let mut value = valid.clone();
			value["disposition"] = json!(disposition);
			assert!(decode(value.clone()).is_err());
			value["mappings"] = json!([]);
			assert_eq!(decode(value.clone()).is_ok(), disposition == "unresolved");
			value["reason"] = json!("intentional scope");
			assert!(decode(value).is_ok());
		}
		let mut oversized = valid.clone();
		oversized["reason"] = json!("a".repeat(501));
		assert!(decode(oversized).is_err());
		assert!(reason(&"a".repeat(500)).is_ok());
		assert!(reason(&"界".repeat(333)).is_ok());
		assert!(reason(&"界".repeat(334)).is_err());
		let mut maximum = valid.clone();
		maximum["mappings"] = json!((1..=8)
			.map(|id| json!({"review_unit_id":id,"assignment_epoch":0}))
			.collect::<Vec<_>>());
		assert!(decode(maximum).is_ok());
		let mut excess = valid.clone();
		excess["mappings"] = json!((1..=9)
			.map(|id| json!({"review_unit_id":id,"assignment_epoch":0}))
			.collect::<Vec<_>>());
		assert!(decode(excess).is_err());
		for raw in [
			valid.to_string().replace(
				"\"expected_revision\":0",
				"\"expected_revision\":0,\"expected_revision\":0",
			),
			valid
				.to_string()
				.replace("\"assignment_epoch\":0", "\"assignment_epoch\":0,\"assignment_epoch\":0"),
			valid
				.to_string()
				.replace("\"assignment_epoch\":0", "\"assignment_epoch\":9223372036854775808"),
		] {
			assert!(decode_raw(&raw).is_err());
		}
	}
	#[test]
	fn digest_covers_every_field_and_preserves_exact_path_identity() {
		let original = decode(request()).unwrap();
		for (field, value) in [
			("client_inventory_disposition_key", json!("entry-b")),
			("source_path", json!("b.rs")),
			("expected_revision", json!(1)),
			("reason", json!("why")),
			("mappings", json!([{"review_unit_id":1,"assignment_epoch":1}])),
		] {
			let mut changed = request();
			changed[field] = value;
			let changed = decode(changed).unwrap();
			assert_ne!(original.digest().unwrap(), changed.digest().unwrap(), "{field}");
		}
		let mut nfc = request();
		nfc["source_path"] = json!("é.rs");
		let nfc = decode(nfc).unwrap();
		let mut nfd = request();
		nfd["source_path"] = json!("e\u{301}.rs");
		let nfd = decode(nfd).unwrap();
		assert_ne!(nfc.digest().unwrap(), nfd.digest().unwrap());
	}
}
