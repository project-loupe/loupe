//! Marked field values. Wire/schema validation remains with each named owner.

use std::fmt;
use std::marker::PhantomData;

use loupe_provenance::{Mark, Source};
use serde::Serialize;

use crate::text::json::CheckedJson;
use crate::text::{checked, policy, AnchorPolicy, Error, IdentPolicy, JsonPolicy, TextPolicy};

/// Validated field text retaining its boundary/content source.
pub struct BoundedText<P: TextPolicy, S: Source>(String, PhantomData<(P, S)>);
/// Validated exact identifier retaining its source.
pub struct Identifier<P: IdentPolicy, S: Source>(String, PhantomData<(P, S)>);
/// Normalized identity anchor retaining its source.
pub struct Anchor<P: AnchorPolicy, S: Source>(String, PhantomData<(P, S)>);
/// Exact validated repository-relative spelling; not filesystem authorization.
pub struct RepoPath<S: Source>(String, PhantomData<S>);
/// Bounded semantic JSON retaining its source and canonical digest.
pub struct BoundedJson<P: JsonPolicy, S: Source>(CheckedJson, PhantomData<(P, S)>);

macro_rules! marked_text {
	($name:ident, $policy:ident, $check:ident) => {
		impl<P: $policy, S: Source> $name<P, S> {
			pub fn new(_mark: &Mark<'_, S>, raw: &str) -> Result<Self, Error> {
				checked::$check::<P>(raw).map(|text| Self(text, PhantomData))
			}
			pub fn expose(&self) -> &str {
				&self.0
			}
		}
		impl<P: $policy, S: Source> Clone for $name<P, S> {
			fn clone(&self) -> Self {
				Self(self.0.clone(), PhantomData)
			}
		}
		impl<P: $policy, S: Source> PartialEq for $name<P, S> {
			fn eq(&self, other: &Self) -> bool {
				self.0 == other.0
			}
		}
		impl<P: $policy, S: Source> Eq for $name<P, S> {}
		impl<P: $policy, S: Source> fmt::Debug for $name<P, S> {
			fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				write!(f, "{}<{}, {}>([redacted])", stringify!($name), P::FIELD, S::NAME)
			}
		}
		impl<P: $policy, S: Source> Serialize for $name<P, S> {
			fn serialize<T: serde::Serializer>(&self, s: T) -> Result<T::Ok, T::Error> {
				s.serialize_str(&self.0)
			}
		}
	};
}
marked_text!(BoundedText, TextPolicy, text);
marked_text!(Identifier, IdentPolicy, identifier);
marked_text!(Anchor, AnchorPolicy, anchor);

impl<S: Source> RepoPath<S> {
	pub fn new(_mark: &Mark<'_, S>, raw: &str) -> Result<Self, Error> {
		checked::path(raw).map(|text| Self(text, PhantomData))
	}
	pub fn expose(&self) -> &str {
		&self.0
	}
}
impl<S: Source> Clone for RepoPath<S> {
	fn clone(&self) -> Self {
		Self(self.0.clone(), PhantomData)
	}
}
impl<S: Source> PartialEq for RepoPath<S> {
	fn eq(&self, other: &Self) -> bool {
		self.0 == other.0
	}
}
impl<S: Source> Eq for RepoPath<S> {}
impl<S: Source> fmt::Debug for RepoPath<S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "RepoPath<{}>(len={}, [redacted])", S::NAME, self.0.len())
	}
}
impl<S: Source> Serialize for RepoPath<S> {
	fn serialize<T: serde::Serializer>(&self, s: T) -> Result<T::Ok, T::Error> {
		s.serialize_str(&self.0)
	}
}

impl<P: JsonPolicy, S: Source> BoundedJson<P, S> {
	/// Check the raw JSON cap before parsing; every string remains semantic
	/// JsonLeaf prose. Exact patches/quotes belong in their named fields.
	pub fn new(_mark: &Mark<'_, S>, raw_json: &str) -> Result<Self, Error> {
		CheckedJson::parse::<P>(raw_json).map(|data| Self(data, PhantomData))
	}
	pub fn expose(&self) -> &str {
		self.0.expose()
	}
	pub fn canonical(&self) -> &[u8] {
		self.0.canonical()
	}
	pub fn digest(&self) -> &[u8; 32] {
		self.0.digest()
	}
}
impl<P: JsonPolicy, S: Source> Clone for BoundedJson<P, S> {
	fn clone(&self) -> Self {
		Self(self.0.clone(), PhantomData)
	}
}
impl<P: JsonPolicy, S: Source> PartialEq for BoundedJson<P, S> {
	fn eq(&self, other: &Self) -> bool {
		self.0 == other.0
	}
}
impl<P: JsonPolicy, S: Source> Eq for BoundedJson<P, S> {}
impl<P: JsonPolicy, S: Source> fmt::Debug for BoundedJson<P, S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"BoundedJson<{}, {}>(len={}, [redacted])",
			P::FIELD,
			S::NAME,
			self.canonical().len()
		)
	}
}
impl<P: JsonPolicy, S: Source> Serialize for BoundedJson<P, S> {
	fn serialize<T: serde::Serializer>(&self, s: T) -> Result<T::Ok, T::Error> {
		self.0.serialize(s)
	}
}

/// A path assertion and optional semantic symbol retaining the same source.
#[derive(Serialize)]
#[serde(bound(serialize = ""))]
pub struct SourceRef<S: Source> {
	pub path: RepoPath<S>,
	pub symbol: Option<BoundedText<policy::Symbol, S>>,
}
record_impls!(SourceRef { path, symbol });
