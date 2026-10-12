//! Typed JSON references preserve Git path bytes rather than NFC-normalizing them.
use loupe_core::text::{Error, Rule, SourceRef};
use loupe_provenance::{Mark, Source};

pub struct SourceRefs<const MAX: usize, S: Source> {
	refs: Vec<SourceRef<S>>,
	canonical: String,
}
pub type UnitRefs<S> = SourceRefs<32, S>;
pub type InspectedRefs<S> = SourceRefs<64, S>;

/// Original-column fixture for the actual private Db-to-Agent decoder.
#[cfg(fuzzing)]
pub fn fuzz_decode<const MAX: usize>(
	raw: &[u8],
) -> Result<SourceRefs<MAX, loupe_provenance::Agent>, Error> {
	crate::ingress::fuzz_source_refs(raw)
}
impl<const MAX: usize, S: Source> Clone for SourceRefs<MAX, S> {
	fn clone(&self) -> Self {
		Self { refs: self.refs.clone(), canonical: self.canonical.clone() }
	}
}
impl<const MAX: usize, S: Source> PartialEq for SourceRefs<MAX, S> {
	fn eq(&self, other: &Self) -> bool {
		self.refs == other.refs && self.canonical == other.canonical
	}
}
impl<const MAX: usize, S: Source> Eq for SourceRefs<MAX, S> {}
impl<const MAX: usize, S: Source> std::fmt::Debug for SourceRefs<MAX, S> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "SourceRefs(count={})", self.refs.len())
	}
}
impl<const MAX: usize, S: Source> SourceRefs<MAX, S> {
	pub fn new(_: &Mark<'_, S>, refs: Vec<SourceRef<S>>) -> Result<Self, Error> {
		if refs.len() > MAX {
			return Err(Error::new("source_refs", Rule::JsonNodes));
		}
		let value =
			serde_json::to_value(&refs).map_err(|_| Error::new("source_refs", Rule::JsonSyntax))?;
		let bytes = crate::canonical::canonical_bytes(&value);
		if bytes.len() > 65536 {
			return Err(Error::new("source_refs", Rule::Bytes));
		}
		let canonical = String::from_utf8(bytes).expect("JSON is UTF-8");
		Ok(Self { refs, canonical })
	}
	pub fn expose(&self) -> &str {
		&self.canonical
	}
	pub fn as_slice(&self) -> &[SourceRef<S>] {
		&self.refs
	}
}
