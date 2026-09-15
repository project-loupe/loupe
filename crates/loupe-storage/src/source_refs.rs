//! Typed JSON references preserve Git path bytes rather than NFC-normalizing them.
use loupe_core::text::{Error, Rule, SourceRef};

#[derive(Clone, PartialEq, Eq)]
pub struct SourceRefs<const MAX: usize> {
	refs: Vec<SourceRef>,
	canonical: String,
}
pub type UnitRefs = SourceRefs<32>;
pub type InspectedRefs = SourceRefs<64>;
impl<const MAX: usize> std::fmt::Debug for SourceRefs<MAX> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "SourceRefs(count={})", self.refs.len())
	}
}
impl<const MAX: usize> SourceRefs<MAX> {
	pub fn new(refs: Vec<SourceRef>) -> Result<Self, Error> {
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
	pub fn as_slice(&self) -> &[SourceRef] {
		&self.refs
	}
}
impl<const MAX: usize> std::str::FromStr for SourceRefs<MAX> {
	type Err = Error;
	fn from_str(raw: &str) -> Result<Self, Error> {
		if raw.len() > 65536 {
			return Err(Error::new("source_refs", Rule::Bytes));
		}
		let refs =
			serde_json::from_str(raw).map_err(|_| Error::new("source_refs", Rule::JsonSyntax))?;
		Self::new(refs)
	}
}
