//! Project-independent identity bytes; database uniqueness supplies scope.

use loupe_core::text::policy::{AnchorText, Family, InstanceKey};
use loupe_core::text::{Anchor, Identifier};
use loupe_provenance::Source;

// debug-ok: content members delegate to redacted typed owners; other members are numeric identifiers or closed states.
#[derive(Debug)]
pub struct Identity<S: Source> {
	pub family: Identifier<Family, S>,
	pub anchor: Anchor<AnchorText, S>,
	pub instance: Option<Anchor<InstanceKey, S>>,
}
impl<S: Source> Clone for Identity<S> {
	fn clone(&self) -> Self {
		Self {
			family: self.family.clone(),
			anchor: self.anchor.clone(),
			instance: self.instance.clone(),
		}
	}
}
impl<S: Source> PartialEq for Identity<S> {
	fn eq(&self, other: &Self) -> bool {
		self.family == other.family
			&& self.anchor == other.anchor
			&& self.instance == other.instance
	}
}
impl<S: Source> Eq for Identity<S> {}
impl<S: Source> Identity<S> {
	pub fn fingerprint(&self) -> [u8; 32] {
		fingerprint(&self.family, &self.anchor, self.instance.as_ref())
	}
}

pub fn fingerprint<S: Source>(
	family: &Identifier<Family, S>, anchor: &Anchor<AnchorText, S>,
	instance: Option<&Anchor<InstanceKey, S>>,
) -> [u8; 32] {
	let bytes = [
		"lead-identity-v1\0",
		family.expose(),
		"\0",
		anchor.expose(),
		"\0",
		instance.map(Anchor::expose).unwrap_or(""),
	]
	.concat();
	crate::canonical::digest(bytes.as_bytes())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn fingerprint_pins_the_versioned_identity_encoding() {
		let family = crate::test_support::identifier::<Family>("auth-bypass").unwrap();
		let anchor = crate::test_support::anchor::<AnchorText>("Token Refresh").unwrap();
		let expected = crate::canonical::digest(b"lead-identity-v1\0auth-bypass\0token refresh\0");
		assert_eq!(
			expected,
			[
				200, 138, 139, 45, 61, 99, 26, 68, 199, 207, 16, 236, 107, 7, 89, 158, 212, 56,
				225, 139, 202, 4, 47, 56, 66, 57, 189, 49, 106, 78, 231, 133
			]
		);
		assert_eq!(
			fingerprint(&family, &anchor, None),
			expected,
			"identity framing must include its version and empty-instance separator"
		);
		let instance = crate::test_support::anchor::<InstanceKey>("admin endpoint").unwrap();
		assert_ne!(fingerprint(&family, &anchor, Some(&instance)), expected);
		assert_eq!(
			fingerprint(&family, &anchor, Some(&instance)),
			crate::canonical::digest(
				b"lead-identity-v1\0auth-bypass\0token refresh\0admin endpoint"
			)
		);
	}

	#[test]
	fn fingerprint_normalization_and_domain_separation() {
		let family = crate::test_support::identifier::<Family>("auth-bypass").unwrap();
		let expected =
			fingerprint(&family, &crate::test_support::anchor("café handler").unwrap(), None);
		for raw in [" CAFÉ   Handler ", "cafe\u{301} handler", "café\u{a0}handler"] {
			assert_eq!(
				fingerprint(&family, &crate::test_support::anchor(raw).unwrap(), None),
				expected
			);
		}
		assert_ne!(
			fingerprint(
				&crate::test_support::identifier("other-family").unwrap(),
				&crate::test_support::anchor("café handler").unwrap(),
				None
			),
			expected
		);
		for bad in ["file.rs:123", "commit 79dec41", "job_9", "campaign 42"] {
			assert!(crate::test_support::anchor::<AnchorText>(bad).is_err());
		}
	}
}
