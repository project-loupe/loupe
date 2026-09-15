//! Project-independent identity bytes; database uniqueness supplies scope.

use loupe_core::text::policy::{AnchorText, Family, InstanceKey};
use loupe_core::text::{Anchor, Identifier};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
	pub family: Identifier<Family>,
	pub anchor: Anchor<AnchorText>,
	pub instance: Option<Anchor<InstanceKey>>,
}
impl Identity {
	pub fn fingerprint(&self) -> [u8; 32] {
		fingerprint(&self.family, &self.anchor, self.instance.as_ref())
	}
}

pub fn fingerprint(
	family: &Identifier<Family>, anchor: &Anchor<AnchorText>,
	instance: Option<&Anchor<InstanceKey>>,
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
		let family = Identifier::<Family>::new("auth-bypass").unwrap();
		let anchor = Anchor::<AnchorText>::new("Token Refresh").unwrap();
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
		let instance = Anchor::<InstanceKey>::new("admin endpoint").unwrap();
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
		let family = Identifier::<Family>::new("auth-bypass").unwrap();
		let expected = fingerprint(&family, &Anchor::new("café handler").unwrap(), None);
		for raw in [" CAFÉ   Handler ", "cafe\u{301} handler", "café\u{a0}handler"] {
			assert_eq!(fingerprint(&family, &Anchor::new(raw).unwrap(), None), expected);
		}
		assert_ne!(
			fingerprint(
				&Identifier::new("other-family").unwrap(),
				&Anchor::new("café handler").unwrap(),
				None
			),
			expected
		);
		for bad in ["file.rs:123", "commit 79dec41", "job_9", "campaign 42"] {
			assert!(Anchor::<AnchorText>::new(bad).is_err());
		}
	}
}
