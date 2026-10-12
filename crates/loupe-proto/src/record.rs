// Wire records own payloads; source marker types need no incidental traits.
macro_rules! record_impls {
	($name:ident<$($source:ident),+> { $($field:ident),+ $(,)? }) => {
		impl<$($source: loupe_provenance::Source),+> Clone for $name<$($source),+> {
			fn clone(&self) -> Self { Self { $($field: self.$field.clone()),+ } }
		}
		impl<$($source: loupe_provenance::Source),+> PartialEq for $name<$($source),+> {
			fn eq(&self, other: &Self) -> bool { true $(&& self.$field == other.$field)+ }
		}
		impl<$($source: loupe_provenance::Source),+> Eq for $name<$($source),+> {}
		impl<$($source: loupe_provenance::Source),+> std::fmt::Debug for $name<$($source),+> {
			fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				f.debug_struct(stringify!($name))
					$(.field(stringify!($source), &$source::NAME))+
					.field("content", &"[redacted]").finish()
			}
		}
	};
}
