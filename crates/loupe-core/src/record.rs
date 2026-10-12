// Payload traits must not impose incidental Clone/Eq/Debug bounds on Source.
macro_rules! record_impls {
	($name:ident { $($field:ident),+ $(,)? }) => {
		record_impls!(@fields $name { $($field),+ });
		impl<S: loupe_provenance::Source> std::fmt::Debug for $name<S> {
			fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				write!(f, "{}<{}>([redacted])", stringify!($name), S::NAME)
			}
		}
	};
	(@fields $name:ident { $($field:ident),+ $(,)? }) => {
		impl<S: loupe_provenance::Source> Clone for $name<S> {
			fn clone(&self) -> Self { Self { $($field: self.$field.clone()),+ } }
		}
		impl<S: loupe_provenance::Source> PartialEq for $name<S> {
			fn eq(&self, other: &Self) -> bool { true $(&& self.$field == other.$field)+ }
		}
		impl<S: loupe_provenance::Source> Eq for $name<S> {}
	};
}
