//! Temporary opt-in API for atomic source adoption.
//!
//! These types retain their source and require a validation mark. The default
//! public API stays unlabelled during ingress preparation. At atomic adoption,
//! remove that legacy API, this feature/namespace and all transitional exits;
//! move these implementations to the final names. There is no conversion from
//! the legacy wrappers. Protocol and storage owners provide named validators;
//! this module provides neither general Deserialize nor an arbitrary decoder.
//!
//! Construction requires a mark of the actual source:
//! ```compile_fail,E0061
//! use loupe_core::{source_migration::text::BoundedText, text::policy::Title};
//! use loupe_provenance::Agent;
//! let value = BoundedText::<Title, Agent>::new("text");
//! ```
//! ```compile_fail,E0308
//! use loupe_core::{source_migration::text::BoundedText, text::policy::Title};
//! use loupe_provenance::{Agent, Repo, Mark};
//! fn wrong(mark: &Mark<'_, Repo>) {
//!     let _ = BoundedText::<Title, Agent>::new(mark, "text");
//! }
//! ```
//! ```compile_fail,E0107
//! use loupe_core::{source_migration::text::BoundedText, text::policy::Title};
//! fn missing_source(_: BoundedText<Title>) {}
//! ```
//! ```compile_fail,E0277
//! use loupe_core::{source_migration::text::BoundedText, text::policy::Title};
//! use loupe_provenance::Unlabelled;
//! fn erased(_: BoundedText<Title, Unlabelled>) {}
//! ```
//! ```compile_fail,E0599
//! use loupe_core::{source_migration::text::BoundedText, text::policy::Title};
//! use loupe_provenance::Agent;
//! let _ = BoundedText::<Title, Agent>::default();
//! ```
//! A mark cannot be forged or retained for later construction:
//! ```compile_fail,E0624
//! use loupe_provenance::{Agent, Mark};
//! let _ = Mark::<Agent>::new(&());
//! ```
//! ```compile_fail
//! use loupe_provenance::{Agent, Mark, Unvalidated, Validate};
//! struct Escape;
//! impl Validate<&'static str, Agent> for Escape {
//!     type Output = Mark<'static, Agent>;
//!     type Error = ();
//!     fn validate<'view>(self, _: Unvalidated<'view, &'static str>, mark: Mark<'view, Agent>)
//!         -> Result<Self::Output, ()> { Ok(mark) }
//! }
//! ```
//! No string parser, serde entry point, or legacy conversion supplies a mark:
//! ```compile_fail,E0277
//! use loupe_core::{source_migration::text::BoundedText, text::policy::Title};
//! use loupe_provenance::Agent;
//! let _: BoundedText<Title, Agent> = "text".parse().unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::{source_migration::text::BoundedText, text::policy::Title};
//! use loupe_provenance::Agent;
//! let _: BoundedText<Title, Agent> = String::from("text").try_into().unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::{source_migration::text::BoundedText, text::policy::Title};
//! use loupe_provenance::Agent;
//! let legacy = loupe_core::text::BoundedText::<Title>::new("text").unwrap();
//! let _: BoundedText<Title, Agent> = legacy.into();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::{source_migration::text::BoundedText, text::policy::Title};
//! use loupe_provenance::Agent;
//! let _: BoundedText<Title, Agent> = serde_json::from_str("\"text\"").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::{source_migration::text::BoundedJson, text::policy::Payload};
//! use loupe_provenance::Agent;
//! let _: BoundedJson<Payload, Agent> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::source_migration::text::SourceRef;
//! use loupe_provenance::Agent;
//! let _: SourceRef<Agent> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::source_migration::text::RepoPath;
//! use loupe_provenance::Repo;
//! let _: RepoPath<Repo> = serde_json::from_str("\"x.rs\"").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::{source_migration::text::Identifier, text::policy::Family};
//! use loupe_provenance::Agent;
//! let _: Identifier<Family, Agent> = serde_json::from_str("\"auth-bypass\"").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::{source_migration::text::Anchor, text::policy::AnchorText};
//! use loupe_provenance::Agent;
//! let _: Anchor<AnchorText, Agent> = serde_json::from_str("\"token refresh\"").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::source_migration::Finding;
//! use loupe_provenance::Agent;
//! let _: Finding<Agent> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::source_migration::Verdict;
//! use loupe_provenance::Agent;
//! let _: Verdict<Agent> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::source_migration::RepoSpec;
//! use loupe_provenance::Agent;
//! let _: RepoSpec<Agent> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::source_migration::ReportingDestination;
//! use loupe_provenance::Config;
//! let _: ReportingDestination<Config> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::source_migration::VerdictPatch;
//! use loupe_provenance::Agent;
//! let _: VerdictPatch<Agent> = serde_json::from_str("{}").unwrap();
//! ```
//! Sources cannot be converted, even when their validated payloads match:
//! ```compile_fail,E0308
//! use loupe_core::source_migration::Finding;
//! use loupe_provenance::{Agent, Repo};
//! fn change(value: Finding<Repo>) -> Finding<Agent> { value }
//! ```
//! ```compile_fail,E0308
//! use loupe_core::{source_migration::text::BoundedText, text::policy::Title};
//! use loupe_provenance::{Agent, Db};
//! fn change(value: BoundedText<Title, Db>) -> BoundedText<Title, Agent> { value }
//! ```
//! Exposure remains deliberate, never an implicit formatting/deref operation:
//! ```compile_fail,E0277
//! use loupe_core::{source_migration::text::BoundedText, text::policy::Title};
//! use loupe_provenance::Agent;
//! fn print(value: BoundedText<Title, Agent>) { let _ = format!("{value}"); }
//! ```
//! ```compile_fail,E0614
//! use loupe_core::source_migration::text::RepoPath;
//! use loupe_provenance::Repo;
//! fn read(value: RepoPath<Repo>) { let _: &str = &*value; }
//! ```

// Payload traits must not impose incidental Clone/Eq/Debug bounds on Source.
macro_rules! record_impls {
	($name:ident { $($field:ident),+ $(,)? }) => {
		impl<S: loupe_provenance::Source> Clone for $name<S> {
			fn clone(&self) -> Self { Self { $($field: self.$field.clone()),+ } }
		}
		impl<S: loupe_provenance::Source> PartialEq for $name<S> {
			fn eq(&self, other: &Self) -> bool { true $(&& self.$field == other.$field)+ }
		}
		impl<S: loupe_provenance::Source> Eq for $name<S> {}
		impl<S: loupe_provenance::Source> std::fmt::Debug for $name<S> {
			fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				write!(f, "{}<{}>([redacted])", stringify!($name), S::NAME)
			}
		}
	};
}

mod finding;
mod repo;
pub mod text;
mod verdict;

pub use finding::Finding;
pub use repo::{RepoSpec, ReportingDestination};
pub use verdict::{Verdict, VerdictPatch};
