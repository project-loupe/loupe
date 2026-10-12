//! A labelled value stays content; no ingress mint is needed to type-check
//! these parameterized bodies.
//! ```
//! use loupe_core::security_event::*;
//! use loupe_core::source_migration::text::BoundedText;
//! use loupe_core::text::policy::Title;
//! use loupe_provenance::Agent;
//! fn valid(_text: BoundedText<Title, Agent>) {
//! 	emit(SecurityEvent::FanOutLimit {
//! 		context: EventContext::default(),
//! 		attempted: 3,
//! 		limit: 2,
//! 	});
//! }
//! ```
//! ```compile_fail,E0308
//! use loupe_core::{source_migration::text::BoundedText, text::policy::Title, security_event::emit};
//! use loupe_provenance::Agent;
//! fn wrong(text: BoundedText<Title, Agent>) { emit(text); }
//! ```
//! ```compile_fail,E0308
//! use loupe_core::{source_migration::text::RepoPath, security_event::emit};
//! use loupe_provenance::Repo;
//! fn wrong(path: RepoPath<Repo>) { emit(path); }
//! ```
//! ```compile_fail,E0308
//! use loupe_core::{source_migration::text::Identifier, text::policy::Family, security_event::emit};
//! use loupe_provenance::Agent;
//! fn wrong(identity: Identifier<Family, Agent>) { emit(identity); }
//! ```
