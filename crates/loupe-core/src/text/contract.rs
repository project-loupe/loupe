//! Source-retaining field API fences. Protocol and storage owners provide
//! named validators; these types have no general Deserialize or raw decoder.
//!
//! Construction requires a mark of the actual source:
//! ```compile_fail,E0061
//! use loupe_core::{text::BoundedText, text::policy::Title};
//! use loupe_provenance::Agent;
//! let value = BoundedText::<Title, Agent>::new("text");
//! ```
//! ```compile_fail,E0308
//! use loupe_core::{text::BoundedText, text::policy::Title};
//! use loupe_provenance::{Agent, Repo, Mark};
//! fn wrong(mark: &Mark<'_, Repo>) {
//!     let _ = BoundedText::<Title, Agent>::new(mark, "text");
//! }
//! ```
//! ```compile_fail,E0107
//! use loupe_core::{text::BoundedText, text::policy::Title};
//! fn missing_source(_: BoundedText<Title>) {}
//! ```
//! ```compile_fail,E0277
//! use loupe_core::{text::BoundedText, text::policy::Title};
//! use loupe_provenance::Unlabelled;
//! fn erased(_: BoundedText<Title, Unlabelled>) {}
//! ```
//! ```compile_fail,E0599
//! use loupe_core::{text::BoundedText, text::policy::Title};
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
//! use loupe_core::{text::BoundedText, text::policy::Title};
//! use loupe_provenance::Agent;
//! let _: BoundedText<Title, Agent> = "text".parse().unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::{text::BoundedText, text::policy::Title};
//! use loupe_provenance::Agent;
//! let _: BoundedText<Title, Agent> = String::from("text").try_into().unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::{text::BoundedText, text::policy::Title};
//! use loupe_provenance::Agent;
//! let _: BoundedText<Title, Agent> = String::from("text").into();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::{text::BoundedText, text::policy::Title};
//! use loupe_provenance::Agent;
//! let _: BoundedText<Title, Agent> = serde_json::from_str("\"text\"").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::{text::BoundedJson, text::policy::Payload};
//! use loupe_provenance::Agent;
//! let _: BoundedJson<Payload, Agent> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::text::SourceRef;
//! use loupe_provenance::Agent;
//! let _: SourceRef<Agent> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::text::RepoPath;
//! use loupe_provenance::Repo;
//! let _: RepoPath<Repo> = serde_json::from_str("\"x.rs\"").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::{text::Identifier, text::policy::Family};
//! use loupe_provenance::Agent;
//! let _: Identifier<Family, Agent> = serde_json::from_str("\"auth-bypass\"").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::{text::Anchor, text::policy::AnchorText};
//! use loupe_provenance::Agent;
//! let _: Anchor<AnchorText, Agent> = serde_json::from_str("\"token refresh\"").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::Finding;
//! use loupe_provenance::Agent;
//! let _: Finding<Agent> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::Verdict;
//! use loupe_provenance::Agent;
//! let _: Verdict<Agent> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::RepoSpec;
//! use loupe_provenance::Agent;
//! let _: RepoSpec<Agent> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::ReportingDestination;
//! use loupe_provenance::Config;
//! let _: ReportingDestination<Config> = serde_json::from_str("{}").unwrap();
//! ```
//! ```compile_fail,E0277
//! use loupe_core::VerdictPatch;
//! use loupe_provenance::Agent;
//! let _: VerdictPatch<Agent> = serde_json::from_str("{}").unwrap();
//! ```
//! Sources cannot be converted, even when their validated payloads match:
//! ```compile_fail,E0308
//! use loupe_core::Finding;
//! use loupe_provenance::{Agent, Repo};
//! fn change(value: Finding<Repo>) -> Finding<Agent> { value }
//! ```
//! ```compile_fail,E0308
//! use loupe_core::{text::BoundedText, text::policy::Title};
//! use loupe_provenance::{Agent, Db};
//! fn change(value: BoundedText<Title, Db>) -> BoundedText<Title, Agent> { value }
//! ```
//! Exposure remains deliberate, never an implicit formatting/deref operation:
//! ```compile_fail,E0277
//! use loupe_core::{text::BoundedText, text::policy::Title};
//! use loupe_provenance::Agent;
//! fn print(value: BoundedText<Title, Agent>) { let _ = format!("{value}"); }
//! ```
//! ```compile_fail,E0614
//! use loupe_core::text::RepoPath;
//! use loupe_provenance::Repo;
//! fn read(value: RepoPath<Repo>) { let _: &str = &*value; }
//! ```
