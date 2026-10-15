//! Independent HTTP wire fixtures for compatibility checks.
//!
//! These unlabelled serde shapes construct synthetic client requests and inspect
//! actual HTTP response bytes. They never deserialize labelled production values
//! or substitute for server ingress. Runtime admission and source ownership are
//! exercised by the real server and worker. Keep the serde defaults and
//! omissions; this module is a compatibility fixture, not a production API.
#![allow(unused_imports)]
mod finding;
mod findings_admin;
mod job_io;
mod job_kind;
mod lease;
mod registry;
mod repo;
mod scan;
mod secret_serde;
mod verdict;
pub use finding::Finding;
pub use findings_admin::*;
pub use job_io::*;
pub use job_kind::JobKind;
pub use lease::*;
pub use loupe_proto::{JOB_CAPABILITY_HEADER, PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
pub use registry::*;
pub use repo::*;
pub use scan::*;
pub use verdict::*;
