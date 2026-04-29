//! `loupe-worker` library surface.
//!
//! The runner loop, scanner registry, and reqwest-based daemon client
//! land in subsequent commits. This commit ships only the LRU bare-clone
//! cache that sits underneath everything else.

pub mod repo_cache;
