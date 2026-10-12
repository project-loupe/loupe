//! Fixed-source fixtures for actual private server validators.
//! These entries exist only in fuzz builds and grant no runtime authority.

pub use crate::reporters::github_app::fuzz_access_token as reporter_token;
pub use crate::reporters::ingress_fuzz::{
	app as reporter_app, installation as reporter_installation, issue as reporter_issue,
	label as reporter_label,
};
