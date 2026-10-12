//! Exact pre-M serde wire schema, retained only as an independent test oracle.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReportingDestination {
	GithubIssue {
		target_owner: String,
		target_repo: String,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		pat_secret_id: Option<i64>,
	},
	Email {
		to: Vec<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		from: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		subject_prefix: Option<String>,
	},
	Manual,
}
