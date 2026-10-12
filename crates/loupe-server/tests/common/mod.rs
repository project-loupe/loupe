//! Shared helpers for `loupe-server` integration tests.
//!
//! Each `tests/*.rs` is a separate binary, so this module is pulled
//! in via `mod common;` per file rather than auto-imported. The
//! helpers here aren't part of any public crate surface — they exist
//! only to dedupe what would otherwise be 9× copies of the same
//! reqwest-PEM plumbing.
//!
//! `#[allow(dead_code)]` because a given test file might use only
//! one of these — mod-level dead-code warnings fire per-binary.

#![allow(dead_code)]
#![deny(unsafe_code)]

pub mod marked;
pub mod wire;

use clap::builder::TypedValueParser;
use loupe_server::config::{ConfiguredHostname, ConfiguredPath, ConfiguredPem};

/// Feed synthetic native arguments through the real Config ingress callback.
pub fn config_path(path: impl AsRef<std::path::Path>) -> ConfiguredPath {
	loupe_server::config::PathParser
		.parse_ref(&clap::Command::new("fixture"), None, path.as_ref().as_os_str())
		.unwrap()
}

pub fn config_hostname(name: &str) -> ConfiguredHostname {
	loupe_server::config::HostnameParser
		.parse_ref(&clap::Command::new("fixture"), None, std::ffi::OsStr::new(name))
		.unwrap()
}

pub fn config_pem(pem: &str) -> ConfiguredPem {
	let argument = loupe_server::config::PemParser
		.parse_ref(&clap::Command::new("fixture"), None, std::ffi::OsStr::new(pem))
		.unwrap();
	loupe_server::config::select_tls_pem("fixture", Some(argument), None, None, "missing").unwrap()
}

/// Reporter fixtures obtain Db owners through the actual SQL reader.
pub fn reporter_repo() -> loupe_storage::repos::RepoRow {
	let db =
		loupe_storage::Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests()).unwrap();
	db.with_conn(|conn| {
		conn.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(1,'https://github.com/example/repo.git','github.com','example','repo','{\"kind\":\"github_issue\",\"target_owner\":\"example\",\"target_repo\":\"repo\"}',0)", [])?;
		Ok(loupe_storage::repos::get(conn, 1)?.unwrap())
	}).unwrap()
}

pub fn file_config(raw: &str) -> anyhow::Result<loupe_server::FileConfig> {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("config.toml");
	std::fs::write(&path, raw).unwrap();
	loupe_server::FileConfig::load(&path)
}

pub fn allowed_owners(
	owners: Option<Vec<String>>,
) -> Option<
	Vec<
		loupe_core::text::BoundedText<
			loupe_core::text::policy::RepoOwner,
			loupe_provenance::Config,
		>,
	>,
> {
	owners.map(|owners| {
		let list = serde_json::to_string(&owners).unwrap();
		file_config(&format!("[github_app]\nallowed_target_owners = {list}\n"))
			.unwrap()
			.github_app
			.allowed_target_owners
			.unwrap()
	})
}

/// Resolve and store policy through the actual campaign owner, then read Db bytes.
pub fn stored_policy(
	policy: &loupe_server::review::policy::ReviewPolicy,
) -> loupe_core::text::BoundedJson<loupe_core::text::policy::Payload, loupe_provenance::Db> {
	use loupe_server::review::campaign::{self, KindHint, OpenCampaign, Opened, RequestedRef};
	let db =
		loupe_storage::Db::open_in_memory(&loupe_storage::secrets::MasterKey::for_tests()).unwrap();
	db.with_conn(|conn| loupe_storage::transaction::immediate(conn, |tx| {
		tx.execute("INSERT INTO registered_repos(id,clone_url,host,owner,repo,reporting,created_at) VALUES(1,'u','github.com','o','r','{\"kind\":\"manual\"}',0)", [])?;
		let reference = marked::operator::text("main");
		let opened = campaign::open(tx, &OpenCampaign { repo_id: 1, trigger: loupe_storage::campaigns::Trigger::Manual, requested_ref: RequestedRef::Branch(&reference), base_sha: None, kind_hint: KindHint::Incremental }, policy, 0)?;
		let Opened::Created { campaign_id, .. } = opened else { panic!("new campaign") };
		let stored = loupe_storage::campaigns::get(tx, campaign_id)?.unwrap().effective_policy;
		let (raw, digest): (String, Vec<u8>) = tx.query_row(
			"SELECT effective_policy,effective_policy_digest FROM review_campaigns WHERE campaign_id=?1",
			[campaign_id], |row| Ok((row.get(0)?, row.get(1)?)))?;
		assert_eq!(raw.as_bytes(), stored.canonical());
		assert_eq!(digest.as_slice(), stored.digest());
		Ok(stored)
	})).unwrap()
}

/// Assert the historical canonical recipe at SQL storage and typed readback.
pub fn assert_survey_recipe(
	conn: &rusqlite::Connection, job: &loupe_storage::jobs::JobRow, recipe: &str,
) {
	let expected = format!(
		r#"{{"assignment_key":"ordinary","phase":"survey","recipe":"{recipe}","version":1}}"#
	);
	let stored = job.recipe.as_ref().expect("survey recipe");
	assert_eq!(stored.expose(), expected);
	assert_eq!(*stored.digest(), loupe_core::canonical::digest(expected.as_bytes()));
	let raw: String =
		conn.query_row("SELECT recipe FROM jobs WHERE id=?1", [job.id], |row| row.get(0)).unwrap();
	assert_eq!(raw, expected);
}

/// Wrap a CA-cert PEM in the form `reqwest::Client::builder()
/// .add_root_certificate` expects.
pub fn pem_to_certificate(pem: &str) -> reqwest::Certificate {
	reqwest::Certificate::from_pem(pem.as_bytes()).expect("parse cert PEM")
}

/// Combine an mTLS client cert + key into the single-PEM-blob form
/// `reqwest::Identity::from_pem` expects. Forces a separator newline
/// so back-to-back PEMs without trailing newlines still parse.
pub fn pem_to_identity(cert_pem: &str, key_pem: &str) -> reqwest::Identity {
	let mut combined = String::with_capacity(cert_pem.len() + key_pem.len() + 1);
	combined.push_str(cert_pem);
	if !cert_pem.ends_with('\n') {
		combined.push('\n');
	}
	combined.push_str(key_pem);
	reqwest::Identity::from_pem(combined.as_bytes()).expect("parse client identity PEM")
}
