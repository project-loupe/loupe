//! Actual DAO admission and diagnostic regression guards for SQL ingress.
#[test]
fn actual_job_error_does_not_reflect_sql_text() {
	let (db, _) = seeded();
	db.with_conn(|c| {
		c.pragma_update(None, "ignore_check_constraints", true)?;
		c.execute("UPDATE jobs SET state=?1", [CANARY])?;
		private_error(jobs::get(c, 1).unwrap_err());
		Ok(())
	})
	.unwrap();
}
#[test]
fn actual_reporting_count_error_does_not_reflect_sql_text() {
	let (db, _) = seeded();
	db.with_conn(|c| {
		c.execute(
			"UPDATE registered_repos SET reporting=?1",
			[format!(r#"{{"kind":"{CANARY}"}}"#)],
		)?;
		private_error(repos::count_github_pat_references(c, 1).unwrap_err());
		Ok(())
	})
	.unwrap();
}

#[test]
fn actual_finding_cap_admission() {
	let (db, id) = seeded();
	let _ = id;
	db.with_conn(|c| {
		c.execute("UPDATE findings SET title=?1", ["x".repeat(CAP + 1)])?;
		assert!(findings::get(c, id).is_err(), "invalid finding_cap accepted");
		Ok(())
	})
	.unwrap();
}

#[test]
fn actual_finding_cr_admission() {
	let (db, id) = seeded();
	let _ = id;
	db.with_conn(|c| {
		c.execute("UPDATE findings SET title=?1", ["bad\rtitle".to_owned()])?;
		assert!(findings::get(c, id).is_err(), "invalid finding_cr accepted");
		Ok(())
	})
	.unwrap();
}

#[test]
fn actual_finding_path_admission() {
	let (db, id) = seeded();
	let _ = id;
	db.with_conn(|c| {
		c.execute("UPDATE findings SET file_path=?1", ["x".repeat(513)])?;
		assert!(findings::get(c, id).is_err(), "invalid finding_path accepted");
		Ok(())
	})
	.unwrap();
}

#[test]
fn actual_worker_name_admission() {
	let (db, id) = seeded();
	let _ = id;
	db.with_conn(|c| {
		c.execute("UPDATE workers SET name=?1", ["bad\0name".to_owned()])?;
		assert!(
			workers::find_active_by_fingerprint(c, &[1]).is_err(),
			"invalid worker_name accepted"
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn actual_job_revision_admission() {
	let (db, id) = seeded();
	let _ = id;
	db.with_conn(|c| {
		c.execute("UPDATE jobs SET head_sha=?1", ["bad\nrevision".to_owned()])?;
		assert!(jobs::get(c, 1).is_err(), "invalid job_revision accepted");
		Ok(())
	})
	.unwrap();
}

#[test]
fn actual_generation_revision_admission() {
	let (db, id) = seeded();
	let _ = id;
	db.with_conn(|c| {
		c.execute(
			"UPDATE review_generations SET generation_commit_sha=?1",
			["bad\nrevision".to_owned()],
		)?;
		assert!(
			loupe_storage::generations::get(c, 11).is_err(),
			"invalid generation_revision accepted"
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn actual_app_summary_slug_admission() {
	let (db, _) = seeded();
	db.with_conn(|c| {
		github_app::set(
			c,
			&github_app::StoredGithubApp {
				app_id: 7,
				slug: "bad\nslug".into(),
				private_key_pem: loupe_provenance::Secret::new("fake-private-key".into()),
			},
			0,
		)?;
		assert!(github_app::summary(c).is_err(), "invalid summary slug accepted");
		Ok(())
	})
	.unwrap();
}
#[path = "support/db.rs"]
mod fixture;

use loupe_storage::secrets::MasterKey;
use loupe_storage::{findings, github_app, jobs, repos, workers, Db};

const CANARY: &str = "SQL_PRIVATE_CANARY_493";
const CAP: usize = 2 * 1024 * 1024;

fn seeded() -> (Db, i64) {
	let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
	let id = fixture::seed(&db, &fixture::finding(), "[]");
	db.with_conn(|c| {
        c.execute("INSERT INTO workers (name,kind,cert_fingerprint,created_at) VALUES ('worker','worker',X'01',0)", [])?;
        Ok(())
    }).unwrap();
	(db, id)
}

fn private_error(error: impl std::error::Error) {
	let rendered = format!("{error} {error:?}");
	assert!(!rendered.contains(CANARY), "stored text reflected in error: {rendered}");
	let mut source = error.source();
	while let Some(error) = source {
		assert!(
			!format!("{error} {error:?}").contains(CANARY),
			"stored text reflected in error chain"
		);
		source = error.source();
	}
}

#[test]
fn actual_reporting_conversion_errors_do_not_reflect_sql_text() {
	let (db, _) = seeded();
	db.with_conn(|c| {
		c.execute(
			"UPDATE registered_repos SET reporting=?1",
			[format!(r#"{{"kind":"{CANARY}"}}"#)],
		)?;
		private_error(repos::get(c, 1).unwrap_err());
		private_error(repos::count_github_pat_references(c, 1).unwrap_err());
		Ok(())
	})
	.unwrap();
}

#[test]
fn actual_worker_conversion_errors_do_not_reflect_sql_text() {
	let (db, _) = seeded();
	db.with_conn(|c| {
		c.pragma_update(None, "ignore_check_constraints", true)?;
		c.execute("UPDATE workers SET kind=?1", [CANARY])?;
		private_error(workers::find_active_by_fingerprint(c, &[1]).unwrap_err());
		Ok(())
	})
	.unwrap();
}

#[test]
fn actual_finding_and_job_enum_errors_do_not_reflect_sql_text() {
	let (db, id) = seeded();
	db.with_conn(|c| {
		c.pragma_update(None, "ignore_check_constraints", true)?;
		c.execute("UPDATE findings SET severity=?1", [CANARY])?;
		private_error(findings::get(c, id).unwrap_err());
		c.execute("UPDATE jobs SET state=?1", [CANARY])?;
		private_error(jobs::get(c, 1).unwrap_err());
		Ok(())
	})
	.unwrap();
}

#[test]
fn actual_finding_admits_exact_text_but_rejects_controls_caps_and_invalid_paths() {
	let (db, id) = seeded();
	db.with_conn(|c| {
		for title in [String::new(), "cafe\u{301}  ".into(), "x".repeat(CAP)] {
			c.execute("UPDATE findings SET title=?1", [&title])?;
			assert_eq!(findings::get(c, id)?.unwrap().title, title);
		}
		for title in ["bad\0title".into(), "bad\rtitle".into(), "x".repeat(CAP + 1)] {
			c.execute("UPDATE findings SET title=?1", [&title])?;
			assert!(findings::get(c, id).is_err(), "invalid stored finding title accepted");
			let unchanged: String = c.query_row("SELECT title FROM findings", [], |r| r.get(0))?;
			assert_eq!(unchanged, title);
		}
		c.execute("UPDATE findings SET title='ok',file_path=?1", ["x".repeat(513)])?;
		assert!(findings::get(c, id).is_err(), "invalid stored finding path accepted");
		Ok(())
	})
	.unwrap();
}

#[test]
fn actual_metadata_reads_reject_invalid_text() {
	let (db, _) = seeded();
	db.with_conn(|c| {
		c.execute("UPDATE registered_repos SET clone_url=?1", ["bad\nurl"])?;
		assert!(repos::get(c, 1).is_err(), "invalid stored repo URL accepted");
		c.execute("UPDATE workers SET name=?1", ["bad\0name"])?;
		assert!(
			workers::find_active_by_fingerprint(c, &[1]).is_err(),
			"invalid stored worker name accepted"
		);
		c.execute("UPDATE jobs SET head_sha=?1", ["bad\nrevision"])?;
		assert!(jobs::get(c, 1).is_err(), "invalid stored job revision accepted");
		c.execute("UPDATE review_generations SET generation_commit_sha=?1", ["bad\nrevision"])?;
		assert!(
			loupe_storage::generations::get(c, 11).is_err(),
			"invalid generation revision accepted"
		);
		Ok(())
	})
	.unwrap();
}

#[test]
fn actual_app_reads_reject_invalid_slug_without_changing_pem_owner() {
	let (db, _) = seeded();
	db.with_conn(|c| {
		github_app::set(
			c,
			&github_app::StoredGithubApp {
				app_id: 7,
				slug: "bad\nslug".into(),
				private_key_pem: loupe_provenance::Secret::new("fake-private-key".into()),
			},
			0,
		)?;
		assert!(github_app::get(c).is_err(), "invalid stored app slug accepted");
		assert!(github_app::summary(c).is_err(), "invalid summary slug accepted");
		Ok(())
	})
	.unwrap();
}

#[test]
fn compatibility_reopen_exact_fields_unknown_job_kind_and_scanner_fallback() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("data.sqlite");
	let key = MasterKey::for_tests();
	let db = Db::open(&path, &key).unwrap();
	let mut original = fixture::finding();
	original.description = "cafe\u{301}\r\n\t  \n\n\n".into();
	original.patch_unified = Some(String::new());
	let id = fixture::seed(&db, &original, "[]");
	db.with_conn(|c| {
		c.execute("UPDATE registered_repos SET scanner_config='invalid json'", [])?;
		c.execute("UPDATE jobs SET head_sha='base'", [])?;
		c.execute("UPDATE findings SET approved_by_cn='same'", [])?;
		Ok(())
	})
	.unwrap();
	drop(db);
	let db = Db::open(&path, &key).unwrap();
	db.with_conn(|c| {
        assert_eq!(findings::get(c, id)?.unwrap().into_finding(), original);
        assert_eq!(jobs::get(c, 1)?.unwrap().head_sha.as_deref(), Some("base"));
        assert_eq!(repos::get(c, 1)?.unwrap().scanner_config, serde_json::Value::Null);
        c.pragma_update(None, "foreign_keys", false)?;
        c.execute("UPDATE jobs SET kind='future-job'", [])?;
        assert!(matches!(jobs::get(c, 1)?.unwrap().kind, loupe_core::JobKind::Unknown(ref name) if name == "future-job"));
        Ok(())
    }).unwrap();
}

#[test]
fn compatibility_reporting_preserves_original_serde_schema_rules() {
	let (db, _) = seeded();
	for raw in [
		r#"{"kind":"manual","unknown":{"valid":"\uD83D\uDE00"}}"#,
		r#"{"to":["same","same"],"kind":"email","subject_prefix":"","from":null}"#,
		r#"{"target_owner":"a","target_repo":"b","kind":"github_issue"}"#,
		r#"{"kind":{"manual":null}}"#,
		r#"{"kind":"manual","kind":"manual"}"#,
		r#"{"kind":"manual","unknown":"\uD800"}"#,
		r#"{"kind":"email","to":null}"#,
		r#"["manual"]"#,
	] {
		let expected = serde_json::from_str::<loupe_core::ReportingDestination>(raw);
		db.with_conn(|c| {
			c.execute("UPDATE registered_repos SET reporting=?1", [raw])?;
			let actual = repos::get(c, 1);
			assert_eq!(actual.is_ok(), expected.is_ok(), "schema mismatch for {raw}");
			if let (Ok(row), Ok(expected)) = (actual, expected.as_ref()) {
				assert_eq!(
					serde_json::to_value(row.unwrap().reporting).unwrap(),
					serde_json::to_value(expected).unwrap()
				);
			}
			Ok(())
		})
		.unwrap();
	}
}

#[test]
fn actual_startup_unknown_kind_error_retains_only_count() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("startup.sqlite");
	let key = MasterKey::for_tests();
	let db = Db::open(&path, &key).unwrap();
	fixture::seed(&db, &fixture::finding(), "[]");
	db.with_conn(|c| {
		c.pragma_update(None, "foreign_keys", false)?;
		c.execute("UPDATE jobs SET kind=?1", [CANARY])?;
		Ok(())
	})
	.unwrap();
	drop(db);
	let error = match Db::open(&path, &key) {
		Err(e) => e,
		Ok(_) => panic!("unknown kind accepted at startup"),
	};
	private_error(error);
}

#[test]
fn compatibility_reporting_all_variants_sequences_and_ignored_content() {
	let (db, _) = seeded();
	let cases = [
		r#"["manual"]"#,
		r#"["manual",null]"#,
		r#"["manual",{}]"#,
		r#"["github_issue","same","same"]"#,
		r#"["github_issue","same","same",null]"#,
		r#"["github_issue","same","same",2]"#,
		r#"["github_issue","same","same",2,3]"#,
		r#"["email",["same","same"]]"#,
		r#"["email",["same"],null,""]"#,
		r#"["email",[],"from","subject",1]"#,
		r#"[{"manual":null}]"#,
		r#"{"kind":{"manual":null}}"#,
		r#"{"target_owner":"same","target_repo":"same","kind":"github_issue","pat_secret_id":null}"#,
		r#"{"kind":"github_issue","target_owner":"a","target_owner":"b","target_repo":"r"}"#,
		r#"{"kind":"github_issue","target_owner":"a","target_repo":"r","from":null,"from":0}"#,
		r#"{"kind":"email","to":[],"from":null,"from":null}"#,
		r#"{"kind":"email","to":["cafe\u0301","\uD83D\uDE00","a\"\\b"]}"#,
		r#"{"kind":"manual","unknown":{"x":1e999}}"#,
		r#"{"kind":"manual","unknown":{"x":"\uD800"}}"#,
		r#"{"kind":"manual","unknown":{"x":1,"x":2}}"#,
		r#"{"kind":"email","to":[null]}"#,
	];
	for raw in cases {
		let expected = serde_json::from_str::<loupe_core::ReportingDestination>(raw);
		db.with_conn(|c| {
			c.execute("UPDATE registered_repos SET reporting=?1", [raw])?;
			let actual = repos::get(c, 1);
			assert_eq!(actual.is_ok(), expected.is_ok(), "reporting compatibility: {raw}");
			if let (Ok(row), Ok(expected)) = (actual, &expected) {
				assert_eq!(row.unwrap().reporting, *expected);
			}
			Ok(())
		})
		.unwrap();
	}
}

#[test]
fn compatibility_actual_reference_reads_match_existing_schema_and_canonical_bytes() {
	let (db, _) = seeded();
	let cases = [
		r#"[{"path":"a","symbol":null,"symbol":null}]"#.into(),
		r#"[{"path":"a","path":"a"}]"#.into(),
		r#"[{"path":"a","unknown":"x"}]"#.into(),
		r#"[{"path":"\uD800"}]"#.into(),
		r#"[["src/cafe\u0301.rs","Cafe\u0301"]]"#.into(),
		r#"[["src/x.rs"]]"#.into(),
		r#"[{"symbol":"same","path":"same"},{"path":"same","symbol":"same"}]"#.into(),
		format!("[{}]", vec![r#"{"path":"a"}"#; 33].join(",")),
		format!("[]{}", " ".repeat(65535)),
	];
	for raw in cases {
		let expected = raw.parse::<loupe_storage::source_refs::UnitRefs>();
		db.with_conn(|c| {
			c.execute("UPDATE review_units SET source_refs=?1", [&raw])?;
			let actual = loupe_storage::review_units::get(c, 1);
			assert_eq!(actual.is_ok(), expected.is_ok(), "reference compatibility: {raw}");
			if let (Ok(row), Ok(expected)) = (actual, &expected) {
				assert_eq!(&row.unwrap().source_refs, expected);
			}
			Ok(())
		})
		.unwrap();
	}
}

#[test]
fn compatibility_full_app_and_summary_keep_distinct_schemas() {
	#[derive(serde::Deserialize)]
	struct OldApp {
		app_id: u64,
		slug: String,
		private_key_pem: String,
	}
	let (db, _) = seeded();
	for raw in [
		r#"{"app_id":7,"slug":"cafe\u0301","private_key_pem":"fake\nkey"}"#,
		r#"{"app_id":7,"slug":"","private_key_pem":null}"#,
		r#"{"app_id":7,"slug":"same"}"#,
		r#"{"app_id":7,"slug":"same","private_key_pem":"\uD800"}"#,
		r#"[7,"same","fake"]"#,
		r#"[7,"same"]"#,
		r#"{"app_id":7,"slug":"same","slug":"same","private_key_pem":"fake"}"#,
		r#"{"app_id":7,"slug":"same","unknown":"\uD800","private_key_pem":"fake"}"#,
	] {
		let old = serde_json::from_str::<OldApp>(raw);
		let old_summary = serde_json::from_str::<github_app::StoredGithubAppSummary>(raw);
		db.with_conn(|c| {
            c.execute("INSERT INTO secrets(kind,label,value,created_at) VALUES('github_app','server',?1,0) ON CONFLICT(kind,label) DO UPDATE SET value=excluded.value",[raw.as_bytes()])?;
            let actual=github_app::get(c);
            assert_eq!(actual.is_ok(),old.is_ok(),"full App compatibility: {raw}");
            if let (Ok(Some(actual)),Ok(old))=(actual,old) {
                assert_eq!((actual.app_id,actual.slug,actual.private_key_pem.expose()),(old.app_id,old.slug,&old.private_key_pem));
            }
            let summary=github_app::summary(c);
            assert_eq!(summary.is_ok(),old_summary.is_ok(),"summary compatibility: {raw}");
            if let (Ok(Some(actual)),Ok(old))=(summary,old_summary) { assert_eq!((actual.app_id,actual.slug),(old.app_id,old.slug)); }
            Ok(())
        }).unwrap();
	}
}

#[test]
fn compatibility_original_document_recursion_budget_is_not_reset_for_tokens() {
	let (db, _) = seeded();
	let mut accepted = 0;
	let mut rejected = 0;
	for depth in 120..=132 {
		let nested = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
		for raw in [
			format!(r#"{{"kind":"manual","ignored":{nested}}}"#),
			format!(r#"{{"kind":"email","to":["same"],"ignored":{nested}}}"#),
			format!(r#"["github_issue","same","same",null,{nested}]"#),
		] {
			let expected = serde_json::from_str::<loupe_core::ReportingDestination>(&raw);
			if expected.is_ok() {
				accepted += 1;
			} else {
				rejected += 1;
			}
			db.with_conn(|c| {
				c.execute("UPDATE registered_repos SET reporting=?1", [&raw])?;
				assert_eq!(repos::get(c, 1).is_ok(), expected.is_ok(), "reporting depth={depth}");
				Ok(())
			})
			.unwrap();
		}
		let refs = format!(r#"[{{"path":{nested}}}]"#);
		db.with_conn(|c| {
			c.execute("UPDATE review_units SET source_refs=?1", [&refs])?;
			assert_eq!(
				loupe_storage::review_units::get(c, 1).is_ok(),
				refs.parse::<loupe_storage::source_refs::UnitRefs>().is_ok()
			);
			Ok(())
		})
		.unwrap();
	}
	println!("original reporting recursion controls: accepted={accepted} rejected={rejected}");
	assert!(accepted > 0 && rejected > 0, "must straddle the original serde recursion boundary");
}
