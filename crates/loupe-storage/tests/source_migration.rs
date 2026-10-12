//! Marked-read fixtures and compatibility with the adopted actual SQL owners.
#[path = "support/db.rs"]
mod fixture;
#[path = "support/stored.rs"]
mod stored;

use std::borrow::Cow;

use loupe_core::text::policy::LEGACY_TEXT_MAX_BYTES;
use loupe_core::text::{decode_json_string_bounded as decode, BoundedText};
use loupe_provenance::Db as DbSource;
use loupe_storage::secrets::MasterKey;
use loupe_storage::{findings, review_units, Db};
use stored::{read_finding, read_inspected_refs, read_unit_refs};

fn memory() -> Db {
	Db::open_in_memory(&MasterKey::for_tests()).unwrap()
}

fn refs_db(raw: &str) -> Db {
	let db = memory();
	fixture::seed(&db, &fixture::finding(), raw);
	db
}

fn update_refs(db: &Db, raw: &str) {
	db.with_conn(|conn| {
		conn.execute("UPDATE review_units SET source_refs=?1 WHERE review_unit_id=1", [raw])?;
		Ok(())
	})
	.unwrap();
}

#[test]
fn actual_sql_text_is_carried_directly_and_audit_columns_remain_db_after_reopen() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("fixture.sqlite");
	let key = MasterKey::for_tests();
	let db = Db::open(&path, &key).unwrap();
	let mut original = fixture::finding();
	original.title = "cafe\u{301} \"quoted\" \\ literal".into();
	original.description = "same\r\n\tline  \n\n\n".into();
	original.patch_unified = Some("diff\r\n cafe\u{301}\t  \n\\ No newline at end of file".into());
	original.poc_unified = Some(String::new());
	let id = fixture::seed(&db, &original, "[]");
	db.with_conn(|conn| {
		conn.execute("UPDATE findings SET approved_by_cn=?1,rejected_by_cn=?1,patch_proposed_by_cn=?1,patch_notes=?2 WHERE id=?3", (&original.title, "notes\r\n\t  ", id))?;
		Ok(())
	}).unwrap();
	drop(db);
	let db = Db::open(&path, &key).unwrap();
	let marked = read_finding(&db, id).unwrap();
	assert_eq!(
		serde_json::to_value(&marked.finding).unwrap(),
		serde_json::to_value(&original).unwrap()
	);
	let _: &BoundedText<stored::AuditName, DbSource> = marked.approved_by_cn.as_ref().unwrap();
	assert_eq!(marked.approved_by_cn.as_ref().unwrap().expose(), original.title);
	assert_eq!(marked.rejected_by_cn.as_ref().unwrap().expose(), original.title);
	assert_eq!(marked.patch_proposed_by_cn.as_ref().unwrap().expose(), original.title);
	assert_eq!(marked.patch_notes.as_ref().unwrap().expose(), "notes\r\n\t  ");
	assert_eq!(marked.finding.poc_unified.as_ref().unwrap().expose(), "");
	for span in &marked.spans {
		println!("SQL column carry: {span:?}");
		assert_eq!(span.range.start, 0, "plain SQL columns must not become synthetic JSON");
		assert_eq!(span.range.end, span.column_len);
		assert_eq!(span.carried_address, span.column_address);
	}
	assert_eq!(
		marked.spans.iter().find(|s| s.field == "title").unwrap().column_len,
		original.title.len()
	);
	assert_eq!(
		format!("{:?}", marked.finding.title),
		"BoundedText<finding_title, agent>([redacted])"
	);
	assert_eq!(
		format!("{:?}", marked.approved_by_cn.unwrap()),
		"BoundedText<audit_common_name, db>([redacted])"
	);
}

#[test]
fn marked_read_rejects_new_caps_and_controls_without_changing_legacy_rows() {
	let db = memory();
	let id = fixture::seed(&db, &fixture::finding(), "[]");
	for title in ["x".repeat(LEGACY_TEXT_MAX_BYTES + 1), "bad\0title".into(), "bad\rtitle".into()] {
		db.with_conn(|conn| {
			conn.execute("UPDATE findings SET title=?1 WHERE id=?2", (&title, id))?;
			assert!(findings::get(conn, id).is_err());
			let stored: String =
				conn.query_row("SELECT title FROM findings WHERE id=?1", [id], |r| r.get(0))?;
			assert_eq!(stored, title);
			Ok(())
		})
		.unwrap();
		assert_eq!(read_finding(&db, id).err().unwrap().to_string(), "invalid stored finding");
	}
	for title in
		["x".repeat(LEGACY_TEXT_MAX_BYTES), "é".repeat(LEGACY_TEXT_MAX_BYTES / 2), String::new()]
	{
		db.with_conn(|conn| {
			conn.execute("UPDATE findings SET title=?1 WHERE id=?2", (&title, id))?;
			Ok(())
		})
		.unwrap();
		assert_eq!(read_finding(&db, id).unwrap().finding.title.expose(), title);
	}
	db.with_conn(|conn| {
		conn.execute("UPDATE findings SET file_path=?1 WHERE id=?2", ("x".repeat(513), id))?;
		assert!(findings::get(conn, id).is_err());
		let len: i64 =
			conn.query_row("SELECT length(file_path) FROM findings WHERE id=?1", [id], |r| {
				r.get(0)
			})?;
		assert_eq!(len, 513);
		Ok(())
	})
	.unwrap();
	assert!(read_finding(&db, id).is_err());
}

#[test]
fn nested_tokens_keep_original_offsets_even_when_fields_and_elements_are_equal() {
	// Deliberately identical spellings in different fields and array positions.
	let raw = r#"[ {"symbol":"same","path":"same"}, {"path":"same","symbol":"same"} ]"#;
	let db = refs_db(raw);
	let refs = read_unit_refs(&db).unwrap();
	assert_eq!(refs.refs.len(), 2);
	let expected =
		[(0, "path", 26..32), (0, "symbol", 12..18), (1, "path", 43..49), (1, "symbol", 59..65)];
	for (span, (index, field, range)) in refs.spans.iter().zip(expected) {
		println!("Nested JSON carry: {span:?}");
		assert_eq!((span.index, span.field, span.range.clone()), (index, field, range));
		assert_eq!(raw.get(span.range.clone()), Some(r#""same""#));
		assert_eq!(span.carried_address.checked_sub(span.column_address), Some(span.range.start));
		assert_eq!(span.column_len, raw.len());
	}
	assert_eq!(refs.spans.len(), 4);
	let legacy = db.with_conn(|conn| Ok(review_units::get(conn, 1)?.unwrap().source_refs)).unwrap();
	assert_eq!(refs.canonical, legacy.expose());
	assert_eq!(
		loupe_core::canonical::digest(refs.canonical.as_bytes()),
		loupe_core::canonical::digest(legacy.expose().as_bytes())
	);
}

#[test]
fn escaped_nested_strings_surrogates_nulls_and_semantic_symbols_retain_their_contract() {
	let raw = r#"[{"symbol":"e\u0301\u0022x\u005c","path":"src/cafe\u0301-\uD83D\uDE00.rs"},
	{"path":"src/%41.rs","symbol":null},{"path":"src/no-symbol.rs"}]"#;
	let db = refs_db(raw);
	let refs = read_unit_refs(&db).unwrap();
	assert_eq!(refs.refs[0].path.expose(), "src/cafe\u{301}-😀.rs");
	assert_eq!(refs.refs[0].symbol.as_ref().unwrap().expose(), "é\"x\\");
	assert_eq!(refs.refs[1].path.expose(), "src/%41.rs");
	assert!(refs.refs[1].symbol.is_none());
	assert!(refs.refs[2].symbol.is_none());
	assert_eq!(refs.spans.len(), 4);
	let encoded_path = raw.get(refs.spans[0].range.clone()).unwrap();
	assert_eq!(encoded_path, r#""src/cafe\u0301-\uD83D\uDE00.rs""#);
	let legacy = db.with_conn(|conn| Ok(review_units::get(conn, 1)?.unwrap().source_refs)).unwrap();
	assert_eq!(refs.canonical, legacy.expose());
}

#[test]
fn source_ref_schema_and_decoded_limits_are_enforced_on_the_original_column() {
	let db = refs_db("[]");
	let invalid = [
		r#"[{"path":"a","path":"b"}]"#.to_owned(),
		r#"[{"path":"a","symbol":null,"symbol":null}]"#.to_owned(),
		r#"[{"path":"a","unknown":"ignored"}]"#.to_owned(),
		r#"[{"path":null}]"#.to_owned(),
		r#"[{"path":1}]"#.to_owned(),
		r#"[{"path":["a"]}]"#.to_owned(),
		r#"[{"path":"a","\u0070ath":"b"}]"#.to_owned(),
		r#"[{"symbol":"a"}]"#.to_owned(),
		r#"[{"path":"\uD800"}]"#.to_owned(),
		r#"[{"path":"\uDC00"}]"#.to_owned(),
		r#"[{"path":"\uD800\u0041"}]"#.to_owned(),
		r#"[{"path":"a","symbol":""}]"#.to_owned(),
		r#"[{"path":"a","symbol":"\u0000"}]"#.to_owned(),
		r#"[{"path":"../a"}]"#.to_owned(),
		format!(r#"[{{"path":"{}"}}]"#, "\\u0061".repeat(513)),
		format!(r#"[{{"path":"a","symbol":"{}"}}]"#, "\\u0061".repeat(257)),
	];
	for raw in invalid {
		update_refs(&db, &raw);
		assert_eq!(read_unit_refs(&db).err().unwrap().to_string(), "invalid stored source refs");
	}
	for raw in [
		format!(r#"[{{"path":"{}"}}]"#, "\\u0061".repeat(512)),
		format!(r#"[{{"path":"a","symbol":"{}"}}]"#, "\\u0065\\u0301".repeat(256)),
	] {
		update_refs(&db, &raw);
		assert!(read_unit_refs(&db).is_ok(), "encoded length must not replace the decoded bound");
	}
}

#[test]
fn raw_column_canonical_and_distinct_collection_budgets_stay_in_force() {
	let db = refs_db("[]");
	for (count, accepted) in [(32, true), (33, false)] {
		update_refs(&db, &format!("[{}]", vec![r#"{"path":"a"}"#; count].join(",")));
		assert_eq!(read_unit_refs(&db).is_ok(), accepted);
	}
	for (len, accepted) in [(65536, true), (65537, false)] {
		update_refs(&db, &format!("[]{}", " ".repeat(len - 2)));
		assert_eq!(read_unit_refs(&db).is_ok(), accepted);
	}
	db.with_conn(|conn| {
		conn.execute("INSERT INTO review_unit_results (review_unit_result_id,review_unit_id,commit_sha,profile_version,disposition,inspected_refs,result_payload,result_digest,created_at) VALUES (1,1,'base',1,'no_lead_found','[]','{}',zeroblob(32),0)", [])?;
		Ok(())
	}).unwrap();
	for (count, accepted) in [(64, true), (65, false)] {
		let raw = format!("[{}]", vec![r#"{"path":"a"}"#; count].join(","));
		db.with_conn(|conn| {
			conn.execute("UPDATE review_unit_results SET inspected_refs=?1", [&raw])?;
			Ok(())
		})
		.unwrap();
		assert_eq!(read_inspected_refs(&db).is_ok(), accepted);
	}
	let raw =
		format!("[{}]", vec![format!(r#"{{"path":"{}"}}"#, "\\\"".repeat(500)); 64].join(","));
	assert!(raw.len() <= 65536);
	db.with_conn(|conn| {
		conn.execute("UPDATE review_unit_results SET inspected_refs=?1", [&raw])?;
		assert!(
			loupe_storage::review_unit_results::list(conn, 1).is_err(),
			"canonical null members exceed the existing limit"
		);
		Ok(())
	})
	.unwrap();
	assert!(read_inspected_refs(&db).is_err());
}

#[test]
fn bounded_string_preflight_precedes_owned_decoding_and_counts_utf8_scalars() {
	let raw = r#""café""#;
	let decoded = decode(raw, "fixture", 6, 5).unwrap();
	assert!(matches!(decoded, Cow::Borrowed(_)));
	assert_eq!(decoded.as_ptr(), raw[1..].as_ptr());
	let escaped = r#""\u00E9\uD83D\uDE00""#;
	// Internal preflight count assertions moved intact to core unit tests;
	// this actual consumer keeps the same public boundary checks.
	assert_eq!(decode(escaped, "fixture", 6, 2).unwrap(), "é😀");
	assert!(decode(escaped, "fixture", 5, 2).is_err());
	assert!(decode(escaped, "fixture", 6, 1).is_err());
	assert_eq!(decode(r#""""#, "fixture", 0, 0).unwrap(), "");
	for raw in [
		r#""\uD800""#,
		r#""\uDC00""#,
		r#""\uD800\u0041""#,
		r#""\x00""#,
		r#""\u12x4""#,
		"true",
		"\"raw\nline\"",
		"\"unterminated",
		"\"extra\"tail",
	] {
		assert!(decode(raw, "fixture", 65536, 65536).is_err());
	}
	let all = r#""\"\\\/\b\f\n\r\t\u0000é\uD834\uDD1E""#;
	let decoded = decode(all, "fixture", 64, 64).unwrap();
	assert_eq!(decoded, serde_json::from_str::<String>(all).unwrap());
}
