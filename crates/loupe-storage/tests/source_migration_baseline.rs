//! Historical storage representation and retained compatibility controls.
//! The D baseline accepted oversized columns; I now rejects their read without
//! changing the original stored bytes (see the saved pre-I runtime evidence).
#[path = "support/db.rs"]
mod fixture;

use loupe_storage::secrets::MasterKey;
use loupe_storage::source_refs::UnitRefs;
use loupe_storage::{findings, review_units, Db};

#[test]
fn invalid_legacy_columns_remain_unchanged_when_actual_read_rejects_them() {
	let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
	let mut finding = fixture::finding();
	finding.title = format!("{}\0\r\n", "x".repeat(2 * 1024 * 1024 + 1));
	finding.description = "cafe\u{301}\r\n\t trailing  \n\n\n".into();
	finding.patch_unified = Some(String::new());
	let id = fixture::seed(&db, &finding, "[]");
	db.with_conn(|conn| {
		conn.execute("UPDATE findings SET approved_by_cn=?1 WHERE id=?2", ("same", id))?;
		assert!(findings::get(conn, id).is_err());
		let raw: String =
			conn.query_row("SELECT title FROM findings WHERE id=?1", [id], |r| r.get(0))?;
		assert_eq!(raw, finding.title);
		conn.execute("UPDATE findings SET title='admitted' WHERE id=?1", [id])?;
		finding.title = "admitted".into();
		let row = findings::get(conn, id)?.unwrap();
		assert_eq!(row.approved_by_cn.as_deref(), Some("same"));
		assert_eq!(row.into_finding(), finding);
		Ok(())
	})
	.unwrap();
}

#[test]
fn legacy_refs_read_actual_column_and_preserve_path_spelling_and_symbol_policy() {
	let raw = r#"[ { "symbol": "Cafe\u0301 token", "path": "src/cafe\u0301.rs" },
	{ "path": "src/cafe\u0301.rs", "symbol": null }, { "path": "src/x.rs" } ]"#;
	let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
	fixture::seed(&db, &fixture::finding(), raw);
	db.with_conn(|conn| {
		let stored: String = conn.query_row(
			"SELECT source_refs FROM review_units WHERE review_unit_id=1",
			[],
			|r| r.get(0),
		)?;
		assert_eq!(stored, raw);
		let unit = review_units::get(conn, 1)?.unwrap();
		assert_eq!(unit.source_refs, raw.parse::<UnitRefs>().unwrap());
		assert_eq!(unit.source_refs.as_slice()[0].path.expose(), "src/cafe\u{301}.rs");
		assert_eq!(unit.source_refs.as_slice()[0].symbol.as_ref().unwrap().expose(), "Café token");
		assert!(unit.source_refs.as_slice()[1].symbol.is_none());
		assert!(unit.source_refs.as_slice()[2].symbol.is_none());
		Ok(())
	})
	.unwrap();
}

#[test]
fn legacy_refs_reject_duplicates_unknowns_bad_surrogates_and_existing_limits() {
	let db = Db::open_in_memory(&MasterKey::for_tests()).unwrap();
	fixture::seed(&db, &fixture::finding(), "[]");
	let mut invalid = vec![
		r#"[{"path":"a","path":"b"}]"#.to_owned(),
		r#"[{"path":"a","symbol":null,"symbol":null}]"#.to_owned(),
		r#"[{"path":"a","extra":1}]"#.to_owned(),
		r#"[{"path":"a","symbol":"  Cafe  "}]"#.to_owned(),
		r#"[{"path":null}]"#.to_owned(),
		r#"[{"path":"\uD800"}]"#.to_owned(),
		format!(r#"[{{"path":"{}"}}]"#, "a".repeat(513)),
		format!(r#"[{{"path":"a","symbol":"{}"}}]"#, "x".repeat(257)),
		format!("[{}]", vec![r#"{"path":"a"}"#; 33].join(",")),
	];
	invalid.push(format!("[]{}", " ".repeat(65535)));
	for raw in invalid {
		db.with_conn(|conn| {
			conn.execute("UPDATE review_units SET source_refs=?1 WHERE review_unit_id=1", [&raw])?;
			assert!(review_units::get(conn, 1).is_err());
			Ok(())
		})
		.unwrap();
	}
}
