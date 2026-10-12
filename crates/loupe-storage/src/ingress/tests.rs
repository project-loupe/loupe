//! Live original-column observations through the production validators.
use std::cell::RefCell;

use super::*;

// debug-ok: static names and live addresses/lengths only, never payload bytes.
#[derive(Debug)]
struct Observation {
	source: &'static str,
	field: &'static str,
	address: usize,
	len: usize,
}
thread_local! {
	static OBSERVATIONS: RefCell<Option<Vec<Observation>>> = const { RefCell::new(None) };
}
pub(super) fn observe(source: &'static str, field: &'static str, bytes: &[u8]) {
	OBSERVATIONS.with_borrow_mut(|events| {
		if let Some(events) = events {
			events.push(Observation {
				source,
				field,
				address: bytes.as_ptr() as usize,
				len: bytes.len(),
			});
		}
	});
}

#[test]
fn actual_finding_read_carries_live_whole_columns_and_keeps_audit_db() {
	let db = crate::review_tests::fixture();
	let finding = loupe_core::Finding {
		scanner_id: crate::test_support::text("fixture").unwrap(),
		severity: loupe_core::Severity::High,
		title: crate::test_support::text("same").unwrap(),
		description: crate::test_support::text("same").unwrap(),
		file_path: Some(crate::test_support::path("src/cafe\u{301}.rs").unwrap()),
		line_start: Some(1),
		line_end: None,
		cwe: None,
		patch_unified: Some(crate::test_support::text("patch\r\n\t  ").unwrap()),
		poc_unified: Some(crate::test_support::text("").unwrap()),
		fingerprint: crate::test_support::text("fixture").unwrap(),
	};
	db.with_conn(|conn| {
		let id = crate::findings::insert_or_ignore(conn, 1, 101, &finding, false, 0)?.unwrap();
		conn.execute(
			"UPDATE findings SET approved_by_cn='same',patch_notes='same' WHERE id=?1",
			[id],
		)?;
		OBSERVATIONS.with_borrow_mut(|events| *events = Some(Vec::new()));
		let read = crate::findings::get(conn, id)?.unwrap();
		let events = OBSERVATIONS.with_borrow_mut(Option::take).unwrap();
		assert_eq!(read.into_finding(), finding);
		let mut carries = 0;
		for (index, event) in events.iter().enumerate() {
			if event.source == "column" {
				let agent = &events[index + 1];
				assert_eq!(
					(agent.source, agent.field, agent.address, agent.len),
					("agent", event.field, event.address, event.len)
				);
				println!(
					"actual SQL carry {}: address={} bytes={}",
					event.field, event.address, event.len
				);
				carries += 1;
			}
		}
		assert_eq!(carries, 8);
		assert!(events.iter().any(|event| event.source == "db" && event.field == "StoredAudit"));
		conn.query_row("SELECT title,approved_by_cn FROM findings WHERE id=?1", [id], |row| {
			let title: BoundedText<policy::FindingTitle, Agent> = finding_title(row, 0)?;
			let audit: BoundedText<AuditName, Db> = audit(row, 1)?;
			assert_eq!(title.expose(), audit.expose());
			assert_eq!(format!("{title:?}"), "BoundedText<finding_title, agent>([redacted])");
			assert_eq!(format!("{audit:?}"), "BoundedText<audit_common_name, db>([redacted])");
			Ok(())
		})?;
		Ok(())
	})
	.unwrap();
}

#[test]
fn original_db_metadata_and_agent_review_policy_outputs_keep_sources_and_normalization() {
	let db = crate::review_tests::fixture();
	db.with_conn(|conn| {
        conn.execute("INSERT INTO review_units (review_unit_id,generation_id,client_review_unit_key,title,objective,source_refs,stale_reason,created_at) VALUES (31,11,'key','Café','objective','[]','Café',0)",[])?;
        conn.query_row("SELECT client_review_unit_key,title,stale_reason FROM review_units WHERE review_unit_id=31",[],|row| {
            let key:Identifier<policy::ClientKey,Db>=client_key(row,0)?;
            let title:BoundedText<policy::Title,Agent>=title(row,1)?;
            let reason:BoundedText<policy::Reason,Db>=reason(row,2)?;
            assert_eq!(key.expose(),"key");
            assert_eq!(title.expose(),"Café");
            assert_eq!(reason.expose(),"Café");
            Ok(())
        })?;
        let read=crate::review_units::get(conn,31)?.unwrap();
        assert_eq!(read.title.expose(),"Café");
        assert_eq!(read.stale_reason.unwrap().expose(),"Café");
        Ok(())
    }).unwrap();
}

#[test]
fn reporting_syntax_and_new_admission_remain_distinct_without_column_errors() {
	let db = crate::review_tests::fixture();
	db.with_conn(|conn| {
		for (raw, admission) in [
			(r#"{"kind":"email","to":[null]}"#, false),
			(r#"{"kind":"email","to":["\uD800"]}"#, false),
			(r#"{"kind":"email","to":["bad\naddress"]}"#, true),
			(r#"{"kind":"unknown-private-value"}"#, false),
		] {
			conn.execute("UPDATE registered_repos SET reporting=?1 WHERE id=1", [raw])?;
			let rusqlite::Error::FromSqlConversionFailure(_, _, error) =
				crate::repos::get(conn, 1).unwrap_err()
			else {
				panic!("wrong conversion category")
			};
			let error = error.downcast_ref::<ReadError>().unwrap();
			assert_eq!(matches!(error, ReadError::Admission { .. }), admission);
			assert!(!format!("{error:?} {error}").contains("private-value"));
		}
		Ok(())
	})
	.unwrap();
}
