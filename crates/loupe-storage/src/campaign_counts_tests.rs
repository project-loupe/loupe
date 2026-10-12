//! Old/new compatibility controls for the closed campaign-count composition.
//! Identical tests run on the pre-M producer; these are not regression reds.
use rusqlite::{params, Connection};

fn seed(conn: &Connection, kinds: &[String]) {
	conn.execute("DELETE FROM jobs WHERE repo_id=1", []).unwrap();
	for kind in kinds {
		conn.execute("INSERT OR IGNORE INTO job_kinds(kind, legacy) VALUES(?1,0)", [kind]).unwrap();
		conn.execute("INSERT INTO jobs(repo_id,kind,state,campaign_id,generation_id,enqueued_at) VALUES(1,?1,'queued',1,11,0)", [kind]).unwrap();
	}
}
fn raw_counts(kinds: &[String]) -> String {
	let jobs: Vec<_> = kinds
		.iter()
		.map(|kind| serde_json::json!({"count":1,"kind":kind,"state":"queued"}))
		.collect();
	serde_json::json!({"jobs":jobs,"leads":{"status":{},"disposition":{}},"findings":{},"verdicts":{}}).to_string()
}
fn at_bytes(size: usize) -> Vec<String> {
	let mut kinds: Vec<_> = (0..500).map(|n| format!("job-{n:04}")).collect();
	let mut remaining = size - raw_counts(&kinds).len();
	for kind in &mut kinds {
		let added = remaining.min(3500);
		kind.push_str(&"x".repeat(added));
		remaining -= added;
	}
	assert_eq!(remaining, 0);
	assert_eq!(raw_counts(&kinds).len(), size);
	kinds
}

#[test]
fn atomic_m_campaign_counts_unknown_spelling_normalization_and_group_order() {
	let db = crate::review_tests::fixture();
	db.with_conn(|conn| {
		seed(conn, &["z future/kind".into(), "cafe\u{301}".into(), "alpha".into()]);
		conn.execute("INSERT INTO leads(lead_id,generation_id,status,disposition,priority_band,identity_family,identity_anchor,identity_fingerprint,anchored_payload,anchored_digest,commit_sha,created_at) VALUES(31,11,'open',NULL,'normal','test-family','first',?1,'{}',zeroblob(32),'base',0),(32,11,'closed','rejected','normal','test-family','second',?2,'{}',zeroblob(32),'base',0)", params![[1u8;32].as_slice(),[2u8;32].as_slice()])?;
		let summary = crate::transaction::immediate(conn, |tx| crate::campaigns::summarize(tx, 1))?;
		assert_eq!(summary.counts.expose(), r#"{"findings":{},"jobs":[{"count":1,"kind":"alpha","state":"queued"},{"count":1,"kind":"café","state":"queued"},{"count":1,"kind":"z future/kind","state":"queued"}],"leads":{"disposition":{"rejected":1},"status":{"closed":1,"open":1}},"verdicts":{}}"#);
		let original: String = conn.query_row("SELECT kind FROM jobs WHERE kind LIKE 'cafe%'", [], |r| r.get(0))?;
		assert_eq!(original, "cafe\u{301}", "rendering must not rewrite SQL kind bytes");
		Ok(())
	}).unwrap();
}

#[test]
fn atomic_m_campaign_counts_exact_raw_byte_cap() {
	let db = crate::review_tests::fixture();
	db.with_conn(|conn| {
		for size in [65535, 65536, 65537] {
			seed(conn, &at_bytes(size));
			let result =
				crate::transaction::immediate(conn, |tx| crate::campaigns::summarize(tx, 1));
			assert_eq!(result.is_ok(), size <= 65536, "original serialized count budget at {size}");
			if let Ok(summary) = result {
				assert_eq!(summary.counts.expose().len(), size);
			}
		}
		Ok(())
	})
	.unwrap();
}

#[test]
fn atomic_m_campaign_counts_node_boundary() {
	let db = crate::review_tests::fixture();
	db.with_conn(|conn| {
		for count in [1022, 1023] {
			let kinds: Vec<_> = (0..count).map(|n| format!("kind-{n:04}")).collect();
			assert!(raw_counts(&kinds).len() < 65536);
			seed(conn, &kinds);
			let result =
				crate::transaction::immediate(conn, |tx| crate::campaigns::summarize(tx, 1));
			assert_eq!(
				result.is_ok(),
				count == 1022,
				"seven fixed plus four nodes per job: {count}"
			);
		}
		Ok(())
	})
	.unwrap();
}

#[test]
fn atomic_m_campaign_counts_normalized_expansion_final_cap() {
	let db = crate::review_tests::fixture();
	db.with_conn(|conn| {
		for raw_len in [65534, 65535] {
			let mut kinds = at_bytes(raw_len);
			// U+0344 expands from two bytes to four under NFC; replace two
			// ASCII bytes so the original serialized byte count is unchanged.
			kinds[0].pop();
			kinds[0].pop();
			kinds[0].push('\u{0344}');
			assert_eq!(raw_counts(&kinds).len(), raw_len);
			seed(conn, &kinds);
			let result =
				crate::transaction::immediate(conn, |tx| crate::campaigns::summarize(tx, 1));
			assert_eq!(result.is_ok(), raw_len == 65534, "canonical expansion across final cap");
			if let Ok(summary) = result {
				assert_eq!(summary.counts.expose().len(), 65536);
			}
		}
		Ok(())
	})
	.unwrap();
}
