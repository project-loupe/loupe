use super::*;

const FIRST: Migration = Migration::Sql { version: 1, sql: V1_INITIAL };
const LAST: Migration =
	Migration::Sql { version: 3, sql: "CREATE TABLE after_structural (value INTEGER);" };

fn markers(conn: &Connection) -> (u32, u32) {
	(
		current_schema_version(conn).unwrap(),
		conn.pragma_query_value(None, "user_version", |row| row.get(0)).unwrap(),
	)
}

fn structural(conn: &mut Connection) -> rusqlite::Result<()> {
	assert!(conn.is_autocommit(), "structural migration must own its transaction");
	assert_eq!(markers(conn), (1, 1), "SQL batch must commit and mirror before dispatch");
	assert!(conn.prepare("SELECT * FROM after_structural").is_err());
	let tx = conn.transaction()?;
	tx.execute_batch("CREATE TABLE structural (value INTEGER);")?;
	set_version(&tx, 2)?;
	tx.pragma_update(None, "user_version", 2)?;
	tx.commit()
}

#[test]
fn structural_migration_splits_sql_batches() {
	let mut conn = Connection::open_in_memory().unwrap();
	apply_migrations(
		&mut conn,
		&[FIRST, Migration::Structural { version: 2, run: structural }, LAST],
	)
	.unwrap();
	assert_eq!(markers(&conn), (3, 3));
	conn.prepare("SELECT * FROM structural, after_structural").unwrap();
}

#[test]
fn structural_failure_retains_the_committed_sql_batch() {
	fn fail(conn: &mut Connection) -> rusqlite::Result<()> {
		assert_eq!(markers(conn), (1, 1));
		let tx = conn.transaction()?;
		tx.execute_batch("CREATE TABLE rolled_back (value INTEGER);")?;
		set_version(&tx, 2)?;
		tx.pragma_update(None, "user_version", 2)?;
		Err(rusqlite::Error::InvalidQuery)
	}
	let mut conn = Connection::open_in_memory().unwrap();
	apply_migrations(&mut conn, &[FIRST, Migration::Structural { version: 2, run: fail }, LAST])
		.unwrap_err();
	assert_eq!(markers(&conn), (1, 1));
	assert!(conn.prepare("SELECT * FROM rolled_back").is_err());
	assert!(conn.prepare("SELECT * FROM after_structural").is_err());
}

#[test]
fn structural_migration_must_record_its_own_version() {
	// A structural body that succeeds without writing schema_meta would
	// otherwise be mirrored into user_version and re-dispatched on the next
	// boot against tables it already created.
	fn forgetful(conn: &mut Connection) -> rusqlite::Result<()> {
		let tx = conn.transaction()?;
		tx.execute_batch("CREATE TABLE forgotten (value INTEGER);")?;
		tx.commit()
	}
	let mut conn = Connection::open_in_memory().unwrap();
	let error =
		apply_migrations(&mut conn, &[FIRST, Migration::Structural { version: 2, run: forgetful }])
			.expect_err("a structural migration that skips its version write must fail");
	assert!(error.to_string().contains("schema_meta"), "{error}");
	assert_eq!(markers(&conn), (1, 1), "neither marker may advance past the recorded version");
}

#[test]
fn consecutive_sql_migrations_roll_back_together() {
	let mut conn = Connection::open_in_memory().unwrap();
	apply_migrations(
		&mut conn,
		&[FIRST, Migration::Sql { version: 2, sql: "INSERT INTO missing VALUES (1);" }],
	)
	.unwrap_err();
	assert_eq!(markers(&conn), (0, 0));
	assert!(conn.prepare("SELECT * FROM jobs").is_err());
}

#[test]
fn sql_only_upgrade_and_stale_mirror_recovery() {
	let mut conn = Connection::open_in_memory().unwrap();
	let migrations = [FIRST, Migration::Sql { version: 2, sql: V2_JOB_CAPABILITIES }];
	apply_migrations(&mut conn, &migrations).unwrap();
	assert_eq!(markers(&conn), (2, 2));
	conn.prepare("SELECT job_capability_hash FROM jobs").unwrap();
	conn.pragma_update(None, "user_version", 0).unwrap();
	apply_migrations(&mut conn, &migrations).unwrap();
	assert_eq!(markers(&conn), (2, 2));
}
