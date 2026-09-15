//! Compose domain mutations in one caller-owned transaction. Propagate an
//! operation's error and roll back; do not commit a partially failed batch.
use rusqlite::{Connection, Transaction, TransactionBehavior};

pub fn immediate<T>(
	conn: &mut Connection, mutate: impl FnOnce(&Transaction<'_>) -> crate::Result<T>,
) -> crate::Result<T> {
	let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
	let value = mutate(&tx)?;
	tx.commit()?;
	Ok(value)
}
