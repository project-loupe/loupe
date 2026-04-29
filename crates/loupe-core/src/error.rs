use std::result::Result as StdResult;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
	#[error("unknown severity: {0:?}")]
	UnknownSeverity(String),

	#[error("unknown job state: {0:?}")]
	UnknownJobState(String),

	#[error("unknown job kind: {0:?}")]
	UnknownJobKind(String),
}

pub type Result<T, E = Error> = StdResult<T, E>;
