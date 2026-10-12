use std::fmt::{self, Write};

use axum::http::StatusCode;

/// Closed parser metadata. Never retains a serde error, input bytes or cause.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DecodeError {
	#[error("invalid JSON syntax")]
	Syntax,
	#[error("{0}")]
	Data(&'static str),
	#[error(transparent)]
	Policy(#[from] loupe_core::text::Error),
}

impl DecodeError {
	pub(crate) fn json(error: serde_json::Error) -> Self {
		if error.is_data() {
			Self::Data(category(&error))
		} else {
			Self::Syntax
		}
	}
	pub(crate) fn response(self) -> (StatusCode, String) {
		match self {
			Self::Syntax => (
				StatusCode::BAD_REQUEST,
				"Failed to parse the request body as JSON: invalid syntax".into(),
			),
			Self::Data(reason) => (
				StatusCode::UNPROCESSABLE_ENTITY,
				format!("Failed to deserialize the JSON body into the target type: {reason}"),
			),
			Self::Policy(error) => (StatusCode::BAD_REQUEST, error.to_string()),
		}
	}
}

/// Recognize only static error prefixes, without copying/formating a supplied
/// value into another String. The formatter stops as soon as a prefix matches
/// or all candidates are excluded. The original parser error is then dropped.
pub(crate) fn category(error: &impl fmt::Display) -> &'static str {
	const PREFIXES: [&str; 5] =
		["missing field", "duplicate field", "invalid type", "unknown field", "unknown variant"];
	struct Classifier {
		candidates: u8,
		offset: usize,
		found: Option<&'static str>,
	}
	impl Write for Classifier {
		fn write_str(&mut self, text: &str) -> fmt::Result {
			for byte in text.bytes() {
				for (index, prefix) in PREFIXES.iter().enumerate() {
					if self.candidates & (1 << index) == 0 {
						continue;
					}
					if prefix.as_bytes().get(self.offset) != Some(&byte) {
						self.candidates &= !(1 << index);
					} else if self.offset + 1 == prefix.len() {
						self.found = Some(prefix);
						return Err(fmt::Error);
					}
				}
				self.offset += 1;
				if self.candidates == 0 {
					return Err(fmt::Error);
				}
			}
			Ok(())
		}
	}
	let mut classifier = Classifier { candidates: 0b11111, offset: 0, found: None };
	let _ = write!(&mut classifier, "{error}");
	classifier.found.unwrap_or("invalid data")
}
