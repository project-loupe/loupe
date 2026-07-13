use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The protocol version produced and accepted by this build.
///
/// Bump this only on a wire-incompatible change; additive fields don't
/// require it because of `#[serde(default)]` / `skip_serializing_if`.
pub const PROTOCOL_VERSION: u16 = 2;

/// Returned by the server (in a 400 body) when a client speaks a version
/// outside the server's supported window.
#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[error(
	"loupe protocol version mismatch: client sent {client}, server supports [{server_min}, {server_max}]"
)]
pub struct ProtocolMismatch {
	pub client: u16,
	pub server_min: u16,
	pub server_max: u16,
}

/// Helper for the server side: confirm a request's `protocol_version`
/// falls within `[min, max]` (inclusive). The current build accepts
/// `PROTOCOL_VERSION..=PROTOCOL_VERSION`, but the function takes a range
/// so we can widen later without touching every call site.
pub fn check_protocol_version(
	client: u16, server_min: u16, server_max: u16,
) -> Result<(), ProtocolMismatch> {
	if client >= server_min && client <= server_max {
		Ok(())
	} else {
		Err(ProtocolMismatch { client, server_min, server_max })
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn current_version_is_in_window() {
		assert!(
			check_protocol_version(PROTOCOL_VERSION, PROTOCOL_VERSION, PROTOCOL_VERSION).is_ok()
		);
	}

	#[test]
	fn future_version_is_rejected() {
		let future = PROTOCOL_VERSION + 1;
		let err = check_protocol_version(future, PROTOCOL_VERSION, PROTOCOL_VERSION).unwrap_err();
		assert_eq!(
			err,
			ProtocolMismatch {
				client: future,
				server_min: PROTOCOL_VERSION,
				server_max: PROTOCOL_VERSION,
			}
		);
		assert!(err.to_string().contains(&format!("client sent {future}")));
	}

	#[test]
	fn ancient_version_is_rejected() {
		assert!(check_protocol_version(1, PROTOCOL_VERSION, PROTOCOL_VERSION).is_err());
	}

	#[test]
	fn protocol_mismatch_round_trips_through_json() {
		let m = ProtocolMismatch { client: 9, server_min: 1, server_max: 3 };
		let s = serde_json::to_string(&m).unwrap();
		let back: ProtocolMismatch = serde_json::from_str(&s).unwrap();
		assert_eq!(m, back);
	}
}
