//! Actual request collectors, router authority and byte accounting.
//! Large boundaries use compact recipes and at most 771 bounded chunks.
use std::sync::OnceLock;

use loupe_proto::PROTOCOL_VERSION;
use loupe_server::fuzz_support::{self as actual, RequestCase};

use crate::utils::test_logger;

const CAP: usize = 2 * 1024 * 1024;
const RAW_CAP: usize = 64 * 1024;

mod reporter;

fn runtime() -> &'static tokio::runtime::Runtime {
	static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
	RUNTIME.get_or_init(|| {
		tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.unwrap_or_else(|error| panic!("transport fixture runtime: {error}"))
	})
}

fn collector(finish: u8, boundary: u8, chunk: usize, prefix: &[u8], schedule: u8) {
	let length = match boundary {
		1 => CAP - 1,
		2 => CAP,
		3 => CAP + 1,
		_ => prefix.len(),
	};
	let padding = length - prefix.len();
	let chunk = if padding > RAW_CAP { chunk.max(4096) } else { chunk };
	let result =
		runtime().block_on(actual::collect_operator(prefix, padding, chunk, finish, schedule));
	// Derive allocation growth from the emitted schedule independently of
	// the product's checked-add helper and actual allocation observations.
	let mut capacity = 0;
	let mut copied = 0;
	let mut allocations = Vec::new();
	let sizes = match schedule {
		1 => [0, chunk, chunk],
		2 => [1, chunk / 2 + 1, chunk],
		_ => [chunk; 3],
	};
	let mut sizes = sizes.into_iter().cycle();
	while copied < length {
		let size = sizes.next().unwrap_or_else(|| unreachable!());
		let size = if padding > RAW_CAP && size != 0 { size.max(4096) } else { size };
		let end = (copied + size).min(length);
		if end > CAP {
			break;
		}
		if end > capacity {
			capacity = 1;
			while capacity < end {
				capacity *= 2;
			}
			allocations.push(capacity);
		}
		copied = end;
	}
	assert_eq!(result.wipes.iter().map(|(size, _)| *size).collect::<Vec<_>>(), allocations);
	assert!(
		result.wipes.iter().all(|(size, zero)| *size <= CAP && *zero),
		"live allocation not wiped"
	);
	assert!(result.shared_owner_retained, "Bytes clone lost its guarded final owner");
	let expected_error = if length > CAP {
		Some((413, "request body exceeds 2097152 bytes"))
	} else if finish == 1 {
		Some((400, "reading request body"))
	} else if finish == 2 {
		Some((0, "fixture cancelled pending collection"))
	} else {
		None
	};
	if let Some((status, text)) = expected_error {
		assert_eq!(result.result, Err((status, text.into())), "actual collector rejection");
	} else {
		let mut digest = blake3::Hasher::new();
		digest.update(prefix);
		let spaces = [b' '; 8192];
		let mut remaining = padding;
		while remaining != 0 {
			let count = remaining.min(spaces.len());
			digest.update(&spaces[..count]);
			remaining -= count;
		}
		assert_eq!(
			result.result,
			Ok((length, *digest.finalize().as_bytes())),
			"collected bytes changed"
		);
	}
}

fn router(case: RequestCase) {
	let result = runtime().block_on(actual::request_route(case));
	assert_eq!(result.protocol.as_deref(), Some(PROTOCOL_VERSION.to_string().as_str()));
	assert!(!result.response.contains("private_body_sentinel"));
	assert!(!result.response.contains("private_stream_sentinel"));
	assert!(result.response.len() < 2048);
	let polled: usize = result.polled_chunks.iter().sum();
	assert!(polled <= result.length);
	let mut denied = false;
	if case.actor == 0 {
		assert_eq!(
			result.byte_charges.iter().map(|(_, cost, _)| *cost as usize).collect::<Vec<_>>(),
			result.polled_chunks,
			"each received worker chunk must be charged exactly once, before cap rejection"
		);
		let mut balance = case.bytes_capacity;
		let mut previous = result.byte_charges.first().map_or(0, |entry| entry.0);
		for &(now, cost, admitted) in &result.byte_charges {
			assert!(!denied, "collector continued after exhausted budget");
			assert!(now >= previous);
			balance = (u128::from(balance) + u128::from(now - previous))
				.min(u128::from(case.bytes_capacity)) as u64;
			assert_eq!(admitted, cost <= balance, "actual budget admission");
			if admitted {
				balance -= cost;
			} else {
				denied = true;
			}
			previous = now;
		}
		assert_eq!(
			result.worker_budget.map(|value| value.0),
			Some(balance),
			"received-byte debt changed"
		);
	} else {
		assert!(result.byte_charges.is_empty());
		assert_eq!(result.worker_budget, None);
	}
	let wrong_role =
		(case.route == 1 && case.actor == 1) || (matches!(case.route, 2 | 3) && case.actor == 0);
	let operator_collects =
		case.actor == 1 && case.route == 2 && case.protocol < 2 && case.media < 2;
	let expected = if case.actor >= 2 {
		401
	} else if case.actor == 0 && denied {
		429
	} else if case.actor == 0 && polled > CAP {
		413
	} else if (case.actor == 0 && case.stream_error) || case.protocol >= 2 {
		400
	} else if wrong_role {
		403
	} else if matches!(case.route, 0 | 3) {
		200
	} else if case.media >= 2 {
		415
	} else if operator_collects && polled > CAP {
		413
	} else if (operator_collects && case.stream_error) || case.body == 1 || case.body == 3 {
		400
	} else if case.body == 2 {
		422
	} else if case.route == 2 {
		201
	} else {
		200
	};
	assert_eq!(result.status, expected, "actual router ordering: {}", result.response);
	if case.actor != 0 && !operator_collects {
		assert_eq!(polled, 0, "unauthorized or ignored Operator body was polled");
	} else if !denied && polled <= CAP {
		assert_eq!(polled, result.length, "actual collector omitted input");
	}
	assert_eq!(
		result.repo_count,
		usize::from(expected == 201),
		"rejected request changed database"
	);
	if expected == 200 && case.route == 1 {
		assert_eq!(
			serde_json::from_str::<serde_json::Value>(&result.response).ok(),
			Some(serde_json::json!({"kind":"empty", "protocol_version":PROTOCOL_VERSION}))
		);
	}
}

pub fn do_test(data: &[u8]) {
	if data.len() > RAW_CAP + 16 {
		return;
	}
	match data {
		[0, finish, boundary, chunk, prefix @ ..] if prefix.len() <= RAW_CAP => {
			collector(
				finish % 3,
				boundary % 4,
				1 + usize::from(*chunk) * 31,
				prefix,
				(finish / 3) % 3,
			);
		},
		[1, route, actor, protocol, media, body, boundary, chunk, budget, flags, ..] => {
			router(RequestCase {
				route: route % 4,
				actor: actor % 5,
				protocol: protocol % 4,
				media: media % 4,
				body: body % 4,
				boundary: boundary % 4,
				chunk_size: 1 + usize::from(*chunk) * 31,
				bytes_capacity: match budget % 4 {
					0 => 1,
					1 => 31,
					2 => CAP as u64,
					_ => 8 * 1024 * 1024,
				},
				stream_error: flags & 1 != 0,
				misleading_length: flags & 2 != 0,
			});
		},
		[2, body, media, capability, ..] => {
			let body = body % 7;
			let (status, text) = runtime().block_on(actual::leased_heartbeat(
				body,
				media & 1 != 0,
				capability & 1 != 0,
			));
			let expected = if body >= 2 {
				400
			} else if capability & 1 != 0 {
				403
			} else {
				200
			};
			assert_eq!(status, expected, "actual leased heartbeat: {text}");
			assert!(!text.contains("private_body_sentinel"));
			if expected == 200 {
				let value = serde_json::from_str::<serde_json::Value>(&text)
					.unwrap_or_else(|error| panic!("heartbeat response: {error}"));
				assert_eq!(value["protocol_version"], PROTOCOL_VERSION);
				assert!(value["lease_expires_at"].as_i64().is_some_and(|value| value > 0));
			}
		},
		[3, recipe @ ..] => reporter::run(recipe),
		_ => {},
	}
}

pub fn server_ingress_transport_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes during this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn server_ingress_transport_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller supplies the readable buffer documented above.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn collector_growth_final_clone_failure_and_cancellation_wipe_live_bytes() {
		for finish in 0..3 {
			for boundary in 0..4 {
				for chunk in [1, 13, 8192] {
					for schedule in 0..3 {
						collector(finish, boundary, chunk, b"nonzero original bytes", schedule);
					}
				}
			}
			collector(finish, 0, 1, b"", 0);
		}
	}

	#[test]
	fn router_auth_protocol_role_media_and_schema_order() {
		for route in 0..4 {
			for actor in 0..5 {
				for protocol in 0..4 {
					for media in 0..4 {
						do_test(&[1, route, actor, protocol, media, 0, 0, 1, 3, 2]);
					}
				}
			}
		}
		for body in 0..4 {
			do_test(&[1, 1, 0, 1, 0, body, 0, 1, 3, 0]);
			do_test(&[1, 2, 1, 1, 0, body, 0, 1, 3, 0]);
		}
	}

	#[test]
	fn received_bytes_precede_caps_and_keep_debt_on_error_or_ignored_routes() {
		for boundary in 0..4 {
			for budget in 0..4 {
				for flags in 0..4 {
					for (route, actor) in [(0, 0), (1, 0), (2, 1), (3, 1)] {
						do_test(&[1, route, actor, 1, 0, 0, boundary, 255, budget, flags]);
					}
				}
			}
		}
	}

	#[test]
	fn heartbeat_empty_body_and_parse_errors_keep_real_lease_authority() {
		for body in 0..7 {
			for media in 0..2 {
				for capability in 0..2 {
					do_test(&[2, body, media, capability]);
				}
			}
		}
	}
}
