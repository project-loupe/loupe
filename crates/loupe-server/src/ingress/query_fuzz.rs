//! Fixed-source Uri fixtures reach actual form decoding before text policy.
use loupe_provenance::Ingress;
use serde_json::json;

use super::*;
use crate::fuzz_support::Decoded;

fn response(error: QueryError) -> (u16, String) {
	let (status, text) = error.response();
	(status.as_u16(), text)
}

pub fn worker_search(uri: &Uri) -> Decoded {
	// SAFETY: this synthetic Uri belongs to the fixed Worker query fixture.
	#[allow(unsafe_code)]
	let input = Untrusted::new(uri, unsafe { Ingress::<Worker>::new() });
	let value: SearchInput<Worker> = input.validate(SearchQueryDecoder).map_err(response)?;
	Ok(json!({"q":value.q.expose(), "limit":value.limit}))
}

pub fn operator_search(uri: &Uri) -> Decoded {
	// SAFETY: this synthetic Uri belongs to the fixed Operator query fixture.
	#[allow(unsafe_code)]
	let input = Untrusted::new(uri, unsafe { Ingress::<Operator>::new() });
	let value: SearchInput<Operator> = input.validate(SearchQueryDecoder).map_err(response)?;
	Ok(json!({"q":value.q.expose(), "limit":value.limit}))
}

pub fn job_query(uri: &Uri) -> Decoded {
	// SAFETY: this synthetic Uri belongs to the fixed Operator job fixture.
	#[allow(unsafe_code)]
	let input = Untrusted::new(uri, unsafe { Ingress::<Operator>::new() });
	let value = input.validate(JobListQueryDecoder).map_err(response)?;
	Ok(json!({"states":value.states.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
		"kind":value.kind.as_ref().map(|k| k.as_str()), "limit":value.limit}))
}
