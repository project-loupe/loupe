//! Per-route body caps through the real router: a body of exactly the cap
//! reaches the decoder, one byte more is refused before any decoding.
use loupe_server::review::http::{CONTROL_ROUTES, PHASE_ROUTES};
use loupe_server::routes::{
	review_compatibility as compat, review_context as context, review_drilldown as drilldown,
	review_evidence as evidence, review_host as host, review_inventory as inventory,
	review_lifecycle as lifecycle, review_survey as survey, review_units as units,
	review_verification as verification,
};

use super::*;

#[derive(Clone, Copy, Debug)]
enum Caller {
	Worker,
	/// Lease-control routes only take the phase transport for a v2 lease.
	PhaseLease,
	Admin,
}

#[derive(Clone, Copy, Debug)]
enum Intake {
	/// The handler enforces `cap` on the captured body before decoding it.
	Capped { configured: usize, cap: usize, caller: Caller },
	/// Context GETs refuse any body at all.
	Empty,
	/// Phase cancellation never reads the body.
	Ignored,
}

struct Row {
	path: &'static str,
	request: Intake,
	configured_response: usize,
	response: usize,
}

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

fn capped(configured: usize, cap: usize, caller: Caller) -> Intake {
	Intake::Capped { configured, cap, caller }
}

fn table() -> Vec<Row> {
	use Caller::*;
	let row = |path, request, configured_response, response| Row {
		path,
		request,
		configured_response,
		response,
	};
	vec![
		row(
			"/v1/review-generations/{id}/reset",
			capped(compat::RESET_REQUEST_CAP, 8 * KIB, Admin),
			compat::RESET_RESPONSE_CAP,
			4 * KIB,
		),
		row("/v1/jobs/{id}/cancel", Intake::Ignored, lifecycle::CANCEL_RESPONSE_CAP, 8 * KIB),
		row(
			"/v1/jobs/{id}/heartbeat",
			capped(lifecycle::HEARTBEAT_REQUEST_CAP, 8 * KIB, PhaseLease),
			lifecycle::HEARTBEAT_RESPONSE_CAP,
			8 * KIB,
		),
		row(
			"/v1/jobs/{id}/complete",
			capped(lifecycle::COMPLETE_REQUEST_CAP, 8 * KIB, PhaseLease),
			lifecycle::COMPLETE_RESPONSE_CAP,
			8 * KIB,
		),
		row(
			"/v1/jobs/{id}/pin-target",
			capped(host::PIN_TARGET_REQUEST_CAP, 2 * KIB, Worker),
			host::PIN_TARGET_RESPONSE_CAP,
			4 * MIB,
		),
		row(
			"/v1/jobs/{id}/inventory-batches",
			capped(host::INVENTORY_BATCH_REQUEST_CAP, 2 * MIB, Worker),
			host::INVENTORY_BATCH_RESPONSE_CAP,
			8 * KIB,
		),
		row(
			"/v1/jobs/{id}/seal-inventory",
			capped(host::SEAL_INVENTORY_REQUEST_CAP, 2 * KIB, Worker),
			host::SEAL_INVENTORY_RESPONSE_CAP,
			8 * KIB,
		),
		row(
			"/v1/jobs/{id}/publish-profile",
			capped(host::PUBLISH_PROFILE_REQUEST_CAP, 256 * KIB, Worker),
			host::PUBLISH_PROFILE_RESPONSE_CAP,
			4 * KIB,
		),
		row(
			"/v1/jobs/{id}/inventory-dispositions",
			capped(
				inventory::REQUEST_CAP,
				loupe_proto::review_inventory::MAX_REQUEST_BYTES,
				Worker,
			),
			inventory::RESPONSE_CAP,
			8 * KIB,
		),
		row(
			"/v1/jobs/{id}/review-units",
			capped(units::REQUEST_CAP, 256 * KIB, Worker),
			units::RESPONSE_CAP,
			8 * KIB,
		),
		row(
			"/v1/jobs/{id}/leads",
			capped(evidence::LEAD_REQUEST_CAP, 256 * KIB, Worker),
			evidence::LEAD_RESPONSE_CAP,
			8 * KIB,
		),
		row(
			"/v1/jobs/{id}/sibling-leads",
			capped(evidence::LEAD_REQUEST_CAP, 256 * KIB, Worker),
			evidence::LEAD_RESPONSE_CAP,
			8 * KIB,
		),
		row(
			"/v1/jobs/{id}/review-unit-results",
			capped(evidence::RESULT_REQUEST_CAP, 256 * KIB, Worker),
			evidence::RESULT_RESPONSE_CAP,
			8 * KIB,
		),
		row(
			"/v1/jobs/{id}/finalize-survey",
			capped(survey::REQUEST_CAP, 128 * KIB, Worker),
			survey::RESPONSE_CAP,
			16 * KIB,
		),
		row(
			"/v1/jobs/{id}/finalize-drilldown",
			capped(drilldown::REQUEST_CAP, 512 * KIB, Worker),
			drilldown::RESPONSE_CAP,
			16 * KIB,
		),
		row(
			"/v1/jobs/{id}/finalize-verification",
			capped(verification::REQUEST_CAP, 512 * KIB, Worker),
			verification::RESPONSE_CAP,
			16 * KIB,
		),
		row("/v1/jobs/{id}/limits", Intake::Empty, context::LIMITS_RESPONSE_CAP, 8 * KIB),
		row(
			"/v1/jobs/{id}/lead-candidates",
			Intake::Empty,
			context::CANDIDATES_RESPONSE_CAP,
			64 * KIB,
		),
	]
}

/// Every route the router mounts on a `routes::review_*` handler, read from
/// the router definition so a new route cannot be added without a row.
fn mounted_review_routes() -> Vec<String> {
	let source = include_str!("../../src/router.rs");
	let mut routes = Vec::new();
	for block in source.split(".route(").skip(1) {
		let block = block.split(".route_layer(").next().unwrap();
		if block.contains("routes::review_") {
			let path = block.split('"').nth(1).expect("route path literal");
			routes.push(path.to_owned());
		}
	}
	routes
}

async fn send(
	f: &Fixture, admin: Option<&PeerCert>, path: &str, body: Body,
) -> (StatusCode, Value) {
	let get = path.ends_with("/limits") || path.ends_with("/lead-candidates");
	let uri = if path.starts_with("/v1/review-generations/") {
		path.replace("{id}", "1")
	} else if path.ends_with("/lead-candidates") {
		path.replace("{id}", &f.job.to_string()) + "?query=auth"
	} else {
		path.replace("{id}", &f.job.to_string())
	};
	let mut builder = Request::builder()
		.method(if get { "GET" } else { "POST" })
		.uri(uri)
		.header(PROTOCOL_VERSION_HEADER, "3")
		.header("content-type", "application/json");
	if admin.is_none() {
		builder = builder.header(JOB_CAPABILITY_HEADER, &f.token);
	}
	let mut request = builder.body(body).unwrap();
	request.extensions_mut().insert(admin.unwrap_or(&f.peer).clone());
	response(f, request).await
}

fn streamed(len: usize) -> Body {
	let half = len / 2;
	Body::new(Chunks(
		[
			axum::body::Bytes::from(" ".repeat(half)),
			axum::body::Bytes::from(" ".repeat(len - half)),
		]
		.into(),
	))
}

fn sized(len: usize) -> Body {
	Body::from(" ".repeat(len))
}

#[tokio::test]
async fn every_review_route_enforces_its_body_and_response_caps() {
	let table = table();
	let rows: Vec<&str> = table.iter().map(|row| row.path).collect();
	assert_eq!(
		mounted_review_routes(),
		rows,
		"every review route in router.rs needs exactly one cap row, in router order"
	);
	let mut capped = rows.clone();
	capped.sort_unstable();
	let mut classed: Vec<&str> = PHASE_ROUTES.iter().chain(CONTROL_ROUTES).copied().collect();
	classed.sort_unstable();
	assert_eq!(capped, classed, "cap rows must equal the phase/control route classes");
	for row in &table {
		assert_eq!(row.configured_response, row.response, "{}: response cap", row.path);
		let f = fixture();
		match row.request {
			Intake::Ignored => {},
			Intake::Empty => {
				for (framing, body) in [("sized", sized(1)), ("streamed", streamed(1))] {
					let (status, value) = send(&f, None, row.path, body).await;
					assert_eq!(
						(status, &value["error"]["code"]),
						(StatusCode::BAD_REQUEST, &json!("invalid_request")),
						"{} ({framing}): a body on a bodiless route must be refused: {value}",
						row.path
					);
				}
				let (status, value) = send(&f, None, row.path, Body::empty()).await;
				assert_ne!(
					status,
					StatusCode::BAD_REQUEST,
					"{}: an empty body must pass the body check: {value}",
					row.path
				);
			},
			Intake::Capped { configured, cap, caller } => {
				assert_eq!(configured, cap, "{}: request cap", row.path);
				let admin = match caller {
					Caller::Admin => Some(phase_lifecycle::admin(&f)),
					Caller::PhaseLease => {
						phase_lifecycle::v2(&f);
						None
					},
					Caller::Worker => None,
				};
				for (framing, at_cap, over_cap) in [
					("with Content-Length", sized(cap), sized(cap + 1)),
					("streamed", streamed(cap), streamed(cap + 1)),
				] {
					let (status, value) = send(&f, admin.as_ref(), row.path, at_cap).await;
					assert_eq!(
						(status, &value["error"]["code"]),
						(StatusCode::BAD_REQUEST, &json!("invalid_request")),
						"{} ({framing}): a {cap}-byte body must reach the decoder: {value}",
						row.path
					);
					let (status, value) = send(&f, admin.as_ref(), row.path, over_cap).await;
					assert_eq!(
						status,
						StatusCode::PAYLOAD_TOO_LARGE,
						"{} ({framing}): a {}-byte body must be refused as oversized: {value}",
						row.path,
						cap + 1
					);
				}
			},
		}
	}
}
