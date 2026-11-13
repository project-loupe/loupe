//! Every review phase request decoder, and the worker's phase lease payload
//! decoders, refuse the sequence form of each object they admit, at the top
//! level and nested inside payloads.

use std::fmt;

use serde::de::{Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::review_lease::{
	ReviewDrilldownLeaseDecoder, ReviewSurveyLeaseDecoder, ReviewVerifyLeaseDecoder,
};
use crate::test_support::{server_response, worker_request};
use crate::{
	review_api, review_drilldown, review_evidence, review_inventory, review_lifecycle,
	review_terminal, review_units, review_verification, LeasePayload,
};

/// Decodes a request and returns its serialization, whose objects list their
/// fields in declaration order, i.e. the order serde's sequence form uses.
type Decode = fn(&[u8]) -> Option<String>;

macro_rules! plain {
	($decoder:expr) => {
		|raw: &[u8]| {
			worker_request(raw).validate($decoder).ok().map(|v| serde_json::to_string(&v).unwrap())
		}
	};
}
macro_rules! carrying {
	($decoder:expr) => {
		|raw: &[u8]| {
			worker_request(raw)
				.validate_carrying($decoder)
				.ok()
				.map(|v| serde_json::to_string(&v).unwrap())
		}
	};
}

/// A phase lease payload serializes through its `kind`-tagged enum, as the
/// server writes it.
macro_rules! lease {
	($decoder:expr, $variant:ident) => {
		|raw: &[u8]| {
			server_response(raw)
				.validate_carrying($decoder)
				.ok()
				.map(|v| serde_json::to_string(&LeasePayload::$variant(Box::new(v))).unwrap())
		}
	};
}

/// JSON that keeps object fields in their textual order.
#[derive(Clone)]
enum Ordered {
	Object(Vec<(String, Ordered)>),
	Array(Vec<Ordered>),
	Scalar(Value),
}

impl<'de> Deserialize<'de> for Ordered {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		struct Any;
		impl<'de> Visitor<'de> for Any {
			type Value = Ordered;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				f.write_str("JSON")
			}
			fn visit_bool<E>(self, v: bool) -> Result<Ordered, E> {
				Ok(Ordered::Scalar(v.into()))
			}
			fn visit_i64<E>(self, v: i64) -> Result<Ordered, E> {
				Ok(Ordered::Scalar(v.into()))
			}
			fn visit_u64<E>(self, v: u64) -> Result<Ordered, E> {
				Ok(Ordered::Scalar(v.into()))
			}
			fn visit_f64<E>(self, v: f64) -> Result<Ordered, E> {
				Ok(Ordered::Scalar(v.into()))
			}
			fn visit_str<E>(self, v: &str) -> Result<Ordered, E> {
				Ok(Ordered::Scalar(v.into()))
			}
			fn visit_unit<E>(self) -> Result<Ordered, E> {
				Ok(Ordered::Scalar(Value::Null))
			}
			fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Ordered, A::Error> {
				let mut values = Vec::new();
				while let Some(value) = seq.next_element()? {
					values.push(value);
				}
				Ok(Ordered::Array(values))
			}
			fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Ordered, A::Error> {
				let mut fields = Vec::new();
				while let Some(field) = map.next_entry()? {
					fields.push(field);
				}
				Ok(Ordered::Object(fields))
			}
		}
		deserializer.deserialize_any(Any)
	}
}

impl fmt::Display for Ordered {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Ordered::Scalar(value) => write!(f, "{value}"),
			Ordered::Array(values) => {
				f.write_str("[")?;
				for (index, value) in values.iter().enumerate() {
					if index > 0 {
						f.write_str(",")?;
					}
					write!(f, "{value}")?;
				}
				f.write_str("]")
			},
			Ordered::Object(fields) => {
				f.write_str("{")?;
				for (index, (key, value)) in fields.iter().enumerate() {
					if index > 0 {
						f.write_str(",")?;
					}
					write!(f, "{}:{value}", Value::from(key.as_str()))?;
				}
				f.write_str("}")
			},
		}
	}
}

/// Paths of every object in `value`, outermost first.
fn objects(value: &Ordered, path: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
	let children: Vec<&Ordered> = match value {
		Ordered::Object(fields) => {
			out.push(path.clone());
			fields.iter().map(|(_, value)| value).collect()
		},
		Ordered::Array(values) => values.iter().collect(),
		Ordered::Scalar(_) => return,
	};
	for (index, child) in children.into_iter().enumerate() {
		path.push(index);
		objects(child, path, out);
		path.pop();
	}
}

/// `value` with the object at `path` replaced by the sequence of its values.
fn array_form(value: &Ordered, path: &[usize]) -> Ordered {
	let Some((&first, rest)) = path.split_first() else {
		let Ordered::Object(fields) = value else { unreachable!() };
		return Ordered::Array(fields.iter().map(|(_, value)| value.clone()).collect());
	};
	match value {
		Ordered::Object(fields) => {
			let mut fields = fields.clone();
			fields[first].1 = array_form(&fields[first].1, rest);
			Ordered::Object(fields)
		},
		Ordered::Array(values) => {
			let mut values = values.clone();
			values[first] = array_form(&values[first], rest);
			Ordered::Array(values)
		},
		Ordered::Scalar(_) => unreachable!(),
	}
}

fn describe(value: &Ordered, path: &[usize]) -> String {
	let mut out = String::new();
	let mut current = value;
	for &index in path {
		current = match current {
			Ordered::Object(fields) => {
				out.push('/');
				out.push_str(&fields[index].0);
				&fields[index].1
			},
			Ordered::Array(values) => {
				out.push_str(&format!("/{index}"));
				&values[index]
			},
			Ordered::Scalar(_) => unreachable!(),
		};
	}
	out
}

/// Name, decoder, a valid input, and the paths of open JSON objects whose
/// content is a schema-free value rather than a struct.
type Case = (&'static str, Decode, Value, &'static [&'static str]);

fn cases() -> Vec<Case> {
	let provenance = json!({"workflow_contract_version":1,"campaign_id":2,"attempt":1,"limits":{"soft_deadline_at":100,"submit_by":100,"hard_deadline_at":200,"token_budget":null,"new_unit_limit":32,"lead_limit":16,"sibling_limit":4}});
	let generation =
		json!({"generation_id":3,"commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"});
	let profile = json!({"profile_version":1,"profile_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","profile":{"purpose":"test"}});
	let mut cases: Vec<Case> = vec![
		(
			"pin",
			plain!(review_api::PinTargetRequestDecoder),
			json!({"protocol_version":3,"commit_sha":"0123456789abcdef0123456789abcdef01234567"}),
			&[],
		),
		(
			"inventory batch",
			plain!(review_api::InventoryBatchRequestDecoder),
			json!({"protocol_version":3,"format_version":1,"expected_entry_count":2,"expected_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","start_position":0,"entries":[{"raw_path_hex":"61","git_mode":33188,"object_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},{"raw_path_hex":"612f62","git_mode":40960,"object_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}),
			&[],
		),
		(
			"seal",
			plain!(review_api::SealInventoryRequestDecoder),
			json!({"protocol_version":3}),
			&[],
		),
		(
			"profile",
			carrying!(review_api::PublishProfileRequestDecoder),
			json!({"protocol_version":3,"profile":{"purpose":"seed"}}),
			&["/profile"],
		),
		(
			"inventory disposition",
			plain!(review_inventory::InventoryDispositionRequestDecoder),
			json!({"protocol_version":3,"client_inventory_disposition_key":"key-1","source_path":"src/lib.rs","expected_revision":0,"disposition":"mapped","reason":null,"mappings":[{"review_unit_id":1,"assignment_epoch":1}]}),
			&[],
		),
		(
			"review unit",
			carrying!(review_units::ReviewUnitRequestDecoder),
			json!({"protocol_version":3,"client_review_unit_key":"unit-1","title":"Parser bounds","objective":"Check every parser bound","priority_band":"high","priority_rationale":"Reachable from input","source_refs":[{"path":"src/lib.rs","symbol":"parse"}],"depends_on_review_unit_ids":[2,3],"closure_criteria":"Each bound has a test","semantic_context":null}),
			&[],
		),
		(
			"lead checkpoint",
			carrying!(review_evidence::LeadCheckpointRequestDecoder),
			json!({"protocol_version":3,"client_lead_key":"lead","evidence":{"format":"loupe.lead_evidence","version":1,"identity_family":"auth-bypass","identity_anchor":"handler","review_unit_id":1,"assignment_epoch":0,"hypothesis":"Attacker crosses boundary","source_refs":[{"path":"a.rs"}],"next_proof_step":"Trace entry","counterevidence":"No guard found","proof_gaps":"Need proof"}}),
			&[],
		),
		(
			"unit result checkpoint",
			carrying!(review_evidence::UnitResultCheckpointRequestDecoder),
			json!({"protocol_version":3,"client_result_key":"result","result":{"format":"loupe.unit_result","version":1,"review_unit_id":1,"assignment_epoch":0,"disposition":"no_lead_found","inspected_refs":[{"path":"a.rs"}],"created_lead_ids":[],"counterevidence":"Guard holds","proof_gaps":"None"}}),
			&[],
		),
		(
			"phase failure",
			plain!(review_lifecycle::PhaseFailureRequestDecoder),
			json!({"protocol_version":3,"outcome":"failed","error":"seed reason"}),
			&[],
		),
		(
			"phase heartbeat",
			plain!(review_lifecycle::PhaseHeartbeatRequestDecoder),
			json!({"protocol_version":3}),
			&[],
		),
		(
			"survey terminal",
			carrying!(review_terminal::FinalizeSurveyRequestDecoder),
			json!({"protocol_version":3,"payload":{"version":1,"terminal_reason":"partial"}}),
			&[],
		),
		(
			"drilldown terminal",
			carrying!(review_drilldown::FinalizeDrilldownRequestDecoder),
			json!({"protocol_version":3,"payload":{"version":1,"disposition":"reject","counterargument":{"argument":"argument","source_refs":[{"path":"a.rs"}]}}}),
			&[],
		),
		(
			"verification terminal",
			carrying!(review_verification::FinalizeVerificationRequestDecoder),
			json!({"protocol_version":3,"payload":{"version":1,"verdict":"rejected","counterargument":{"argument":"argument","source_refs":[{"path":"a.rs"}]}}}),
			&[],
		),
	];
	cases.extend::<[Case; 3]>([
		(
			"survey lease",
			lease!(ReviewSurveyLeaseDecoder, ReviewSurvey),
			json!({"kind":"review_survey","provenance":provenance,"context":{"recipe":"ordinary","generation":generation,"profile":profile,"ordinary_recipe":"coverage","assignments":[{"review_unit_id":5,"assignment_epoch":2,"title":"Review parser","objective":"Check input bounds","source_refs":[{"path":"src/lib.rs","symbol":"parse"}],"depends_on":[4],"closure_criteria":null}]}}),
			&["/context/profile/profile"],
		),
		(
			"drilldown lease",
			lease!(ReviewDrilldownLeaseDecoder, ReviewDrilldown),
			json!({"kind":"review_drilldown","provenance":provenance,"generation":generation,"profile":profile,"lead":{"lead_id":4,"producer_commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","identity_family":"memory-safety","identity_anchor":"request allocation","identity_instance_key":"allocator","hypothesis":"Unbounded input","invariant_or_boundary":"Only authorized callers","source_refs":[{"path":"src/lib.rs","symbol":"allocate"}],"next_proof_step":"Trace length","counterevidence":"Authentication","proof_gaps":"Caller scope"}}),
			&["/profile/profile"],
		),
		(
			"verify lease",
			lease!(ReviewVerifyLeaseDecoder, ReviewVerify),
			json!({"kind":"review_verify","provenance":provenance,"generation":generation,"profile":profile,"finding":{"finding_id":4,"reviewed_commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","severity":"high","title":"Unbounded allocation","description":"Requests allocate without a limit","identity_family":"memory-safety","identity_anchor":"request allocation","identity_instance_key":null,"evidence":{"version":1,"l2_argument":{"attacker_source":"Remote request","control":"Request length","sink":"Allocation","reachable_path":"Handler calls the allocator","trust_boundary":"Request to memory"},"material_locations":[{"role":"sink","file":"src/lib.rs","line_start":3,"line_end":4}],"counterevidence":"Authentication precedes allocation","assumptions_gaps":"Authenticated attacker","confidence":"medium"}}}),
			&["/profile/profile"],
		),
	]);
	cases
}

#[test]
fn every_object_refuses_its_array_form() {
	let mut accepted = Vec::new();
	for (name, decode, valid, open) in cases() {
		let canonical = decode(valid.to_string().as_bytes())
			.unwrap_or_else(|| panic!("{name} seed is refused"));
		let canonical: Ordered = serde_json::from_str(&canonical).unwrap();
		let mut paths = Vec::new();
		objects(&canonical, &mut Vec::new(), &mut paths);
		for path in paths {
			let pointer = describe(&canonical, &path);
			// A sequence inside open JSON is a different value, not another
			// spelling of a struct.
			if open.iter().any(|open| {
				pointer
					.strip_prefix(open)
					.is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
			}) {
				continue;
			}
			let mutated = array_form(&canonical, &path).to_string();
			if decode(mutated.as_bytes()).is_some() {
				accepted.push(format!("{name} at '{pointer}'"));
			}
		}
	}
	assert!(accepted.is_empty(), "array form accepted: {accepted:?}");
}
