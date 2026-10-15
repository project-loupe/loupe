//! Exercise handler controls by feeding their fixture Values
//! through the production raw-record decoder. This is not a production bridge.

use super::*;

#[allow(unsafe_code)]
fn decode_fixture(request: &Request) -> Result<ingress::DecodedRequest> {
	let record = serde_json::to_vec(request)?;
	// SAFETY: test-only, explicitly constructed sandbox-record fixture.
	let record = Untrusted::new(record, unsafe { Ingress::<Sandbox>::new() });
	Ok(record
		.as_bytes()
		.validate_carrying(ingress::McpRequestDecoder)?
		.expect("fixture is not blank"))
}
pub(super) fn arguments(name: &str, args: &Value) -> Result<ingress::Arguments> {
	decode_fixture(&Request {
		jsonrpc: "2.0".into(),
		id: Some(json!(1)),
		method: "tools/call".into(),
		params: Some(json!({"name":name,"arguments":args})),
	})?
	.call
	.arguments
}
pub(super) async fn handle_tool_call(
	session: &Arc<Session>, request: &Request, id: Value,
) -> Response {
	handle_decoded_tool_call(session, decode_fixture(request).unwrap().call, id).await
}
pub(super) async fn handle_request(
	session: &Arc<Session>, request: &Request, id: Value,
) -> Response {
	let request = decode_fixture(request).unwrap();
	handle_decoded_request(session, request.method, request.call, id).await
}
pub(super) async fn tool_validate_diff(
	workdir: &Path, args: &Value, field: &str,
) -> Result<String> {
	match arguments(if field == "poc_unified" { "validate_poc" } else { "validate_patch" }, args)? {
		ingress::Arguments::Poc(diff) => validate_diff(workdir, AgentDiff::Poc(&diff)).await,
		ingress::Arguments::ValidatePatch(diff) => {
			validate_diff(workdir, AgentDiff::Patch(&diff)).await
		},
		_ => unreachable!(),
	}
}
pub(super) async fn tool_query_prior_findings(
	client: &Arc<ServerClient>, capability: &JobCapability, repo_id: i64, args: &Value,
) -> Result<String> {
	let ingress::Arguments::Query(args) = arguments("query_prior_findings", args)? else {
		unreachable!()
	};
	query_prior_findings(
		client,
		capability,
		repo_id,
		&args.query,
		args.limit,
		crate::llm::prompt::JobToolBoundary::new()?,
		crate::llm::prompt::DataMode::Delimited,
	)
	.await
}
pub(super) async fn tool_get_finding_by_id(
	client: &Arc<ServerClient>, capability: &JobCapability, args: &Value,
) -> Result<String> {
	let ingress::Arguments::Get(id) = arguments("get_finding_by_id", args)? else { unreachable!() };
	get_finding_by_id(
		client,
		capability,
		id,
		crate::llm::prompt::JobToolBoundary::new()?,
		crate::llm::prompt::DataMode::Delimited,
	)
	.await
}
pub(super) async fn tool_submit_verdict(session: &Arc<Session>, args: &Value) -> Result<String> {
	let ingress::Arguments::Verdict(args) = arguments("submit_verdict", args)? else {
		unreachable!()
	};
	submit_verdict(session, args).await
}
pub(super) async fn tool_submit_patch(session: &Arc<Session>, args: &Value) -> Result<String> {
	let ingress::Arguments::Patch(args) = arguments("submit_patch", args)? else { unreachable!() };
	submit_patch(session, args).await
}
