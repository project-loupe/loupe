#[test]
fn registration_retains_mixed_ca_bytes_without_debug_disclosure() {
	let wire = r#"{"protocol_version":1,"worker_id":42,"client_cert_pem":"public client","client_key_pem":"FAKE_CLIENT_KEY","ca_cert_pem":"FAKE_MIXED_CA_PRIVATE_KEY"}"#;
	let response: loupe_proto::RegisterWorkerResponse = serde_json::from_str(wire).unwrap();
	let exported = response.credential_json().unwrap();
	assert_eq!(
		serde_json::from_slice::<serde_json::Value>(exported.expose()).unwrap()["ca_cert_pem"],
		"FAKE_MIXED_CA_PRIVATE_KEY"
	);
	assert!(!format!("{response:#?}").contains("FAKE_MIXED_CA_PRIVATE_KEY"));
}
