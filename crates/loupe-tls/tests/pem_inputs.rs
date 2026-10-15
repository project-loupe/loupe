use loupe_tls::{decode_pem_base64, encode_pem_base64, read_pem_file, PemInput};

#[test]
fn shared_input_keeps_one_allocation_and_redacts_every_formatter() {
	let input: PemInput = "FAKE_SHARED_PEM".parse().unwrap();
	let clone = input.clone();
	assert_eq!(input.expose().as_ptr(), clone.expose().as_ptr());
	for text in
		[format!("{input}"), format!("{input:#}"), format!("{input:?}"), format!("{input:#?}")]
	{
		assert_eq!(text, "[redacted]");
	}
	drop(input);
	assert_eq!(clone.expose(), "FAKE_SHARED_PEM");
}

#[test]
fn base64_helpers_preserve_exact_pem_and_reject_invalid_utf8() {
	let pem = "FAKE_PEM\n\"\\λ\r\n";
	let encoded = encode_pem_base64(pem).unwrap();
	let decoded = decode_pem_base64(encoded.expose()).unwrap();
	assert_eq!(decoded.expose(), pem);
	assert!(decode_pem_base64("/w==").is_err());
	assert!(decode_pem_base64("!!!!").is_err());
	assert_eq!(decode_pem_base64("").unwrap().expose(), "");
}

#[test]
fn guarded_file_read_preserves_bytes_across_growth_and_reports_fixed_errors() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("input.pem");
	let pem = "FAKE_MULTIBLOCK_PEM\n".repeat(2000);
	std::fs::write(&path, &pem).unwrap();
	assert_eq!(read_pem_file(&path).unwrap().expose(), &pem);
	std::fs::write(&path, b"FAKE_INVALID_UTF8\xff").unwrap();
	let error = read_pem_file(&path).unwrap_err();
	assert_eq!(format!("{error:#}"), "PEM input is not valid UTF-8");
	assert!(!format!("{error:?}").contains("FAKE_INVALID"));
}
