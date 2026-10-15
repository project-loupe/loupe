use super::*;

struct CancellingReads {
	cancel: tokio_util::sync::CancellationToken,
	reads: usize,
}
impl Read for CancellingReads {
	fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
		self.reads += 1;
		self.cancel.cancel();
		if self.reads <= 4 {
			buffer.fill(b'a');
			Ok(buffer.len())
		} else {
			Ok(0)
		}
	}
}

#[test]
fn source_traversal_refuses_cancelled_work_before_reading() {
	let cancel = tokio_util::sync::CancellationToken::new();
	cancel.cancel();
	let mut source = CancellingReads { cancel: cancel.clone(), reads: 0 };
	let result = scan(&mut source, "source.rs", 1, 1, &[b"a"], Some(&cancel));
	assert!(
		matches!(result, Err(CitationError::Cancelled)),
		"cancelled source traversal must refuse before reading or producing a fingerprint"
	);
	assert_eq!(source.reads, 0, "pre-cancelled traversal must perform no reads");
}

#[test]
fn source_traversal_stops_when_quarantine_arrives_during_a_read() {
	let cancel = tokio_util::sync::CancellationToken::new();
	let mut source = CancellingReads { cancel: cancel.clone(), reads: 0 };
	let result = scan(&mut source, "source.rs", 1, 1, &[b"a"], Some(&cancel));
	assert!(
		matches!(result, Err(CitationError::Cancelled)),
		"source traversal must stop after the observed cancellation instead of finishing the file"
	);
	assert_eq!(source.reads, 1, "no further read may follow the cancellation barrier");
}

#[test]
fn streaming_fingerprint_matches_original_full_window_normalization() {
	let scalars = (0..0x500).chain((0..=0x10ffff).step_by(257)).filter_map(char::from_u32);
	for scalar in scalars {
		let source =
			format!("aΣ'{scalar}A\nAΣ'{scalar}!\n{scalar}Σ{scalar}\n{scalar}\tİ ΟΣ ΣΣ  \r\n");
		for (start, end) in [(1, 1), (2, 3), (4, 4), (12, 13)] {
			let (_, actual, _) =
				scan(source.as_bytes(), "source.rs", start, end, &[], None).unwrap();
			let expected = crate::fingerprint::compute(
				super::super::SCANNER_ID,
				"source.rs",
				&crate::fingerprint::extract_window(
					&source,
					start,
					end,
					super::super::FINGERPRINT_CONTEXT_LINES,
				),
			);
			assert_eq!(
				actual.to_hex().as_str(),
				expected,
				"scalar U+{:04X}, range {start}:{end}",
				u32::from(scalar)
			);
		}
	}
}

struct TinyReads<'a> {
	source: &'a [u8],
	size: usize,
	maximum: usize,
}
impl Read for TinyReads<'_> {
	fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
		self.maximum = self.maximum.max(buffer.len());
		let count = buffer.len().min(self.size).min(self.source.len());
		buffer[..count].copy_from_slice(&self.source[..count]);
		self.source = &self.source[count..];
		Ok(count)
	}
}

#[test]
fn utf8_and_exact_quote_matches_cross_every_read_boundary() {
	let source = "skip\n  cafe\u{301} 😀\r\nother\n";
	let quote = "cafe\u{301} 😀\r\nother";
	for size in 1..=source.len() {
		let mut reader = TinyReads { source: source.as_bytes(), size, maximum: 0 };
		let (lines, _, matches) =
			scan(&mut reader, "source.rs", 2, 3, &[quote.as_bytes()], None).unwrap();
		assert_eq!(lines, 3);
		assert_eq!(matches, vec![Some(7..7 + quote.len() as u64)]);
		assert!(reader.maximum <= 8192);
		let (_, _, outside) =
			scan(source.as_bytes(), "source.rs", 1, 1, &[quote.as_bytes()], None).unwrap();
		assert_eq!(outside, vec![None]);
	}
}

#[test]
fn exact_fences_keep_payload_indentation_line_endings_and_normalization() {
	let description = "prose\r\n   ````rust\r\n  cafe\u{301}\r\n```\r\n  ~~~\r\n ````` \t\r\n";
	assert_eq!(
		fences(description.as_bytes()).unwrap(),
		vec!["  cafe\u{301}\r\n```\r\n  ~~~".as_bytes()]
	);
	for source in [b"".as_slice(), b"x", b"x\n", b"\r\n", b"\n\n"] {
		let (lines, _, _) = scan(source, "source.rs", 1, 1, &[], None).unwrap();
		assert_eq!(lines, std::str::from_utf8(source).unwrap().lines().count().max(1) as u64);
	}
	for source in [b"x\xff".as_slice(), b"x\xf0\x9f\x98", b"x\xed\xa0\x80"] {
		assert!(matches!(scan(source, "source.rs", 1, 1, &[], None), Err(CitationError::Utf8)));
	}
}
