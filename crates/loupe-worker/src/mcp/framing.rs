//! Bounded line framing with the same LF/CRLF/EOF convention as Tokio Lines.

use std::io;

use tokio::io::{AsyncBufRead, AsyncBufReadExt};

fn oversized() -> io::Error {
	io::Error::new(io::ErrorKind::InvalidData, "MCP record exceeds the local byte limit")
}

/// A pending CR may become framing at LF; at EOF it is ordinary content.
pub(crate) fn admitted_record_len(
	current: usize, take: usize, limit: usize, pending_cr: bool, eof: bool,
) -> Option<usize> {
	let required = current.checked_add(take)?;
	let framing = usize::from(pending_cr && !eof);
	(required.saturating_sub(framing) <= limit).then_some(required)
}

pub(super) async fn next_record<R: AsyncBufRead + Unpin>(
	reader: &mut R, limit: usize,
) -> io::Result<Option<Vec<u8>>> {
	let mut record = Vec::new();
	loop {
		let available = reader.fill_buf().await?;
		if available.is_empty() {
			// Without LF, a final CR is data, exactly as in Lines::next_line.
			admitted_record_len(record.len(), 0, limit, false, true).ok_or_else(oversized)?;
			return Ok((!record.is_empty()).then_some(record));
		}
		let newline = available.iter().position(|byte| *byte == b'\n');
		let take = newline.unwrap_or(available.len());
		let last = available.get(..take).and_then(|part| part.last()).or_else(|| record.last());
		let cr = usize::from(last == Some(&b'\r'));
		// One pending CR is the only permitted byte beyond the content cap.
		// It becomes framing only if the following byte is LF.
		let required =
			admitted_record_len(record.len(), take, limit, cr != 0, false).ok_or_else(oversized)?;
		if required > record.capacity() {
			record.reserve_exact(required - record.len());
		}
		record.extend_from_slice(&available[..take]);
		reader.consume(take + usize::from(newline.is_some()));
		if newline.is_some() {
			if cr != 0 {
				record.pop();
			}
			return Ok(Some(record));
		}
	}
}
