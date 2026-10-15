//! Incremental equivalent of fingerprint::normalize_window followed by BLAKE3.
//! Two hash states retain Unicode final-sigma lookahead without retaining a
//! word, line or source window. Citation matching never uses this normalization.

pub(super) struct Fingerprint {
	hash: blake3::Hasher,
	final_sigma: Option<blake3::Hasher>,
	preceding_cased: bool,
	content: bool,
	line_content: bool,
	space: bool,
}
impl Fingerprint {
	pub(super) fn new(file: &str) -> Self {
		let mut hash = blake3::Hasher::new();
		hash.update(super::super::SCANNER_ID.as_bytes());
		hash.update(b"\0");
		hash.update(file.as_bytes());
		hash.update(b"\0");
		Self {
			hash,
			final_sigma: None,
			preceding_cased: false,
			content: false,
			line_content: false,
			space: false,
		}
	}
	pub(super) fn push(&mut self, ch: char) {
		if ch == '\n' {
			self.finish_case();
			self.line_content = false;
			self.space = false;
			return;
		}
		if ch.is_whitespace() {
			self.space |= self.line_content;
			return;
		}
		if !self.line_content {
			if self.content {
				self.lower('\n');
			}
			self.line_content = true;
			self.content = true;
		} else if self.space {
			self.lower(' ');
		}
		self.space = false;
		self.lower(ch);
	}
	fn lower(&mut self, ch: char) {
		let (ignorable, cased) = case_context(ch);
		if !ignorable
			&& let Some(final_sigma) = self.final_sigma.take()
			&& !cased
		{
			self.hash = final_sigma;
		}
		if ch == 'Σ' && self.preceding_cased {
			let mut final_sigma = self.hash.clone();
			final_sigma.update("ς".as_bytes());
			self.final_sigma = Some(final_sigma);
			self.hash.update("σ".as_bytes());
		} else {
			for lower in ch.to_lowercase() {
				let mut bytes = [0; 4];
				let encoded = lower.encode_utf8(&mut bytes).as_bytes();
				self.hash.update(encoded);
				if let Some(final_sigma) = self.final_sigma.as_mut() {
					final_sigma.update(encoded);
				}
			}
		}
		if !ignorable {
			self.preceding_cased = cased;
		}
	}
	fn finish_case(&mut self) {
		if let Some(final_sigma) = self.final_sigma.take() {
			self.hash = final_sigma;
		}
		self.preceding_cased = false;
	}
	pub(super) fn finish(mut self) -> blake3::Hash {
		self.finish_case();
		self.hash.finalize()
	}
}

fn case_context(ch: char) -> (bool, bool) {
	static ASCII: std::sync::LazyLock<[(bool, bool); 128]> = std::sync::LazyLock::new(|| {
		std::array::from_fn(|index| unicode_context(char::from(index as u8)))
	});
	if ch.is_ascii() {
		ASCII[usize::from(ch as u8)]
	} else {
		unicode_context(ch)
	}
}

fn unicode_context(ch: char) -> (bool, bool) {
	// Delegate to this exact Rust version's Unicode tables. In AΣxA, sigma
	// stays medial if x is case-ignorable or cased. In AΣx!, it stays medial
	// only if x is non-ignorable and cased. This avoids a second library's
	// potentially different Unicode version and uses two <=9-byte inputs.
	let mut probe = String::with_capacity(9);
	probe.push_str("AΣ");
	probe.push(ch);
	probe.push('A');
	let followed_by_cased = probe.to_lowercase().starts_with("aσ");
	probe.pop();
	probe.push('!');
	let followed_by_boundary = probe.to_lowercase().starts_with("aσ");
	(followed_by_cased && !followed_by_boundary, followed_by_boundary)
}
