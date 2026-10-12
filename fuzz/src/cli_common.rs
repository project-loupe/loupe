//! Independent harness policy oracle. No production validator predicts itself.
use unicode_general_category::{get_general_category, GeneralCategory};
pub const TEXT_LIMIT: usize = 2 * 1024 * 1024;
pub const INPUT_LIMIT: usize = 64 * 1024;
pub fn exact(text: &str, multiline: bool) -> bool {
	text.len() <= TEXT_LIMIT
		&& text.chars().count() <= TEXT_LIMIT
		&& text.chars().all(|c| {
			if multiline && matches!(c, '\r' | '\n' | '\t') {
				return true;
			}
			let point = u32::from(c);
			!matches!(
				get_general_category(c),
				GeneralCategory::Control
					| GeneralCategory::Format
					| GeneralCategory::Unassigned
					| GeneralCategory::PrivateUse
					| GeneralCategory::LineSeparator
					| GeneralCategory::ParagraphSeparator
			) && !(0xfdd0..=0xfdef).contains(&point)
				&& !matches!(point % 0x10000, 0xfffe | 0xffff)
		})
}
pub fn path(text: &str) -> bool {
	text.len() <= 512
		&& exact(text, false)
		&& !text.contains(['\\', '\0'])
		&& !text.split('/').any(|s| matches!(s, "" | "." | ".."))
}
pub fn boundary(recipe: u8) -> String {
	let bytes = match recipe % 3 {
		0 => TEXT_LIMIT - 1,
		1 => TEXT_LIMIT,
		_ => TEXT_LIMIT + 1,
	};
	if recipe & 4 != 0 {
		let mut s = "é".repeat(bytes / 2);
		if bytes % 2 == 1 {
			s.push('x')
		}
		s
	} else {
		"x".repeat(bytes)
	}
}
