//! Source-parsing check that every review DTO and typed evidence schema that
//! derives `Deserialize` rejects unknown fields.
//!
//! A derived `Deserialize` on a struct with named fields, or on an enum with a
//! struct or tuple variant, must carry `#[serde(deny_unknown_fields)]`. Items
//! that cannot take unknown fields are exempt by shape: unit-variant enums
//! (decoded from a single string), tuple and unit structs, and containers that
//! decode through `transparent`, `try_from` or `from` (the proxy type is
//! checked where it is defined). Anything else must be listed in `EXCEPTIONS`
//! with its reason, and a listed exception that no longer matches fails.
use std::path::{Path, PathBuf};

/// (file suffix, item name, reason)
const EXCEPTIONS: &[(&str, &str, &str)] = &[
	(
		"loupe-core/src/review_payload.rs",
		"Tagged",
		"checked_enum peeks only the tag; each per-variant Wire re-parses the same bytes with deny_unknown_fields",
	),
	(
		"loupe-proto/src/review_lease/decode.rs",
		"Tag",
		"bootstrap and context peek only the kind/recipe tag; each per-variant Wire re-parses the same bytes with deny_unknown_fields",
	),
];

struct Item {
	file: String,
	name: String,
	attributes: String,
	shape: Shape,
}

#[derive(Debug, PartialEq)]
enum Shape {
	NamedStruct,
	TupleOrUnitStruct,
	UnitEnum,
	DataEnum,
}

fn sources(root: &Path) -> Vec<PathBuf> {
	let proto = root.join("loupe-proto/src");
	let core = root.join("loupe-core/src");
	let mut files = Vec::new();
	for (dir, prefix) in [(&proto, "review_"), (&core, "review_payload")] {
		for entry in std::fs::read_dir(dir).unwrap() {
			let path = entry.unwrap().path();
			let name = path.file_name().unwrap().to_str().unwrap().to_owned();
			if !name.starts_with(prefix) {
				continue;
			}
			if path.is_dir() {
				for nested in std::fs::read_dir(&path).unwrap() {
					let nested = nested.unwrap().path();
					if nested.extension().is_some_and(|ext| ext == "rs") {
						files.push(nested);
					}
				}
			} else if name.ends_with(".rs") {
				files.push(path);
			}
		}
	}
	files.sort();
	files
}

/// Drop a trailing line comment, and the brackets inside string and char
/// literals so they cannot skew bracket balance. Attribute values keep their
/// quotes and words, which is all the checks below read.
fn code_of(line: &str) -> String {
	let mut out = String::new();
	let mut chars = line.chars().peekable();
	let mut in_string = false;
	while let Some(c) = chars.next() {
		if in_string {
			match c {
				'\\' => {
					chars.next();
				},
				'"' => {
					in_string = false;
					out.push(c);
				},
				'(' | ')' | '[' | ']' | '{' | '}' => {},
				_ => out.push(c),
			}
			continue;
		}
		match c {
			'"' => {
				in_string = true;
				out.push(c);
			},
			'/' if chars.peek() == Some(&'/') => break,
			'\'' if matches!(chars.peek(), Some('(' | ')' | '[' | ']' | '{' | '}')) => {
				chars.next();
			},
			_ => out.push(c),
		}
	}
	out
}

fn balance(text: &str) -> i64 {
	text.chars().fold(0, |depth, c| match c {
		'(' | '[' | '{' => depth + 1,
		')' | ']' | '}' => depth - 1,
		_ => depth,
	})
}

/// Remove `#[...]` attributes, bracket-matched, from an item body.
fn strip_attributes(body: &str) -> String {
	let mut out = String::new();
	let mut rest = body;
	while let Some(start) = rest.find("#[") {
		out.push_str(&rest[..start]);
		let mut depth = 0;
		let mut end = rest.len();
		for (index, c) in rest[start + 1..].char_indices() {
			match c {
				'[' => depth += 1,
				']' => {
					depth -= 1;
					if depth == 0 {
						end = start + 1 + index + 1;
						break;
					}
				},
				_ => {},
			}
		}
		rest = &rest[end..];
	}
	out.push_str(rest);
	out
}

fn item_header(line: &str) -> Option<(&'static str, String)> {
	let mut words = line.split_whitespace().peekable();
	if words.peek().is_some_and(|word| word.starts_with("pub")) {
		words.next();
	}
	let keyword = match words.next()? {
		"struct" => "struct",
		"enum" => "enum",
		_ => return None,
	};
	let name: String =
		words.next()?.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
	Some((keyword, name))
}

fn classify_enum(body: &str) -> Shape {
	// Macro repetition tokens wrap variants in parentheses; they are not
	// tuple variants.
	let body = strip_attributes(body)
		.replace("$(", "")
		.replace("),*", ",")
		.replace(")*", "")
		.replace(")?", "");
	let inner = &body[body.find('{').unwrap() + 1..body.rfind('}').unwrap()];
	if inner.contains('{') || inner.contains('(') {
		Shape::DataEnum
	} else {
		Shape::UnitEnum
	}
}

fn items(file: &Path) -> Vec<Item> {
	let text = std::fs::read_to_string(file).unwrap();
	let lines: Vec<String> = text.lines().map(code_of).collect();
	let mut found = Vec::new();
	let mut attributes = String::new();
	let mut index = 0;
	while index < lines.len() {
		let line = lines[index].trim();
		if line.starts_with("#[") {
			let mut attribute = line.to_owned();
			while balance(&attribute) > 0 {
				index += 1;
				attribute.push(' ');
				attribute.push_str(lines[index].trim());
			}
			attributes.push_str(&attribute);
			attributes.push(' ');
			index += 1;
			continue;
		}
		if line.is_empty() && !attributes.is_empty() {
			index += 1;
			continue;
		}
		// Test-only fixtures build adversarial inputs; they are not decoders.
		if attributes.contains("cfg(test)") && line.starts_with("mod ") && line.ends_with('{') {
			let mut depth = balance(line);
			while depth > 0 && index + 1 < lines.len() {
				index += 1;
				depth += balance(&lines[index]);
			}
			attributes.clear();
			index += 1;
			continue;
		}
		if let Some((keyword, name)) = item_header(line) {
			let derives_deserialize = attributes.split("derive(").skip(1).any(|derive| {
				let list = &derive[..derive.find(')').unwrap_or(derive.len())];
				list.split(',').any(|name| {
					let name = name.trim();
					name == "Deserialize" || name.ends_with("::Deserialize")
				})
			});
			if derives_deserialize {
				let mut body = line.to_owned();
				let mut end = index;
				if keyword == "enum" || line.contains('{') {
					while !body.contains('{') || balance(&body) > 0 {
						end += 1;
						body.push(' ');
						body.push_str(lines[end].trim());
					}
				}
				let shape = if keyword == "enum" {
					classify_enum(&body)
				} else {
					let after_name = &line[line.find(&name).unwrap() + name.len()..];
					// The brace of a named struct may follow on a later line.
					let brace = after_name.find('{').unwrap_or(usize::MAX);
					let tuple = after_name.find('(').is_some_and(|paren| paren < brace);
					if tuple || after_name.trim_end().ends_with(';') {
						Shape::TupleOrUnitStruct
					} else {
						Shape::NamedStruct
					}
				};
				found.push(Item {
					file: file.to_string_lossy().into_owned(),
					name,
					attributes: attributes.clone(),
					shape,
				});
			}
		}
		attributes.clear();
		index += 1;
	}
	found
}

fn serde_has(attributes: &str, word: &str) -> bool {
	attributes.split("serde(").skip(1).any(|serde| {
		let list = &serde[..serde.find(")]").unwrap_or(serde.len())];
		list.split(',').any(|entry| {
			let key = entry.split('=').next().unwrap_or("").trim();
			key == word
		})
	})
}

#[test]
fn deny_unknown_fields_holds() {
	let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
	let files = sources(root);
	assert!(files.iter().any(|f| f.ends_with("loupe-proto/src/review_lease/decode.rs")));
	assert!(files.iter().any(|f| f.ends_with("loupe-core/src/review_payload.rs")));
	let mut violations = Vec::new();
	let mut checked = 0;
	let mut unit_enums = 0;
	let mut used_exceptions = vec![false; EXCEPTIONS.len()];
	for file in &files {
		for item in items(file) {
			let proxied = ["transparent", "try_from", "from"]
				.iter()
				.any(|word| serde_has(&item.attributes, word));
			let required = match item.shape {
				Shape::NamedStruct | Shape::DataEnum => !proxied,
				Shape::UnitEnum => {
					unit_enums += 1;
					false
				},
				Shape::TupleOrUnitStruct => false,
			};
			if !required {
				continue;
			}
			checked += 1;
			if serde_has(&item.attributes, "deny_unknown_fields") {
				continue;
			}
			let exception = EXCEPTIONS
				.iter()
				.position(|(suffix, name, _)| item.file.ends_with(suffix) && item.name == *name);
			match exception {
				Some(position) => used_exceptions[position] = true,
				None => violations.push(format!("{}: {} ({:?})", item.file, item.name, item.shape)),
			}
		}
	}
	assert!(
		violations.is_empty(),
		"Deserialize items without #[serde(deny_unknown_fields)]:\n{}",
		violations.join("\n")
	);
	for ((suffix, name, _), used) in EXCEPTIONS.iter().zip(used_exceptions) {
		assert!(used, "stale exception {suffix}: {name}");
	}
	// The scan must reach the review surface rather than pass vacuously.
	assert!(checked >= 40, "only {checked} field-bearing Deserialize items found");
	assert!(unit_enums >= 5, "only {unit_enums} unit-variant enums found");
}
