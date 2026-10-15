use super::*;

fn text(value: &str) -> loupe_core::Finding<Agent> {
	crate::llm::prompts::prompt_baseline_tests::finding(value)
}

#[test]
fn collision_retries_are_global_and_stop_after_three_draws() {
	let a = "11111111111111111111111111111111";
	let b = "22222222222222222222222222222222";
	let finding = text(&format!("{a} later {b}"));
	let mut builder = PromptBuilder::new(PREAMBLE);
	builder.data("description", &finding.description).unwrap();
	let mut draws = 0;
	let prompt = builder
		.render_with(|| {
			draws += 1;
			Ok([draws * 0x11; 16])
		})
		.unwrap();
	assert_eq!(draws, 3);
	assert!(prompt.expose().contains("boundary=\"33333333333333333333333333333333\""));
	let mut builder = PromptBuilder::new(PREAMBLE);
	builder.data("description", &finding.description).unwrap();
	let mut draws = 0;
	assert_eq!(
		builder
			.render_with(|| {
				draws += 1;
				Ok([0x11; 16])
			})
			.unwrap_err(),
		PromptError::Collision
	);
	assert_eq!(draws, 3);
}

#[test]
fn entropy_failure_is_fixed_and_never_falls_back() {
	let builder = PromptBuilder::new(PREAMBLE);
	assert_eq!(
		builder.render_with(|| Err(PromptError::Entropy)).unwrap_err(),
		PromptError::Entropy
	);
}

fn recover(marked: &str) -> String {
	let mut result = String::new();
	let mut chars = marked.chars();
	while let Some(ch) = chars.next() {
		if ch == '\u{241e}' {
			match chars.next().unwrap() {
				'\u{241e}' => result.push(ch),
				'.' => {},
				_ => panic!("invalid marked suffix"),
			}
		} else {
			result.push(ch);
		}
	}
	assert_eq!(
		marked,
		reference_marked(&result),
		"canonical Marked encoding by original scalar groups"
	);
	result
}

fn reference_marked(original: &str) -> String {
	original
		.chars()
		.collect::<Vec<_>>()
		.chunks(32)
		.map(|group| group.iter().collect::<String>().replace('␞', "␞␞"))
		.collect::<Vec<_>>()
		.join("␞.")
}

#[test]
fn both_modes_preserve_exact_original_scalars_and_whitespace() {
	for value in [
		String::new(),
		"x".repeat(31),
		"é".repeat(32),
		"␞".repeat(33),
		"␞.e\u{301}\r\n\t  \n".into(),
	] {
		let finding = text(&value);
		for mode in [DataMode::Delimited, DataMode::Marked] {
			let mut builder = PromptBuilder::new(PREAMBLE).mode(mode);
			builder.data("description", &finding.description).unwrap();
			let prompt = builder.render_with(|| Ok([0; 16])).unwrap();
			let payload = crate::llm::prompts::prompt_baseline_tests::blocks(
				prompt.expose(),
				&[(PREAMBLE, "description", "agent")],
				"",
			)[0];
			assert_eq!(
				if mode == DataMode::Marked { recover(payload) } else { payload.into() },
				value
			);
			assert!(prompt.expose().starts_with(PREAMBLE));
		}
	}
}

#[test]
fn marked_positions_are_exact_for_scalar_and_literal_marker_boundaries() {
	let cases = [
		("é".repeat(31), "é".repeat(31)),
		("é".repeat(32), "é".repeat(32)),
		("é".repeat(33), format!("{}␞.é", "é".repeat(32))),
		("é".repeat(64), format!("{}␞.{}", "é".repeat(32), "é".repeat(32))),
		("é".repeat(65), format!("{}␞.{}␞.é", "é".repeat(32), "é".repeat(32))),
		(format!("{}␞", "x".repeat(31)), format!("{}␞␞", "x".repeat(31))),
		(format!("{}␞y", "x".repeat(31)), format!("{}␞␞␞.y", "x".repeat(31))),
		(format!("{}␞", "x".repeat(32)), format!("{}␞.␞␞", "x".repeat(32))),
		("␞".repeat(33), format!("{}␞.␞␞", "␞␞".repeat(32))),
		(
			format!("{}\r\n\t  ", "e\u{301}".repeat(16)),
			format!("{}␞.\r\n\t  ", "e\u{301}".repeat(16)),
		),
	];
	for (original, expected) in cases {
		let finding = text(&original);
		let mut builder = PromptBuilder::new(PREAMBLE).mode(DataMode::Marked);
		builder.data("description", &finding.description).unwrap();
		let prompt = builder.render_with(|| Ok([0; 16])).unwrap();
		let payload = crate::llm::prompts::prompt_baseline_tests::blocks(
			prompt.expose(),
			&[(PREAMBLE, "description", "agent")],
			"",
		)[0];
		assert_eq!(
			payload,
			expected,
			"exact marker positions for {} original scalars",
			original.chars().count()
		);
		assert_eq!(recover(payload), original);
	}
}

#[test]
fn field_and_part_limits_reject_before_growth() {
	let finding = text("ordinary");
	let mut builder = PromptBuilder::new(PREAMBLE);
	assert_eq!(builder.data("bad\"field", &finding.description).unwrap_err(), PromptError::Field);
	for _ in 0..MAX_PARTS {
		builder.instruction("").unwrap();
	}
	assert_eq!(builder.instruction("").unwrap_err(), PromptError::Parts);
}

#[test]
fn fixed_tool_collision_does_not_change_the_job_boundary() {
	let boundary = JobToolBoundary::from_test_bytes([0x11; 16]);
	let bad = text("11111111111111111111111111111111");
	let good = text("later safe content");
	let mut builder = PromptBuilder::new(PREAMBLE);
	builder.data("description", &bad.description).unwrap();
	assert_eq!(builder.render_fixed(boundary).unwrap_err(), PromptError::Collision);
	let mut builder = PromptBuilder::new(PREAMBLE);
	builder.data("description", &good.description).unwrap();
	assert!(builder
		.render_fixed(boundary)
		.unwrap()
		.expose()
		.contains("boundary=\"11111111111111111111111111111111\""));
}

#[test]
fn canonical_injection_corpus_replays_both_modes_and_closed_projection() {
	let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
		.join("../../fuzz/test_cases/worker_prompt_render");
	let mut admitted = 0;
	let mut rejected = 0;
	for entry in std::fs::read_dir(directory).unwrap() {
		let path = entry.unwrap().path();
		let name = path.file_name().unwrap().to_str().unwrap();
		if !name.starts_with("injection-") {
			continue;
		}
		let raw = std::fs::read(&path).unwrap();
		let negative = matches!(
			name,
			"injection-bidi-isolate" | "injection-bidi-override" | "injection-forbidden-control"
		);
		for mode in [DataMode::Delimited, DataMode::Marked] {
			for projection in [false, true] {
				let result = fuzz_support::render(
					&raw,
					mode,
					projection,
					[[0x11; 16], [0x22; 16], [0x33; 16]],
				);
				if negative {
					assert!(result.is_none(), "forbidden control was admitted: {name}");
					continue;
				}
				let prompt =
					result.unwrap_or_else(|| panic!("admissible corpus rejected: {name}")).unwrap();
				let field = if projection { "finding" } else { "description" };
				let payload = crate::llm::prompts::prompt_baseline_tests::blocks(
					prompt.expose(),
					&[(PREAMBLE, field, "agent")],
					"",
				)[0];
				let recovered =
					if mode == DataMode::Marked { recover(payload) } else { payload.into() };
				if projection {
					let value: serde_json::Value = serde_json::from_str(&recovered).unwrap();
					assert_eq!(value["description"].as_str().unwrap().as_bytes(), raw, "{name}");
					assert_eq!(value.as_object().unwrap().len(), 8);
					assert_eq!(value["id"], "LUP-7");
				} else {
					assert_eq!(recovered.as_bytes(), raw, "{name}");
				}
				let prefix =
					format!("{PREAMBLE}<loupe-data field=\"{field}\" source=\"agent\" boundary=\"");
				assert!(prompt.expose().starts_with(&prefix), "static recipe changed");
			}
		}
		if negative {
			rejected += 1;
		} else {
			admitted += 1;
		}
	}
	assert_eq!((admitted, rejected), (37, 3));
}

#[test]
fn exact_output_limit_and_checked_overflow() {
	assert_eq!(bounded_add(usize::MAX, 1), Err(PromptError::Size));
	let mut empty = PromptBuilder::new("");
	empty.raw_data("description", "agent", Cow::Borrowed("")).unwrap();
	let overhead = empty.rendered_size().unwrap();
	let payload = "x".repeat(MAX_RENDERED_PROMPT_BYTES - overhead);
	let mut exact = PromptBuilder::new("");
	exact.raw_data("description", "agent", Cow::Borrowed(&payload)).unwrap();
	assert_eq!(
		exact.render_with(|| Ok([0; 16])).unwrap().expose().len(),
		MAX_RENDERED_PROMPT_BYTES
	);
	let payload = format!("{payload}x");
	let mut over = PromptBuilder::new("");
	over.raw_data("description", "agent", Cow::Borrowed(&payload)).unwrap();
	assert_eq!(
		over.render_with(|| panic!("over-budget prompt must fail before entropy")).unwrap_err(),
		PromptError::Size
	);
}

#[test]
fn later_projection_collision_retries_all_blocks_together() {
	let finding = text("11111111111111111111111111111111");
	let ordinary = text("ordinary");
	let mut builder = PromptBuilder::new(PREAMBLE);
	builder.data("first", &ordinary.description).unwrap();
	builder.verification(7, &finding).unwrap();
	let mut draws = 0;
	let rendered = builder
		.render_with(|| {
			draws += 1;
			Ok([0x11 * draws; 16])
		})
		.unwrap();
	assert_eq!(draws, 2);
	assert_eq!(
		rendered.expose().matches("boundary=\"22222222222222222222222222222222\"").count(),
		4
	);
}
