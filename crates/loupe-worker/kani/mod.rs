//! Bounded proofs for the production broker and sandbox decisions.
//! Run only through ci/kani.sh; host discovery and JSON wire parsing remain
//! exercised by their integration tests and S1 fuzz targets.

use std::ffi::OsString;
use std::path::PathBuf;

#[cfg(kani)]
use serde_json::{Map, Value};

#[cfg(kani)]
use crate::llm::model_broker::{
	apply_request_policy, strip_request_header_name, ModelBrokerBackend,
};
use crate::sandbox::{SandboxBuilder, SandboxHostFacts, SandboxNetworkConfig};

// invariant: I3, I10
// All fixed denied names (including those longer than 12 bytes), plus an
// arbitrary byte prefix of length 0..=12. This covers proxy- plus six bytes;
// the pure core is checked even for bytes HeaderName itself would reject.
// ci: fast
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(32)]
fn strip_request_header_strips_every_listed_name() {
	let denied: [&[u8]; 13] = [
		b"authorization",
		b"cookie",
		b"x-api-key",
		b"host",
		b"content-length",
		b"connection",
		b"keep-alive",
		b"proxy-authenticate",
		b"proxy-authorization",
		b"te",
		b"trailer",
		b"transfer-encoding",
		b"upgrade",
	];
	let fixed: usize = kani::any();
	kani::assume(fixed < denied.len());
	assert!(strip_request_header_name(denied[fixed], false));
	let bytes: [u8; 12] = kani::any();
	let len: usize = kani::any();
	kani::assume(len <= bytes.len());
	let name = &bytes[..len];
	let named: bool = kani::any();
	let listed = denied.iter().any(|item| *item == name);
	let proxy = len >= 6 && name[..6] == *b"proxy-";
	let actual = strip_request_header_name(name, named);
	assert_eq!(actual, listed || proxy || named);
	kani::cover!(name == b"proxy-custom" && !named, "proxy extension is stripped");
	kani::cover!(name == b"accept" && !actual, "ordinary unlisted header is retained");
	kani::cover!(named && name == b"x-nominated", "connection-nominated header is stripped");
}

fn forbidden_flag(flag: &[u8]) -> bool {
	matches!(
		flag,
		b"--not-a-security-boundary"
			| b"--unshare-user-try"
			| b"--cap-add"
			| b"--dev-bind"
			| b"--share-net"
			| b"--unshare-all"
	)
}

const ENV_NAMES: [&str; 8] = [
	"SAFE",
	"HOME",
	"PATH",
	"ANTHROPIC_API_KEY",
	"CLAUDE_CODE_OAUTH_TOKEN",
	"CODEX_API_KEY",
	"OPENAI_API_KEY",
	"LOUPE_MASTER_KEY",
];

fn sandbox_fixture(
	network: bool, supervisor: bool, bind: bool, explicit: Option<usize>,
) -> (SandboxBuilder, SandboxHostFacts) {
	let mut builder = SandboxBuilder::new("/repo");
	if network {
		builder = builder.with_network(SandboxNetworkConfig::default(), vec!["api.test".into()]);
	}
	if supervisor {
		builder = builder.with_network_supervisor("/pinned-worker");
	}
	if bind {
		// A flag-looking operand must never be mistaken for an option.
		builder = builder.bind_ro("--cap-add", "/home/scanner/config");
	}
	if let Some(index) = explicit {
		builder = builder.set_env(ENV_NAMES[index], "--share-net");
	}
	let host = SandboxHostFacts {
		launcher: PathBuf::from(if !network {
			"bwrap"
		} else if supervisor {
			"/pinned-worker"
		} else {
			"/worker"
		}),
		path: "/bin".into(),
		system_dirs: vec!["/usr"],
		system_binds: vec![(PathBuf::from("/public/passwd"), "/etc/passwd")],
		forwarded_env: vec![],
	};
	(builder, host)
}

fn golden_option<'a>(expected: &mut Vec<&'a str>, flag: &'a str, operands: &[&'a str]) {
	assert!(!forbidden_flag(flag.as_bytes()));
	assert!(flag != "--bind" || operands.get(1) != Some(&"/proc"));
	expected.push(flag);
	expected.extend_from_slice(operands);
}

fn check_sandbox_argv(
	argv: &[OsString], network: bool, supervisor: bool, bind: bool, explicit: Option<usize>,
) {
	// A complete independent golden vector makes every option position and
	// operand explicit. It also rules out additional env names/separators.
	// Compare sequentially to avoid symbolic cursor/option matching overhead.
	let mut expected = Vec::with_capacity(56);
	expected.push(if !network {
		"bwrap"
	} else if supervisor {
		"/pinned-worker"
	} else {
		"/worker"
	});
	if network {
		expected.extend_from_slice(&[
			"sandbox-exec",
			"--network",
			"public",
			"--required-host",
			"api.test",
			"--",
			"bwrap",
		]);
	}
	for flag in [
		"--die-with-parent",
		"--new-session",
		"--clearenv",
		"--unshare-user",
		"--unshare-net",
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
	] {
		golden_option(&mut expected, flag, &[]);
	}
	golden_option(&mut expected, "--ro-bind-try", &["/usr", "/usr"]);
	golden_option(&mut expected, "--dir", &["/etc"]);
	golden_option(&mut expected, "--ro-bind", &["/public/passwd", "/etc/passwd"]);
	if network {
		golden_option(&mut expected, "--ro-bind", &["@LOUPE_RESOLV_CONF@", "/etc/resolv.conf"]);
	}
	golden_option(&mut expected, "--proc", &["/proc"]);
	golden_option(&mut expected, "--dev", &["/dev"]);
	golden_option(&mut expected, "--tmpfs", &["/tmp"]);
	golden_option(&mut expected, "--tmpfs", &["/home/scanner"]);
	golden_option(&mut expected, "--setenv", &["HOME", "/home/scanner"]);
	golden_option(&mut expected, "--setenv", &["TMPDIR", "/tmp"]);
	golden_option(&mut expected, "--setenv", &["PATH", "/bin"]);
	if bind {
		golden_option(&mut expected, "--ro-bind-try", &["--cap-add", "/home/scanner/config"]);
	}
	golden_option(&mut expected, "--ro-bind", &["/repo", "/workdir"]);
	golden_option(&mut expected, "--chdir", &["/home/scanner"]);
	if let Some(index) = explicit {
		golden_option(&mut expected, "--setenv", &[ENV_NAMES[index], "--share-net"]);
	}
	expected.extend_from_slice(&["--", "/bin/true", "--cap-add", "--"]);
	assert_eq!(argv.len(), expected.len());
	for (actual, expected) in argv.iter().zip(&expected) {
		assert_eq!(actual, *expected);
	}
	#[cfg(kani)]
	std::mem::forget(expected);
}

// invariant: I9
// Symbolic network/supervisor/bind choices, with one system directory, one
// public system file and at most one extra bind. Repeating a bind cannot add
// a new flag kind. Partition the eight boolean combinations before allocating
// fixtures so CBMC need not merge unrelated heap pointers before the policy.
// Unwind 64 exceeds the largest growth copy (32) and golden vector (56).
// Fixture destruction is irrelevant to argument policy and omitted.
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(64)]
fn argv_never_contains_a_forbidden_flag() {
	let configuration: u8 = kani::any();
	kani::assume(configuration < 8);
	match configuration {
		0 => check_sandbox_case(false, false, false, None),
		1 => check_sandbox_case(false, false, true, None),
		2 => check_sandbox_case(false, true, false, None),
		3 => check_sandbox_case(false, true, true, None),
		4 => check_sandbox_case(true, false, false, None),
		5 => check_sandbox_case(true, false, true, None),
		6 => check_sandbox_case(true, true, false, None),
		_ => check_sandbox_case(true, true, true, None),
	}
	kani::cover!(configuration == 7, "supervised network with an extra bind");
	kani::cover!(configuration == 0, "default isolated sandbox");
}

fn check_sandbox_case(network: bool, supervisor: bool, bind: bool, explicit: Option<usize>) {
	let (builder, host) = sandbox_fixture(network, supervisor, bind, explicit);
	let args = [OsString::from("--cap-add"), OsString::from("--")];
	let argv = builder.argv("/bin/true", &args, &host);
	assert_eq!(argv[0], host.launcher.as_os_str());
	check_sandbox_argv(&argv, network, supervisor, bind, explicit);
	#[cfg(kani)]
	{
		std::mem::forget(argv);
		std::mem::forget(builder);
		std::mem::forget(host);
	}
}

// invariant: I3, I9
// Eight names cover ordinary/fixed names and every secret denylist entry.
// Zero or one explicit entry suffices for the per-entry name property; the
// production loop appends each additional entry by the same projection.
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(64)]
fn setenv_names_are_fixed_or_explicit() {
	let configuration: u8 = kani::any();
	kani::assume(configuration <= 8);
	match configuration {
		0 => check_sandbox_case(false, false, false, None),
		1 => check_sandbox_case(false, false, false, Some(0)),
		2 => check_sandbox_case(false, false, false, Some(1)),
		3 => check_sandbox_case(false, false, false, Some(2)),
		4 => check_sandbox_case(false, false, false, Some(3)),
		5 => check_sandbox_case(false, false, false, Some(4)),
		6 => check_sandbox_case(false, false, false, Some(5)),
		7 => check_sandbox_case(false, false, false, Some(6)),
		_ => check_sandbox_case(false, false, false, Some(7)),
	}
	kani::cover!(configuration == 0, "only fixed environment names");
	kani::cover!(configuration == 1, "ordinary explicit environment name");
	kani::cover!(configuration >= 4, "secret names require an explicit caller entry");
}

#[cfg(kani)]
fn small_value(choice: u8, tool: u8) -> Value {
	match choice {
		0 => Value::Null,
		1 => Value::String("m".into()),
		2 => Value::String("wrong".into()),
		3 => {
			let mut config = Map::new();
			config.insert("effort".into(), Value::String("low".into()));
			Value::Object(config)
		},
		4 => {
			let name = match tool {
				0 => "function",
				1 => "web_fetch",
				2 => "web_fetch_test",
				3 => "mcp",
				_ => "remote_mcp",
			};
			let mut item = Map::new();
			item.insert("type".into(), Value::String(name.into()));
			Value::Array(vec![Value::Object(item)])
		},
		5 => Value::Array(vec![]),
		_ => Value::Array(vec![Value::Null]),
	}
}

// invariant: I10
// Up to three symbolic keys from six names; seven shapes include malformed
// configs, empty/nonempty server lists and all provider-side tool classes.
// The real inner object policy is called; S1 covers wire parsing/serialization.
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(20)]
fn request_policy_fixes_model_and_effort() {
	let claude: bool = kani::any();
	let configured_model = if kani::any() { "m" } else { "configured" };
	let configured_effort = if kani::any() { "low" } else { "high" };
	let backend = if claude {
		ModelBrokerBackend::Claude {
			model: configured_model.into(),
			effort: configured_effort.into(),
		}
	} else {
		ModelBrokerBackend::Codex {
			model: configured_model.into(),
			effort: configured_effort.into(),
		}
	};
	let keys = ["mcp_servers", "model", "other", "output_config", "reasoning", "tools"];
	let count: usize = kani::any();
	kani::assume(count <= 3);
	let chosen_keys: [usize; 3] = kani::any();
	let mut object = Map::new();
	for index in 0..count {
		let key = chosen_keys[index];
		// JSON objects have unique keys; sorted insertion represents every
		// such object without repeatedly dropping overwritten fixture values.
		kani::assume(key < keys.len());
		if index > 0 {
			kani::assume(chosen_keys[index - 1] < key);
		}
		let value: u8 = kani::any();
		let tool: u8 = kani::any();
		kani::assume(value <= 6 && tool <= 4);
		object.insert(keys[key].into(), small_value(value, tool));
	}
	let denied_servers = match object.get("mcp_servers") {
		None => false,
		Some(Value::Array(items)) => !items.is_empty(),
		Some(_) => true,
	};
	let denied_tool = object.get("tools").and_then(Value::as_array).is_some_and(|tools| {
		tools.iter().any(|tool| match tool.get("type").and_then(Value::as_str) {
			Some("web_fetch" | "web_fetch_test") => true,
			Some("mcp" | "remote_mcp") => !claude,
			_ => false,
		})
	});
	let mut value = Value::Object(object);
	let result = apply_request_policy(&mut value, &backend);
	assert_eq!(result.is_err(), denied_servers || denied_tool);
	if result.is_ok() {
		assert_eq!(value.get("model").and_then(Value::as_str), Some(configured_model));
		let field = if claude { "output_config" } else { "reasoning" };
		assert_eq!(
			value.get(field).and_then(|v| v.get("effort")).and_then(Value::as_str),
			Some(configured_effort)
		);
	}
	kani::cover!(denied_servers, "nonempty or malformed MCP server list is denied");
	kani::cover!(denied_tool && !denied_servers, "provider-side tool is denied");
	kani::cover!(matches!(result, Ok(false)), "already matching request preserves wire bytes");
	kani::cover!(matches!(result, Ok(true)) && claude, "Claude policy repairs the request");
	kani::cover!(matches!(result, Ok(true)) && !claude, "Codex policy repairs the request");
	std::mem::forget(value);
	std::mem::forget(backend);
}

#[test]
fn bounded_sandbox_golden_cases_match_launch_policy() {
	for network in [false, true] {
		for supervisor in [false, true] {
			for bind in [false, true] {
				check_sandbox_case(network, supervisor, bind, None);
			}
		}
	}
	check_sandbox_case(false, false, false, None);
	for index in 0..ENV_NAMES.len() {
		check_sandbox_case(false, false, false, Some(index));
	}
}
