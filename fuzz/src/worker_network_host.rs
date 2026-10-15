//! Raw UTF-8 host bytes; no DNS or processes are invoked.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use loupe_worker::sandbox::{fuzzing, validate_network_host, SandboxNetworkMode};

use crate::utils::test_logger;

pub fn do_test(data: &[u8]) {
	if data.len() > 16 * 1024 {
		return;
	}
	if let Ok(host) = std::str::from_utf8(data) {
		assert_eq!(
			validate_network_host(host).is_ok(),
			allowed(host),
			"network hostname acceptance disagrees with RFC 1123 oracle"
		);
	}
	check_rules(data);
}

fn check_rules(data: &[u8]) {
	let addresses: Vec<Ipv4Addr> =
		data.as_chunks::<4>().0.iter().take(48).copied().map(Ipv4Addr::from).collect();
	let allowed: BTreeSet<_> = addresses.iter().step_by(3).copied().collect();
	let blocked: BTreeSet<_> = addresses.iter().skip(1).step_by(3).copied().collect();
	let routes: BTreeSet<_> = addresses
		.iter()
		.skip(2)
		.step_by(3)
		.map(|address| format!("{address}/{}", address.octets()[3] % 33))
		.collect();
	for mode in [SandboxNetworkMode::Allowlist, SandboxNetworkMode::Public] {
		let actual = fuzzing::network_policy(mode, &allowed, &routes, &blocked);
		let mut lines = vec![
			"table inet loupe_sandbox {".to_owned(),
			"\tchain output {".to_owned(),
			format!(
				"\t\ttype filter hook output priority filter; policy {};",
				if mode == SandboxNetworkMode::Public { "accept" } else { "drop" }
			),
			"\t\toifname \"lo\" accept".into(),
			"\t\tip daddr 10.0.2.3 udp dport 53 accept".into(),
			"\t\tip daddr 10.0.2.3 tcp dport 53 accept".into(),
			"\t\tct state established,related accept".into(),
		];
		lines.extend(allowed.iter().map(|address| format!("\t\tip daddr {address} accept")));
		if mode == SandboxNetworkMode::Public {
			for route in [
				"0.0.0.0/8",
				"10.0.0.0/8",
				"100.64.0.0/10",
				"127.0.0.0/8",
				"169.254.0.0/16",
				"172.16.0.0/12",
				"192.168.0.0/16",
				"198.18.0.0/15",
				"224.0.0.0/4",
				"240.0.0.0/4",
			] {
				lines.push(format!("\t\tip daddr {route} reject"));
			}
			lines.extend(routes.iter().map(|route| format!("\t\tip daddr {route} reject")));
			lines.extend(blocked.iter().map(|address| format!("\t\tip daddr {address} reject")));
			lines.push("\t\tip6 daddr ::/0 reject".into());
		} else {
			lines.push("\t\treject".into());
		}
		lines.extend(["\t}".into(), "}".into(), String::new()]);
		assert_eq!(actual, lines.join("\n"), "network policy differs from golden rule set");
		assert!(
			actual.bytes().all(|byte| byte.is_ascii_lowercase()
				|| byte.is_ascii_digit()
				|| b"./: ,;{}\n\t\"_".contains(&byte)),
			"unexpected nft syntax byte"
		);
	}
}

pub(crate) fn allowed(host: &str) -> bool {
	let host = host.trim();
	if host.is_empty() || host.len() > 253 {
		return false;
	}
	// Every canonical IPv4 address also meets the hostname grammar. Numeric
	// dotted names which are not IPv4 are also valid DNS names.
	host.as_bytes().split(|byte| *byte == b'.').all(|label| {
		(1..=63).contains(&label.len())
			&& label.first().is_some_and(u8::is_ascii_alphanumeric)
			&& label.last().is_some_and(u8::is_ascii_alphanumeric)
			&& label.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
	})
}

pub fn worker_network_host_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// # Safety
/// `data` must point to `datalen` readable bytes for the duration of this call.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn worker_network_host_run(data: *const u8, datalen: usize) {
	// SAFETY: the caller provides readable bytes for the duration of this call.
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
