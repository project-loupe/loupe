//! Per-operation Git authentication on the trusted host. Only the private
//! socket and helper stdout carry credential bytes; Git/kernel copies are
//! outside the owned-buffer erasure guarantee.

use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use loupe_provenance::{Secret, Zeroise};
use rustix::event::{poll, PollFd, PollFlags};

const FRAME_LIMIT: usize = 16 * 1024;
const TOKEN_LIMIT: usize = 8 * 1024;
const IO_DEADLINE: Duration = Duration::from_secs(3);
const CONNECTION_LIMIT: usize = 16;
const QUIT: &[u8] = b"quit=true\n\n";

struct Destination {
	host: String,
	port: u16,
	path: String,
}

impl Destination {
	fn parse(raw: &str) -> Result<(String, Option<Self>)> {
		if raw.is_empty()
			|| raw.starts_with('-')
			|| raw.bytes().any(|b| b.is_ascii_control())
			|| raw.contains('\\')
		{
			bail!("invalid Git destination");
		}
		let is_http = raw.get(..7).is_some_and(|s| s.eq_ignore_ascii_case("http://"));
		let is_https = raw.get(..8).is_some_and(|s| s.eq_ignore_ascii_case("https://"));
		if !is_http && !is_https {
			// Keep local and SSH CLI transport. A supplied PAT is rejected
			// separately unless a validated HTTPS destination is present.
			return Ok((raw.to_owned(), None));
		}
		let (_, rest) = raw.split_once("://").context("invalid Git destination")?;
		let authority = rest.split('/').next().unwrap_or_default();
		if authority.contains('@') {
			bail!("Git destination contains userinfo");
		}
		let url =
			reqwest::Url::parse(raw).map_err(|_| anyhow::anyhow!("invalid Git destination"))?;
		if url.query().is_some() || url.fragment().is_some() || url.host_str().is_none() {
			bail!("invalid Git destination");
		}
		let raw_path = rest.get(authority.len()..).unwrap_or_default();
		let path = decode_path(raw_path).context("invalid Git repository path")?;
		if path.is_empty() || path.split('/').any(|part| matches!(part, "." | "..")) {
			bail!("invalid Git repository path");
		}
		#[allow(
			clippy::unwrap_used,
			reason = "The host was checked above; this HTTPS branch always has the standard port when omitted."
		)]
		let destination = is_https.then(|| Self {
			host: url.host_str().unwrap().to_owned(),
			port: url.port_or_known_default().unwrap(),
			path,
		});
		Ok((url.to_string(), destination))
	}

	fn matches(&self, frame: &[u8]) -> bool {
		let Some(context) = CredentialContext::parse(frame) else {
			return false;
		};
		if context.protocol != "https" || context.host.contains(['/', '@', '?', '#', '\\']) {
			return false;
		}
		let Ok(authority) = reqwest::Url::parse(&format!("https://{}", context.host)) else {
			return false;
		};
		authority.host_str() == Some(self.host.as_str())
			&& authority.port_or_known_default() == Some(self.port)
			// Git has already percent-decoded this field. Decoding again
			// would broaden the authority for a repository containing '%'.
			&& context.path.trim_matches('/') == self.path
	}
}

fn decode_path(raw: &str) -> Option<String> {
	let mut bytes = Vec::with_capacity(raw.len());
	let mut input = raw.as_bytes().iter().copied();
	while let Some(byte) = input.next() {
		let byte = if byte == b'%' {
			let hi = char::from(input.next()?).to_digit(16)?;
			let lo = char::from(input.next()?).to_digit(16)?;
			(hi * 16 + lo) as u8
		} else {
			byte
		};
		if byte.is_ascii_control() || byte == b'\\' {
			return None;
		}
		bytes.push(byte);
	}
	Some(String::from_utf8(bytes).ok()?.trim_matches('/').to_owned())
}

struct CredentialContext<'a> {
	protocol: &'a str,
	host: &'a str,
	path: &'a str,
}

impl<'a> CredentialContext<'a> {
	fn parse(frame: &'a [u8]) -> Option<Self> {
		if frame.len() > FRAME_LIMIT {
			return None;
		}
		let text = std::str::from_utf8(frame).ok()?.strip_suffix("\n\n")?;
		let (mut protocol, mut host, mut path) = (None, None, None);
		for line in text.split('\n') {
			if line.bytes().any(|b| b.is_ascii_control()) {
				return None;
			}
			let (key, value) = line.split_once('=')?;
			if key.is_empty() {
				return None;
			}
			let field = match key {
				"protocol" => &mut protocol,
				"host" => &mut host,
				"path" => &mut path,
				_ => continue,
			};
			if field.replace(value).is_some() || value.is_empty() {
				return None;
			}
		}
		Some(Self { protocol: protocol?, host: host?, path: path? })
	}
}

/// Mutable, fixed-allocation protocol input: Git's store/erase requests and
/// the helper response can contain credentials. No reallocation or printable
/// representation is offered; the full allocation is wiped on every exit.
struct WireBuffer {
	bytes: Vec<u8>,
	len: usize,
}

impl WireBuffer {
	fn read(fd: &impl AsFd, deadline: Instant, git_eof: bool) -> io::Result<Self> {
		let mut frame = Self { bytes: vec![0; FRAME_LIMIT], len: 0 };
		loop {
			ready(fd, PollFlags::IN, deadline)?;
			let count =
				rustix::io::read(fd, &mut frame.bytes[frame.len..]).map_err(io::Error::from)?;
			if count == 0 {
				// Git closes helper stdin after a single final newline. The
				// private socket protocol uses an explicit blank terminator.
				if git_eof && frame.len > 0 && frame.len + 2 <= FRAME_LIMIT {
					if frame.bytes[frame.len - 1] != b'\n' {
						frame.bytes[frame.len] = b'\n';
						frame.len += 1;
					}
					frame.bytes[frame.len] = b'\n';
					frame.len += 1;
					return Ok(frame);
				}
				return Err(io::ErrorKind::UnexpectedEof.into());
			}
			frame.len += count;
			if let Some(end) = frame.bytes[..frame.len].windows(2).position(|p| p == b"\n\n") {
				if end + 2 != frame.len {
					return Err(io::ErrorKind::InvalidData.into());
				}
				return Ok(frame);
			}
			if frame.len == FRAME_LIMIT {
				return Err(io::ErrorKind::InvalidData.into());
			}
		}
	}

	fn expose(&self) -> &[u8] {
		&self.bytes[..self.len]
	}
}

impl Drop for WireBuffer {
	fn drop(&mut self) {
		self.bytes.zeroise();
	}
}

fn ready(fd: &impl AsFd, events: PollFlags, deadline: Instant) -> io::Result<()> {
	loop {
		let remaining =
			deadline.checked_duration_since(Instant::now()).ok_or(io::ErrorKind::TimedOut)?;
		let timeout = rustix::event::Timespec {
			tv_sec: remaining.as_secs() as _,
			tv_nsec: remaining.subsec_nanos() as _,
		};
		match poll(&mut [PollFd::new(fd, events)], Some(&timeout)) {
			Ok(0) => return Err(io::ErrorKind::TimedOut.into()),
			Ok(_) => return Ok(()),
			Err(rustix::io::Errno::INTR) => {},
			Err(error) => return Err(error.into()),
		}
	}
}

fn write(fd: &impl AsFd, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
	while !bytes.is_empty() {
		ready(fd, PollFlags::OUT, deadline)?;
		// Keep pipe writes below PIPE_BUF after poll signals capacity.
		let count =
			rustix::io::write(fd, &bytes[..bytes.len().min(1024)]).map_err(io::Error::from)?;
		if count == 0 {
			return Err(io::ErrorKind::WriteZero.into());
		}
		bytes = &bytes[count..];
	}
	Ok(())
}

struct Session {
	_dir: tempfile::TempDir,
	// Keep the original allocation alive even after the listener's cap.
	_token: Arc<Secret<String>>,
	socket: PathBuf,
	stop: Arc<AtomicBool>,
	thread: Option<JoinHandle<()>>,
}

impl Session {
	fn start(destination: Destination, token: Arc<Secret<String>>) -> Result<Self> {
		// Explicit host /tmp: never honor a TMPDIR that could be a sandbox
		// bind, repository, or the persistent cache. Sandboxes get fresh /tmp.
		let dir =
			tempfile::Builder::new().prefix("loupe-git-").rand_bytes(22).tempdir_in("/tmp")?;
		#[allow(
			clippy::disallowed_methods,
			reason = "The credential owner restricts its fresh private temporary directory to the owner."
		)]
		std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
		let socket = dir.path().join("credential.sock");
		let listener = UnixListener::bind(&socket)?;
		#[allow(
			clippy::disallowed_methods,
			reason = "The credential owner restricts its freshly bound local socket to the owner."
		)]
		std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
		listener.set_nonblocking(true)?;
		let stop = Arc::new(AtomicBool::new(false));
		let stopping = stop.clone();
		let retained_token = token.clone();
		let thread =
			std::thread::Builder::new().name("git-credential".into()).spawn(move || {
				let mut connections = 0;
				while !stopping.load(Ordering::Acquire) && connections < CONNECTION_LIMIT {
					match listener.accept() {
						Ok((stream, _)) => {
							connections += 1;
							let deadline = Instant::now() + IO_DEADLINE;
							let accepted = WireBuffer::read(&stream, deadline, false)
								.is_ok_and(|request| destination.matches(request.expose()));
							if accepted {
								// Borrow the PAT directly into the authentication pipe;
								// no intermediate String or encoded URL owns another copy.
								let _ =
									write(&stream, b"username=x-access-token\npassword=", deadline)
										.and_then(|()| {
											write(&stream, token.expose().as_bytes(), deadline)
										})
										.and_then(|()| write(&stream, b"\n\n", deadline));
							} else {
								let _ = write(&stream, QUIT, deadline);
							}
						},
						Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
							std::thread::sleep(Duration::from_millis(10))
						},
						Err(_) => break,
					}
				}
			})?;
		Ok(Self { _dir: dir, _token: retained_token, socket, stop, thread: Some(thread) })
	}
}

impl Drop for Session {
	fn drop(&mut self) {
		self.stop.store(true, Ordering::Release);
		if let Some(thread) = self.thread.take() {
			let _ = thread.join();
		}
	}
}

pub(crate) struct GitCredentialOperation {
	pub(crate) url: String,
	session: Option<Session>,
	helper: Option<PathBuf>,
}

impl GitCredentialOperation {
	pub(crate) fn new(
		url: &str, token: Option<Arc<Secret<String>>>, helper: Option<&Path>,
	) -> Result<Self> {
		let (url, destination) = Destination::parse(url)?;
		let session = if let Some(token) = token {
			let destination = destination.context("Git PAT requires HTTPS")?;
			let helper = helper.context("Git credential helper is unavailable")?;
			if !helper.is_absolute() || helper.to_str().is_none() {
				bail!("invalid Git credential helper path");
			}
			// The credential protocol is line-oriented; validate once before
			// starting either process, borrowing the retained secret owner.
			if token.expose().is_empty()
				|| token.expose().len() > TOKEN_LIMIT
				|| token.expose().bytes().any(|b| b.is_ascii_control())
			{
				bail!("invalid Git credential");
			}
			Some(Session::start(destination, token).context("starting Git credential helper")?)
		} else {
			None
		};
		Ok(Self { url, session, helper: helper.map(Path::to_owned) })
	}

	pub(crate) fn command(&self) -> Command {
		#[allow(
			clippy::disallowed_methods,
			reason = "GitCredentialOperation owns the fixed Git command and clears inherited credential configuration."
		)]
		let mut command = Command::new("git");
		command.env_clear();
		// Preserve ordinary Git transport/config discovery explicitly. In
		// particular no GIT_TRACE*, GIT_CONFIG_PARAMETERS/COUNT, askpass,
		// worker credential variables, or curl verbose settings survive.
		for name in [
			"PATH",
			"HOME",
			"XDG_CONFIG_HOME",
			"GIT_CONFIG_GLOBAL",
			"GIT_CONFIG_SYSTEM",
			"GIT_CONFIG_NOSYSTEM",
			"GIT_SSL_CAINFO",
			"SSL_CERT_FILE",
			"SSL_CERT_DIR",
			"SSH_AUTH_SOCK",
			"http_proxy",
			"https_proxy",
			"no_proxy",
			"HTTP_PROXY",
			"HTTPS_PROXY",
			"NO_PROXY",
		] {
			if let Some(value) = std::env::var_os(name) {
				command.env(name, value);
			}
		}
		command
			.env("GIT_TERMINAL_PROMPT", "0")
			.env("GIT_ASKPASS", "/bin/false")
			.env("SSH_ASKPASS", "/bin/false");
		for config in [
			"credential.helper=",
			"credential.useHttpPath=true",
			"core.askPass=/bin/false",
			"http.followRedirects=false",
			"trace2.normalTarget=0",
			"trace2.eventTarget=0",
			"trace2.perfTarget=0",
		] {
			command.args(["-c", config]);
		}
		self.configure_urls(&mut command, None);
		command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
		command
	}

	fn install_helper(&self, command: &mut Command) {
		if let (Some(session), Some(helper)) = (&self.session, &self.helper) {
			#[allow(
				clippy::expect_used,
				reason = "The selected helper path was explicitly validated as UTF-8 during operation construction."
			)]
			let helper = shell_quote(helper.to_str().expect("validated helper"));
			#[allow(
				clippy::expect_used,
				reason = "The socket path is created under literal /tmp with an ASCII random basename."
			)]
			let socket = shell_quote(session.socket.to_str().expect("private ASCII socket path"));
			command.args([
				"-c",
				&format!("credential.helper=!{helper} git-credential --socket {socket}"),
			]);
		}
	}

	fn configure_urls(&self, command: &mut Command, pinned: Option<(&str, &str)>) {
		let mut config = vec![
			(format!("http.{}.followRedirects", self.url), "false".to_owned()),
			(format!("credential.{}.useHttpPath", self.url), "true".to_owned()),
		];
		if let Some((effective, alias)) = pinned {
			config.extend([
				(format!("http.{effective}.followRedirects"), "false".to_owned()),
				(format!("credential.{effective}.useHttpPath"), "true".to_owned()),
				(format!("url.{effective}.insteadOf"), alias.to_owned()),
				// Git's empty URL value resets the merged list before clone
				// selects origin; inherited entries must not precede our pin.
				("remote.origin.url".to_owned(), String::new()),
				("remote.origin.url".to_owned(), alias.to_owned()),
			]);
		}
		// Only validated URL/socket metadata enters these owned variables.
		// Separate keys/values preserve '=' in URL paths; `-c key=value`
		// would split such a key incorrectly. Inherited config env is gone.
		command.env("GIT_CONFIG_COUNT", config.len().to_string());
		for (index, (key, value)) in config.into_iter().enumerate() {
			command.env(format!("GIT_CONFIG_KEY_{index}"), key);
			command.env(format!("GIT_CONFIG_VALUE_{index}"), value);
		}
	}

	pub(crate) fn transport_command(&self, directory: Option<&Path>) -> Result<(Command, String)> {
		let mut command = self.command();
		if let Some(directory) = directory {
			command.current_dir(directory);
		}
		let Some(session) = &self.session else {
			return Ok((command, self.url.clone()));
		};
		let effective = self.effective_url(directory)?;
		#[allow(
			clippy::unwrap_used,
			reason = "The private tempfile directory created by Session always has its generated basename."
		)]
		let alias = format!(
			"loupe-git://{}/repository",
			session._dir.path().file_name().unwrap().to_string_lossy()
		);
		// Git applies insteadOf once, choosing the longest matching prefix.
		// An unpredictable complete alias outranks inherited prefix rules,
		// including includes discovered only after clone creates its repo.
		self.configure_urls(&mut command, Some((&effective, &alias)));
		self.install_helper(&mut command);
		Ok((command, alias))
	}

	fn effective_url(&self, directory: Option<&Path>) -> Result<String> {
		// This local projection does no network I/O and has no helper. It
		// resolves only the current clean URL, never a stored legacy origin.
		let mut command = self.command();
		if let Some(directory) = directory {
			command.current_dir(directory);
		}
		#[allow(
			clippy::disallowed_methods,
			reason = "Local Git URL projection uses the credential owner's cleared environment and bounded stdout reader."
		)]
		let mut child = command
			.args(["ls-remote", "--get-url", "--", &self.url])
			.stdout(Stdio::piped())
			.spawn()
			.context("starting Git URL projection")?;
		let deadline = Instant::now() + IO_DEADLINE;
		#[allow(
			clippy::expect_used,
			reason = "This newly spawned projection command explicitly pipes stdout and has not taken it."
		)]
		let output =
			WireBuffer::read(child.stdout.as_ref().expect("piped Git output"), deadline, true);
		if output.is_err() {
			let _ = child.kill();
			let _ = child.wait();
			bail!("Git URL projection output failed");
		}
		let status = loop {
			match child.try_wait() {
				Ok(Some(status)) => break status,
				Ok(None) if Instant::now() < deadline => {
					std::thread::sleep(Duration::from_millis(10))
				},
				_ => {
					let _ = child.kill();
					let _ = child.wait();
					bail!("Git URL projection did not complete");
				},
			}
		};
		if !status.success() {
			bail!("Git URL projection failed ({status})");
		}
		#[allow(
			clippy::expect_used,
			reason = "The error branch above returns after killing and reaping the child."
		)]
		let output = output.expect("checked projection output");
		let raw = std::str::from_utf8(output.expose())
			.ok()
			.and_then(|text| text.strip_suffix("\n\n"))
			.context("invalid Git URL projection")?;
		validate_projection(raw)?;
		let _ = Destination::parse(raw)?;
		// Validation must not reserialize this URL: Git's HTTP URL matching
		// distinguishes reserved escapes such as %2F from literal '/'.
		Ok(raw.to_owned())
	}
}

fn uri_byte(bytes: &mut std::str::Bytes<'_>) -> Result<Option<u8>> {
	let Some(byte) = bytes.next() else { return Ok(None) };
	if byte != b'%' {
		return Ok(Some(byte));
	}
	let hex = |byte: u8| char::from(byte).to_digit(16);
	let hi = bytes.next().and_then(hex).context("invalid Git URL projection escape")?;
	let lo = bytes.next().and_then(hex).context("invalid Git URL projection escape")?;
	Ok(Some((hi * 16 + lo) as u8))
}

// Inspect borrowed bytes before making URL metadata copies. Git decodes URI
// escapes once, but leaves SCP/local spellings literal. Reject ambiguous URI
// forms more strictly than Git; never report the rejected text.
fn validate_projection(raw: &str) -> Result<()> {
	let uri = raw.split_once("://").filter(|(scheme, _)| {
		!scheme.is_empty()
			&& scheme.bytes().enumerate().all(|(index, byte)| {
				byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'+' | b'-' | b'.'))
			})
	});
	if let Some((scheme, rest)) = uri {
		let authority = rest.split('/').next().unwrap_or_default();
		let mut bytes = authority.bytes();
		let mut first = true;
		let mut bracket_open = false;
		while let Some(byte) = uri_byte(&mut bytes)? {
			if byte == b'@' {
				bail!("Git URL projection contains userinfo");
			}
			if byte.is_ascii_control() || matches!(byte, b'/' | b'\\' | b'?' | b'#') {
				bail!("invalid Git URL projection authority");
			}
			match byte {
				b'[' if first => bracket_open = true,
				b']' if bracket_open => bracket_open = false,
				b'[' | b']' => bail!("invalid Git URL projection authority"),
				_ => {},
			}
			first = false;
		}
		if bracket_open {
			bail!("invalid Git URL projection authority");
		}
		if matches!(scheme, "ssh" | "git+ssh" | "ssh+git") {
			// Git's native SSH host_end searches the whole decoded remainder
			// for "@[" before splitting off the path. Refuse this cross-path
			// host syntax while permitting ordinary '@' in repository paths.
			let mut bytes = rest.bytes();
			let mut previous = None;
			while let Some(byte) = uri_byte(&mut bytes)? {
				if byte.is_ascii_control() {
					bail!("invalid Git URL projection escape");
				}
				if previous == Some(b'@') && byte == b'[' {
					bail!("Git URL projection contains userinfo");
				}
				previous = Some(byte);
			}
		}
	} else if let Some((prefix, _)) = raw.split_once(':') {
		// A slash before the first colon denotes a local path. Local and
		// SCP paths are never percent-decoded by Git's transport parser.
		if !prefix.contains('/') {
			#[allow(
				clippy::string_slice,
				reason = "The closing bracket is an ASCII byte found by str::find, so its end is a UTF-8 boundary."
			)]
			let host_end = if raw.starts_with('[') {
				let close = raw.find(']').context("invalid Git URL projection authority")?;
				close
					+ 1
					+ raw[close + 1..].find(':').context("invalid Git URL projection authority")?
			} else {
				prefix.len()
			};
			#[allow(
				clippy::string_slice,
				reason = "The endpoint is an ASCII delimiter position returned by str::find or split_once."
			)]
			if raw[..host_end].contains('@') || raw.contains("@[") {
				bail!("Git URL projection contains userinfo");
			}
		}
	}
	Ok(())
}

fn shell_quote(text: &str) -> String {
	format!("'{}'", text.replace('\'', "'\\''"))
}

fn connect(socket: &Path, deadline: Instant) -> io::Result<UnixStream> {
	use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
	let fd = rustix::net::socket_with(
		AddressFamily::UNIX,
		SocketType::STREAM,
		SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
		None,
	)?;
	match rustix::net::connect(&fd, &SocketAddrUnix::new(socket)?) {
		Ok(()) => {},
		Err(rustix::io::Errno::INPROGRESS) => {
			ready(&fd, PollFlags::OUT, deadline)?;
			rustix::net::sockopt::socket_error(&fd)??;
		},
		// A full Unix backlog returns EAGAIN. Fail closed immediately;
		// a blocking connect would evade the credential I/O deadline.
		Err(error) => return Err(error.into()),
	}
	Ok(UnixStream::from(fd))
}

/// Internal worker mode. It deliberately loads no worker configuration or
/// tracing and accepts no credential in arguments or environment.
#[doc(hidden)]
pub fn run_git_credential_helper(socket: &Path, operation: &str) {
	let result = (|| -> io::Result<()> {
		let deadline = Instant::now() + IO_DEADLINE;
		let request = WireBuffer::read(&io::stdin(), deadline, true)?;
		match operation {
			"store" | "erase" => Ok(()),
			"get" => {
				let stream = connect(socket, deadline)?;
				write(&stream, request.expose(), deadline)?;
				let response = WireBuffer::read(&stream, deadline, false)?;
				// Handoff into Git's credential pipe. This allocation
				// is wiped after the direct write, including error exits.
				write(&io::stdout(), response.expose(), deadline)
			},
			_ => Err(io::ErrorKind::InvalidInput.into()),
		}
	})();
	if result.is_err() && operation == "get" {
		let _ = write(&io::stdout(), QUIT, Instant::now() + IO_DEADLINE);
	}
}

#[cfg(fuzzing)]
pub(crate) fn matches_context(url: &str, frame: &[u8]) -> bool {
	Destination::parse(url)
		.ok()
		.and_then(|(_, destination)| destination)
		.is_some_and(|destination| destination.matches(frame))
}

#[cfg(test)]
mod tests {
	use super::*;

	const URL: &str = "https://example.invalid/acme/repo.git";
	const REQUEST: &[u8] = b"protocol=https\nhost=example.invalid\npath=acme/repo.git\n\n";

	#[test]
	fn destination_is_exact_and_uses_git_decoded_path() {
		let (_, expected) =
			Destination::parse("HTTPS://EXAMPLE.INVALID:443/acme/repo%2Egit/").unwrap();
		let expected = expected.unwrap();
		assert!(expected.matches(REQUEST));
		assert!(expected.matches(
			b"protocol=https\nhost=example.invalid:443\npath=/acme/repo.git/\nusername=ignored\n\n"
		));
		for frame in [
			b"protocol=http\nhost=example.invalid\npath=acme/repo.git\n\n".as_slice(),
			b"protocol=https\nhost=other.invalid\npath=acme/repo.git\n\n",
			b"protocol=https\nhost=example.invalid:444\npath=acme/repo.git\n\n",
			b"protocol=https\nhost=example.invalid\npath=acme/repo.git/child\n\n",
			b"protocol=https\nhost=example.invalid\npath=acme/repo%2Egit\n\n",
			b"protocol=https\nhost=example.invalid\npath=acme/repo.git\nhost=other.invalid\n\n",
			b"protocol=https\nhost=example.invalid\n\n",
			b"protocol=https\nhost=example.invalid\npath=acme/repo.git\r\n\n",
			b"protocol=https\nhost=example.invalid\npath=acme/repo.git\0\n\n",
			b"protocol=https\nhost=example.invalid\npath=acme/repo.git\n\nignored=yes\n\n",
		] {
			assert!(!expected.matches(frame));
		}
	}

	#[test]
	fn ambiguous_destinations_and_invalid_tokens_fail_closed() {
		for url in [
			"https://user:password@example.invalid/a/b",
			"http://@example.invalid/a/b",
			"https://example.invalid/a/../b",
			"https://example.invalid/a/%2e%2E/b",
			"https://example.invalid/a%00b",
			"https://example.invalid/a%0Ab",
			"https://example.invalid/a%5Cb",
			"https://example.invalid/a%GGb",
			"https://example.invalid/a?b=c",
			"https://example.invalid/a#b",
			"https://example.invalid",
			"-upload-pack=unsafe",
			"https://example.invalid/a\nb",
		] {
			assert!(Destination::parse(url).is_err(), "accepted {url}");
		}
		for value in ["", "line\nbreak", "carriage\rreturn", "zero\0byte"] {
			assert!(GitCredentialOperation::new(
				URL,
				Some(Arc::new(Secret::new(value.into()))),
				Some(Path::new("/bin/false"))
			)
			.is_err());
		}
		assert!(GitCredentialOperation::new(
			URL,
			Some(Arc::new(Secret::new("x".repeat(TOKEN_LIMIT + 1)))),
			Some(Path::new("/bin/false"))
		)
		.is_err());
		for url in ["http://example.invalid/a/b", "file:///tmp/repo", "/tmp/repo"] {
			assert!(GitCredentialOperation::new(
				url,
				Some(Arc::new(Secret::new("token".into()))),
				Some(Path::new("/bin/false"))
			)
			.is_err());
		}
	}

	#[test]
	fn command_has_no_secret_and_uses_only_private_helper() {
		let token = Arc::new(Secret::new("command-canary".to_owned()));
		let operation =
			GitCredentialOperation::new(URL, Some(token), Some(Path::new("/tmp/worker's helper")))
				.unwrap();
		let mut command = operation.command();
		operation.install_helper(&mut command);
		let args: Vec<_> = command.get_args().map(|a| a.to_string_lossy()).collect();
		let rendered = args.join(" ");
		assert!(!rendered.contains("command-canary"));
		assert!(rendered.contains("credential.helper= -c"));
		assert!(rendered.contains("'worker") || rendered.contains("worker'\\''s helper'"));
		assert!(command.get_envs().any(|(key, value)| key == "GIT_CONFIG_KEY_0"
			&& value.is_some_and(
				|value| value == "http.https://example.invalid/acme/repo.git.followRedirects"
			)));
		for (name, value) in command.get_envs() {
			assert!(!name.to_string_lossy().starts_with("GIT_TRACE"));
			assert!(!value.is_some_and(|v| v.to_string_lossy().contains("command-canary")));
		}
	}

	#[test]
	fn session_is_private_bounded_and_releases_owner() {
		let token = Arc::new(Secret::new("session-canary".to_owned()));
		let weak = Arc::downgrade(&token);
		let operation =
			GitCredentialOperation::new(URL, Some(token), Some(Path::new("/bin/false"))).unwrap();
		let socket = operation.session.as_ref().unwrap().socket.clone();
		let parent = socket.parent().unwrap();
		assert_eq!(std::fs::metadata(parent).unwrap().permissions().mode() & 0o777, 0o700);
		assert_eq!(std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777, 0o600);
		assert!(parent.parent().is_some_and(|path| path == Path::new("/tmp")));
		for index in 0..CONNECTION_LIMIT {
			let stream = UnixStream::connect(&socket).unwrap();
			let deadline = Instant::now() + IO_DEADLINE;
			let request = if index == 0 {
				REQUEST
			} else {
				b"protocol=http\nhost=example.invalid\npath=acme/repo.git\n\n"
			};
			write(&stream, request, deadline).unwrap();
			let response = WireBuffer::read(&stream, deadline, false).unwrap();
			if index == 0 {
				assert!(response.expose().ends_with(b"password=session-canary\n\n"));
			} else {
				assert_eq!(response.expose(), QUIT);
			}
		}
		let deadline = Instant::now() + Duration::from_secs(1);
		while !operation.session.as_ref().unwrap().thread.as_ref().unwrap().is_finished() {
			assert!(Instant::now() < deadline, "connection cap did not stop the listener");
			std::thread::sleep(Duration::from_millis(10));
		}
		assert!(weak.upgrade().is_some(), "connection cap dropped the live Git credential owner");
		// Dropping joins the bounded owner thread before unlinking the socket.
		drop(operation);
		assert!(!socket.exists());
		assert!(!parent.exists());
		assert!(UnixStream::connect(&socket).is_err());
		assert!(weak.upgrade().is_none());
	}

	#[test]
	fn partial_frame_has_a_deadline_and_oversize_is_rejected() {
		let (reader, writer) = UnixStream::pair().unwrap();
		write(&writer, b"protocol=", Instant::now() + IO_DEADLINE).unwrap();
		let started = Instant::now();
		assert!(WireBuffer::read(&reader, started + Duration::from_millis(50), false).is_err());
		assert!(started.elapsed() < Duration::from_secs(1));
		write(&writer, &vec![b'x'; FRAME_LIMIT], Instant::now() + IO_DEADLINE).unwrap();
		assert!(WireBuffer::read(&reader, Instant::now() + IO_DEADLINE, false).is_err());
	}
}
