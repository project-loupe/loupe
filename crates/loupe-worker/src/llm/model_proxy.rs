//! Credential-free loopback adapter used inside an agent sandbox.
//!
//! The adapter accepts a bounded set of local TCP connections and relays
//! each to the per-job model broker Unix socket. It has no provider
//! destination or credential of its own.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::net::{TcpListener, UnixStream};
use tokio::task::JoinSet;

const MAX_BROKER_CONNECTIONS: usize = 16;

#[derive(Debug)]
pub struct ModelProxy {
	listener: TcpListener,
	socket_path: PathBuf,
}

impl ModelProxy {
	pub async fn bind(socket_path: PathBuf, listen: SocketAddr, port_file: &Path) -> Result<Self> {
		if !listen.ip().is_loopback() {
			anyhow::bail!("model proxy listener must use a loopback address");
		}
		let listener = TcpListener::bind(listen)
			.await
			.with_context(|| format!("binding model proxy at {listen}"))?;
		let local_addr = listener.local_addr().context("reading model proxy listener address")?;
		tokio::fs::write(port_file, format!("{}\n", local_addr.port()))
			.await
			.with_context(|| format!("writing model proxy port file at {}", port_file.display()))?;
		Ok(Self { listener, socket_path })
	}

	pub fn local_addr(&self) -> SocketAddr {
		self.listener.local_addr().expect("bound model proxy listener has an address")
	}

	pub fn base_url(&self) -> String {
		format!("http://{}", self.local_addr())
	}

	pub async fn relay(self) -> Result<()> {
		let mut connections = JoinSet::new();
		loop {
			tokio::select! {
				biased;
				Some(result) = connections.join_next(), if !connections.is_empty() => {
					match result.context("model proxy connection task panicked")? {
						Ok(()) => {},
						Err(error) => tracing::debug!(%error, "model proxy client connection ended"),
					}
				},
				accepted = self.listener.accept() => {
					let (tcp, peer) = accepted.context("accepting model API connection")?;
					if !peer.ip().is_loopback() {
						anyhow::bail!("model proxy refused a non-loopback peer");
					}
					if connections.len() >= MAX_BROKER_CONNECTIONS {
						tracing::warn!(limit = MAX_BROKER_CONNECTIONS, "model proxy connection limit reached");
						continue;
					}
					let unix = UnixStream::connect(&self.socket_path).await.with_context(|| {
						format!("connecting model broker socket at {}", self.socket_path.display())
					})?;
					connections.spawn(relay_connection(tcp, unix));
				},
			}
		}
	}
}

async fn relay_connection(mut tcp: tokio::net::TcpStream, mut unix: UnixStream) -> Result<()> {
	tokio::io::copy_bidirectional(&mut tcp, &mut unix)
		.await
		.context("relaying model API connection")?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use std::net::{IpAddr, Ipv4Addr, SocketAddr};

	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::net::{TcpStream, UnixListener};

	use super::*;

	#[tokio::test]
	async fn relays_multiple_loopback_connections_to_the_job_socket() {
		let scratch = tempfile::tempdir().unwrap();
		let socket = scratch.path().join("broker.sock");
		let unix = UnixListener::bind(&socket).unwrap();
		let echo = tokio::spawn(async move {
			for _ in 0..2 {
				let (mut stream, _) = unix.accept().await.unwrap();
				let mut request = [0; 4];
				stream.read_exact(&mut request).await.unwrap();
				assert_eq!(&request, b"ping");
				stream.write_all(b"pong").await.unwrap();
			}
		});

		let port_file = scratch.path().join("model.port");
		let proxy = ModelProxy::bind(
			socket,
			SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
			&port_file,
		)
		.await
		.unwrap();
		let address = proxy.local_addr();
		assert_eq!(std::fs::read_to_string(&port_file).unwrap(), format!("{}\n", address.port()));
		let relay = tokio::spawn(proxy.relay());

		for _ in 0..2 {
			let mut client = TcpStream::connect(address).await.unwrap();
			client.write_all(b"ping").await.unwrap();
			let mut response = [0; 4];
			client.read_exact(&mut response).await.unwrap();
			assert_eq!(&response, b"pong");
			client.shutdown().await.unwrap();
		}

		echo.await.unwrap();
		relay.abort();
		let _ = relay.await;
	}

	#[tokio::test]
	async fn refuses_a_non_loopback_listener() {
		let scratch = tempfile::tempdir().unwrap();
		let error = ModelProxy::bind(
			scratch.path().join("unused.sock"),
			"0.0.0.0:0".parse().unwrap(),
			&scratch.path().join("model.port"),
		)
		.await
		.expect_err("the credential-free adapter must remain sandbox-local");
		assert!(error.to_string().contains("loopback"), "unexpected error: {error:#}");
	}
}
