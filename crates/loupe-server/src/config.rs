use std::net::SocketAddr;
use std::path::PathBuf;

/// Server configuration. Populated by `loupe-server`'s clap parser; lives
/// here so integration tests can construct one directly without going
/// through env / CLI.
#[derive(Debug, Clone)]
pub struct Config {
	pub bind_addr: SocketAddr,
	pub db_path: PathBuf,
	pub server_cert_pem: String,
	pub server_key_pem: String,
	pub ca_cert_pem: String,
	pub ca_key_pem: String,
}
