use anyhow::Result;
use rustls::ServerConfig;

use crate::Config;

/// Build the rustls server config from the PEM material in [`Config`].
pub fn build(cfg: &Config) -> Result<ServerConfig> {
	cfg.build_tls()
}
