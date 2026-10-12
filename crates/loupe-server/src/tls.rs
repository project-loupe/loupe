use anyhow::{Context, Result};
use loupe_tls::server_config;
use rustls::ServerConfig;

use crate::Config;

/// Build the rustls server config from the PEM material in [`Config`].
pub fn build(cfg: &Config) -> Result<ServerConfig> {
	server_config(
		cfg.server_cert_pem.expose(),
		cfg.server_key_pem.expose(),
		cfg.ca_cert_pem.expose(),
	)
	.context("building loupe-server rustls config")
}
