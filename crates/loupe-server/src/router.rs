use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::routing::get;
use axum::Router;
use hyper::body::Incoming;
use hyper::Request;
use hyper_util::rt::TokioIo;
use loupe_proto::{PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER};
use rustls::pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;
use tower::Service;

use crate::state::AppState;
use crate::{routes, tls, Config};

/// Request extension carrying the peer's leaf certificate (DER bytes), if
/// the connection presented one. The auth middleware (added in a later
/// commit) reads this to identify the worker; route handlers should not
/// touch it directly.
#[derive(Debug, Clone)]
pub struct PeerCert(pub CertificateDer<'static>);

/// Build the axum `Router` for the server. Pure function — exposed so
/// integration tests can mount it without spinning up TLS.
pub fn router(state: AppState) -> Router {
	Router::new().route("/v1/health", get(routes::health::get)).with_state(state).layer(
		axum::middleware::from_fn(|req, next: axum::middleware::Next| async move {
			let mut resp = next.run(req).await;
			resp.headers_mut().insert(
				PROTOCOL_VERSION_HEADER,
				PROTOCOL_VERSION.to_string().parse().expect("u16 parses as header value"),
			);
			resp
		}),
	)
}

/// Handle returned by [`serve`]. Drop or call `shutdown` to stop the
/// server.
pub struct ServeHandle {
	pub local_addr: SocketAddr,
	shutdown_tx: Option<oneshot::Sender<()>>,
	join: Option<tokio::task::JoinHandle<()>>,
}

impl ServeHandle {
	pub async fn shutdown(mut self) {
		if let Some(tx) = self.shutdown_tx.take() {
			let _ = tx.send(());
		}
		if let Some(join) = self.join.take() {
			let _ = join.await;
		}
	}
}

/// Bind to `cfg.bind_addr` and serve over mTLS. Returns once the listener
/// is bound so callers can read `local_addr` synchronously.
pub async fn serve(cfg: Config, state: AppState) -> Result<ServeHandle> {
	let rustls_cfg = tls::build(&cfg)?;
	let acceptor = TlsAcceptor::from(Arc::new(rustls_cfg));
	let listener = TcpListener::bind(cfg.bind_addr).await.context("binding loupe-server")?;
	let local_addr = listener.local_addr().context("local_addr on bound listener")?;
	let app = router(state);

	let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
	let join = tokio::spawn(serve_loop(listener, acceptor, app, shutdown_rx));

	Ok(ServeHandle { local_addr, shutdown_tx: Some(shutdown_tx), join: Some(join) })
}

async fn serve_loop(
	listener: TcpListener, acceptor: TlsAcceptor, app: Router,
	mut shutdown_rx: oneshot::Receiver<()>,
) {
	loop {
		tokio::select! {
			biased;
			_ = &mut shutdown_rx => {
				tracing::debug!("loupe-server: shutdown signal received");
				return;
			}
			res = listener.accept() => {
				match res {
					Ok((sock, peer_addr)) => {
						tokio::spawn(handle_connection(acceptor.clone(), sock, peer_addr, app.clone()));
					}
					Err(e) => {
						tracing::warn!(error = %e, "accept failed");
					}
				}
			}
		}
	}
}

async fn handle_connection(
	acceptor: TlsAcceptor, sock: tokio::net::TcpStream, peer_addr: SocketAddr, app: Router,
) {
	let tls_stream = match acceptor.accept(sock).await {
		Ok(s) => s,
		Err(e) => {
			tracing::debug!(peer = %peer_addr, error = %e, "tls handshake failed");
			return;
		},
	};

	let peer_cert = tls_stream
		.get_ref()
		.1
		.peer_certificates()
		.and_then(|certs| certs.first())
		.map(|c| PeerCert(c.clone().into_owned()));

	let io = TokioIo::new(tls_stream);

	// Wrap the axum service in a per-connection layer that injects the
	// peer cert into request extensions before the router dispatches.
	let svc = hyper::service::service_fn(move |mut req: Request<Incoming>| {
		if let Some(cert) = peer_cert.clone() {
			req.extensions_mut().insert(cert);
		}
		let mut app = app.clone();
		async move {
			let resp = match app.call(req).await {
				Ok(r) => r,
				Err(e) => match e {},
			};
			Ok::<_, std::convert::Infallible>(resp)
		}
	});

	if let Err(e) = hyper::server::conn::http1::Builder::new().serve_connection(io, svc).await {
		tracing::debug!(peer = %peer_addr, error = %e, "connection terminated");
	}
}
