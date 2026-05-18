ARG RUST_VERSION=1.88.0

FROM rust:${RUST_VERSION}-bookworm AS app-builder
WORKDIR /src
RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		ca-certificates \
		cmake \
		libssl-dev \
		make \
		perl \
		pkg-config \
		zlib1g-dev \
	&& rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p loupe-server -p loupe-worker -p loupe-cli

FROM rust:${RUST_VERSION}-bookworm AS bkb-mcp-builder
ARG BKB_MCP_VERSION=0.2.0
RUN cargo install bkb-mcp --version "${BKB_MCP_VERSION}" --locked

FROM debian:bookworm-slim AS loupe-server
# No `ca-certificates` here: loupe-server's only outbound TLS is the
# GitHub reporter, which uses reqwest + rustls with webpki-roots
# compiled into the binary (see workspace Cargo.toml). Sendmail is
# local. Worker / admin mTLS pins the private loupe CA explicitly.
RUN apt-get update \
	&& apt-get install -y --no-install-recommends tini \
	&& rm -rf /var/lib/apt/lists/* \
	&& useradd --uid 10001 --user-group --home-dir /var/lib/loupe --create-home --shell /usr/sbin/nologin loupe
COPY --from=app-builder /src/target/release/loupe-server /usr/local/bin/loupe-server
COPY --from=app-builder /src/target/release/loupectl /usr/local/bin/loupectl
COPY contrib/docker/loupe-container-entrypoint.sh /usr/local/bin/loupe-container-entrypoint
RUN chmod 0755 /usr/local/bin/loupe-container-entrypoint \
	&& install -d -o loupe -g loupe -m 0700 /var/lib/loupe /run/loupe
USER loupe
WORKDIR /var/lib/loupe
ENV LOUPE_BIND=0.0.0.0:8443 \
	LOUPE_DB=/var/lib/loupe/loupe.sqlite
EXPOSE 8443
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/loupe-container-entrypoint"]
CMD ["loupe-server", "serve"]

FROM node:22-bookworm-slim AS loupe-worker
ARG CLAUDE_CODE_VERSION=latest
ARG CODEX_VERSION=latest
ARG INSTALL_CLAUDE=1
ARG INSTALL_CODEX=1
ENV NPM_CONFIG_AUDIT=false \
	NPM_CONFIG_FUND=false \
	NPM_CONFIG_UPDATE_NOTIFIER=false
RUN apt-get update \
	&& apt-get install -y --no-install-recommends bubblewrap ca-certificates git tini \
	&& rm -rf /var/lib/apt/lists/* \
	&& if [ "$INSTALL_CLAUDE" = "1" ]; then npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}"; fi \
	&& if [ "$INSTALL_CODEX" = "1" ]; then npm install -g "@openai/codex@${CODEX_VERSION}"; fi \
	&& useradd --uid 10002 --user-group --home-dir /var/lib/loupe-worker --create-home --shell /usr/sbin/nologin loupe-worker
COPY --from=app-builder /src/target/release/loupe-worker /usr/local/bin/loupe-worker
COPY --from=bkb-mcp-builder /usr/local/cargo/bin/bkb-mcp /usr/local/bin/bkb-mcp
COPY contrib/docker/loupe-container-entrypoint.sh /usr/local/bin/loupe-container-entrypoint
RUN chmod 0755 /usr/local/bin/loupe-container-entrypoint \
	&& install -d -o loupe-worker -g loupe-worker -m 0700 /var/lib/loupe-worker /var/cache/loupe-worker /run/loupe
USER loupe-worker
WORKDIR /var/lib/loupe-worker
ENV HOME=/var/lib/loupe-worker
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/loupe-container-entrypoint"]
CMD ["loupe-worker", "run"]
