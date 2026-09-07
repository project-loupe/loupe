# Releasing Loupe

All eight crates share the workspace release version. Update
`workspace.package.version`, every versioned `loupe-*` dependency, and
`Cargo.lock` together, and add the release notes to `CHANGELOG.md`.

## Validate the release

Run these commands from the workspace root. Use Rust 1.88 or newer for builds;
the workspace publication commands below use Cargo 1.95 or newer. Formatting
requires nightly Rust.

The Docker build uses `rust:1.88.0-bookworm` for compilation, then copies the
binaries into Debian Trixie runtime images (`debian:trixie-slim` for the server
and `node:22-trixie-slim` for the worker). The runtime images do not need Rust.
Building directly on a Trixie host still requires Rust 1.88 or newer.

```sh
export CARGO_TARGET_DIR="$(mktemp -d /tmp/cargo-target-loupe-release-XXXXXX)"
cargo +nightly fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo publish --workspace --dry-run --locked
```

The publication dry run packages and builds every crate without uploading it.
Inspect the archives under `$CARGO_TARGET_DIR/package`: each must contain its
README and both license texts, and `loupe-web` must include its `assets/` files.
Keep each crate's `LICENSE-MIT` and `LICENSE-APACHE` identical to the root copies.

Run the cross-crate integration tests from the Git checkout. The server and
worker have mutual, path-only dev-dependencies for those tests. Do not add
versions to these two edges: Cargo strips unversioned dev-dependencies from
published manifests, avoiding a circular dependency during the first release.
Their production dependencies are versioned and do not form a cycle.

## Publish

Before uploading, confirm ownership or availability of all eight crate names
on crates.io, authenticate the publishing account, and verify that the release
commit and changelog are final. A dry run does not reserve names or establish
publishing permissions.

Use `cargo publish --workspace --locked` with Cargo 1.95 or newer to publish
the crates in dependency order. For individual uploads, a valid order is:

1. `loupe-core`
2. `loupe-tls`
3. `loupe-proto`
4. `loupe-storage`
5. `loupe-server`
6. `loupe-worker`
7. `loupe-cli`
8. `loupe-web`

Wait for each dependency to become available on crates.io before publishing
its dependents. Publish all crates at the same release version.
