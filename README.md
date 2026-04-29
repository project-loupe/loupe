# loupe

A security-scanning harness for GitHub repositories.

`loupe-server` manages a registry of repositories and a queue of scan jobs;
`loupe-worker` processes leases jobs, clones the target repo, runs scanners
(LLM agents, fuzzers, linters), and submits findings back. Findings can
optionally be cross-checked by additional verifier jobs before being
reported via GitHub issues (and later, email or pull requests).

## Building

```
cargo build --workspace
cargo test --workspace
```

The workspace currently has no member crates — code lands in subsequent
commits.

## Continuous integration

GitHub Actions (`.github/workflows/ci.yml`) runs three jobs on every push
and pull request:

- **fmt** — `cargo fmt --all -- --check` on a nightly toolchain (the
  `rustfmt.toml` uses nightly-only options).
- **clippy** — `cargo clippy --workspace --all-targets --all-features
  -- -D warnings` on stable.
- **test** — `cargo test --workspace --all-targets` on stable.
