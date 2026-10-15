# Local validation and campaigns

Run `ci/check.sh` before committing. `ci/check.sh --full` also runs
`sh fuzz/test-harness.sh`, committed corpus replay, generator checks,
available Kani proofs and ignored integration tests. The Rust checks need
stable and nightly toolchains. Workspace enumeration requires `jq`.
Sandbox integration tests require Bubblewrap (`bwrap`), `curl`, `mawk`,
and permission to create unprivileged user namespaces. On Ubuntu, install
the test dependencies with `sudo apt-get install bubblewrap curl jq mawk`.
These sandbox tests are mandatory and use scripted clients and local servers.
The CI runner grants `/usr/bin/bwrap` user namespace access through its
AppArmor profile and checks sandbox startup before compiling the workspace.
Generator checks compare files before and after regeneration, so correct
staged additions pass locally. With `CI=true`, generated files must also
match `HEAD` and have no untracked additions.

The existing `test (stable)` CI job invokes the same normal gate, including
production lint and boundary self-tests, per-crate checks and nightly negative
API doctests. Its stable toolchain remains the default; nightly is selected
explicitly for formatting and doctests. The separate fuzz-replay job checks
saved inputs and generated runners. The fuzz job selects one registered target
at random, excluding smoke, and runs it for five minutes on every push and PR.
Build time is additional; crashes fail the job and are uploaded as artifacts.
Scheduled Kani runs retain their bounded wrapper and selected fast harnesses.
Full local verification additionally requires the worker image's toolchains
for the five ignored build checks.

Campaign scripts require Bash, GNU coreutils (`timeout`, `nice`, `date`),
and util-linux (`flock`, `setsid`, `taskset`). Fuzzing needs `cargo-fuzz`
and nightly; Kani needs `cargo-kani`. `ci/tooling-selftest.sh` exercises
the scripts with disposable fixtures and stub tools, without compiling or
starting a real campaign. It checks member selection, locks, status reporting,
build paths, retry behavior, and shutdown of spawned processes.
Every normal check also enforces the unsafe-code allowlist, package lint
inheritance, visible Rust sources and build scripts, and the absence of fuzz
dependencies in product crates. `ci/gate-selftest.sh` exercises real compiler
bypass attempts on each run. These checks are mandatory; the former
`LOUPE_GATE_UNSAFE` opt-in no longer controls them.
The derived-`Debug` gate covers every product crate by default. A derive needs
an adjacent `// debug-ok: <reason>` explaining its closed/scalar fields or
redacted children. The scanner recognizes multiline attributes and accepts
reasons only from actual Rust line comments; literal text cannot grant an
exception. `LOUPE_DEBUG_GATE_CRATES` no longer narrows the checked crates.

Production Clippy runs separately on every workspace library and binary,
denying `unwrap_used`, `expect_used`, `string_slice`, `mem_forget`, `dbg_macro`,
`todo`, `unimplemented` and `disallowed_methods`. Crate-root attributes also
apply those denials outside test builds. The dedicated invocation covers
future members even if their root omits the attributes. The existing
all-target pass keeps the deferred test lint policy; the workspace baseline
allows `disallowed_methods` because its configured method list would otherwise
warn in test targets too. Production attributes and command-line denials
override that baseline. `ci/production-lint-selftest.sh` compiles all eight
violation classes, aliases and UFCS against the real policy, and checks a
reviewed call, an adjacent unreviewed call, and deferred test fixtures.
See [BOUNDARIES.md](BOUNDARIES.md) for the API list's scope and reviewed owners.

The normal gate also rejects production calls or qualified references to
`forward_env` until sandbox values carry provenance. It strips Rust comments
and literals and skips explicitly `#[cfg(test)]`-gated items; calls after a
test module remain checked. This is a source convention check, with deliberately
obscured macro expansion or name resolution still subject to review.

`ci/env.sh` defaults build output to `/tmp/cargo-target-loupe-<branch>`;
continuous campaigns use `/tmp/cargo-target-loupe-<kind>-<branch>`. An
explicit `CARGO_TARGET_DIR` wins. Supply a fresh task-specific directory
under `/tmp` when starting a new task. Compiler concurrency defaults to six
jobs and is capped at six; the continuous fuzzer always uses one.

`LOUPE_LOCAL` defaults to the invoking worktree's `.local` directory and
holds persistent corpus, detached worktrees and logs. Locks live separately
under `LOUPE_LOCK_DIR`, default `/tmp/loupe-locks-<uid>`, so every worktree
uses the same locks. Keep this setting consistent across processes that
must coordinate. Kani may override its slot directory using
`LOUPE_KANI_LOCK_DIR` for compatibility with other repositories.

`ci/fuzz.sh <target> [seconds]` serializes short campaigns on `fuzz.lock`.
The default is 120 seconds, with a 2 GiB libFuzzer RSS limit and a wall-time
allowance for compilation. Timeout sends TERM, then KILL after 30 seconds.

`ci/fuzz-continuous.sh [branch]` runs one campaign per repository and also
owns a lock for its branch. Another start exits 3. It uses a separate lock
from short campaigns, runs at niceness 19 on `LOUPE_FUZZ_CPU` (default the
last numbered core), and rotates targets in 300-second slices. Set the CPU
explicitly when another campaign occupies that core. Corpus and rotation
state survive restarts. Branch changes are picked up between slices.

Fuzz state lives under `$LOUPE_LOCAL/fuzz-continuous`. `FOUND.log` records
new artifacts with commit, target and path; `FAILED.log` records timeouts,
build failures and setup errors with their exit status and log path.
`progress.log` distinguishes clean slices and finds. Failed builds retain
the current target and retry after `LOUPE_FUZZ_RETRY` seconds (default 30),
refreshing the branch before retrying. Empty target lists also wait.

`ci/kani-continuous.sh [branch]` owns a branch singleton lock and uses
`ci/kani.sh` for the machine-wide slots (default and maximum two), address-space
limit (default and maximum 12 GiB), and per-harness timeout. Environment
variables and `--mem-gb` may lower these ceilings; larger values exit 2
before starting tools. Its state lives under
`$LOUPE_LOCAL/kani-continuous`. It records wrapper failures even if no
verdict was printed, and retries unsuccessful tips after `LOUPE_KANI_POLL`
seconds (default 120). Successful tips wait for the branch to change.
An exit status of zero counts as a proof only with an explicit successful
verification verdict and at least one cover property, with every cover
satisfied. Kani's overall success alone does not exclude unreachable covers.
Missing verdicts and failed checks remain failures.
The wrapper enables Kani's explicit per-proof stubbing feature. Harness
attributes name any replaced dependency; these substitutions and their
limits must be stated alongside the invariant and bounds.

To stop a campaign, send TERM to its script PID and wait for it to exit;
for a shell-started background process, use `kill -TERM "$campaign_pid"`
then `wait "$campaign_pid"`. Shutdown signals the active process group,
allows five seconds for cleanup, then kills remaining members and reaps
the direct child before releasing the locks. Each Kani harness owns a separate
group, which is cleaned before the next harness runs. Under a continuous
campaign, the Kani wrapper uses a shorter two-second cleanup grace so its
compiler and solver stop before the parent's escalation. Restart only after
that wait completes, using the
same local-state and lock directories. Review `FOUND.log` and `FAILED.log`
before each commit batch and handoff.
