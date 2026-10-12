# Fuzzing

The rule the harness enforces:

> Every function that consumes bytes which originated outside the
> process has a fuzz target, and the target is written in the same
> change as the function.

"Outside the process" for Loupe means: a worker's request to the server
(and the agent text inside it), an operator's request, a server's
response to a worker, everything that crosses the sandbox boundary (the
MCP socket, the model-proxy socket, the CLI's output, the export
directory), the repository under review (file contents, paths, `git`
output), model-provider and report-destination responses, rows read
back from the database, and configuration. Being authenticated does not
make a source trusted: a worker that logged in is still a host that can
be compromised, and the agent text it relays is hostile by definition.

Layout:

- `fuzz/` (this crate, `loupe-fuzz`): one module per target in `src/`,
  each exposing `do_test(&[u8])`, `<name>_test(&[u8], Output)` and an
  `extern "C" <name>_run` for external fuzzers.
- `fuzz/runners/` (`loupe-fuzz-runners`): one generated binary per
  target in `src/bin/`, selecting the engine by feature:
  `afl_fuzz`, `honggfuzz_fuzz`, `libfuzzer_fuzz`, `stdin_fuzz`.
- `fuzz/src/bin/gen_target.sh` and `target_template.txt`: generate the
  runner binaries. CI fails if the generated files are stale.
- `fuzz/test_cases/<target>/`: committed inputs. Every runner binary has
  a `#[test]` that replays them, so `cargo test` in `runners/` is the
  regression suite for every crash ever found.
- `fuzz/src/utils/`: `test_logger` (output sinks), `input` (a bounded
  byte cursor for stateful targets), `arb` (structure-aware input over
  Loupe's own types) and `redact` (comparison with a fixed redacted
  rendering for the same public metadata).
- `fuzz/targets.h`: C prototypes of the `_run` entry points, for
  fuzzers driving the static library directly.

## Running

Corpus commands below run from `fuzz/`; `ci/` commands run from the repository
root. The `fuzzing` cfg is required so product
crates can swap deterministic stand-ins for randomness and time when
they need to.

Set `CARGO_TARGET_DIR` to a task-specific directory under `/tmp` before
running Cargo directly. The `ci/` wrappers choose one when it is unset.
`sh test-harness.sh` checks the generated C header, removal of stale
runners, and refusal to replay a missing corpus. It uses a private copy
under `/tmp` and never moves the real seeds.

Replay committed cases (this is also what CI's `fuzz-replay` job runs):

```sh
RUSTFLAGS="--cfg=fuzzing" cargo test --lib
RUSTFLAGS="--cfg=fuzzing" cargo test --manifest-path runners/Cargo.toml --features stdin_fuzz --bins
```

libFuzzer needs nightly and cargo-fuzz. This host uses the installed tool in
`/tmp/cargo-home/bin`. From the repository root:

```sh
export PATH="/tmp/cargo-home/bin:$PATH"
ci/fuzz.sh core_text_bounded_target 120
```

Run short campaigns through `ci/fuzz.sh <name>_target [seconds]`: it takes the
machine-wide fuzz lock, seeds from
`test_cases/`, and applies the RSS and wall-time caps. If the link step
fails under the release profile's LTO, `ci/fuzz.sh` already sets
`CARGO_PROFILE_RELEASE_LTO=false`. Run one campaign at a time.

Continuous fuzzing: `ci/fuzz-continuous.sh [branch]` cycles through
every target on the branch in a fixed rotation with an equal time slice
each (`LOUPE_FUZZ_SLICE`, 300 s), resuming where it stopped, with a
persistent corpus per target under `$LOUPE_LOCAL/fuzz-continuous/`. It
is pinned to one CPU core (`LOUPE_FUZZ_CPU`, default the last) at the
lowest priority and does not take the fuzz lock. New crash inputs are
listed in `FOUND.log`; each one is triaged and fixed with a regression
test and the input committed as a seed, in one commit, on the branch
where it was found. The campaign starts as soon as the first targets
exist and keeps running while the rest of the work goes on.

The runner refreshes the committed branch tip and target list between slices;
uncommitted integration work is never its input. Restart the process after
changing its scripts. Its singleton lock prevents a second continuous process
for this repository. Keep the default shared lock directory; choosing another
directory would bypass host coordination.

### Continuous runbook

The initial implementation uses branch `2026-10-security-first`, worktree
`/home/tnull/worktrees/loupe/2026-10-security-harness`, CPU15, nice19 and
300-second slices. Before starting on another host, select an available CPU.
From that worktree, the detached launch used is:

```sh
export PATH="/tmp/cargo-home/bin:$PATH"
mkdir -p .local
setsid -f bash -c '
  echo $$ > .local/fuzz-continuous.pid
  exec env CARGO_TARGET_DIR=/tmp/cargo-target-loupe-fuzz-continuous-2026-10-security-first \
    LOUPE_FUZZ_CPU=15 LOUPE_FUZZ_SLICE=300 \
    ci/fuzz-continuous.sh 2026-10-security-first
' </dev/null >>.local/fuzz-launch.log 2>&1
```

The PID file identifies the launch. Check its current command before sending
a signal, since an old PID file can outlive its process:

```sh
campaign_pid=$(cat .local/fuzz-continuous.pid)
ps -p "$campaign_pid" -o pid,psr,ni,args
# After verifying that this is the campaign shown above:
kill -TERM "$campaign_pid"
```

The wrapper terminates its active child process group too. Wait for it to exit
before relaunching. Logs and corpus survive; do not delete them to obtain a
clean status. The active paths under the worktree are:

| Path | Contents |
|---|---|
| `.local/fuzz-continuous/progress.log` | Commit, target, result and log for completed slices |
| `.local/fuzz-continuous/FOUND.log` | Newly discovered crash artifacts, if any |
| `.local/fuzz-continuous/FAILED.log` | Timeouts, build failures and other unsuccessful slices |
| `.local/fuzz-continuous/last-<target>.log` | Most recent build and execution output for that target |
| `.local/fuzz-continuous/corpus/<target>/` | Persistent seed and generated corpus |
| `.local/fuzz-continuous/crashes/<target>/` | Preserved crashing inputs |
| `.local/wt/fuzz-2026-10-security-first/` | Detached checkout of the committed input |

Record the commit and exact input for each finding. Reproduce it through the
stdin runner, distinguish product bugs from bad test oracles, and preserve the
failing input and pre-fix assertion before repairing it. A TIMEOUT is not a
clean run: the whole-command watchdog includes initial compilation. Preserve
its log before a retry overwrites `last-<target>.log`, then repeat the slice
after determining whether compilation or the input exhausted the budget.

### Other engines and reproduction

honggfuzz and AFL++ work through the same runner features
(`cargo hfuzz run`, `cargo afl fuzz`); see the engines' own
documentation. honggfuzz needs binutils development headers (`bfd.h`).

From `fuzz/`, reproduce a crash from bytes, no files needed:

```sh
printf '\x02\x05\x00\x01' | RUSTFLAGS="--cfg=fuzzing" \
  cargo run --manifest-path runners/Cargo.toml --features stdin_fuzz --bin smoke_target
```

Panics abort the process (`panic = "abort"`), so a non-zero exit is the
signal. To keep a crash as a regression test, write the bytes to
`test_cases/<name>/<anything>` and commit it.

## Adding a target

1. Copy `src/smoke.rs` to `src/<name>.rs`, replace `smoke` with
   `<name>` in the three function names, write `do_test`.
2. Add `pub mod <name>;` to `src/lib.rs`, and the product crate to
   `Cargo.toml` if it is new.
3. Add `GEN_TEST <name>` to `src/bin/gen_target.sh` (alphabetical) and
   run it.
4. Put at least one valid input and one malformed input under
   `test_cases/<name>/`.
5. Add the file to `ci/unsafe-allow.txt` (the C entry point is
   `unsafe`), and run `ci/fuzz.sh <name>_target 120` before committing;
   record the run in the commit message ("fuzzed clean: N runs, M
   edges").

Names are `<crate>_<thing>` (`core_text_bounded`, `worker_mcp_rpc`).

## What a target should assert

Beyond "no panic": round trip (decode, re-encode, decode again,
compare), bounded output (output size is a function of input size with
a known constant), redaction (`format!("{:?}")` of a decoded value
matches its documented redacted rendering: `utils::redact::assert_redacted`),
and for renderers "no escape" (agent text appears only inside its
delimited block or fence). For stateful targets, that every state
transition is reachable only through the documented API. A target that
only checks for crashes is the minimum, not the goal.

For a fixed metadata shape, `Redaction::baseline` stores the exact expected
rendering. This avoids accidental matches between a payload and fixed text
such as `[redacted]`, and detects an extra leaked copy of those same bytes.
Types with variable public metadata must construct a matching baseline or
check their documented output directly. Do not exclude payload substrings
merely because those substrings also occur in the fixed template.

Two input shapes: a byte cursor (`utils::input::ByteSource`) for
parsers, where the attacker controls bytes; and `arbitrary` over
Loupe's own types (`utils::arb`) for typed, stateful targets
(transition sequences, policy snapshots, tool calls), which the fuzzer
mutates far better when it sees the structure. Both read the same raw
bytes, so corpus files stay plain files.

## Dependencies

The fuzz workspace is not a product workspace: `ci/gates.sh
gate_no_tool_deps` refuses a product crate that depends on it. Its own
dependencies are `arbitrary` (structure-aware input; maintained by the
rust-fuzz organisation, the same as `cargo-fuzz` and `libfuzzer-sys`)
and `serde_json` (already a product dependency). Anything else needs a
sentence here saying why.

`unicode-general-category` and `unicode-normalization` let text targets
independently check character categories and NFC instead of calling the
validator being tested. They use the same Unicode data as the product.

`blake3` cross-checks digest bytes. `serde_json/preserve_order` is enabled
only in the fuzz workspace to expose insertion order: otherwise its sorted
map would mask a missing sort in the production canonicalizer.

`serde` supports independent duplicate-preserving JSON trees in the budget
oracle, before any map insertion could discard repeated keys.

`loupe-storage` is a path dependency so the source-reference target exercises
the persisted aggregate's actual constructor and parser, without opening a
database. Symbol and canonicalization behavior compose the core validators
already covered by their own independent targets.

`loupe-proto` exercises the actual public wire DTOs and protocol negotiation.
`subtle` compares capability bytes in constant time; capability-bearing DTOs
compare their public fields only after replacing both capabilities with a
fixed public value. Debug checks compare exact field-matched baselines.

`loupe-tls` exercises the production certificate, key and trust-root loaders.
`sha2` checks that worker fingerprints hash the exact supplied DER bytes.
`base64` provides a reference decoder/encoder for guarded PEM input and export
byte transfers; that comparison does not independently verify base64 itself.
The PEM pair in `fixtures/` is deliberately public test material, never an
authentication credential. Seeds vary each PEM field independently.

`loupe-server` exposes the pure parsers used by its actual request handlers.
`http` constructs capability headers independently of the route machinery;
header admission includes HTAB and exactly 43 bytes, without an alphabet
restriction. Accepted bytes are checked against their BLAKE3 hash.

`tempfile` isolates the actual configuration loader's files. `toml` supplies
an independent value tree for checking relative path resolution and accepted
root keys after that loader succeeds.

`loupe-http` owns the shared 16 MiB response-body budget. `loupe-worker`,
`reqwest` and `tokio` let the response target call real worker client methods
against loopback chunked HTTP. It checks all four typed responses and errors,
including exact-budget and oversized streams without Content-Length.

`loupe-cli` exposes the actual terminal renderer for plain and colored detail,
list and search output. Its oracle permits only intentional styling and
layout controls, while requiring visible spellings of input controls.

`loupe-web`, `axum` and `tower` exercise the dashboard's actual router with
an isolated loopback upstream. The target verifies capability and browser
header guards, counts upstream requests, and requires variable diagnostics
to remain inside JSON envelopes.

The canonical target found a float parsing drift on
`-9223372036855078478`: parsing serialized bytes changed their next
serialization and digest. The product enables `serde_json/float_roundtrip`
to make retransmission stable. The original input and a unit regression
remain committed; existing integer and canonical fixed vectors still apply.

The initial lockfile uses `arbitrary` 1.5.0 and `libfuzzer-sys` 0.4.13.
`arbitrary` is confined to this unpublished workspace: derive it for local
input models that select product operations, rather than adding fuzz-only
traits to production types. For parsers, pass the original bytes directly;
for a sequence of operations, consume `ByteSource` or `Unstructured` until
exhaustion, with an explicit operation/allocation bound.

The first verified toolchain was stable Rust 1.95.0, nightly 1.97.0
(`b954122bb`, 2026-05-20), and cargo-fuzz 0.13.2. This host installs Cargo
tools in `/tmp/cargo-home/bin`, which must be on `PATH`; it has no `bfd.h`,
so libFuzzer is the active engine. Corpus replay needs neither that engine
nor nightly. The smoke campaign completed 7,554,177 runs with 34 covered
edges, and malformed-corpus checks were verified to fail before repair.

The ingress backlog below was checked against main `db99745` before adding
targets. The source inventory includes response accounting, repository
metadata, source discovery and network command output; these are parsing
boundaries even when their producer is authenticated or runs locally.

## Targets and coverage

Implemented targets (each corpus includes valid and malformed inputs):

| Target | Assertions |
|---|---|
| `cli_render` | Control escaping, exact visible text, intentional ANSI styling, row/column integrity and extreme timestamps |
| `core_canonical` | Independent sorted serialization, reordered/whitespace-equivalent JSON, idempotence, bounded output and BLAKE3 digest |
| `core_state_machine` | Independent adjacency/precedence tables, terminal exits only through documented operator retries; SQL permutation/scope invariant covered in storage tests |
| `core_text_bounded` | All ten policies: exact admission, raw/normalized caps, NFC, character categories, whitespace and metadata-only diagnostics |
| `core_json_string` | Original JSON string tokens versus serde, exact decoded bytes, byte/scalar limits and error order, borrowed/owned output and fixed diagnostics |
| `core_text_exact` | All 17 source-aware exact policies: independent admission, decoded caps, unchanged UTF-8/wire bytes, named policy combinations and redacted diagnostics |
| `core_text_ident` | Four policies: independent byte recognizers, length/spacing limits, exact spelling and metadata-only diagnostics |
| `core_text_json` | Duplicate-preserving reference tree, depth/node/byte budgets, composed key/leaf rules, entry-point equivalence and redaction |
| `core_text_repo_path` | Strict path invariants and independent legacy DTO/MCP acceptance, preserving documented disagreements |
| `proto_dto` | All 36 public DTO types and enum variants, field-preserving round trips, capability redaction and independent LLM submission admission |
| `proto_version` | Inclusive protocol windows, inverted-window rejection and exact mismatch fields and diagnostics |
| `server_capability_header` | Exact header-text/length admission, unchanged hash bytes and closed denial diagnostics |
| `server_config` | Actual file loader, owner-list rejection, root keys, and exact relative path resolution |
| `server_github_response` | All five real response decoders, typed-serde object/sequence admission, ignored-field syntax, closed error diagnostics and credential Debug |
| `server_report_email` | Exact header boundary, CR/LF admission and finding-content isolation from headers |
| `server_report_github` | Title normalization, title/body character caps and observed S3 fence-containment cases |
| `server_request_parsers` | Protocol headers, state/kind filters, legacy clone URLs and exact FTS stripping/token admission |
| `storage_source_refs` | Independent path admission, 32/64-item limits, raw and canonical byte budgets, preserved path bytes, aggregate Debug redaction |
| `storage_identity` | Independent anchor recognition, equivalent spelling, metadata-only diagnostics, explicit identity framing and reference BLAKE3 |
| `storage_policy_snapshot` | Independent campaign-policy admission, capped retry arithmetic, phase mapping and redacted conflict errors |
| `tls_fingerprint` | Exact SHA-256 of arbitrary DER bytes and repeatability |
| `tls_input` | Actual guarded file/base64/argument owners, exact bytes, UTF-8 admission, fixed errors and redacted formatting |
| `tls_pem` | Certificate/key/root parsing, successful CA reload, direct-loader controls and shared reqwest admission against its previous constructor |
| `worker_broker_policy` | Both provider policies, denied tools and request headers, exact output reservation accounting |
| `worker_broker_usage` | Independent JSON/SSE accounting, response header filtering and an empty tracing baseline |
| `worker_config` | Actual file load/merge/validation, absolute resolved paths, model/effort/host policy and nonzero resource limits |
| `worker_extract_json` | Independent character-based balanced-span oracle, quoted braces, escapes and malformed JSON |
| `worker_mcp_rpc` | Real dispatcher/catalogues, request IDs and notifications, stateful verdict/patch order, independent finding admission and metadata-only logs |
| `worker_mcp_submission` | Independent lexical admission, existing-file containment, symlink rejection, unchanged submitted ranges and snippet clamping |
| `worker_network_host` | RFC 1123 hostname boundaries, IPv4 acceptance and complete allowlist/public nft rule templates |
| `worker_network_parsers` | Actual PID, uid_map, route and address parsers, typed-serde PID forms, identity-pair and complete-set checks |
| `worker_regex_secrets` | Actual scanner walk, independent byte-match/line oracle, size/cancellation/symlink behavior and metadata-only finding Debug |
| `worker_repo_cache` | Exact cursor magic/version/body, round trips and status/UTF-8/whitespace behavior of git origin parsing |
| `worker_sandbox_args` | Exact namespace/safety flags, supervisor framing, explicit environment names and bind operands, including flag-shaped values |
| `worker_server_response` | Actual client methods over chunked HTTP, typed response admission, exact byte budget and bounded errors |
| `worker_source_discovery` | Actual manifest/glob/exclusion parsing, canonical containment, sorted unique paths and complete known-fixture selection |
| `web_api` | Actual browser guards, no upstream call on rejected headers, JSON-enclosed diagnostics and bounded responses |

`storage_source_refs` takes one policy byte (even: 32 items, odd: 64),
followed by JSON reference bytes. Inputs up to 128 KiB exercise both sides of
the 64 KiB raw and canonical limits. The corpus includes item-count, path-byte
and serialized-size boundaries, malformed JSON and decomposed path spelling.

`storage_policy_snapshot` takes a little-endian u32 attempt count followed
by policy JSON. `BoundedJson<Payload>` applies the raw input and JSON budgets
before snapshot decoding. The oracle checks validated retry delays in u128
at the supplied count and fixed overflow boundaries; unknown job kinds must
never acquire a phase policy. This uses the same storage path dependency.

`storage_identity` takes JSON with `family`, `anchor` and optional `instance`
strings, capped at 64 KiB. Both anchor policies pass through normalization
before fingerprinting. A separate byte recognizer checks transient IDs and
location/hash exclusions; Unicode helpers check NFC, case and whitespace.
Equivalent spellings must share fingerprints, while different families must
have different framed bytes. The target does not assume collision freedom.

`proto_dto` takes one selector byte modulo 36 followed by up to 512 KiB of
JSON. The corpus covers every public DTO and enum variant, malformed JSON,
capability collisions with public Debug text, and semantic finding limits.
The independent finding oracle records the existing lexical path and diff
rules rather than imposing a new validation policy.

`proto_version` consumes six little-endian bytes for the client, minimum
and maximum u16 versions. A widened interval oracle checks both endpoints,
inverted windows and integer boundaries; shorter inputs are ignored.

`core_text_repo_path` preserves the legacy validators' different contracts.
Its corpus records nine legacy-accepted classes rejected by strict RepoPath,
plus whitespace-only input accepted by strict RepoPath but rejected by both
legacy validators. MCP's lexical core remains on the actual submission path;
filesystem containment stays separate. This target adds no path tightening.

`worker_extract_json` takes raw UTF-8 text and checks the first balanced brace
span against an independent character-based quote and escape oracle. Balanced
invalid JSON remains accepted by this retained helper, which has no production
caller. This uses the existing `loupe-worker` dependency without new libraries.

`worker_mcp_rpc` drives the actual session over bounded request bytes and
models both discovery and verification tool catalogues. Independent checks
cover valid fixture paths and line ranges, finding fields, tool identifiers,
notifications, protocol refusal, verdict/patch ordering and closed log schemas.
The corpus retains ordinary and side-fixture files, inside/outside symlinks,
malformed requests, and the two former fixture-path oracle counterexamples.

`worker_mcp_submission` consumes little-endian u32 start/end lines, a
little-endian u16 path length capped at 2048 bytes, UTF-8 path bytes and the
remaining file content. Fresh temporary directories contain an ordinary file,
an internal symlink and an escaping symlink. Fuzzed names are materialized only
inside the fixture. The existing `tempfile` and `loupe-worker` dependencies
exercise actual containment and submission code without a server or sandbox.

`server_request_parsers` selects one of five parsers with byte zero and sends
the remaining bytes to it. Bit 7 selects an absent protocol/state/kind field.
Protocol versions allow the existing unsigned-decimal leading plus; clone
URLs retain their permissive legacy grammar. See [server target contracts](SERVER-TARGETS.md)
for these parsers, configuration and reporting boundaries, including the
GitHub response target.

The report targets pass JSON findings to the actual renderers. Email input
also supplies `from`, `to` and `subject`, whose newline checks must match
admission and whose header block must stay independent of finding content.
GitHub titles are capped at 100 Unicode scalar values and body admission at
65,536. Static `escape-*` seeds preserve closing-fence escapes and a large
email body for S3; these targets do not claim containment or an email-body
cap that the current renderers do not provide.

`worker_regex_secrets` interprets byte zero as cancellation and exact/over
one-MiB file-size modes; the remaining bytes supply file content and a bounded
safe filename. Inputs are capped at 64 KiB before boundary-mode padding.
An independent byte recognizer checks every match and line number. `.git`
and escaping symlink controls must remain excluded, and finding Debug must
contain only severity and line metadata even when the filename is a secret.

`worker_source_discovery` uses byte zero for inside/outside source-root and
build-script symlinks; remaining NUL-separated fields contain root/member
Cargo manifests and an exclusion pattern. Bit 3 instead passes all remaining
bytes directly to the root manifest. A 64 KiB input cap bounds fixture work.
Known fixtures assert complete legitimate selection as well as containment;
the canonical check does not make concurrent filesystem changes atomic.
`runner::submodule_paths` remains owned by runner integration tests, including
`checkout_tolerates_submodule_gitlinks`; generated git2 tree cases remain in
that integration-test backlog.

`worker_repo_cache` passes raw bytes through the persisted cursor decoder
and the actual git-origin output parser. It preserves legacy opaque SHA and
URL strings, including the origin parser's lossy UTF-8 and whitespace trim.
It adds no stronger URL or hash grammar.

`worker_config` writes raw TOML, capped at 128 KiB, to an absolute temporary
path and calls the real loader. Independent checks cover its merge and
validation decisions, relative path resolution, host policy and resource
limits. The `url` dependency checks the configured provider endpoint's URL
shape; sandbox startup and process environment behavior remain integration
test responsibilities.

`worker_network_host` takes raw UTF-8 hosts up to 16 KiB and derives typed
IPv4 addresses/routes from the same bytes. Hostnames have at most 253 bytes,
labels of 1..63 bytes, alphanumeric edges and alphanumeric/hyphen interiors.
The complete nft output must match the golden rule template. Its tabs,
quotes and underscores belong to the fixed syntax, including the table name
and loopback rule; dynamic fields contain only typed addresses and routes.

`worker_network_parsers` uses byte zero modulo four to select PID JSON,
uid_map, connected routes or host addresses. The remaining input is capped
at 64 KiB; uid_map starts with a little-endian u32 identity. The PID oracle
independently models one required u32 field or a one-element sequence,
including duplicate refusal and ignored-field syntax. Complete route/address
sets and both uid identity columns must match their separate oracles.

The broker policy target interprets raw bytes as provider JSON, header lines
and up to 129 little-endian u64 words for output reservations. Its 128 KiB
input cap bounds harness work; widened arithmetic independently checks the
remaining output budget. The usage target accepts JSON/SSE up to the default
32 MiB output ceiling and walks parsed values iteratively to check the
saturating maximum of total tokens and input-plus-output tokens. Header
fixtures use `hyper`; `tracing` and `tracing-subscriber` capture diagnostics
and require the pure accounting and filtering paths to emit none.

`worker_sandbox_args` projects raw JSON into the real builder's command without
spawning it. It checks the complete option/operand sequence, supervisor and
bubblewrap separators, explicit environment variables and binary binds. A
separate fixture directory keeps arbitrary entrypoint names from colliding
with the package installation. Flag-shaped values remain operands in the
oracle; the target does not mistake those values for security options.

All 34 main-surface S1 targets plus smoke are registered. S3 additionally
registers `core_text_exact` for the marked exact-text policies and `tls_input`
for guarded PEM readers and exports. The former's temporary
`source-migration` dependency is removed at atomic source adoption; the target
and its independent oracle remain. Each real target has
a retained corpus, a clean short campaign and a detected guard mutation.
The broader ingress gaps below remain separate from this named target set.

## Remaining ingress and later work

The source inventory includes custom boundaries beyond the named S1 targets.
The table identifies their owners and limits; it does not claim complete
coverage merely because a nearby parser is fuzzed. Unassigned malformed-input
or resource-limit coverage remains an explicit gap in the broad ingress rule.

| Surface | Existing owner and remaining scope |
|---|---|
| git2 submodule extraction | [runner.rs](../crates/loupe-worker/src/runner.rs), `checkout_tolerates_submodule_gitlinks`, owns real gitlink-tree tests as assigned by S1 target 24b. Generated malformed-tree cases remain an integration-test backlog. |
| Clone/fetch/checkout and Git failures | [repo_cache.rs](../crates/loupe-worker/src/repo_cache.rs) and runner tests cover fetch/reclone/checkout behavior. The cursor/origin target does not cover all Git transport failures or filesystem effects; S3 owns Repo provenance and diagnostic sinks. Arbitrary failure-output coverage remains unassigned. |
| Raw database rows and secret BLOB reads | Storage round-trip/migration tests own database fixtures. The three storage targets cover named value parsers, not every row decoder or corruption error. S2 owns scope decisions; S3 owns secret holders and Db decoding. General corrupt-row parser coverage remains unassigned. |
| CLI/env/startup loaders | CLI, web-config, server-main and provider-auth tests own PEM/base64 precedence and credential loading. `tls_input` covers the shared guarded readers, not combined argv/env behavior. S3 owns Config minting and Secret migration; arbitrary combined-loader coverage remains unassigned. |
| Sendmail status/stderr and pipe interaction | [email_dispatch.rs](../crates/loupe-server/tests/email_dispatch.rs) covers successful stdin delivery; renderer tests reject header injection. No dedicated failure/backpressure target or process-output budget is specified. S3's renderer/log work alone does not establish those properties. |
| Reporter HTTP collection | GitHub HTTP integration tests and the response target own response decoding. Reporter `.bytes()`/`.text()` collection is outside L3's three clients and remains uncapped; its transport budget is an unresolved contract. S3 owns Reporter ingress. |
| CLI collection and Git diagnostics | Both CLI backend tests exercise L5's one-MiB retention, drain, head/tail and deadlines. L2 tests UTF-8-safe Git display truncation after collection, not a Git pipe-allocation limit. S3 owns labels and disclosure; bounded buffers do not imply redacted logs. |
| MCP framing and session resources | The RPC target reaches the real loop with at most 64 KiB and 32 fixture lines. Production line collection and session resources have no corresponding transport budget; this remains an unassigned resource-limit gap. S3 labels alone do not impose those limits. |
| Supervisor process output | PID, uid-map, route and address targets bound fixture bytes and cover actual parsers. PID accumulation, command stdout and file reads retain their existing I/O behavior; no production allocation ceiling follows from the harness caps. |
| HTTP/TLS and DAO authorization orchestration | Server auth/health/jobs and storage scope/lease integration tests own full request/database behavior. Header/DTO/TLS targets cover named custom parsers. S2 adds authority/scope proofs while retaining SQL-boundary tests; S3 adds ingress labels. |
| Broker relay and stream effects | [model_broker.rs](../crates/loupe-worker/src/llm/model_broker.rs) tests output termination, token exhaustion, authenticated routing and redirect isolation. Policy/accounting targets complement those tests. S2/S3 add proofs and labels. |

The worker response target reaches four real decoders and errors over chunked
HTTP. L3's shared [loupe-http reader](../crates/loupe-http/src/lib.rs) also
serves CLI and web, whose own regressions cover their response paths. Its
16 MiB limit is a transport budget; valid oversized lists fail explicitly.
Pagination remains future work. `web_api` already reaches the real router,
browser guards and extraction errors; those are not missing S1 targets.

S3 owns prompt data blocks, report containment and destination caps, labelled
logging/Debug, canary scanning and citation checks. The report `escape-*`
seeds are its acceptance inputs. The retained JSON-span helper has no current
production caller and is not evidence about the active MCP verdict path.

After B4 actually lands, S1 items 30–35 add the ten `proto_review_<module>`
DTO targets; `core_review_payload`, inventory-manifest, candidate and priority
targets; `storage_admission_policy`; `server_review_authority`; and router
body-cap integration tests. Existing review storage/schema modules do not
mean that this phase ingress or its targets have landed. Artifact-export
coverage gets an owner when Stage C introduces that boundary.
