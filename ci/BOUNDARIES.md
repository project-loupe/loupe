# Boundary lint ownership

`clippy.toml` enumerates process, filesystem and HTTP entry methods. Clippy
resolves their definitions, so aliases and UFCS calls remain checked. Rust
paths are explicit: `std::fs::*` and `reqwest::*` are policy descriptions,
not supported Clippy wildcards. The compiler self-test uses the pinned
workspace dependencies to verify std, Tokio and Reqwest examples.

Each production exception belongs on the smallest call statement and names
the boundary and admitted input in `reason = "..."`. A module-wide allowance
would authorize unrelated later calls and is inappropriate. The inventory
below records existing responsibilities; it does not grant a module blanket.
Changes to these responsibilities require review of the corresponding
source, validation and egress behavior.

| Owner | Accepted responsibility |
| --- | --- |
| `loupe-cli/src/main.rs` API operation functions | Send the named operator operation to the configured Loupe server, using Config-admitted arguments and guarded credential request bodies. |
| `loupe-cli/src/main.rs::build_client` | Construct the configured mTLS client used by those operator operations. |
| `loupe-cli/src/main.rs::write_secret_file` | Explicit credential export to the operator-selected file; exclusive creation and owner-only permissions remain enforced. |
| `loupe-tls/src/input.rs::read_pem_file` | Read a selected configuration PEM file through the guarded buffer and UTF-8 validator. |
| `loupe-web/src/config/input.rs` | Construct the configured mTLS client and requests selected by the closed dashboard `AdminRequest` operation set. |
| `loupe-web/src/client.rs` | Send bodyless admitted dashboard operations and the fixed startup health request. |
| `loupe-web/src/ingress/{bodies,queries,mod}.rs` | Send operation-specific Browser bodies and bounded/numeric query fields through their admitted owners. |

These CLI, dashboard and TLS responsibilities already existed before the
lint gate. They reconcile the earlier abbreviated broker/reporter/cache
module list with the application's actual operator and configuration paths;
they do not add a general network or file API to source-bearing values.
Worker, server and storage owners maintain the same per-call convention for
their own process, repository, configuration, database and reporting paths.

The list covers std/Tokio process construction and execution, filesystem
path operations and file mutations, and Reqwest construction, request and
send/execute methods. It is a compiler-enforced API boundary convention,
not a whole-program information-flow proof. Generic I/O on an already open
handle, other networking/filesystem libraries, macro expansion, FFI and
deliberate lint suppression remain review obligations. Adding an alternate
API requires extending this list and its compiler probes as appropriate.
The unsafe/source gates provide separate checks for their own invariants.

## Infallible private invariants

Production `expect`/`unwrap` exceptions use statement-level `#[expect]` with
an invariant-specific reason. The following cases retain those checks:

| Site | Invariant |
| --- | --- |
| `loupe-core::canonical::canonical_bytes` | The closed serializer accepts JSON values/string keys and writes to a Vec; neither a custom serializer nor a failing writer is accepted. |
| `loupe-core::text::checked::anchor` | The regex is a checked-in literal exercised by anchor tests, with no runtime pattern input. |
| `loupe-core::text::json::CheckedJson::expose` | Only the private canonical JSON serializer creates the immutable UTF-8 bytes. |
| `loupe-tls::input::PemBuffer::finish` | The same bytes pass UTF-8 validation before truncation and ownership transfer. |
| `loupe-web::ingress::server::ServerText::text` | Private construction retains valid original UTF-8 or assembles complete valid chunks plus U+FFFD. |
| `loupe-cli::register_repo_request` | Its sole production caller supplies clap-validated arguments requiring both GitHub target fields unless reporting is disabled. |

These exceptions preserve the checked invariants and their existing panic
diagnostics. They do not replace errors with empty/default output. A new
fallible path must propagate a typed error: for example, CLI URL joining now
returns an error for a non-hierarchical configured URL instead of panicking.
