# Direct CLI ingress coverage

The `cli_ingress_response` and `cli_config_input` targets compile the same
private source files used by the binary into the library only under
`cfg(fuzzing)`. Normal builds expose neither the fixture API nor a decoder.
The fixture API has closed selectors and concrete observations, without a
caller-selected source, decoder, callback, or provenance token export.

The response fixture supplies guarded synthetic Server bytes to all thirteen
real response entries and the discard entry. Actual entry observations make
wrong routing visible even when two operations share a DTO schema. Finding
observations inspect the actual typed Agent content and Server audit values
before the temporary legacy exits. They also record the ranges used by the
real carry operation. An independently constructed append ledger compares
those ranges, including equal tokens in other fields and array elements.
Escaped keys, UTF-16 pairs, NFD, quotes, backslashes and optional fields retain
their original token locations.

The unchanged public DTO deserializers provide the schema oracle. A separate
harness predicate checks exact text/path policies; it does not invoke the
production validator to predict itself. Every admitted output field is
compared, including fake worker credentials through the existing closed
encoder. Reporting cases cover tags, defaults, duplicates, positional forms,
ignored content and recursion at the original enclosing depth.

The Config fixture invokes all twelve actual native Clap callbacks, with
entry and mint observations. Typed text is observed before the legacy exit.
CommonName's closed default requires no mint; explicit command-line and
environment values use Config admission. Native paths retain Unix bytes.
PAT/PEM input has no new text cap or grammar. PAT observations use only live
owners: shared identity, clone/drop sequences, exact formatters, unique moves,
guarded shared exports and independent output-byte comparisons.

Each iteration processes at most 64 KiB of ordinary input. Compact recipes
expand one Config field to at most 2 MiB+1, or a response to at most 16 MiB.
These are harness bounds, not additional production admission limits.
Thread-local observations are cleared before each invocation and on unwind.

These targets do not exercise HTTP collection, status handling, protocol
headers, transport cancellation, OS argv startup, the Clap command tree,
environment precedence, file/base64 input selection or TLS trust. The existing
69 CLI tests retain those runtime and renderer controls; the two carried-span
HTTP tests remain available in both binary and fuzz-library test builds.
Config's actual PEM file read remains outside these two direct targets.

There is no new CLI Kani proof. Core bounded JSON-string harness no-verdicts
remain unchanged; the carry primitive proof does not prove field attribution.
Mutation failures establish sensitivity of this validation unit, not new
historical product regressions. Campaign results are bounded evidence.

At atomic M, reconnect these fixtures to the retained source-bearing output
types and remove their dependence on the explicit private legacy projections.
The current fixture exports and observations remain cfg-only.
