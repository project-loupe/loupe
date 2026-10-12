# Source-aware wire and original-message fixtures

Source-bearing protocol DTOs deliberately have no general Deserialize or raw
string constructor. Unit and credential tests assemble synthetic marked values
and compare the complete serialized wire shape with explicit expected JSON.
The fixed Server mark in `support/fixtures.rs` exists only in test binaries;
it is not an ingress decoder or evidence of authentication/source assignment.
Real missing/null/default admission belongs to the named server, worker and
CLI decoders. Output-omission tests here do not establish input compatibility.
Credential-only DTOs that still implement Deserialize retain their actual
roundtrip tests, including private/mixed PEM and escaped credential bytes.

The private `support/legacy_verdict.rs` oracle preserves the pre-adoption
VerdictSubmission serde shape for the existing original-token comparison,
including
all variants, reordered tags, map and sequence representations, duplicates,
ignored fields, null/default options, and exact text. It does not mistake
new source-aware API admission for an existing production security regression.

The private Worker fixture retains the immutable original message, borrows
RawValue fields, computes checked pointer ranges, carries those exact spans
to Agent, and only then calls the shared bounded string decoder and marked
constructors. Repeated equal values assert different hard-coded offsets and
live carried addresses. No reserialization or content search locates a token.
The storage fixture independently covers repeated nested array entries.

The fixture's 2 MiB original-message cap precedes raw DTO parsing. It is
separate from decoded field caps and does not change production route budgets.
The shared helper admits controls as JSON syntax; the named marked policy
decides whether each decoded character is valid. Exact text remains exact.

Serde's internally tagged legacy enum validates even ignored inner values.
After all designated fields have been carried and decoded, a discard-only
visitor traverses the original envelope to retain this Unicode/numeric/depth
behavior. It retains no dynamic values; serde scratch remains bounded by the
original message cap. Unknown outer values retain ordinary IgnoredAny behavior.

This remains fixture evidence, not production ingress adoption. The historical
oracle intentionally accepts strings the final marked field policy rejects;
it is private to these tests and cannot deserialize a production labelled DTO.
Actual authenticated Worker ingress, route budgets, protocol-version checks,
and exact patch bytes through SQL/reopen/Server/Agent/Git must be covered by
their production owners. The parser's independent fuzz and mutation evidence
also remains separate from these fixed original-token controls.
