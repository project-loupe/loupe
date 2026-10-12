# Staged original-message fixtures

The baseline records unchanged VerdictSubmission serde behavior, including
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

This is fixture evidence for D, not production ingress adoption. I/M still
owns actual authenticated Worker ingress, route budgets and protocol-version
checks, full owner migration, staging deletion, and exact patch bytes through
the eventual Git applicability check. The shared parser also needs its
independent arbitrary-byte/valid-token fuzz and mutation join before D closes.
