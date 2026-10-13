# Stored source and schema controls

Production DAO signatures now retain sources. The historical fixture filenames
`source_migration.rs` and `source_migration_baseline.rs` identify their original
staged evidence; there is no remaining staging feature or alternate text API.
The SQL compatibility tests preserve original bytes and close/reopen behavior.

`support/stored.rs` is an independent original-column fixture. It mints Db only
at actual SQLite TEXT reads and carries designated content to Agent while the
borrowed columns live; audit common names remain Db. Production reads use the
private `ingress` validators instead. RawValue fields in stored reference JSON
retain pointer-derived original spans, never decoded-text matching or JSON
reserialization. Trace addresses are observations of live owners only.

The source-ref controls retain raw/canonical 64 KiB caps, 32/64 entry limits,
duplicate/unknown rejection, optional symbols, semantic symbol normalization
and exact 512-byte repository paths. Original-message JSON string preflight
counts UTF-8 bytes/scalars before allocation; unchanged strings stay borrowed.
The helper itself neither labels content nor authorizes a source.

Schema v5 assigns a random 16-byte immutable report identity, distinct from the
reusable SQLite integer row ID. Migration, close/reopen, NULL, mutation, duplicate
fingerprint, random failure/collision and recycled-row tests distinguish these
properties. New inserts target the repo/fingerprint conflict specifically so an
identity collision cannot silently suppress a different finding. Schema v6
adds the twelve designated source columns with conservative historical agent
classification, without asserting model authorship. Audit/native/closed host
metadata is excluded. Invalid stored content fails with fixed diagnostics.

Typed DAO tests retain the mixed-source execution, attempt, artifact and
verification tuples. Closed campaign policy/phase/count/pending-follow-up
compositions have separate canonical bytes, ordering, normalization and budget
controls. Actual server integration tests additionally compare Resolved/Survey
stored JSON and digests; constructor-only tests do not replace those checks.

The historical fixture assertions are compatibility/acceptance evidence. The
new-row/NULL/recycled-ID cases have separately retained pre-fix assertion reds;
source arity and mixed-input rejection are compiler acceptance controls, not
runtime exploit or memory-erasure claims. Full source-aware joins still require
the combined workspace, direct fuzz and final API checks.
