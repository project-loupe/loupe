# Staged storage source fixtures

These integration tests exercise the committed core `source-migration` API
without replacing production DAOs. The compatibility file runs the unchanged
read paths. The staged file reads actual SQLite TEXT values using `get_ref`,
including a database close/reopen, and validates while those borrowed columns
are alive.

`support/stored.rs` mints Db only at its finding-row and source-ref-column
reads. Named finding-column validators carry each original plain column's
entire byte range to Agent; audit common names remain Db. Source refs borrow
`RawValue` fields directly from their original SQL JSON column and carry
checked pointer-derived spans. Neither decoded text matching nor a JSON
reserialization locates a carried token. Test traces record live addresses
and offsets without dereferencing expired pointers.

`loupe_core::text::decode_json_string_bounded` is source-neutral support shared
with the original-message protocol fixture. Its
first pass counts decoded UTF-8 bytes and scalars without an output allocation;
only a successful complete preflight permits the second pass's bounded String.
Unescaped text remains borrowed. This helper is deliberately not a generic
typed/source decoder. Internal preflight assertions now live in core; this
consumer retains its decoding/borrowing/cap/malformed-token checks. The parser
fuzz join is independently required before full D acceptance.

The fixtures retain SourceRefs' existing raw/canonical 64 KiB limits, 32/64
entry limits, duplicate/unknown-field rejection, optional symbol semantics,
semantic symbol policy, and exact 512-byte repository paths. New finding/audit
admission uses the accepted exact 2 MiB field policies and fixed read errors.
Audit text equal to finding content still has a different source type.

The new fixtures are acceptance and compatibility evidence, not regressions
against an active source-aware production read path. Atomic adoption M still
owns production signatures, source metadata migration, invalid-row behavior,
staging deletion, and the remaining original-span owner joins.
