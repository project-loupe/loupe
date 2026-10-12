# loupe-http

Shared, bounded HTTP response transport for the Loupe worker, CLI, and web
clients. `read_response_bytes` collects at most `MAX_RESPONSE_BYTES =
16 * 1024 * 1024` bytes, including whitespace. It refuses a declared
oversized length before polling the body and checks each streamed chunk
before extending the buffer. Every allocation is capped too. It returns
`ResponseBodyError::TooLarge` without retaining or echoing the partial body.

The returned `Bytes` shares a private owner through clones and slices. That
owner wipes its entire allocation when the last reference drops. Collection
also wipes partial bodies on error or cancellation. Growth allocates a guarded
replacement, copies the used prefix, then wipes the previous allocation; it
never reallocates populated storage. Small bodies get proportionate storage.
During the largest doubling, old and new allocations temporarily total 24 MiB,
in addition to transport-owned chunks. The cap is not a peak-memory guarantee.
Dependency buffers, later caller-created copies and external receivers remain
outside this allocation's erasure contract.

The crate owns only transport: status handling, protocol checks, text
presentation, and JSON decoding remain in the clients. Keeping it separate
allows all three clients to share one limit without adding HTTP dependencies
to the pure protocol DTO crate or creating client-to-client dependencies.

The 16 MiB limit is an explicit transport budget, not a promise that every
valid list fits. Unbounded admin lists and large worker search summaries can
exceed it. Such responses fail explicitly without truncation; pagination is
future work. See `ARCH.md` for the fixture calculation and scope.

Run `cargo test -p loupe-http` from the workspace root, with
`CARGO_TARGET_DIR` set to a task-specific directory under `/tmp`.
