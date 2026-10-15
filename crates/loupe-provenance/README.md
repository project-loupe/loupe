# loupe-provenance

Provenance labels: `Untrusted<T, S>` says where a value came from and
cannot be read until a `Validate` impl parses it; `Secret<T>` prints
`[redacted]` and zeroises on drop.

- `no_std` plus `alloc`; no dependencies.
- Trust model: `SECURITY-FIRST-REFACTOR.md` section 2 in the planning
  repository (sources, secrets, sinks); the `Source` set in
  `src/source.rs` is that table.
- Practices: `PRACTICES.md` lists what this implementation commits to
  (P1 to P13), numbered so tests cite them.
- Fuzz targets: none; there is no parser. Kani harnesses: `kani/`.
- Feature `ingress`: enables `Ingress::new`; see its doc for what the
  gate does and does not enforce.
- Opts into the parser lint block (no indexing, no unchecked
  arithmetic, no panic) although it is not a parser, because it
  promises never to panic.

The supplied crate is adapted in three API details: plain `Validate`
receives an Unlabelled view and a same-lifetime `Mark` of the actual
source; a carrying view's `mark()` borrows that view with its source
fixed; and tokenless `Untrusted::empty()` is removed. Initialise empty
receive buffers with `Untrusted::new(Vec::new(), ingress)`. A mark
supports same-source owned typed outputs; its lifetime prevents it
escaping as reusable constructor authority. Correct derivation remains
the named validator's review obligation.

Carrying remains restricted to original input sub-slices and exactly
four sealed pairs: Agent from Worker, Sandbox, Db and Server. Carry
encoded fields before decoding or normalizing them in a nested Agent
validator; `to_vec()` can retain the encoded bytes with the same label.
There is no owned-value relabelling operation or generic passthrough.

Unit and doc tests run with `cargo test -p loupe-provenance` and again
with `--features ingress`. Run doc tests on nightly too to check their
specified error codes. Run the ten bounded Kani harnesses only through
`ci/kani.sh -p loupe-provenance`; each includes non-vacuity covers.
`PRACTICES.md` states their bounds and the Miri check.
