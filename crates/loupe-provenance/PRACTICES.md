# loupe-provenance: practices this crate commits to

Numbered so tests cite them (`// P<n>` in the test body). The trust
model (which sources exist and which may carry to which) is
`SECURITY-FIRST-REFACTOR.md` section 2; this file is the contract of
the types that encode it.

P1. `Untrusted<T, S>` exposes no path to `T`. No `Deref`, no
    `AsRef`, no `Borrow`, no `From<Untrusted<T, S>> for T`, no
    `into_inner`, no field access, no `PartialEq`, no `Hash`. `Debug`
    prints the source name and `[redacted]`, never `T`, and does not
    require `T: Debug`. There is no `Display`.

P2. The only exits are `validate`, which runs a `Validate` impl over
    an `Unvalidated<'view, T>` view with a `Mark<'view, S>` of the
    actual source, neither of which can outlive the call, and
    `map_ref`, which maps `&T` to `&U` and returns the result still
    wrapped with the same source. `as_bytes` and `split_at` are closed
    reslicing helpers that show bytes to no one. The closure passed to
    `map_ref` does see `&T`; it is a validation-class review site,
    exactly like a `Validate::validate` body, and the rule for it is:
    project a field or reslice, nothing else. `grep -rn 'map_ref('`
    together with `grep -rn 'Unvalidated<'` lists every place in the
    tree where untrusted bytes are looked at.

P3. An `Untrusted` is born only at ingress. `Untrusted::new` takes an
    `Ingress<S>` token. `Ingress::new` is an `unsafe fn` whose
    `# Safety` section states the contract: the value about to be
    wrapped really arrived from source `S` at the ingress point the
    call site names. `unsafe` here marks a security contract the
    compiler cannot check, as `unsafe trait Send` does in std, not a
    memory-safety one. The workspace denies `unsafe_code`, so every
    call site needs `#[allow(unsafe_code)]`, and `ci/check.sh` accepts
    that only in files listed with a reason in `ci/unsafe-allow.txt`
    (the ingress modules, test fixtures, fuzz and Kani harnesses).
    `ci/gate-selftest.sh` keeps the known bypass forms as fixtures that
    must fail. The `ingress` feature additionally hides the constructor
    from crates that do not enable it; Cargo unifies features across a
    workspace build, so the feature documents intent and the `unsafe`
    enforces it.

    Threat model of this enforcement: it makes it impossible for the
    project's own developers and agents to mint a trust-asserting
    label by mistake, and makes every deliberate route visible in a
    diff a reviewer reads (an allow-list entry, an `unsafe` keyword, a
    manifest change). It does not try to stop a malicious contributor
    who writes deliberately obfuscated code; that is code review's
    job. Two classes of label follow from it:
    - Trust-asserting: `Worker`, `Operator`, `Server` (each unlocks
      authority: a worker route, an admin route, trust in a response).
      These are minted only at the listed sites, after the check the
      site's doc names (the mTLS row lookup).
    - Hostility-marking: `Agent`, `Repo`, `Sandbox`, `Provider`,
      `Reporter`, `Db`, `Config`, `Browser`. Marking chosen bytes as
      hostile grants nothing: every consumer parses them as hostile
      anyway, and the only carries they allow stay hostile.

P4. The source is a type. `Source` is sealed, so the set of sources
    is exactly the eleven the trust model lists and cannot be extended
    from outside the crate, and `Untrusted<T, S>` carries `S` through
    `map_ref` and into every `Validate` impl so a sink can be written
    for one source only.

P5. `Unvalidated<'a, T>` has no public constructor, no `Clone`, no
    `Debug` of the payload, and one accessor, `get`, returning
    `&'a T`. It can only exist inside `Validate::validate` because the
    lifetime it carries is the borrow `validate` takes of the consumed
    `Untrusted`. A `Validate::Output` that tries to carry the view out
    is a compile error. Borrowed output (`T = &'x [u8]`, `Output`
    borrowing `'x`) is allowed and is the zero-copy path.

    `Mark<'view, S>` has private fields and a private constructor, no
    `Default`, `Clone`, `Deserialize`, or source conversion. A plain
    validator receives it with the same explicit `'view` lifetime as
    its Unlabelled view. A carrying view's `mark()` borrows that view
    and fixes `S` from the view; callers cannot select another source.
    Typed constructors borrow a mark and may return owned outputs
    which outlive the call. The mark identifies the source, not the
    correctness of the derivation: that remains the named validator's
    review obligation. It cannot carry or wrap arbitrary values.

P6. The crate has no `Limits`, no `Error` and no fallible operation
    of its own. `validate` returns the `Validate` impl's error type
    unchanged. No method on any type in this crate panics for any
    input: the crate opts into the parser lint block (no indexing, no
    unchecked arithmetic, no `panic!`), and `len`, `is_empty`,
    `as_bytes`, `split_at` and `map_ref` are proven panic-free by Kani
    for slices up to the bound in `kani/mod.rs`. Allocation failure is
    outside this promise, as for any `alloc` code; `to_vec`, `extend`
    and `split_off` allocate.

P7. `Secret<T>` exposes `T` through one accessor, `expose(&self) ->
    &T`, and nothing else: no `Deref`, no `AsRef`, no `Clone`, no
    `PartialEq`, no `into_inner`. `Debug` and `Display` both print
    exactly `[redacted]`.

P8. Formatting any type in this crate never emits a payload byte.
    The test for this uses a payload whose bytes are all absent from
    the fixed output text and asserts that none of them appears.

P9. Zeroisation is in-tree, by volatile byte writes followed by a
    compiler fence, in one module (`src/volatile.rs`) that is the
    only place in the crate allowed to use `unsafe` for memory. The
    crate root keeps the workspace `unsafe_code = "deny"`; that module
    alone carries `#[allow(unsafe_code)]`, each `unsafe` block carries
    a `SAFETY:` comment, and the module is run under Miri. There is no
    safe, guaranteed way to write memory that the optimiser will not
    elide before a free.

P10. The claim `Secret<T>` makes is: at the moment it is dropped, the
    bytes the wrapped value owns are overwritten with zero; for `Vec`
    and `String` that includes the spare capacity. It does not claim
    to reach copies the compiler or an earlier reallocation made.
    Secrets that live long or are large belong in `Secret<Vec<u8>>`
    or `Secret<Box<[u8]>>` so that moving the wrapper moves a pointer
    and not the bytes.

P11. `no_std` with `alloc`, no dependencies, no `std` feature: there
    is no error type to implement `std::error::Error` for.

P12. Egress without parsing (forwarding a stream, storing raw bytes,
    handing a renderer its buffer) is a `Validate` impl whose output
    is the bytes, one per sink, named for the sink and written where
    the sink is, so the `impl Validate` grep lists every egress as
    well as every parser. The crate ships no generic passthrough type
    on purpose.

P13. Relabelling is one sealed, typed operation. Bytes that the
    protocol defines as content of another source are handed on with
    `Unvalidated::carry::<D>(range)`, which exists only on the view a
    `ValidateCarrying` impl gets (the view knows its source `S`), and
    only for `D: CarriedFrom<S>`. `CarriedFrom` is sealed and
    implemented for `Agent` from `Worker` (the text fields of a phase
    payload a worker relays), `Agent` from `Sandbox` (tool-call
    arguments and CLI output), `Agent` from `Db` (stored agent text
    read back), and `Agent` from `Server` (stored agent text in lease,
    search and detail responses). A plain `Validate` body sees an `Unlabelled` view and
    cannot carry; outside a validator there is no view. The carried
    value is still `Untrusted`: relabelling changes which parsers may
    take the bytes, never whether they must be parsed. `Untrusted<&[u8],
    S>::to_vec` makes an owned copy with the same label, and
    `Untrusted<Vec<u8>, S>` has the closed buffer operations a receive
    loop needs (`extend` from the same source, `split_off`,
    `discard_front`), so a reader can hold bytes between reads without
    the label ever coming off. Empty buffers require an actual ingress
    token too: `Untrusted::new(Vec::new(), ingress)`. The supplied
    tokenless `empty()` was removed before introducing marks, since
    otherwise it could grant constructor authority for any source.
    Authentically sourced empty values remain valid. A `ValidateCarrying` impl can
    carry any sub-range, including the whole input, so the trait binds
    the range to the bytes of the same call and gives a grep site, not
    a proof that the bytes are content; each carry site is a review
    site.

## Test list

Unit tests, `src/tests.rs`, each citing the practice it checks:

| Test | Practice |
|---|---|
| `untrusted_debug_contains_no_payload_byte` (all eleven sources) | P1, P8 |
| `untrusted_debug_does_not_need_the_payload_to_be_debug` | P1 |
| `secret_debug_and_display_are_redacted` | P7, P8 |
| `len_and_is_empty_report_the_byte_length` | P6 |
| `validate_runs_the_validator_and_returns_its_output` | P2 |
| `validate_returns_the_validators_error_unchanged` | P2, P6 |
| `validate_can_return_a_value_borrowed_from_the_input` | P5 |
| `map_ref_reslices_without_unwrapping_and_keeps_the_source` | P2, P4 |
| `as_bytes_and_split_at_reslice_without_a_closure` | P2, P6 |
| `framing_loop_keeps_the_input_lifetime` | P5 |
| `untrusted_view_is_copy_and_still_untrusted` | P1 |
| `untrusted_secret_zeroises_without_exposing` | P1, P9 |
| `clone_of_untrusted_is_still_untrusted` | P1 |
| `source_names_are_the_eleven_sources_and_distinct` | P4 |
| `untrusted_is_send_and_sync_when_the_payload_is` | P1 |
| `secret_expose_returns_the_value` | P7 |
| `secret_drop_zeroises_the_bytes_it_owns` | P9, P10 |
| `zeroise_covers_array_slice_vec_string_and_box` | P9, P10 |
| `zeroise_of_empty_values_does_nothing_and_does_not_panic` | P6 |
| `vec_and_string_zeroise_keep_their_capacity` | P10 |
| `ingress_token_is_a_copyable_zero_sized_marker` | P3 |
| `to_vec_keeps_the_source_and_the_bytes` | P13 |
| `carry_relabels_a_sub_slice_to_agent` | P13 |
| `carry_out_of_range_is_none` | P6, P13 |
| `receive_buffer_operations_keep_the_label` | P13 |
| `plain_marks_construct_owned_outputs_of_the_actual_source` | P3, P4, P5 |
| `carrying_marks_keep_the_source_and_nested_validation_uses_agent` | P4, P5, P13 |

Compile-fail doc tests (`src/compile_fail.rs`, one item per
guarantee): no `Deref`, `AsRef`, `Display`, `PartialEq` or public
field on `Untrusted`; `new` needs a token; `Ingress::new` is absent
without the feature and `unsafe` with it; `Unvalidated` has no
constructor, cannot be returned, has no `Debug`; `Secret` has no
`Deref`, `AsRef`, `Clone`, `PartialEq` or public field; `carry` only
for the sealed pairs, only inside a `ValidateCarrying` body;
`CarriedFrom` cannot be implemented downstream; tokenless empty is
absent; marks have no public construction/default/clone/conversion,
cannot escape (including with static input), and cannot change source
or carry. Existing plain-validator examples use the mark signature so
failures cannot pass merely because their trait method is stale.

Kani harnesses (`kani/mod.rs`): `len`, `is_empty`, `map_ref`,
`split_at` and `carry` are checked through 32 bytes with unconstrained
`usize` ranges and positions. `to_vec` and receive-buffer operations
are checked through 8 input bytes with unconstrained split/discard
positions. The zeroise loop writes every byte of arrays and slices
through 32 bytes, also through `Secret`'s `Drop`; `Vec::zeroise`
leaves the vector empty with its capacity intact for requested
capacities through 8. These bounded checks do not establish induction
over arbitrary sizes, physical deallocation effects or optimiser
behaviour. Every harness includes reachable cover witnesses. Run only
through `ci/kani.sh -p loupe-provenance`; record actual verdicts,
cover results, bounds and timings in the stage evidence.

Miri: `cargo +nightly miri test -p loupe-provenance` where the
installed toolchain supports Miri; the volatile module and every
`Zeroise` impl are exercised. Record unsupported configurations
explicitly rather than treating ordinary unit tests as a Miri pass.
