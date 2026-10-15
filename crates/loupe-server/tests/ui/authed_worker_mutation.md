# Authenticated identity mutation acceptance check

Run this file separately with nightly rustdoc and the built loupe-server and
loupe-storage libraries. It is not included by the ordinary test suite. Before
the ingress migration the compile-fail example must fail because it compiles;
afterward it must reject public row mutation with E0616. This is an API
acceptance control, not a claim of a runtime authentication exploit.

Read-only role metadata remains usable:

```rust
use loupe_server::auth::AuthedWorker;

fn metadata(identity: &AuthedWorker) -> (i64, bool) {
    (identity.id(), identity.is_worker())
}
```

Callers must not change the authenticated role by mutating its row:

```compile_fail,E0616
use loupe_server::auth::AuthedWorker;
use loupe_storage::workers::WorkerKind;

fn change_role(identity: &mut AuthedWorker) {
    identity.worker.kind = WorkerKind::Admin;
}
```

Cloning preserves read-only metadata; it does not expose a mutable row:

```rust
use loupe_server::auth::AuthedWorker;
fn duplicate_metadata(identity: &AuthedWorker) {
    let copy = identity.clone();
    assert_eq!(copy.id(), identity.id());
    assert_eq!(copy.kind(), identity.kind());
    assert_eq!(copy.name(), identity.name());
}
```

New authority API controls (absence checks, not runtime regressions): callers
cannot manufacture authority from a row, use Default, or select a source token.

```compile_fail,E0308
use loupe_server::auth::AuthedWorker;
use loupe_storage::workers::WorkerRow;
fn manufacture(row: WorkerRow) {
    let _ = AuthedWorker::from(row);
}
```

```compile_fail,E0599
use loupe_server::auth::AuthedWorker;
let _ = AuthedWorker::default();
```

```compile_fail,E0624
use loupe_server::auth::AuthedWorker;
fn select_operator(identity: &AuthedWorker) {
    let _ = identity.operator_ingress();
}
```
