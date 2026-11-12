
The returned scope borrows its transaction and cannot leave the callback:

```compile_fail
use loupe_server::review::authority::{authorize, with_transaction, Access, Phase};
fn leak(
    db: &loupe_storage::Db, worker: &loupe_server::auth::AuthedWorker,
    headers: &axum::http::HeaderMap,
) {
    let _ = with_transaction(db, worker, headers, 1, || 0, |tx| {
        authorize(tx, Phase::Survey, Access::Domain)
    });
}
```

Using it inside the callback compiles:

```no_run
use loupe_server::review::authority::{authorize, with_transaction, Access, Phase};
fn inside(
    db: &loupe_storage::Db, worker: &loupe_server::auth::AuthedWorker,
    headers: &axum::http::HeaderMap,
) {
    let _ = with_transaction(db, worker, headers, 1, || 0, |tx| {
        authorize(tx, Phase::Survey, Access::Domain).map(|scope| scope.is_some())
    });
}
```
