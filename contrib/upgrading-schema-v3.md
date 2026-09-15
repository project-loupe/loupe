# Upgrading to schema v3 (PR-B1)

This upgrade prepares storage for the v2 review harness. It does **not**
activate survey/drilldown orchestration: the existing scan and verification
pipeline remains in production. Queued legacy work, repository configuration
bytes, findings, verification history, and legacy PoCs are preserved without
reinterpretation or synthetic backfills.

Redeploy the **server** to apply this migration; it runs automatically when
the new server opens the database. B1 changes neither the worker protocol nor
worker behavior, so it does not itself require rebuilding workers. All workers
must nevertheless be stopped for the offline upgrade and restarted afterwards.
This is distinct from the earlier worker-side model-broker deployment.

## Before starting the new server

1. Take and verify a recoverable, consistent SQLCipher database backup with
   your existing backup tooling, and retain the matching master key securely.
   Follow that tool's WAL/checkpoint requirements: copying only the main file
   while the server writes is not a complete backup. Retain the old server
   image/binary. Loupe does not create, validate, or retain backups for you.
2. Arrange a maintenance window. Allow in-flight work to finish if practical,
   then stop every worker service (including any automatic restarts).
   Stopping a worker does not clear its persisted lease. While the old server
   is still running and workers cannot claim more jobs, inspect outstanding
   jobs with the dashboard/API or `loupectl job list` and `loupectl job get ID`.
   Wait for abandoned leases to be reaped, or explicitly cancel them with
   `loupectl job cancel ID`. Cancellation may discard unaccepted findings;
   let work finish if that is not the intended outcome. A limited recent-jobs
   listing is not proof that all leases have cleared; the migration checks
   the entire table.
3. Stop the old server. Keep all workers stopped. Ensure that no second server,
   database shell, backup reader, or other process has the database open from
   **before the pre-check through completion of the rebuild**. WAL permits
   concurrent readers; WAL mode is not an exclusive-ownership guarantee.
4. Deploy and start the new server with the existing database and master key.
   For containers, follow [the deployment guide](docker/README.md) only after
   completing this offline preparation. Migration and `integrity_check` can
   take time on large databases; allow for the database copy, indexes, and
   journal/WAL in your free-space and startup-time budgets.
5. After successful startup, restart the workers. Check a queued scan and
   verification job, inspect existing findings and history, and confirm normal
   processing resumes. Do not manually enqueue new phase kinds: their runtime
   support and production activation belong to later PRs.

Queued `scan` and `verify` jobs may remain throughout B1. You do not need to
drain or bulk-cancel the queue. The later PR-C4 production cutover has a
separate activation gate that requires all legacy work to be terminal, even
when the database has already been at schema v3 for some time.

## Refusals and recovery

The migration refuses to start if any job is `leased` or an unexpected legacy
kind is present. A leased-job diagnostic asks you to wait or cancel before
retrying. Stop the new server's restart loop before recovery; use the old
server to resolve leases, then repeat the offline steps above. Do not edit
version markers or job kinds to bypass a refusal.

If legacy data contains duplicate queued verify jobs for a finding, the new
unique index cannot be created. SQLite's underlying diagnostic names
`jobs.target_finding_id`; Loupe adds `idx_jobs_active_verify`, the conflicting
finding ID, and the recovery action. The migration rolls back. Restart the old
server with workers stopped, inspect the jobs, cancel the redundant queued
verify job, then stop the server and retry the upgrade. There is no automatic
job cancellation or data repair during migration.

Supported upgrades are v2 → v3 and v1 → v3:

- Before v3 commits, any failure rolls back its entire change, leaving a
  complete v2 database. For v2 input, legacy data and schema remain unchanged.
- On v1 input, the existing v2 capability migration commits first: interrupted
  leases are requeued and verifies with recorded verdicts are completed. A
  subsequent v3 refusal therefore leaves **v2, not v1**, with both version
  markers at 2. A v0.1 server can reopen it.
- All copy, foreign-key, and integrity validation precedes the transactional
  update of both `schema_meta.version` and `PRAGMA user_version` to 3.
- If restoring foreign-key enforcement fails after commit, startup fails and
  discards the connection, but the database is already complete v3 with both
  markers at 3. Reopening with the new server enables FKs and has no migration
  left to apply. Do not use an old binary on that database.

Every subsequent startup rejects job kinds missing from `job_kinds`, even if
schema v3 was already applied. Investigate the reported kinds rather than
disabling validation.

After successful migration, old binaries reject schema v3. There is no
automatic downgrade: restoring the external backup with its matching key is
the rollback path, and it loses writes accepted since the backup. Once new
canonical evidence has been accepted, prefer a forward fix unless that data
loss is an explicit operator decision.

## Verification coverage

Generated encrypted fixtures cover legacy states and relationships, queued
claims, capability hashes, FTS, config bytes, approval settings, v1 upgrades,
ownership constraints, and generation purge with canonical evidence retained.
Failure probes cover pre-check, table creation, copy, replacement, indexes,
validation, commit, and FK restoration. Separate tests corrupt equal-length
copy values and provoke a real SQLite commit failure with a held reader lock.

The existing workspace end-to-end tests run unchanged. Targeted checks:

```sh
export CARGO_TARGET_DIR="$(mktemp -d /tmp/cargo-target-loupe-schema-v3.XXXXXX)"
cargo test -p loupe-storage migrations
cargo test -p loupe-storage startup_rejects_unknown_job_kinds_on_an_already_migrated_db
```
