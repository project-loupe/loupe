# Upgrading to schema v7

Schema v7 adds lossless inventory identity, retained typed review evidence and
the storage layout for preparation and admission. The server implements the
pre-proof phase API, and current workers advertise each review phase they have
an agent for. Those advertisements are separate from legacy verification tags.
Schema migration opens no campaign and production triggers remain legacy, so
workers are leased only legacy jobs until the later cutover.

The new server applies pending migrations automatically when opening the
database. This branch also requires the coordinated
[protocol-3 rollout](upgrading-protocol-v3.md). Update server, workers, CLI and
web together; there is no protocol-2/3 mixed-version window.

## Offline upgrade

1. Disable new submissions and let in-flight work finish where practical.
   Stop workers and their automatic restarts. Stopping a worker does not clear
   its persisted lease. While the old server is still running, wait for
   abandoned leases to be reaped or cancel them through the old deployment.
   Cancellation can discard unaccepted findings. The migration checks the
   entire jobs table; a recent-jobs listing cannot prove all leases cleared.
2. Stop the old server and every other database user, including shells and
   backup readers. Take and verify a consistent SQLCipher backup with your
   existing tooling. Retain its matching master key securely and the original
   coordinated binary/image set. Follow the backup tool's WAL/checkpoint
   requirements; copying only the main database file may be incomplete.
   Loupe does not create or validate the backup for you.
3. Keep exclusive operational ownership of the database throughout migration.
   WAL and the IMMEDIATE transaction do not prevent another process from
   keeping a reader open. Allow space and startup time for table copies,
   indexes, admission validation and the journal/WAL.
4. Start the new server with the existing database and key. Confirm successful
   startup, schema version 7 and protocol 3 before restarting matching workers
   and web/CLI clients. Keep production campaign triggers disabled; workers'
   review advertisements need no change, as without a campaign no review phase
   is leased.
5. Inspect existing findings and verification history. Smoke-test queued
   legacy scan and verification work and CLI/web access before resuming
   submissions.

Queued legacy work may remain: v7 requires no leased jobs, not an empty queue.
Published v1–v6 migrations are retained unchanged. They include GitHub App
compatibility, report identity and source metadata. See the
[historical upgrade runbook](upgrading-schema-v3.md) for their checks.

## Preserved data and new state

Historical inventory IDs and display paths are preserved. Unknown raw Git
path bytes are not guessed from display strings, and old inventory digests do
not certify a managed manifest. Trusted pinned-checkout reconstruction and
sealing require the authenticated host-preparation API.

Findings, verification details, proofs, identities and source metadata remain
intact. Absent typed payloads remain explicitly historical, not fabricated
evidence. Unsupported source classifications or content that fails admission
cause refusal; they are never silently relabelled, normalized or discarded.

Preparation, pending-work and admission-accounting tables start without
invented historical records. Campaign snapshots are not rewritten, and this
migration does not switch campaign policy or enable phase workers.

## Refusals and recovery

Any leased job causes refusal before the v7 table rebuilds. Stop the new
server's restart loop and keep workers stopped. All pending migrations share
one transaction, including data admission, both schema markers, foreign-key
checks and restoration. Failure before commit leaves the original schema and
canonical rows unchanged, even when upgrading from an earlier version.

Use the original compatible server and client set to resolve leases, then
repeat the offline procedure. For admission errors, preserve the backup and
use the reported closed table/column/row identifiers to investigate the data.
Do not edit schema markers or job states to bypass refusal. Canonical findings
and reports must not be deleted to make an upgrade pass.

Both schema markers advance to 7 only when the complete upgrade commits.
Foreign-key restoration is checked before commit; failure rolls back and
discards the connection. After an interrupted startup, inspect the logged
schema version rather than assuming which side of commit was reached.

After a successful v7 migration, older binaries cannot reopen the database.
Rollback requires restoring the verified pre-upgrade backup, matching key and
original coordinated binary set. Restoration loses writes accepted since that
backup: make that an explicit operator decision, and prefer a forward fix
when possible. Binary-only rollback is not supported.

## Incompatible derived review state

Do not truncate closure criteria or rewrite a frozen profile to fit a newer
lease. An authenticated administrator may POST
`/v1/review-generations/{generation_id}/reset` with the exact protocol-3 header
and `{"protocol_version":3}`. This discards that generation's rebuildable
inventory, units, leads and derived scheduling state; back up first if those
details are needed. It is not an automatic migration or background GC.

Reset refuses active repository campaigns, nonterminal referencing jobs or
assignments, and competing active/building generations. Settle that work first;
never edit database states to bypass the guards. Findings, canonical evidence,
reports, attempts, job audits and replay receipts survive. Unfinished mandatory
verification intent remains visible as blocked `requires_successor`, with its
original source/profile/provenance preserved; B8 owns later revalidation and
re-admission. Reset does not discard those obligations or fabricate a verdict.

The next normal campaign open starts a fresh bootstrap with incomplete coverage
and a new immutable profile. A minimal retired identity stub prevents a delayed
reset request from naming the replacement generation within the same repository
lifetime. Do not delete those stubs independently. Explicit repository deletion
is a separate operation and is outside that nonreuse guarantee.
