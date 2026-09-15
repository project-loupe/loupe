//! Schema v3 DDL, mapped to SPEC-01 sections (planning commit 720fc9c).
//! Published migrations are immutable; later changes require a new version.

/// SPEC-01 §1.
pub(super) const JOB_KINDS: &str = r#"
CREATE TABLE job_kinds (
    -- NOT NULL is explicit: SQLite admits NULL in a non-INTEGER PRIMARY KEY.
    kind        TEXT PRIMARY KEY NOT NULL,
    legacy      INTEGER NOT NULL DEFAULT 0
);
INSERT INTO job_kinds (kind, legacy) VALUES
    ('scan', 1), ('verify', 0), ('survey', 0), ('drilldown', 0);
"#;

/// SPEC-01 §2: replacement table, populated only through the legacy projection.
pub(super) const JOBS_NEW: &str = r#"
CREATE TABLE jobs_new (
    id                  INTEGER PRIMARY KEY,
    repo_id             INTEGER NOT NULL REFERENCES registered_repos(id) ON DELETE CASCADE,
    kind                TEXT    NOT NULL REFERENCES job_kinds(kind),
    state               TEXT    NOT NULL CHECK (state IN ('queued','leased','succeeded','failed','cancelled')),
    incremental         INTEGER NOT NULL DEFAULT 0,
    since_sha           TEXT,
    head_sha            TEXT,
    parent_job_id       INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
    target_finding_id   INTEGER,
    worker_id           INTEGER REFERENCES workers(id) ON DELETE SET NULL,
    lease_expires_at    INTEGER,
    attempts            INTEGER NOT NULL DEFAULT 0,
    enqueued_at         INTEGER NOT NULL,
    started_at          INTEGER,
    finished_at         INTEGER,
    error               TEXT,
    job_capability_hash BLOB,
    -- v3 additions (all NULL on legacy rows)
    campaign_id            INTEGER,           -- composite FK below (ownership)
    generation_id          INTEGER REFERENCES review_generations(generation_id) ON DELETE SET NULL,
    assigned_lead_id       INTEGER REFERENCES leads(lead_id) ON DELETE SET NULL,
    continuation_of_job_id INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
    scheduling_band        TEXT    CHECK (scheduling_band IN ('urgent','high','normal','background')),
    effective_priority     INTEGER,
    eligible_at            INTEGER,
    soft_deadline_at       INTEGER,
    hard_deadline_at       INTEGER,
    submit_by              INTEGER,
    token_budget           INTEGER,          -- NULL = no token cap; 0 is invalid
    recipe                 TEXT,             -- versioned JSON job recipe snapshot
    workflow_contract_version INTEGER,
    CHECK (token_budget IS NULL OR token_budget > 0),
    FOREIGN KEY (repo_id, campaign_id)
        REFERENCES review_campaigns(repo_id, campaign_id)
);
"#;

/// SPEC-01 §3.
pub(super) const REVIEW_CAMPAIGNS: &str = r#"
CREATE TABLE review_campaigns (
    campaign_id          INTEGER PRIMARY KEY,
    repo_id              INTEGER NOT NULL REFERENCES registered_repos(id) ON DELETE CASCADE,
    recipe               TEXT    NOT NULL CHECK (recipe IN ('bootstrap','incremental','reconciliation','corroboration')),
    trigger              TEXT    NOT NULL CHECK (trigger IN ('manual','scheduled','compat_scan_api','reconciliation','operator')),
    requested_base_sha   TEXT,
    target_commit_sha    TEXT    NOT NULL,
    generation_id        INTEGER REFERENCES review_generations(generation_id) ON DELETE SET NULL,
    state                TEXT    NOT NULL CHECK (state IN ('active','finished','cancelled')),
    terminal_reason      TEXT,
    effective_policy     TEXT    NOT NULL,   -- resolved budget/deadline/limit snapshot (JSON)
    effective_policy_digest BLOB NOT NULL,
    deadline_at          INTEGER,
    root_campaign_id     INTEGER REFERENCES review_campaigns(campaign_id) ON DELETE SET NULL,
    continuation_of_campaign_id INTEGER REFERENCES review_campaigns(campaign_id) ON DELETE SET NULL,
    coverage_at_finish   TEXT    CHECK (coverage_at_finish IN ('complete','partial','unknown')),
    terminal_counts      TEXT,               -- JSON: jobs by kind/state, leads, findings, verdicts
    created_at           INTEGER NOT NULL,
    finished_at          INTEGER,
    UNIQUE (repo_id, campaign_id)            -- composite parent key (ownership)
);
CREATE INDEX idx_campaigns_repo ON review_campaigns(repo_id, created_at DESC);
CREATE UNIQUE INDEX idx_campaigns_one_active
    ON review_campaigns(repo_id) WHERE state = 'active';
"#;

/// SPEC-01 §4.
pub(super) const REVIEW_GENERATIONS: &str = r#"
CREATE TABLE review_generations (
    generation_id         INTEGER PRIMARY KEY,
    repo_id               INTEGER NOT NULL REFERENCES registered_repos(id) ON DELETE CASCADE,
    predecessor_generation_id INTEGER REFERENCES review_generations(generation_id) ON DELETE SET NULL,
    generation_commit_sha TEXT    NOT NULL,
    state                 TEXT    NOT NULL CHECK (state IN ('building','active','retired')),
    workflow_contract_version INTEGER NOT NULL,
    profile_version       INTEGER NOT NULL DEFAULT 1,
    generated_profile     TEXT,              -- bounded JSON, written by the bootstrap survey
    generated_profile_digest BLOB,
    inventory_digest      BLOB,
    coverage              TEXT    NOT NULL DEFAULT 'unknown'
                                  CHECK (coverage IN ('complete','partial','unknown')),
    corroboration_state   TEXT    NOT NULL DEFAULT 'pending'
                                  CHECK (corroboration_state IN ('pending','sampled','satisfied','contradicted')),
    pending_follow_up     TEXT,              -- bounded JSON: coalesced newer heads/triggers
    created_at            INTEGER NOT NULL,
    activated_at          INTEGER,
    retired_at            INTEGER,
    retired_reason        TEXT
);
CREATE UNIQUE INDEX idx_generations_one_active
    ON review_generations(repo_id) WHERE state = 'active';
CREATE INDEX idx_generations_repo ON review_generations(repo_id, created_at DESC);
"#;

/// SPEC-01 §5.
pub(super) const GENERATION_INVENTORY: &str = r#"
CREATE TABLE generation_inventory (
    inventory_entry_id INTEGER PRIMARY KEY,
    generation_id      INTEGER NOT NULL REFERENCES review_generations(generation_id) ON DELETE CASCADE,
    path               TEXT    NOT NULL,
    blob_sha           TEXT,               -- git blob id when available
    entry_kind         TEXT    NOT NULL CHECK (entry_kind IN ('tracked','submodule')),
    disposition        TEXT    NOT NULL DEFAULT 'unresolved'
                               CHECK (disposition IN ('mapped','context','excluded','unresolved')),
    disposition_reason TEXT,
    highlighted        INTEGER NOT NULL DEFAULT 0,  -- e.g. SECURITY.md candidates
    created_at         INTEGER NOT NULL,
    UNIQUE (generation_id, path)
);
"#;

/// SPEC-01 §6.
pub(super) const REVIEW_UNITS: &str = r#"
CREATE TABLE review_units (
    review_unit_id     INTEGER PRIMARY KEY,
    generation_id      INTEGER NOT NULL REFERENCES review_generations(generation_id) ON DELETE CASCADE,
    client_review_unit_key TEXT NOT NULL,
    title              TEXT    NOT NULL,
    objective          TEXT    NOT NULL,
    status             TEXT    NOT NULL DEFAULT 'open'
                               CHECK (status IN ('open','deferred','retired')),
    defer_reason       TEXT,
    priority_band      TEXT    NOT NULL DEFAULT 'normal'
                               CHECK (priority_band IN ('urgent','high','normal','background')),
    priority_proposal  TEXT,               -- bounded JSON: structured support
    source_refs        TEXT    NOT NULL,   -- bounded JSON: validated paths/symbols
    depends_on         TEXT,               -- bounded JSON: review_unit_id list
    closure_criteria   TEXT,
    semantic_context   TEXT,               -- bounded JSON
    carry_depth        INTEGER NOT NULL DEFAULT 0,
    carried_from_review_unit_id INTEGER REFERENCES review_units(review_unit_id) ON DELETE SET NULL,
    stale              INTEGER NOT NULL DEFAULT 0,
    stale_reason       TEXT,
    assignment_epoch   INTEGER NOT NULL DEFAULT 0,  -- bumped when claimed; see below
    created_by_job_id  INTEGER REFERENCES jobs(id),
    created_at         INTEGER NOT NULL,
    UNIQUE (generation_id, client_review_unit_key)
);
CREATE INDEX idx_units_sched ON review_units(generation_id, status, priority_band);

CREATE TABLE job_assigned_review_units (
    job_id           INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    review_unit_id   INTEGER NOT NULL REFERENCES review_units(review_unit_id) ON DELETE CASCADE,
    position         INTEGER NOT NULL,
    completed        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (job_id, review_unit_id)
);
"#;

/// SPEC-01 §7.
pub(super) const REVIEW_UNIT_RESULTS: &str = r#"
CREATE TABLE review_unit_results (
    review_unit_result_id INTEGER PRIMARY KEY,
    review_unit_id     INTEGER NOT NULL REFERENCES review_units(review_unit_id) ON DELETE CASCADE,
    produced_by_job_id INTEGER REFERENCES jobs(id),
    commit_sha         TEXT    NOT NULL,
    profile_version    INTEGER NOT NULL,
    disposition        TEXT    NOT NULL
                       CHECK (disposition IN ('lead_created','no_lead_found','not_applicable','needs_follow_up')),
    inspected_refs     TEXT    NOT NULL,   -- bounded JSON: refs actually inspected
    counterevidence    TEXT,               -- strongest counterevidence (required by contract)
    proof_gaps         TEXT,
    result_payload     TEXT    NOT NULL,   -- bounded JSON
    result_digest      BLOB    NOT NULL,
    invalidated        INTEGER NOT NULL DEFAULT 0,
    invalidated_reason TEXT,
    corroborates_review_unit_result_id INTEGER
        REFERENCES review_unit_results(review_unit_result_id) ON DELETE SET NULL,
    corroborates_inventory_exclusion_id INTEGER
        REFERENCES generation_inventory(inventory_entry_id) ON DELETE SET NULL,
    created_at         INTEGER NOT NULL,
    CHECK (corroborates_review_unit_result_id IS NULL
           OR corroborates_inventory_exclusion_id IS NULL)
);
CREATE INDEX idx_unit_results_unit ON review_unit_results(review_unit_id, created_at DESC);
"#;

/// SPEC-01 §8.
pub(super) const LEADS: &str = r#"
CREATE TABLE leads (
    lead_id            INTEGER PRIMARY KEY,
    generation_id      INTEGER NOT NULL REFERENCES review_generations(generation_id) ON DELETE CASCADE,
    review_unit_id     INTEGER REFERENCES review_units(review_unit_id) ON DELETE SET NULL,
    status             TEXT    NOT NULL DEFAULT 'open'
                               CHECK (status IN ('open','deferred','closed')),
    disposition        TEXT    CHECK (disposition IN ('promoted','rejected','duplicate','hardening','stale')),
    defer_reason       TEXT,
    retry_condition    TEXT,
    priority_band      TEXT    NOT NULL DEFAULT 'normal'
                               CHECK (priority_band IN ('urgent','high','normal','background')),
    priority_proposal  TEXT,               -- bounded JSON
    -- semantic identity (server-derived fingerprint; see below)
    identity_family    TEXT    NOT NULL,
    identity_anchor    TEXT    NOT NULL,
    identity_instance_key TEXT,
    identity_fingerprint BLOB  NOT NULL,
    anchored_payload   TEXT    NOT NULL,   -- bounded JSON: hypothesis, anchors, next proof step,
                                           -- counterevidence, proof gap
    anchored_digest    BLOB    NOT NULL,
    commit_sha         TEXT    NOT NULL,
    needs_revalidation INTEGER NOT NULL DEFAULT 0,
    carry_depth        INTEGER NOT NULL DEFAULT 0,
    supersedes_lead_id INTEGER REFERENCES leads(lead_id) ON DELETE SET NULL,
    duplicate_of_lead_id    INTEGER REFERENCES leads(lead_id) ON DELETE SET NULL,
    duplicate_of_finding_id INTEGER,       -- informational; no FK cascade into canonical
    promoted_finding_id     INTEGER,       -- informational; set at promotion
    created_by_job_id  INTEGER REFERENCES jobs(id),
    created_at         INTEGER NOT NULL,
    closed_at          INTEGER,
    CHECK ((status = 'closed') = (disposition IS NOT NULL))
);
CREATE UNIQUE INDEX idx_leads_identity
    ON leads(generation_id, identity_fingerprint)
    WHERE status <> 'closed' OR disposition <> 'stale';
CREATE INDEX idx_leads_sched ON leads(generation_id, status, priority_band);

CREATE TABLE lead_observations (
    lead_observation_id INTEGER PRIMARY KEY,
    lead_id            INTEGER NOT NULL REFERENCES leads(lead_id) ON DELETE CASCADE,
    submitted_by_job_id INTEGER REFERENCES jobs(id),
    observation_payload TEXT   NOT NULL,
    observation_digest  BLOB   NOT NULL,
    commit_sha          TEXT   NOT NULL,
    created_at          INTEGER NOT NULL
);
"#;

/// SPEC-01 §9.
pub(super) const JOB_RECEIPTS: &str = r#"
-- [transient-ish: retained for replay, GC'd with the job's retry grace]
CREATE TABLE job_checkpoints (
    job_checkpoint_id INTEGER PRIMARY KEY,
    job_id           INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    client_key       TEXT    NOT NULL,    -- domain-qualified, e.g. client_lead_key
    operation        TEXT    NOT NULL,    -- tool/endpoint name
    payload_digest   BLOB    NOT NULL,
    response         TEXT    NOT NULL,    -- canonical JSON returned to the caller
    created_at       INTEGER NOT NULL,
    UNIQUE (job_id, client_key)
);

-- [canonical]
CREATE TABLE job_terminal_receipts (
    job_terminal_receipt_id INTEGER PRIMARY KEY,
    job_id             INTEGER NOT NULL UNIQUE REFERENCES jobs(id) ON DELETE CASCADE,
    phase              TEXT    NOT NULL,
    terminal_reason    TEXT    NOT NULL,   -- e.g. completed, partial, deferred, rejected
    subject_title      TEXT,
    subject_digest     BLOB,
    pinned_commit_sha  TEXT    NOT NULL,
    effective_recipe   TEXT    NOT NULL,   -- copied JSON recipe + limits
    result_digest      BLOB    NOT NULL,
    evidence_rung      TEXT    CHECK (evidence_rung IN ('L1','L2','L3','L4')),
    result_counts      TEXT,               -- JSON
    finishing_capability_hash BLOB,        -- non-authoritative, for terminal replay
    created_at         INTEGER NOT NULL
);
"#;

/// SPEC-01 §10.
pub(super) const FINDING_EXTENSIONS: &str = r#"
CREATE TABLE finding_review_details (
    finding_id         INTEGER PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    repo_id            INTEGER NOT NULL REFERENCES registered_repos(id) ON DELETE CASCADE,
    workflow_contract_version INTEGER NOT NULL,
    profile_version    INTEGER NOT NULL,
    profile_digest     BLOB,
    reviewed_commit_sha TEXT   NOT NULL,
    identity_family    TEXT    NOT NULL,
    identity_anchor    TEXT    NOT NULL,
    identity_instance_key TEXT,
    identity_fingerprint BLOB  NOT NULL,
    l2_argument        TEXT    NOT NULL,   -- JSON: source/control/sink/path/boundary + locations
    counterevidence    TEXT    NOT NULL,
    assumptions_gaps   TEXT    NOT NULL,
    confidence         TEXT    NOT NULL CHECK (confidence IN ('low','medium','high')),
    submitted_rung     TEXT    NOT NULL CHECK (submitted_rung IN ('L2','L3')),
    origin_lead_id     INTEGER REFERENCES leads(lead_id) ON DELETE SET NULL,
    created_at         INTEGER NOT NULL,
    UNIQUE (repo_id, identity_fingerprint),
    FOREIGN KEY (repo_id, finding_id)
        REFERENCES findings(repo_id, id) ON DELETE CASCADE
);

CREATE TABLE verification_attempt_details (
    verification_id    INTEGER PRIMARY KEY REFERENCES finding_verifications(id) ON DELETE CASCADE,
    workflow_contract_version INTEGER NOT NULL,
    checkout_commit_sha TEXT   NOT NULL,
    established_rung   TEXT    CHECK (established_rung IN ('L2','L3','L4')),
    e2e_applicability  TEXT    NOT NULL CHECK (e2e_applicability IN ('applicable','not_applicable')),
    e2e_rationale      TEXT,               -- required when not_applicable
    blocker            TEXT,
    retry_condition    TEXT,
    verification_proof_id INTEGER,
    terminal_digest    BLOB    NOT NULL,
    created_at         INTEGER NOT NULL,
    -- the proof must belong to this very verification attempt
    FOREIGN KEY (verification_id, verification_proof_id)
        REFERENCES verification_proofs(verification_id, verification_proof_id)
);
"#;

/// SPEC-01 §11.
pub(super) const PROOF_STORAGE: &str = r#"
CREATE TABLE proof_artifact_blobs (
    proof_artifact_blob_id INTEGER PRIMARY KEY,
    repo_id            INTEGER NOT NULL REFERENCES registered_repos(id) ON DELETE CASCADE,
    sha256             BLOB    NOT NULL,
    byte_len           INTEGER NOT NULL,
    content            BLOB    NOT NULL,
    created_at         INTEGER NOT NULL,
    UNIQUE (repo_id, sha256),
    UNIQUE (repo_id, proof_artifact_blob_id)   -- composite parent key
);

CREATE TABLE proof_artifacts (
    proof_artifact_id  INTEGER PRIMARY KEY,
    repo_id            INTEGER NOT NULL REFERENCES registered_repos(id) ON DELETE CASCADE,
    proof_artifact_blob_id INTEGER NOT NULL,
    artifact_role      TEXT    NOT NULL CHECK (artifact_role IN
        ('reproducer_source','crafted_input','test_patch','command_stdout','command_stderr','execution_trace')),
    media_type         TEXT    NOT NULL,
    label              TEXT,
    original_name      TEXT    NOT NULL,   -- display only; never used as a path
    sha256             BLOB    NOT NULL,
    byte_len           INTEGER NOT NULL,
    produced_by_job_id INTEGER,
    created_at         INTEGER NOT NULL,
    UNIQUE (repo_id, proof_artifact_id),       -- composite parent key
    FOREIGN KEY (repo_id, proof_artifact_blob_id)
        REFERENCES proof_artifact_blobs(repo_id, proof_artifact_blob_id),
    FOREIGN KEY (repo_id, produced_by_job_id) REFERENCES jobs(repo_id, id)
);

-- [transient]
CREATE TABLE staged_proof_artifacts (
    staged_proof_artifact_id INTEGER PRIMARY KEY,
    job_id             INTEGER NOT NULL,
    repo_id            INTEGER NOT NULL REFERENCES registered_repos(id) ON DELETE CASCADE,
    proof_artifact_blob_id INTEGER NOT NULL,
    artifact_role      TEXT    NOT NULL,
    media_type         TEXT    NOT NULL,
    label              TEXT,
    original_name      TEXT    NOT NULL,
    created_at         INTEGER NOT NULL,
    FOREIGN KEY (repo_id, job_id) REFERENCES jobs(repo_id, id) ON DELETE CASCADE,
    FOREIGN KEY (repo_id, proof_artifact_blob_id)
        REFERENCES proof_artifact_blobs(repo_id, proof_artifact_blob_id)
);

CREATE TABLE proof_executions (
    proof_execution_id INTEGER PRIMARY KEY,
    repo_id            INTEGER NOT NULL REFERENCES registered_repos(id) ON DELETE CASCADE,
    produced_by_job_id INTEGER NOT NULL,
    target_commit_sha  TEXT    NOT NULL,
    clean_tree         INTEGER NOT NULL,
    argv               TEXT    NOT NULL,   -- JSON array
    working_dir        TEXT    NOT NULL,   -- logical, relative
    env_names          TEXT    NOT NULL,   -- JSON: allowlisted names + non-secret values
    fixture_artifact_ids TEXT,             -- JSON: staged fixture references
    network_policy     TEXT    NOT NULL,   -- 'isolated' (only value until networked-e2e ships)
    limits             TEXT    NOT NULL,   -- JSON: cpu/mem/pids/file/time/output
    timeout_seconds    INTEGER NOT NULL,
    started_at         INTEGER NOT NULL,
    duration_ms        INTEGER NOT NULL,
    exit_status        INTEGER,
    term_signal        INTEGER,
    stdout_artifact_id INTEGER,
    stderr_artifact_id INTEGER,
    output_truncated   INTEGER NOT NULL DEFAULT 0,
    staged             INTEGER NOT NULL DEFAULT 1,  -- cleared at finalization
    created_at         INTEGER NOT NULL,
    UNIQUE (repo_id, proof_execution_id),      -- composite parent key
    FOREIGN KEY (repo_id, produced_by_job_id) REFERENCES jobs(repo_id, id),
    FOREIGN KEY (repo_id, stdout_artifact_id)
        REFERENCES proof_artifacts(repo_id, proof_artifact_id),
    FOREIGN KEY (repo_id, stderr_artifact_id)
        REFERENCES proof_artifacts(repo_id, proof_artifact_id)
);

CREATE TABLE verification_proofs (
    verification_proof_id INTEGER PRIMARY KEY,
    finding_id         INTEGER NOT NULL,
    verification_id    INTEGER NOT NULL,
    repo_id            INTEGER NOT NULL REFERENCES registered_repos(id) ON DELETE CASCADE,
    rung               TEXT    NOT NULL CHECK (rung IN ('L3','L4')),
    pinned_commit_sha  TEXT    NOT NULL,
    manifest           TEXT    NOT NULL,   -- JSON: boundary, attacker action, expected property,
                                           -- observed consequence, stock assertion, limitations
    manifest_digest    BLOB    NOT NULL,
    created_at         INTEGER NOT NULL,
    UNIQUE (repo_id, verification_proof_id),           -- composite parent key
    UNIQUE (verification_id, verification_proof_id),   -- for attempt details
    FOREIGN KEY (repo_id, finding_id)
        REFERENCES findings(repo_id, id) ON DELETE CASCADE,
    FOREIGN KEY (finding_id, verification_id)
        REFERENCES finding_verifications(finding_id, id) ON DELETE CASCADE
);

CREATE TABLE verification_proof_artifacts (
    repo_id            INTEGER NOT NULL,
    verification_proof_id INTEGER NOT NULL,
    proof_artifact_id  INTEGER NOT NULL,
    PRIMARY KEY (verification_proof_id, proof_artifact_id),
    FOREIGN KEY (repo_id, verification_proof_id)
        REFERENCES verification_proofs(repo_id, verification_proof_id) ON DELETE CASCADE,
    FOREIGN KEY (repo_id, proof_artifact_id)
        REFERENCES proof_artifacts(repo_id, proof_artifact_id)
);
CREATE TABLE verification_proof_executions (
    repo_id            INTEGER NOT NULL,
    verification_proof_id INTEGER NOT NULL,
    proof_execution_id INTEGER NOT NULL,
    PRIMARY KEY (verification_proof_id, proof_execution_id),
    FOREIGN KEY (repo_id, verification_proof_id)
        REFERENCES verification_proofs(repo_id, verification_proof_id) ON DELETE CASCADE,
    FOREIGN KEY (repo_id, proof_execution_id)
        REFERENCES proof_executions(repo_id, proof_execution_id)
);

-- composite parent keys on pre-existing tables (created in v3):
CREATE UNIQUE INDEX idx_findings_repo_id_id ON findings(repo_id, id);
CREATE UNIQUE INDEX idx_finding_verifications_finding_id_id
    ON finding_verifications(finding_id, id);
"#;

pub(super) const NEW_TABLES: &[&str] = &[
	REVIEW_CAMPAIGNS,
	REVIEW_GENERATIONS,
	GENERATION_INVENTORY,
	REVIEW_UNITS,
	REVIEW_UNIT_RESULTS,
	LEADS,
	JOB_RECEIPTS,
	FINDING_EXTENSIONS,
	PROOF_STORAGE,
];

pub(super) const JOB_INDEXES: &[(&str, &str)] = &[
	("idx_jobs_queued", r#"CREATE INDEX idx_jobs_queued ON jobs(state, enqueued_at);"#),
	("idx_jobs_lease", r#"CREATE INDEX idx_jobs_lease  ON jobs(state, lease_expires_at);"#),
	("idx_jobs_repo", r#"CREATE INDEX idx_jobs_repo   ON jobs(repo_id);"#),
	(
		"idx_jobs_capability",
		r#"CREATE UNIQUE INDEX idx_jobs_capability
    ON jobs(job_capability_hash)
    WHERE job_capability_hash IS NOT NULL;"#,
	),
	("idx_jobs_repo_id_id", r#"CREATE UNIQUE INDEX idx_jobs_repo_id_id ON jobs(repo_id, id);"#),
	(
		"idx_jobs_active_drilldown",
		r#"CREATE UNIQUE INDEX idx_jobs_active_drilldown
    ON jobs(assigned_lead_id)
    WHERE assigned_lead_id IS NOT NULL AND state IN ('queued','leased') AND kind = 'drilldown';"#,
	),
	(
		"idx_jobs_active_verify",
		r#"CREATE UNIQUE INDEX idx_jobs_active_verify
    ON jobs(target_finding_id)
    WHERE target_finding_id IS NOT NULL AND state IN ('queued','leased') AND kind = 'verify';"#,
	),
	(
		"idx_jobs_scheduler",
		r#"CREATE INDEX idx_jobs_scheduler
    ON jobs(state, kind, scheduling_band, effective_priority, eligible_at);"#,
	),
];
