//! Conservative metadata for the designated content groups in these tables.
//! It does not classify excluded audit/revision fields or assert authorship.

pub(super) const SOURCE_METADATA: &str = "
ALTER TABLE findings ADD COLUMN source TEXT NOT NULL DEFAULT 'agent';
ALTER TABLE finding_verifications ADD COLUMN source TEXT NOT NULL DEFAULT 'agent';
ALTER TABLE review_units ADD COLUMN source TEXT NOT NULL DEFAULT 'agent';
ALTER TABLE review_unit_results ADD COLUMN source TEXT NOT NULL DEFAULT 'agent';
ALTER TABLE leads ADD COLUMN source TEXT NOT NULL DEFAULT 'agent';
ALTER TABLE lead_observations ADD COLUMN source TEXT NOT NULL DEFAULT 'agent';
ALTER TABLE finding_review_details ADD COLUMN source TEXT NOT NULL DEFAULT 'agent';
ALTER TABLE verification_attempt_details ADD COLUMN source TEXT NOT NULL DEFAULT 'agent';
ALTER TABLE proof_artifacts ADD COLUMN source TEXT NOT NULL DEFAULT 'agent';
ALTER TABLE staged_proof_artifacts ADD COLUMN source TEXT NOT NULL DEFAULT 'agent';
ALTER TABLE proof_executions ADD COLUMN source TEXT NOT NULL DEFAULT 'agent';
ALTER TABLE verification_proofs ADD COLUMN source TEXT NOT NULL DEFAULT 'agent';
";
