//! Authenticated host preparation. Storage owns the transaction and all
//! mutations; the server decodes original Worker spans and renders bounded wire.
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Extension;
use loupe_core::review_metadata::ReviewCommit;
use loupe_proto::review_api::{
	InventoryBatchRequestDecoder, ManifestProgress, PinTargetRequest, PinTargetRequestDecoder,
	PinTargetResponse, PreparationDeferral, PublishProfileRequestDecoder, PublishedProfile,
	ReviewProtocol, SealInventoryRequestDecoder, UnsupportedRecipe,
};
use loupe_provenance::{Agent, Db, Worker};
use loupe_storage::host_preparation::{self, PinOutcome, PinReplay};
use loupe_storage::terminal_receipt::{Receipt, Reject};

use crate::auth::AuthedWorker;
use crate::ingress::WorkerBody;
use crate::review::authority::{self, Access, Phase};
use crate::review::envelope;
use crate::review::http::{self, ApiError, Result};
use crate::AppState;

pub const PIN_TARGET_REQUEST_CAP: usize = 2 * 1024;
pub const PIN_TARGET_RESPONSE_CAP: usize = 4 * 1024 * 1024;
pub const INVENTORY_BATCH_REQUEST_CAP: usize = 2 * 1024 * 1024;
pub const INVENTORY_BATCH_RESPONSE_CAP: usize = 8 * 1024;
pub const SEAL_INVENTORY_REQUEST_CAP: usize = 2 * 1024;
pub const SEAL_INVENTORY_RESPONSE_CAP: usize = 8 * 1024;
pub const PUBLISH_PROFILE_REQUEST_CAP: usize = 256 * 1024;
pub const PUBLISH_PROFILE_RESPONSE_CAP: usize = 4 * 1024;

fn progress(manifest: host_preparation::Manifest) -> ManifestProgress<Db> {
	ManifestProgress {
		protocol_version: ReviewProtocol,
		expected_entry_count: manifest.expected_count,
		expected_digest: manifest.digest_hex,
		received_entry_count: manifest.received_count,
		received_canonical_bytes: manifest.received_bytes,
		sealed: manifest.sealed_at.is_some(),
	}
}

fn pin_digest(request: &PinTargetRequest<Worker>) -> Result<[u8; 32]> {
	let value = serde_json::to_value(request).map_err(ApiError::invalid)?;
	let mut hasher = blake3::Hasher::new();
	hasher.update(b"loupe.host.pin.v1\0");
	hasher.update(&loupe_core::canonical::canonical_bytes(&value));
	Ok(*hasher.finalize().as_bytes())
}

fn deferred(receipt: &Receipt, commit: ReviewCommit<Db>) -> Result<PinTargetResponse<Agent, Db>> {
	if receipt.terminal_reason.expose() != "unsupported_recipe" {
		return Err(ApiError::denied());
	}
	Ok(PinTargetResponse::Deferred {
		protocol_version: ReviewProtocol,
		receipt: PreparationDeferral {
			receipt_id: receipt.receipt_id.try_into().map_err(ApiError::invalid)?,
			commit_sha: commit,
			reason: UnsupportedRecipe::UnsupportedRecipe,
		},
	})
}

pub async fn pin_target(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, headers: HeaderMap, body: WorkerBody,
) -> Result<Response> {
	let body = http::body(&headers, body, PIN_TARGET_REQUEST_CAP)?;
	let request = body.0.as_bytes().validate(PinTargetRequestDecoder).map_err(ApiError::invalid)?;
	let digest = pin_digest(&request)?;
	http::transaction(&state.db, &worker, &headers, job, PIN_TARGET_RESPONSE_CAP, |tx| {
		match tx.replay_pin_target(&request.commit_sha, &digest)? {
			PinReplay::Receipt { receipt, commit } => return deferred(&receipt, commit),
			PinReplay::Reject(Reject::WrongDigest) => {
				return Err(ApiError::conflict("terminal_conflict"))
			},
			PinReplay::Reject(Reject::Denied) => {},
		}
		match tx.pin_target(&request.commit_sha, &digest, authority::policy)? {
			PinOutcome::Prepared(scope) => envelope::preparation(scope.preparation_snapshot()?),
			PinOutcome::Deferred { receipt, commit } => deferred(&receipt, commit),
		}
	})
}

pub async fn inventory_batch(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, headers: HeaderMap, body: WorkerBody,
) -> Result<Response> {
	let body = http::body(&headers, body, INVENTORY_BATCH_REQUEST_CAP)?;
	let request =
		body.0.as_bytes().validate(InventoryBatchRequestDecoder).map_err(ApiError::invalid)?;
	let digest: Vec<u8> = request
		.expected_digest
		.expose()
		.as_bytes()
		.as_chunks::<2>()
		.0
		.iter()
		.map(|pair| {
			std::str::from_utf8(pair)
				.ok()
				.and_then(|raw| u8::from_str_radix(raw, 16).ok())
				.ok_or_else(|| ApiError::invalid("manifest digest"))
		})
		.collect::<Result<_>>()?;
	let digest: [u8; 32] = digest.try_into().map_err(|_| ApiError::invalid("manifest digest"))?;
	let entries = request
		.entries
		.as_slice()
		.iter()
		.map(|entry| entry.to_manifest().map_err(ApiError::invalid))
		.collect::<Result<Vec<_>>>()?;
	http::transaction(&state.db, &worker, &headers, job, INVENTORY_BATCH_RESPONSE_CAP, |tx| {
		let scope = authority::authorize(tx, Phase::Survey, Access::PreparedHost)?
			.ok_or_else(ApiError::denied)?;
		scope.declare_manifest(request.expected_entry_count, &digest)?;
		Ok(progress(scope.upload_manifest(request.start_position, &entries)?))
	})
}

pub async fn seal_inventory(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, headers: HeaderMap, body: WorkerBody,
) -> Result<Response> {
	let body = http::body(&headers, body, SEAL_INVENTORY_REQUEST_CAP)?;
	body.0.as_bytes().validate(SealInventoryRequestDecoder).map_err(ApiError::invalid)?;
	http::transaction(&state.db, &worker, &headers, job, SEAL_INVENTORY_RESPONSE_CAP, |tx| {
		let scope = authority::authorize(tx, Phase::Survey, Access::PreparedHost)?
			.ok_or_else(ApiError::denied)?;
		Ok(progress(scope.seal_manifest()?))
	})
}

pub async fn publish_profile(
	State(state): State<AppState>, Path(job): Path<i64>,
	Extension(worker): Extension<AuthedWorker>, headers: HeaderMap, body: WorkerBody,
) -> Result<Response> {
	let body = http::body(&headers, body, PUBLISH_PROFILE_REQUEST_CAP)?;
	let request = body
		.0
		.as_bytes()
		.validate_carrying(PublishProfileRequestDecoder)
		.map_err(ApiError::invalid)?;
	http::transaction(&state.db, &worker, &headers, job, PUBLISH_PROFILE_RESPONSE_CAP, |tx| {
		let scope = authority::authorize(tx, Phase::Survey, Access::PreparedHost)?
			.ok_or_else(ApiError::denied)?;
		let profile = scope.publish_profile(&request.profile)?;
		Ok(PublishedProfile {
			protocol_version: ReviewProtocol,
			profile_version: profile.version.try_into().map_err(ApiError::invalid)?,
			profile_digest: profile.digest_hex,
		})
	})
}
