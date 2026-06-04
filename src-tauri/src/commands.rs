use std::{collections::HashMap, fs, path::PathBuf, sync::Mutex};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State, Window};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;

use crate::crypto_vault::{
    decode_16_hex, BackendAuthChallenge, CiphertextHeader, EncryptedFolder, EncryptedNote,
    FolderCiphertextHeader, PlaintextFolderDocument, PlaintextNoteDocument, VaultContext,
    VaultMaterial, BACKEND_AUTH_ALGORITHM, BACKEND_AUTH_KEY_VERSION, CIPHERTEXT_SCHEMA_VERSION,
    MIN_CIPHERTEXT_SCHEMA_VERSION,
};
use crate::local_store::{
    self, LocalEncryptedFolderRecord, LocalEncryptedNoteRecord, LocalVaultData, MergeSummary,
    RemoteCloudState, RemoteFolderRecord, RemoteNoteRecord, SaveLocalFolderInput,
    SaveLocalNoteInput, StorageMode, SyncBlockedReason, SyncedRecordRef, VaultPreference,
};
use crate::vault_archive::{self, BackupInspection};
use crate::wallet_protocol::{verify_wallet_generic_response, VerifyWalletResponseInput};
#[cfg(debug_assertions)]
use crate::wallet_response::decrypt_encrypted_app_response;
use crate::wallet_response::{
    decrypt_verified_app_response, prepare_response_encryption, CancelWalletUnlockSessionInput,
    EncryptedWalletResponseInput, GenericWalletResponseInput, PendingWalletUnlockState,
    PrepareWalletResponseEncryptionOutput, RegisterWalletUnlockSessionInput,
    ResponseEncryptionState,
};
use crate::wallet_unlock_policy::{active_wallet_unlock_policy, WalletUnlockPolicy};

const CIPHERTEXT_ALGORITHM: &str = "XCHACHA20-POLY1305";
const BACKUP_IMPORT_TOKEN_TTL_MS: u64 = 10 * 60 * 1000;
const EXTERNAL_LINK_MAX_BYTES: usize = 2048;
const WALLET_UNLOCK_SESSION_TTL_MS: u64 = 10 * 60 * 1000;

#[derive(Default)]
pub struct VaultState {
    inner: Mutex<Option<VaultRuntime>>,
}

#[derive(Default)]
pub struct BackupImportState {
    inner: Mutex<HashMap<String, BackupImportSelection>>,
}

pub struct VaultRuntime {
    material: VaultMaterial,
    policy: VaultRuntimePolicy,
}

#[derive(Clone, Debug)]
pub struct VaultRuntimePolicy {
    vault_id: String,
    app_encryption_request_id: String,
    #[allow(dead_code)]
    app_encryption_address: String,
    app_identity_i_address: String,
    backend_auth_algorithm: String,
    backend_auth_key_id: String,
    backend_auth_public_key: String,
    backend_auth_key_version: u64,
    chain: String,
    derivation_number: u64,
    key_version: u64,
    wallet_signer_identity_i_address: String,
    wallet_signer_identity_name: Option<String>,
    cloud_auth_attestation: Option<CloudAuthAttestation>,
}

#[derive(Clone, Debug)]
pub struct CloudAuthAttestation {
    cloud_attestation_expires_at: u64,
    cloud_attestation_id: String,
    cloud_attestation_secret: Secret<String>,
    request_hash_hex: String,
    #[allow(dead_code)]
    signer_base_url: String,
    signer_session_id: String,
}

struct BackupImportSelection {
    vault_id: String,
    path: PathBuf,
    expires_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartWalletUnlockSessionInput {
    pub signer_url: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartWalletUnlockSessionOutput {
    pub session_id: String,
    pub deeplink: String,
    pub expires_at: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PollWalletUnlockSessionInput {
    pub session_id: String,
    pub device_id_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PollWalletUnlockSessionOutput {
    Pending,
    Unlocked {
        #[serde(rename = "unlockContext")]
        unlock_context: WalletUnlockContextOutput,
        vault: UnlockWalletResponseOutput,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletUnlockContextOutput {
    pub app_encryption_request_id: String,
    pub app_identity_i_address: String,
    pub chain: String,
    pub derivation_number: u64,
    pub key_version: u64,
    pub wallet_signer_identity_i_address: String,
    pub wallet_signer_identity_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectBackupForImportInput {
    pub vault_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectBackupForImportOutput {
    pub token: String,
    pub inspection: BackupInspection,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignerWalletSession {
    #[serde(rename = "appEncryptionRequestID")]
    app_encryption_request_id: String,
    #[serde(rename = "appEncryptionRequestIDHex")]
    app_encryption_request_id_hex: String,
    app_identity_i_address: String,
    callback_url: String,
    chain: String,
    cloud_attestation_expires_at: u64,
    cloud_attestation_id: String,
    cloud_attestation_secret: String,
    deeplink: String,
    derivation_number: u64,
    expires_at: u64,
    #[serde(default)]
    expected_wallet_signer_identity_i_address: Option<String>,
    key_version: u64,
    poll_url: String,
    request_hash_hex: String,
    response_encryption_key_id: Option<String>,
    session_id: String,
    unsigned_request_hash_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignerPollResponse {
    status: String,
    unlock_payload: Option<SignerUnlockPayload>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignerUnlockPayload {
    response_mode: String,
    response_base64_url: String,
}

struct CompletedWalletUnlock {
    context: WalletUnlockContextOutput,
    vault: UnlockWalletResponseOutput,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetCloudAuthAttestationInput {
    pub vault_id: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GetCloudAuthAttestationOutput {
    Ready {
        #[serde(rename = "cloudAttestationExpiresAt")]
        cloud_attestation_expires_at: u64,
        #[serde(rename = "cloudAttestationId")]
        cloud_attestation_id: String,
        #[serde(rename = "cloudAttestationSecret")]
        cloud_attestation_secret: String,
        #[serde(rename = "requestHashHex")]
        request_hash_hex: String,
        #[serde(rename = "signerSessionId")]
        signer_session_id: String,
        #[serde(rename = "unlockContext")]
        unlock_context: WalletUnlockContextOutput,
        vault: UnlockWalletResponseOutput,
    },
    WalletUnlockRequired {
        reason: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockWalletResponseOutput {
    pub vault_id: String,
    pub backend_auth_algorithm: String,
    pub backend_auth_key_id: String,
    pub backend_auth_public_key: String,
    pub backend_auth_key_version: u64,
    pub export_check_hash: String,
    pub wallet_signer_identity_i_address: String,
    pub wallet_signer_identity_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptNoteInput {
    pub header: CiphertextHeader,
    pub document: PlaintextNoteDocument,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptFolderInput {
    pub header: FolderCiphertextHeader,
    pub document: PlaintextFolderDocument,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetVaultPreferenceInput {
    pub vault_id: String,
    pub storage_mode: StorageMode,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableVaultSyncInput {
    pub vault_id: String,
    pub included_note_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportMarkdownNoteInput {
    pub markdown: String,
    pub suggested_file_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MarkRecordsSyncedInput {
    pub vault_id: String,
    pub synced_record_refs: Vec<SyncedRecordRef>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoteSyncBlockedInput {
    pub vault_id: String,
    pub note_id: String,
    pub expected_revision_hash: Option<String>,
    pub reason: SyncBlockedReason,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoteCloudSyncScopeInput {
    pub vault_id: String,
    pub note_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MergeRemoteRecordsInput {
    pub vault_id: String,
    pub notes: Vec<RemoteNoteRecord>,
    pub folders: Vec<RemoteFolderRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportVaultBackupInput {
    pub suggested_file_name: String,
    pub vault_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportVaultBackupInput {
    pub token: String,
    pub vault_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenExternalLinkInput {
    pub href: String,
}

#[tauri::command]
pub async fn start_wallet_unlock_session(
    input: StartWalletUnlockSessionInput,
    app: AppHandle,
) -> Result<StartWalletUnlockSessionOutput, String> {
    run_wallet_unlock_worker(move || {
        let response_encryption_state = app.state::<ResponseEncryptionState>();
        let pending_unlock_state = app.state::<PendingWalletUnlockState>();
        start_wallet_unlock_session_blocking(
            input,
            response_encryption_state.inner(),
            pending_unlock_state.inner(),
        )
    })
    .await
}

fn start_wallet_unlock_session_blocking(
    input: StartWalletUnlockSessionInput,
    response_encryption_state: &ResponseEncryptionState,
    pending_unlock_state: &PendingWalletUnlockState,
) -> Result<StartWalletUnlockSessionOutput, String> {
    let policy = active_wallet_unlock_policy();
    let signer_url = resolve_signer_url(input.signer_url.as_deref(), &policy)?;
    let prepared = prepare_response_encryption(response_encryption_state)
        .map_err(|error| error.to_string())?;
    let session = create_signer_wallet_session(&signer_url, &prepared, &policy)?;

    let response_encryption_key_id = session
        .response_encryption_key_id
        .clone()
        .ok_or_else(|| "wallet signer did not echo the response encryption key id".to_string())?;

    if response_encryption_key_id != prepared.key_id {
        response_encryption_state
            .discard(&prepared.key_id)
            .map_err(|error| error.to_string())?;
        return Err("wallet signer returned mismatched response encryption key id".to_string());
    }

    pending_unlock_state
        .insert(RegisterWalletUnlockSessionInput {
            app_encryption_request_id: session.app_encryption_request_id.clone(),
            app_identity_i_address: session.app_identity_i_address.clone(),
            chain: session.chain.clone(),
            cloud_attestation_expires_at: session.cloud_attestation_expires_at,
            cloud_attestation_id: session.cloud_attestation_id.clone(),
            cloud_attestation_secret: session.cloud_attestation_secret.clone(),
            derivation_number: session.derivation_number,
            expires_at: session.expires_at,
            expected_app_encryption_request_id_hex: session.app_encryption_request_id_hex.clone(),
            expected_signed_request_hash_hex: session.request_hash_hex.clone(),
            expected_unsigned_request_hash_hex: session.unsigned_request_hash_hex.clone(),
            expected_wallet_signer_identity_i_address: session
                .expected_wallet_signer_identity_i_address
                .clone(),
            key_version: session.key_version,
            response_encryption_key_id,
            session_id: session.session_id.clone(),
            signer_base_url: signer_url,
        })
        .map_err(|error| error.to_string())?;

    Ok(StartWalletUnlockSessionOutput {
        session_id: session.session_id,
        deeplink: session.deeplink,
        expires_at: session.expires_at,
    })
}

#[tauri::command]
pub async fn poll_wallet_unlock_session(
    input: PollWalletUnlockSessionInput,
    app: AppHandle,
) -> Result<PollWalletUnlockSessionOutput, String> {
    run_wallet_unlock_worker(move || {
        let response_encryption_state = app.state::<ResponseEncryptionState>();
        let pending_unlock_state = app.state::<PendingWalletUnlockState>();
        let vault_state = app.state::<VaultState>();
        poll_wallet_unlock_session_blocking(
            input,
            response_encryption_state.inner(),
            pending_unlock_state.inner(),
            vault_state.inner(),
        )
    })
    .await
}

fn poll_wallet_unlock_session_blocking(
    input: PollWalletUnlockSessionInput,
    response_encryption_state: &ResponseEncryptionState,
    pending_unlock_state: &PendingWalletUnlockState,
    vault_state: &VaultState,
) -> Result<PollWalletUnlockSessionOutput, String> {
    let pending_session = pending_unlock_state
        .get_fresh_by_session_id(&input.session_id)
        .map_err(|error| error.to_string())?;
    let poll = poll_signer_wallet_session(&pending_session.signer_base_url, &input.session_id)?;

    match poll.status.as_str() {
        "pending" => Ok(PollWalletUnlockSessionOutput::Pending),
        "ready" => {
            let payload = poll
                .unlock_payload
                .ok_or_else(|| "wallet signer response is missing unlock payload".to_string())?;
            if payload.response_mode != "generic_response" {
                return Err("wallet signer returned unsupported unlock payload".to_string());
            }

            let unlocked = complete_generic_wallet_unlock(
                GenericWalletResponseInput {
                    device_id_hex: input.device_id_hex,
                    response_base64_url: payload.response_base64_url,
                    response_encryption_key_id: pending_session.response_encryption_key_id,
                },
                response_encryption_state,
                pending_unlock_state,
                vault_state,
            )?;

            Ok(PollWalletUnlockSessionOutput::Unlocked {
                unlock_context: unlocked.context,
                vault: unlocked.vault,
            })
        }
        "missing" => Err("wallet session not found".to_string()),
        "consumed" => fail_consumed_wallet_unlock_session(&input.session_id, pending_unlock_state),
        "expired" => {
            let _ = pending_unlock_state.discard_by_session_id(&input.session_id);
            Err("wallet session expired".to_string())
        }
        "failed" => {
            let _ = pending_unlock_state.discard_by_session_id(&input.session_id);
            Err("wallet session failed".to_string())
        }
        _ => Err("wallet signer returned unknown session status".to_string()),
    }
}

fn fail_consumed_wallet_unlock_session(
    session_id: &str,
    pending_unlock_state: &PendingWalletUnlockState,
) -> Result<PollWalletUnlockSessionOutput, String> {
    let _ = pending_unlock_state.discard_by_session_id(session_id);
    Err("wallet session response was already consumed; retry wallet unlock".to_string())
}

async fn run_wallet_unlock_worker<T>(
    task: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String>
where
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|_| "wallet unlock worker failed".to_string())?
}

#[tauri::command(async)]
#[allow(dead_code)]
pub fn prepare_wallet_response_encryption(
    state: State<'_, ResponseEncryptionState>,
) -> Result<PrepareWalletResponseEncryptionOutput, String> {
    prepare_response_encryption(&state).map_err(|error| error.to_string())
}

#[tauri::command(async)]
#[allow(dead_code)]
pub fn register_wallet_unlock_session(
    input: RegisterWalletUnlockSessionInput,
    response_encryption_state: State<'_, ResponseEncryptionState>,
    pending_unlock_state: State<'_, PendingWalletUnlockState>,
) -> Result<(), String> {
    response_encryption_state
        .purge_expired()
        .map_err(|error| error.to_string())?;
    pending_unlock_state
        .purge_expired()
        .map_err(|error| error.to_string())?;
    response_encryption_state
        .ensure_fresh(&input.response_encryption_key_id)
        .map_err(|error| error.to_string())?;
    pending_unlock_state
        .insert(input)
        .map_err(|error| error.to_string())
}

#[tauri::command(async)]
pub fn cancel_wallet_unlock_session(
    input: CancelWalletUnlockSessionInput,
    response_encryption_state: State<'_, ResponseEncryptionState>,
    pending_unlock_state: State<'_, PendingWalletUnlockState>,
) -> Result<(), String> {
    if let Some(key_id) = pending_unlock_state
        .discard_by_session_id(&input.session_id)
        .map_err(|error| error.to_string())?
    {
        response_encryption_state
            .discard(&key_id)
            .map_err(|error| error.to_string())?;
    }

    Ok(())
}

#[tauri::command(async)]
#[allow(dead_code)]
pub fn unlock_encrypted_wallet_response(
    input: EncryptedWalletResponseInput,
    response_encryption_state: State<'_, ResponseEncryptionState>,
    vault_state: State<'_, VaultState>,
) -> Result<UnlockWalletResponseOutput, String> {
    #[cfg(not(debug_assertions))]
    {
        let _ = (input, response_encryption_state, vault_state);
        return Err("extracted encrypted wallet response unlock is debug-only".to_string());
    }

    #[cfg(debug_assertions)]
    {
        let response = decrypt_encrypted_app_response(&input, &response_encryption_state)
            .map_err(|error| error.to_string())?;
        let device_id =
            decode_16_hex("device id", &input.device_id_hex).map_err(|error| error.to_string())?;
        let context = VaultContext {
            app_encryption_address: response.app_encryption_address,
            app_identity_i_address: input.app_identity_i_address,
            chain: input.chain,
            derivation_number: input.derivation_number,
            key_version: input.key_version,
            wallet_signer_identity_i_address: input.wallet_signer_identity_i_address.clone(),
        };
        let material = VaultMaterial::derive(*response.incoming_viewing_key, context, &device_id)
            .map_err(|error| error.to_string())?;
        let runtime = VaultRuntime::new(material, input.app_encryption_request_id, None, None);
        let output = runtime.output();

        *vault_state
            .inner
            .lock()
            .map_err(|_| "vault state lock poisoned".to_string())? = Some(runtime);

        Ok(output)
    }
}

#[tauri::command(async)]
#[allow(dead_code)]
pub fn unlock_wallet_generic_response(
    input: GenericWalletResponseInput,
    response_encryption_state: State<'_, ResponseEncryptionState>,
    pending_unlock_state: State<'_, PendingWalletUnlockState>,
    vault_state: State<'_, VaultState>,
) -> Result<UnlockWalletResponseOutput, String> {
    Ok(complete_generic_wallet_unlock(
        input,
        &response_encryption_state,
        &pending_unlock_state,
        vault_state.inner(),
    )?
    .vault)
}

#[tauri::command(async)]
pub fn encrypt_note(
    input: EncryptNoteInput,
    state: State<'_, VaultState>,
) -> Result<EncryptedNote, String> {
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|error| format!("nonce generation failed: {error}"))?;

    with_unlocked_vault(&state, |runtime| {
        runtime.validate_note_header(&input.header)?;
        runtime
            .material
            .encrypt_note_document(input.header, &input.document, nonce)
    })
}

#[tauri::command(async)]
pub fn decrypt_note(
    encrypted: EncryptedNote,
    state: State<'_, VaultState>,
) -> Result<PlaintextNoteDocument, String> {
    with_unlocked_vault(&state, |runtime| {
        runtime.validate_note_header(&encrypted.header)?;
        runtime.material.decrypt_note_document(&encrypted)
    })
}

#[tauri::command(async)]
pub fn encrypt_folder(
    input: EncryptFolderInput,
    state: State<'_, VaultState>,
) -> Result<EncryptedFolder, String> {
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|error| format!("nonce generation failed: {error}"))?;

    with_unlocked_vault(&state, |runtime| {
        runtime.validate_folder_header(&input.header)?;
        runtime
            .material
            .encrypt_folder_document(input.header, &input.document, nonce)
    })
}

#[tauri::command(async)]
pub fn decrypt_folder(
    encrypted: EncryptedFolder,
    state: State<'_, VaultState>,
) -> Result<PlaintextFolderDocument, String> {
    with_unlocked_vault(&state, |runtime| {
        runtime.validate_folder_header(&encrypted.header)?;
        runtime.material.decrypt_folder_document(&encrypted)
    })
}

#[tauri::command(async)]
pub fn sign_backend_challenge(
    challenge: BackendAuthChallenge,
    state: State<'_, VaultState>,
) -> Result<String, String> {
    with_unlocked_vault(&state, |runtime| {
        runtime.validate_backend_challenge(&challenge)?;
        runtime.material.sign_backend_challenge(&challenge)
    })
}

#[tauri::command(async)]
pub fn get_cloud_auth_attestation(
    input: GetCloudAuthAttestationInput,
    state: State<'_, VaultState>,
) -> Result<GetCloudAuthAttestationOutput, String> {
    with_unlocked_vault_string(&state, |runtime| {
        runtime.require_vault_id(&input.vault_id)?;
        let Some(attestation) = runtime.policy.cloud_auth_attestation.as_ref() else {
            return Ok(GetCloudAuthAttestationOutput::WalletUnlockRequired {
                reason: "wallet_unlock_required".to_string(),
            });
        };

        if attestation.cloud_attestation_expires_at <= now_ms() {
            return Ok(GetCloudAuthAttestationOutput::WalletUnlockRequired {
                reason: "wallet_unlock_required".to_string(),
            });
        }

        Ok(GetCloudAuthAttestationOutput::Ready {
            cloud_attestation_expires_at: attestation.cloud_attestation_expires_at,
            cloud_attestation_id: attestation.cloud_attestation_id.clone(),
            cloud_attestation_secret: attestation.cloud_attestation_secret.expose_secret().clone(),
            request_hash_hex: attestation.request_hash_hex.clone(),
            signer_session_id: attestation.signer_session_id.clone(),
            unlock_context: runtime.unlock_context(),
            vault: runtime.output(),
        })
    })
}

#[tauri::command(async)]
pub fn lock_vault(
    state: State<'_, VaultState>,
    response_encryption_state: State<'_, ResponseEncryptionState>,
    pending_unlock_state: State<'_, PendingWalletUnlockState>,
) -> Result<(), String> {
    *state
        .inner
        .lock()
        .map_err(|_| "vault state lock poisoned".to_string())? = None;
    pending_unlock_state
        .clear()
        .map_err(|error| error.to_string())?;
    response_encryption_state
        .clear()
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[tauri::command(async)]
pub fn get_vault_preference(
    vault_id: String,
    app: AppHandle,
    state: State<'_, VaultState>,
) -> Result<Option<VaultPreference>, String> {
    require_active_vault_id(&state, &vault_id)?;
    let connection = local_store::open_app_store(&app).map_err(|error| error.to_string())?;
    local_store::get_preference(&connection, &vault_id).map_err(|error| error.to_string())
}

#[tauri::command(async)]
pub fn set_vault_preference(
    input: SetVaultPreferenceInput,
    app: AppHandle,
    state: State<'_, VaultState>,
) -> Result<VaultPreference, String> {
    require_active_vault_id(&state, &input.vault_id)?;
    let connection = local_store::open_app_store(&app).map_err(|error| error.to_string())?;
    local_store::set_preference(&connection, &input.vault_id, input.storage_mode, now_ms())
        .map_err(|error| error.to_string())
}

#[tauri::command(async)]
pub fn enable_vault_sync(
    input: EnableVaultSyncInput,
    app: AppHandle,
    state: State<'_, VaultState>,
) -> Result<VaultPreference, String> {
    require_active_vault_id(&state, &input.vault_id)?;
    let connection = local_store::open_app_store(&app).map_err(|error| error.to_string())?;
    local_store::enable_sync(
        &connection,
        &input.vault_id,
        now_ms(),
        input.included_note_ids.as_deref(),
    )
    .map_err(|error| error.to_string())
}

#[tauri::command(async)]
pub fn mark_cloud_copy_deleted(
    vault_id: String,
    app: AppHandle,
    state: State<'_, VaultState>,
) -> Result<VaultPreference, String> {
    require_active_vault_id(&state, &vault_id)?;
    let connection = local_store::open_app_store(&app).map_err(|error| error.to_string())?;
    local_store::mark_cloud_copy_deleted(&connection, &vault_id, now_ms())
        .map_err(|error| error.to_string())
}

#[tauri::command(async)]
pub fn queue_cloud_replica_rebuild(
    vault_id: String,
    app: AppHandle,
    state: State<'_, VaultState>,
) -> Result<LocalVaultData, String> {
    require_active_vault_id(&state, &vault_id)?;
    let connection = local_store::open_app_store(&app).map_err(|error| error.to_string())?;
    local_store::queue_cloud_replica_rebuild(&connection, &vault_id)
        .map_err(|error| error.to_string())
}

#[tauri::command(async)]
pub fn load_local_vault(
    vault_id: String,
    app: AppHandle,
    state: State<'_, VaultState>,
) -> Result<LocalVaultData, String> {
    require_active_vault_id(&state, &vault_id)?;
    let connection = local_store::open_app_store(&app).map_err(|error| error.to_string())?;
    local_store::load_vault(&connection, &vault_id).map_err(|error| error.to_string())
}

#[tauri::command(async)]
pub fn save_local_note(
    input: SaveLocalNoteInput,
    app: AppHandle,
    state: State<'_, VaultState>,
) -> Result<LocalEncryptedNoteRecord, String> {
    with_unlocked_vault_string(&state, |runtime| {
        runtime.validate_note_header_string(&input.encrypted_note.header)
    })?;
    let connection = local_store::open_app_store(&app).map_err(|error| error.to_string())?;
    local_store::save_note(&connection, input).map_err(|error| error.to_string())
}

#[tauri::command(async)]
pub fn save_local_folder(
    input: SaveLocalFolderInput,
    app: AppHandle,
    state: State<'_, VaultState>,
) -> Result<LocalEncryptedFolderRecord, String> {
    with_unlocked_vault_string(&state, |runtime| {
        runtime.validate_folder_header_string(&input.encrypted_folder.header)
    })?;
    let connection = local_store::open_app_store(&app).map_err(|error| error.to_string())?;
    local_store::save_folder(&connection, input).map_err(|error| error.to_string())
}

#[tauri::command]
pub fn open_external_link(input: OpenExternalLinkInput, app: AppHandle) -> Result<(), String> {
    let href = validate_external_link_href(&input.href)?;
    app.opener()
        .open_url(href, None::<&str>)
        .map_err(|_| "external link open failed".to_string())
}

#[tauri::command(async)]
pub fn export_markdown_note(
    input: ExportMarkdownNoteInput,
    app: AppHandle,
    state: State<'_, VaultState>,
    window: Window,
) -> Result<bool, String> {
    require_unlocked(&state)?;
    let Some(path) = app
        .dialog()
        .file()
        .set_parent(&window)
        .add_filter("Markdown", &["md"])
        .set_file_name(input.suggested_file_name)
        .blocking_save_file()
    else {
        return Ok(false);
    };
    let destination_path = dialog_path(path)?;
    fs::write(&destination_path, input.markdown)
        .map_err(|error| format!("markdown export failed: {error}"))?;
    Ok(true)
}

#[tauri::command(async)]
pub fn tombstone_local_note(
    vault_id: String,
    note_id: String,
    app: AppHandle,
    state: State<'_, VaultState>,
) -> Result<LocalEncryptedNoteRecord, String> {
    require_active_vault_id(&state, &vault_id)?;
    let connection = local_store::open_app_store(&app).map_err(|error| error.to_string())?;
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|error| format!("nonce generation failed: {error}"))?;
    with_unlocked_vault_string(&state, |runtime| {
        local_store::tombstone_note(
            &connection,
            &runtime.material,
            &vault_id,
            &note_id,
            now_ms(),
            nonce,
        )
        .map_err(|error| error.to_string())
    })
}

#[tauri::command(async)]
pub fn tombstone_local_folder(
    vault_id: String,
    folder_id: String,
    app: AppHandle,
    state: State<'_, VaultState>,
) -> Result<LocalEncryptedFolderRecord, String> {
    require_active_vault_id(&state, &vault_id)?;
    let connection = local_store::open_app_store(&app).map_err(|error| error.to_string())?;
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|error| format!("nonce generation failed: {error}"))?;
    with_unlocked_vault_string(&state, |runtime| {
        local_store::tombstone_folder(
            &connection,
            &runtime.material,
            &vault_id,
            &folder_id,
            now_ms(),
            nonce,
        )
        .map_err(|error| error.to_string())
    })
}

#[tauri::command(async)]
pub fn list_pending_sync(
    vault_id: String,
    app: AppHandle,
    state: State<'_, VaultState>,
) -> Result<LocalVaultData, String> {
    require_active_vault_id(&state, &vault_id)?;
    let connection = local_store::open_app_store(&app).map_err(|error| error.to_string())?;
    local_store::list_pending_sync(&connection, &vault_id).map_err(|error| error.to_string())
}

#[tauri::command(async)]
pub fn mark_records_synced(
    input: MarkRecordsSyncedInput,
    app: AppHandle,
    state: State<'_, VaultState>,
) -> Result<(), String> {
    require_active_vault_id(&state, &input.vault_id)?;
    let connection = local_store::open_app_store(&app).map_err(|error| error.to_string())?;
    local_store::mark_records_synced(&connection, &input.vault_id, &input.synced_record_refs)
        .map_err(|error| error.to_string())
}

#[tauri::command(async)]
pub fn mark_note_sync_blocked(
    input: NoteSyncBlockedInput,
    app: AppHandle,
    state: State<'_, VaultState>,
) -> Result<LocalEncryptedNoteRecord, String> {
    require_active_vault_id(&state, &input.vault_id)?;
    let connection = local_store::open_app_store(&app).map_err(|error| error.to_string())?;
    local_store::mark_note_sync_blocked(
        &connection,
        &input.vault_id,
        &input.note_id,
        input.expected_revision_hash.as_deref(),
        input.reason,
    )
    .map_err(|error| error.to_string())
}

#[tauri::command(async)]
pub fn include_note_in_cloud_sync(
    input: NoteCloudSyncScopeInput,
    app: AppHandle,
    state: State<'_, VaultState>,
) -> Result<LocalEncryptedNoteRecord, String> {
    require_active_vault_id(&state, &input.vault_id)?;
    let connection = local_store::open_app_store(&app).map_err(|error| error.to_string())?;
    local_store::include_note_in_cloud_sync(&connection, &input.vault_id, &input.note_id)
        .map_err(|error| error.to_string())
}

#[tauri::command(async)]
pub fn mark_note_local_only(
    input: NoteCloudSyncScopeInput,
    app: AppHandle,
    state: State<'_, VaultState>,
) -> Result<LocalEncryptedNoteRecord, String> {
    require_active_vault_id(&state, &input.vault_id)?;
    let connection = local_store::open_app_store(&app).map_err(|error| error.to_string())?;
    local_store::mark_note_local_only(
        &connection,
        &input.vault_id,
        &input.note_id,
        Some(RemoteCloudState::RemovedFromSync),
        Some(now_ms()),
    )
    .map_err(|error| error.to_string())
}

#[tauri::command(async)]
pub fn merge_remote_records(
    input: MergeRemoteRecordsInput,
    app: AppHandle,
    state: State<'_, VaultState>,
) -> Result<MergeSummary, String> {
    require_active_vault_id(&state, &input.vault_id)?;
    let connection = local_store::open_app_store(&app).map_err(|error| error.to_string())?;
    with_unlocked_vault_string(&state, |runtime| {
        local_store::merge_remote_records(
            &connection,
            &runtime.material,
            &input.vault_id,
            &input.notes,
            &input.folders,
        )
        .map_err(|error| error.to_string())
    })
}

#[tauri::command(async)]
pub fn export_vault_backup(
    input: ExportVaultBackupInput,
    app: AppHandle,
    state: State<'_, VaultState>,
    window: Window,
) -> Result<Option<BackupInspection>, String> {
    require_active_vault_id(&state, &input.vault_id)?;
    let Some(path) = app
        .dialog()
        .file()
        .set_parent(&window)
        .add_filter("Verus Notes Backup", &["verusnotes"])
        .set_file_name(input.suggested_file_name)
        .blocking_save_file()
    else {
        return Ok(None);
    };
    let destination_path = dialog_path(path)?;
    let destination_path = destination_path
        .to_str()
        .ok_or_else(|| "backup destination path is not valid UTF-8".to_string())?
        .to_string();
    let connection = local_store::open_app_store(&app).map_err(|error| error.to_string())?;
    with_unlocked_vault_string(&state, |vault| {
        vault_archive::export_vault_backup(
            &connection,
            &vault.material,
            &input.vault_id,
            &destination_path,
            now_ms(),
        )
    })
    .map(Some)
}

#[tauri::command(async)]
pub fn select_backup_for_import(
    input: SelectBackupForImportInput,
    app: AppHandle,
    state: State<'_, VaultState>,
    backup_import_state: State<'_, BackupImportState>,
    window: Window,
) -> Result<Option<SelectBackupForImportOutput>, String> {
    require_active_vault_id(&state, &input.vault_id)?;
    let Some(path) = app
        .dialog()
        .file()
        .set_parent(&window)
        .add_filter("Verus Notes Backup", &["verusnotes"])
        .blocking_pick_file()
    else {
        return Ok(None);
    };
    let path = dialog_path(path)?;
    let path_string = path
        .to_str()
        .ok_or_else(|| "backup path is not valid UTF-8".to_string())?
        .to_string();
    let inspection = vault_archive::inspect_backup_file(&path_string)?;
    let token = backup_import_state.insert(input.vault_id, path)?;

    Ok(Some(SelectBackupForImportOutput { token, inspection }))
}

#[tauri::command(async)]
pub fn import_vault_backup(
    input: ImportVaultBackupInput,
    app: AppHandle,
    state: State<'_, VaultState>,
    backup_import_state: State<'_, BackupImportState>,
) -> Result<MergeSummary, String> {
    require_active_vault_id(&state, &input.vault_id)?;
    let path = backup_import_state.take(&input.token, &input.vault_id)?;
    let path_string = path
        .to_str()
        .ok_or_else(|| "backup path is not valid UTF-8".to_string())?
        .to_string();
    let connection = local_store::open_app_store(&app).map_err(|error| error.to_string())?;

    with_unlocked_vault_string(&state, |vault| {
        vault_archive::import_vault_backup(
            &connection,
            &vault.material,
            &input.vault_id,
            &path_string,
        )
    })
}

fn with_unlocked_vault<T>(
    state: &State<'_, VaultState>,
    action: impl FnOnce(&VaultRuntime) -> Result<T, crate::crypto_vault::CryptoVaultError>,
) -> Result<T, String> {
    let guard = state
        .inner
        .lock()
        .map_err(|_| "vault state lock poisoned".to_string())?;
    let vault = guard
        .as_ref()
        .ok_or_else(|| "vault is locked".to_string())?;

    action(vault).map_err(|error| error.to_string())
}

fn with_unlocked_vault_string<T>(
    state: &State<'_, VaultState>,
    action: impl FnOnce(&VaultRuntime) -> Result<T, String>,
) -> Result<T, String> {
    let guard = state
        .inner
        .lock()
        .map_err(|_| "vault state lock poisoned".to_string())?;
    let vault = guard
        .as_ref()
        .ok_or_else(|| "vault is locked".to_string())?;

    action(vault)
}

fn require_unlocked(state: &State<'_, VaultState>) -> Result<(), String> {
    with_unlocked_vault_string(state, |_| Ok(()))
}

fn require_active_vault_id(state: &State<'_, VaultState>, vault_id: &str) -> Result<(), String> {
    with_unlocked_vault_string(state, |runtime| runtime.require_vault_id(vault_id))
}

fn complete_generic_wallet_unlock(
    input: GenericWalletResponseInput,
    response_encryption_state: &ResponseEncryptionState,
    pending_unlock_state: &PendingWalletUnlockState,
    vault_state: &VaultState,
) -> Result<CompletedWalletUnlock, String> {
    response_encryption_state
        .ensure_fresh(&input.response_encryption_key_id)
        .map_err(|error| error.to_string())?;
    let pending_session = pending_unlock_state
        .get_fresh(&input.response_encryption_key_id)
        .map_err(|error| error.to_string())?;
    let device_id =
        decode_16_hex("device id", &input.device_id_hex).map_err(|error| error.to_string())?;

    let verified = verify_wallet_generic_response(&VerifyWalletResponseInput {
        // Current Verus Mobile builds may omit GenericResponse.requestHash. The
        // encrypted app-encryption payload is still bound below by mandatory
        // requestID validation and one-time response encryption key consumption.
        allow_missing_request_hash: true,
        chain: pending_session.chain.clone(),
        expected_signed_request_hash_hex: Some(
            pending_session.expected_signed_request_hash_hex.clone(),
        ),
        expected_unsigned_request_hash_hex: Some(
            pending_session.expected_unsigned_request_hash_hex.clone(),
        ),
        expected_wallet_signer_identity_i_address: pending_session
            .expected_wallet_signer_identity_i_address
            .clone(),
        response_base64_url: input.response_base64_url.clone(),
    })
    .map_err(|error| error.to_string())?;

    let response = match decrypt_verified_app_response(
        &input.response_encryption_key_id,
        verified.encrypted_data,
        verified.ephemeral_public_key,
        &pending_session.expected_app_encryption_request_id_hex,
        response_encryption_state,
    ) {
        Ok(response) => {
            pending_unlock_state
                .discard(&input.response_encryption_key_id)
                .map_err(|error| error.to_string())?;
            response
        }
        Err(error) => {
            let _ = pending_unlock_state.discard(&input.response_encryption_key_id);
            return Err(error.to_string());
        }
    };

    let cloud_auth_attestation = CloudAuthAttestation {
        cloud_attestation_expires_at: pending_session.cloud_attestation_expires_at,
        cloud_attestation_id: pending_session.cloud_attestation_id.clone(),
        cloud_attestation_secret: pending_session.cloud_attestation_secret.clone(),
        request_hash_hex: pending_session.expected_signed_request_hash_hex.clone(),
        signer_base_url: pending_session.signer_base_url.clone(),
        signer_session_id: pending_session.session_id.clone(),
    };
    let context = VaultContext {
        app_encryption_address: response.app_encryption_address,
        app_identity_i_address: pending_session.app_identity_i_address,
        chain: pending_session.chain,
        derivation_number: pending_session.derivation_number,
        key_version: pending_session.key_version,
        wallet_signer_identity_i_address: verified.wallet_signer_identity_i_address,
    };
    let material = VaultMaterial::derive(*response.incoming_viewing_key, context, &device_id)
        .map_err(|error| error.to_string())?;
    let runtime = VaultRuntime::new(
        material,
        pending_session.app_encryption_request_id,
        verified.wallet_signer_identity_name,
        Some(cloud_auth_attestation),
    );
    let vault = runtime.output();
    let context = runtime.unlock_context();

    *vault_state
        .inner
        .lock()
        .map_err(|_| "vault state lock poisoned".to_string())? = Some(runtime);

    Ok(CompletedWalletUnlock { context, vault })
}

fn create_signer_wallet_session(
    signer_url: &str,
    prepared: &PrepareWalletResponseEncryptionOutput,
    policy: &WalletUnlockPolicy,
) -> Result<SignerWalletSession, String> {
    let session = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .post(&format!("{signer_url}/wallet-sessions"))
        .set("Accept", "application/json")
        .set("Content-Type", "application/json")
        .send_json(serde_json::json!({
            "encryptResponseToAddress": &prepared.encrypt_response_to_address,
            "responseEncryptionKeyId": &prepared.key_id,
        }))
        .map_err(signer_http_error)?
        .into_json::<SignerWalletSession>()
        .map_err(|error| format!("wallet signer session response was invalid: {error}"))?;

    validate_signer_session(&session, policy)?;
    Ok(session)
}

fn poll_signer_wallet_session(
    signer_url: &str,
    session_id: &str,
) -> Result<SignerPollResponse, String> {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .get(&format!("{signer_url}/wallet-sessions/{session_id}"))
        .set("Accept", "application/json")
        .call()
        .map_err(signer_http_error)?
        .into_json::<SignerPollResponse>()
        .map_err(|error| format!("wallet signer poll response was invalid: {error}"))
}

fn validate_signer_session(
    session: &SignerWalletSession,
    policy: &WalletUnlockPolicy,
) -> Result<(), String> {
    let mut missing = Vec::new();
    if session.app_encryption_request_id.trim().is_empty() {
        missing.push("appEncryptionRequestID");
    }
    if session.app_encryption_request_id_hex.trim().is_empty() {
        missing.push("appEncryptionRequestIDHex");
    }
    if session.callback_url.trim().is_empty() {
        missing.push("callbackUrl");
    }
    if session.cloud_attestation_id.trim().is_empty() {
        missing.push("cloudAttestationId");
    }
    if session.cloud_attestation_secret.trim().is_empty() {
        missing.push("cloudAttestationSecret");
    }
    if session.request_hash_hex.trim().is_empty() {
        missing.push("requestHashHex");
    }
    if session.unsigned_request_hash_hex.trim().is_empty() {
        missing.push("unsignedRequestHashHex");
    }
    if session.session_id.trim().is_empty() {
        missing.push("sessionId");
    }
    if session.deeplink.trim().is_empty() {
        missing.push("deeplink");
    }
    if session.poll_url.trim().is_empty() {
        missing.push("pollUrl");
    }
    if session
        .response_encryption_key_id
        .as_ref()
        .is_none_or(|key_id| key_id.trim().is_empty())
    {
        missing.push("responseEncryptionKeyId");
    }
    if !missing.is_empty() {
        return Err(format!(
            "wallet signer session is missing required policy: {}",
            missing.join(", ")
        ));
    }

    let now = now_ms();
    if session.expires_at <= now
        || session.expires_at.saturating_sub(now) > WALLET_UNLOCK_SESSION_TTL_MS
    {
        return Err("wallet signer session expiry is outside the allowed window".to_string());
    }
    if session.cloud_attestation_expires_at <= now
        || session.cloud_attestation_expires_at > session.expires_at
    {
        return Err(
            "wallet signer cloud attestation expiry is outside the allowed window".to_string(),
        );
    }

    if session.chain != policy.chain {
        return Err("wallet signer session chain does not match release policy".to_string());
    }
    if session.app_identity_i_address != policy.app_identity_i_address {
        return Err("wallet signer session app identity does not match release policy".to_string());
    }
    if session.derivation_number != policy.derivation_number {
        return Err(
            "wallet signer session derivation number does not match release policy".to_string(),
        );
    }
    if session.key_version != policy.key_version {
        return Err("wallet signer session key version does not match release policy".to_string());
    }
    validate_write_callback_url(&session.callback_url, policy)?;
    validate_poll_url(&session.poll_url, policy)?;

    Ok(())
}

fn resolve_signer_url(value: Option<&str>, policy: &WalletUnlockPolicy) -> Result<String, String> {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        let normalized = normalize_signer_url(value)?;
        require_allowed_signer_url(&normalized, policy)?;
    }

    Ok(policy.signer_base_url.to_string())
}

fn normalize_signer_url(value: &str) -> Result<String, String> {
    let normalized = value.trim().trim_end_matches('/').to_string();
    if normalized.is_empty() {
        return Err("wallet signer URL is required".to_string());
    }

    if !normalized.starts_with("https://") {
        return Err("wallet signer URL must use HTTPS".to_string());
    }

    Ok(normalized)
}

fn require_allowed_signer_url(normalized: &str, policy: &WalletUnlockPolicy) -> Result<(), String> {
    if normalized == policy.signer_base_url {
        Ok(())
    } else {
        Err("wallet signer URL does not match release policy".to_string())
    }
}

fn validate_write_callback_url(url: &str, policy: &WalletUnlockPolicy) -> Result<(), String> {
    let parts = callback_url_parts(url, policy)?;

    if is_callback_token(parts[1]) && parts[1] != "response" {
        Ok(())
    } else {
        Err("wallet signer callback URL does not match release policy".to_string())
    }
}

fn validate_poll_url(url: &str, policy: &WalletUnlockPolicy) -> Result<(), String> {
    let parts = callback_url_parts(url, policy)?;

    if parts[1] == "response" {
        Ok(())
    } else {
        Err("wallet signer poll URL does not match release policy".to_string())
    }
}

fn callback_url_parts<'a>(
    url: &'a str,
    policy: &WalletUnlockPolicy,
) -> Result<Vec<&'a str>, String> {
    let callback_prefix = format!("{}/wallet-callback/", policy.callback_base_url);
    let path = url
        .strip_prefix(&callback_prefix)
        .ok_or_else(|| "wallet signer callback URL does not match release policy".to_string())?;

    if path.contains('?') || path.contains('#') {
        return Err("wallet signer callback URL must not contain query or fragment".to_string());
    }

    let parts = path.split('/').collect::<Vec<_>>();
    if parts.len() != 2 || !is_callback_token(parts[0]) {
        return Err("wallet signer callback URL does not match release policy".to_string());
    }

    Ok(parts)
}

fn is_callback_token(value: &str) -> bool {
    (32..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn validate_external_link_href(href: &str) -> Result<String, String> {
    if href.is_empty()
        || href.len() > EXTERNAL_LINK_MAX_BYTES
        || href.trim() != href
        || href.chars().any(char::is_control)
    {
        return Err("external link URL is not allowed".to_string());
    }

    let url =
        tauri::Url::parse(href).map_err(|_| "external link URL is not allowed".to_string())?;

    if !matches!(url.scheme(), "http" | "https") {
        return Err("external link URL is not allowed".to_string());
    }

    match url.host_str() {
        Some(host) if !host.is_empty() => {}
        _ => return Err("external link URL is not allowed".to_string()),
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err("external link URL is not allowed".to_string());
    }

    Ok(url.to_string())
}

fn signer_http_error(error: ureq::Error) -> String {
    match error {
        ureq::Error::Status(status, _response) => format!("wallet signer request failed: {status}"),
        ureq::Error::Transport(error) => {
            format!("wallet signer is not reachable: {error}")
        }
    }
}

fn dialog_path(path: tauri_plugin_dialog::FilePath) -> Result<PathBuf, String> {
    path.into_path()
        .map_err(|error| format!("selected file path is unavailable: {error}"))
}

impl BackupImportState {
    fn insert(&self, vault_id: String, path: PathBuf) -> Result<String, String> {
        let now = now_ms();
        let mut token_bytes = [0u8; 32];
        getrandom::fill(&mut token_bytes)
            .map_err(|error| format!("backup import token generation failed: {error}"))?;
        let token = URL_SAFE_NO_PAD.encode(token_bytes);
        let mut selections = self
            .inner
            .lock()
            .map_err(|_| "backup import state lock poisoned".to_string())?;
        selections.retain(|_, selection| selection.expires_at_ms > now);
        selections.insert(
            token.clone(),
            BackupImportSelection {
                vault_id,
                path,
                expires_at_ms: now + BACKUP_IMPORT_TOKEN_TTL_MS,
            },
        );

        Ok(token)
    }

    fn take(&self, token: &str, vault_id: &str) -> Result<PathBuf, String> {
        let now = now_ms();
        let mut selections = self
            .inner
            .lock()
            .map_err(|_| "backup import state lock poisoned".to_string())?;
        selections.retain(|_, selection| selection.expires_at_ms > now);
        let selection = selections
            .remove(token)
            .ok_or_else(|| "backup import selection expired or was already used".to_string())?;

        if selection.vault_id != vault_id {
            return Err("backup import selection does not match active vault".to_string());
        }

        Ok(selection.path)
    }
}

impl VaultRuntime {
    fn new(
        material: VaultMaterial,
        app_encryption_request_id: String,
        wallet_signer_identity_name: Option<String>,
        cloud_auth_attestation: Option<CloudAuthAttestation>,
    ) -> Self {
        let context = material.context().clone();
        let policy = VaultRuntimePolicy {
            vault_id: material.vault_id().to_string(),
            app_encryption_request_id,
            app_encryption_address: context.app_encryption_address,
            app_identity_i_address: context.app_identity_i_address,
            backend_auth_algorithm: material.backend_auth_algorithm().to_string(),
            backend_auth_key_id: material.backend_auth_key_id().to_string(),
            backend_auth_public_key: material.backend_auth_public_key_b64(),
            backend_auth_key_version: material.backend_auth_key_version(),
            chain: context.chain,
            derivation_number: context.derivation_number,
            key_version: context.key_version,
            wallet_signer_identity_i_address: context.wallet_signer_identity_i_address,
            wallet_signer_identity_name,
            cloud_auth_attestation,
        };

        Self { material, policy }
    }

    fn output(&self) -> UnlockWalletResponseOutput {
        UnlockWalletResponseOutput {
            vault_id: self.policy.vault_id.clone(),
            backend_auth_algorithm: self.policy.backend_auth_algorithm.clone(),
            backend_auth_key_id: self.policy.backend_auth_key_id.clone(),
            backend_auth_public_key: self.policy.backend_auth_public_key.clone(),
            backend_auth_key_version: self.policy.backend_auth_key_version,
            export_check_hash: self.material.export_check_hash(),
            wallet_signer_identity_i_address: self.policy.wallet_signer_identity_i_address.clone(),
            wallet_signer_identity_name: self.policy.wallet_signer_identity_name.clone(),
        }
    }

    fn unlock_context(&self) -> WalletUnlockContextOutput {
        WalletUnlockContextOutput {
            app_encryption_request_id: self.policy.app_encryption_request_id.clone(),
            app_identity_i_address: self.policy.app_identity_i_address.clone(),
            chain: self.policy.chain.clone(),
            derivation_number: self.policy.derivation_number,
            key_version: self.policy.key_version,
            wallet_signer_identity_i_address: self.policy.wallet_signer_identity_i_address.clone(),
            wallet_signer_identity_name: self.policy.wallet_signer_identity_name.clone(),
        }
    }

    fn require_vault_id(&self, vault_id: &str) -> Result<(), String> {
        if self.policy.vault_id == vault_id {
            Ok(())
        } else {
            Err("requested vault does not match active vault".to_string())
        }
    }

    fn validate_note_header(
        &self,
        header: &CiphertextHeader,
    ) -> Result<(), crate::crypto_vault::CryptoVaultError> {
        self.validate_note_header_string(header)
            .map_err(crate::crypto_vault::CryptoVaultError::Policy)
    }

    fn validate_folder_header(
        &self,
        header: &FolderCiphertextHeader,
    ) -> Result<(), crate::crypto_vault::CryptoVaultError> {
        self.validate_folder_header_string(header)
            .map_err(crate::crypto_vault::CryptoVaultError::Policy)
    }

    fn validate_note_header_string(&self, header: &CiphertextHeader) -> Result<(), String> {
        self.validate_ciphertext_policy(
            &header.vault_id,
            header.key_version,
            header.schema_version,
            &header.algorithm,
            &header.note_id,
        )
    }

    fn validate_folder_header_string(&self, header: &FolderCiphertextHeader) -> Result<(), String> {
        self.validate_ciphertext_policy(
            &header.vault_id,
            header.key_version,
            header.schema_version,
            &header.algorithm,
            &header.folder_id,
        )
    }

    fn validate_ciphertext_policy(
        &self,
        vault_id: &str,
        key_version: u64,
        schema_version: u64,
        algorithm: &str,
        record_id: &str,
    ) -> Result<(), String> {
        self.require_vault_id(vault_id)?;
        if key_version != self.policy.key_version {
            return Err("ciphertext key version does not match active vault".to_string());
        }
        if !(MIN_CIPHERTEXT_SCHEMA_VERSION..=CIPHERTEXT_SCHEMA_VERSION).contains(&schema_version) {
            return Err("ciphertext schema version is unsupported".to_string());
        }
        if algorithm != CIPHERTEXT_ALGORITHM {
            return Err("ciphertext algorithm is unsupported".to_string());
        }
        if record_id.trim().is_empty() {
            return Err("ciphertext record id is required".to_string());
        }
        Ok(())
    }

    fn validate_backend_challenge(
        &self,
        challenge: &BackendAuthChallenge,
    ) -> Result<(), crate::crypto_vault::CryptoVaultError> {
        if challenge.vault_id != self.policy.vault_id
            || challenge.app_encryption_request_id != self.policy.app_encryption_request_id
            || challenge.app_identity_i_address != self.policy.app_identity_i_address
            || challenge.derivation_number != self.policy.derivation_number
            || challenge.wallet_signer_identity_i_address
                != self.policy.wallet_signer_identity_i_address
        {
            return Err(crate::crypto_vault::CryptoVaultError::Policy(
                "backend challenge does not match active vault policy".to_string(),
            ));
        }
        if challenge.backend_auth_public_key != self.policy.backend_auth_public_key {
            return Err(crate::crypto_vault::CryptoVaultError::Policy(
                "backend challenge does not match active backend auth public key".to_string(),
            ));
        }
        if challenge.backend_auth_algorithm != self.policy.backend_auth_algorithm
            || challenge.backend_auth_key_id != self.policy.backend_auth_key_id
            || challenge.backend_auth_key_version != self.policy.backend_auth_key_version
        {
            return Err(crate::crypto_vault::CryptoVaultError::Policy(
                "backend challenge does not match active backend auth metadata".to_string(),
            ));
        }
        if challenge.backend_auth_algorithm != BACKEND_AUTH_ALGORITHM
            || challenge.backend_auth_key_version != BACKEND_AUTH_KEY_VERSION
        {
            return Err(crate::crypto_vault::CryptoVaultError::Policy(
                "backend challenge auth algorithm is unsupported".to_string(),
            ));
        }
        if challenge.expires_at_ms <= now_ms() {
            return Err(crate::crypto_vault::CryptoVaultError::Policy(
                "backend challenge expired".to_string(),
            ));
        }
        Ok(())
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_signer_session() -> SignerWalletSession {
        let policy = active_wallet_unlock_policy();
        let callback_url = format!(
            "{}/wallet-callback/{}/{}",
            policy.callback_base_url,
            "request12345678901234567890123456789012",
            "write1234567890123456789012345678901234"
        );
        let poll_url = format!(
            "{}/wallet-callback/{}/response",
            policy.callback_base_url, "request12345678901234567890123456789012"
        );

        SignerWalletSession {
            app_encryption_request_id: "verus-notes-request".to_string(),
            app_encryption_request_id_hex: "01".to_string(),
            app_identity_i_address: policy.app_identity_i_address.to_string(),
            callback_url: callback_url.clone(),
            chain: policy.chain.to_string(),
            cloud_attestation_expires_at: now_ms() + 60_000,
            cloud_attestation_id: "cloud-attestation-1".to_string(),
            cloud_attestation_secret: "cloud-attestation-secret-1".to_string(),
            deeplink: "verus://x-callback-url/veruspay".to_string(),
            derivation_number: policy.derivation_number,
            expires_at: now_ms() + 60_000,
            expected_wallet_signer_identity_i_address: None,
            key_version: policy.key_version,
            poll_url,
            request_hash_hex: "02".to_string(),
            response_encryption_key_id: Some("response-key-1".to_string()),
            session_id: "session-1".to_string(),
            unsigned_request_hash_hex: "03".to_string(),
        }
    }

    #[test]
    fn external_link_accepts_http_and_https_urls() {
        assert_eq!(
            validate_external_link_href("https://www.verus.io/path?q=1#section").unwrap(),
            "https://www.verus.io/path?q=1#section"
        );
        assert_eq!(
            validate_external_link_href("http://127.0.0.1:3000/docs").unwrap(),
            "http://127.0.0.1:3000/docs"
        );
    }

    #[test]
    fn external_link_rejects_disallowed_urls() {
        let oversized = format!(
            "https://example.com/{}",
            "a".repeat(EXTERNAL_LINK_MAX_BYTES)
        );
        let cases = [
            "",
            "javascript:alert(1)",
            "file:///tmp/private-note",
            "data:text/plain,secret",
            "mailto:test@example.com",
            "www.verus.io",
            "/relative/path",
            "https://",
            " https://www.verus.io",
            "https://www.verus.io ",
            "https://exa\nmple.com",
            "https://user@example.com",
            "https://user:pass@example.com",
            oversized.as_str(),
        ];

        for href in cases {
            let error = validate_external_link_href(href).unwrap_err();
            assert_eq!(error, "external link URL is not allowed");
            if !href.is_empty() {
                assert!(!error.contains(href));
            }
        }
    }

    #[test]
    fn release_policy_accepts_expected_signer_session() {
        let policy = active_wallet_unlock_policy();

        validate_signer_session(&valid_signer_session(), &policy).unwrap();
    }

    #[test]
    fn release_policy_rejects_missing_response_encryption_key_id() {
        let policy = active_wallet_unlock_policy();
        let mut session = valid_signer_session();
        session.response_encryption_key_id = None;

        let error = validate_signer_session(&session, &policy).unwrap_err();

        assert!(error.contains("responseEncryptionKeyId"));
    }

    #[test]
    fn release_policy_rejects_chain_mismatch() {
        let policy = active_wallet_unlock_policy();
        let mut session = valid_signer_session();
        session.chain = "VRSC".to_string();

        let error = validate_signer_session(&session, &policy).unwrap_err();

        assert!(error.contains("chain"));
    }

    #[test]
    fn release_policy_rejects_app_identity_mismatch() {
        let policy = active_wallet_unlock_policy();
        let mut session = valid_signer_session();
        session.app_identity_i_address = "iWrongAppIdentityAddress".to_string();

        let error = validate_signer_session(&session, &policy).unwrap_err();

        assert!(error.contains("app identity"));
    }

    #[test]
    fn release_policy_rejects_derivation_number_mismatch() {
        let policy = active_wallet_unlock_policy();
        let mut session = valid_signer_session();
        session.derivation_number = policy.derivation_number + 1;

        let error = validate_signer_session(&session, &policy).unwrap_err();

        assert!(error.contains("derivation number"));
    }

    #[test]
    fn release_policy_rejects_key_version_mismatch() {
        let policy = active_wallet_unlock_policy();
        let mut session = valid_signer_session();
        session.key_version = policy.key_version + 1;

        let error = validate_signer_session(&session, &policy).unwrap_err();

        assert!(error.contains("key version"));
    }

    #[test]
    fn release_policy_rejects_callback_origin_mismatch() {
        let policy = active_wallet_unlock_policy();
        let mut session = valid_signer_session();
        session.callback_url =
            format!("{}.evil.test/wallet-callback/a/b", policy.callback_base_url);

        let error = validate_signer_session(&session, &policy).unwrap_err();

        assert!(error.contains("callback URL"));
    }

    #[test]
    fn release_policy_rejects_poll_origin_mismatch() {
        let policy = active_wallet_unlock_policy();
        let mut session = valid_signer_session();
        session.poll_url = format!(
            "{}.evil.test/wallet-callback/a/response",
            policy.callback_base_url
        );

        let error = validate_signer_session(&session, &policy).unwrap_err();

        assert!(error.contains("callback URL"));
    }

    #[test]
    fn release_policy_rejects_callback_url_with_query() {
        let policy = active_wallet_unlock_policy();
        let mut session = valid_signer_session();
        session.poll_url = format!(
            "{}/wallet-callback/{}/response?pollToken=secret",
            policy.callback_base_url, "request12345678901234567890123456789012"
        );

        let error = validate_signer_session(&session, &policy).unwrap_err();

        assert!(error.contains("query or fragment"));
    }

    #[test]
    fn release_policy_rejects_poll_shape_in_callback_url() {
        let policy = active_wallet_unlock_policy();
        let mut session = valid_signer_session();
        session.callback_url = format!(
            "{}/wallet-callback/{}/response",
            policy.callback_base_url, "request12345678901234567890123456789012"
        );

        let error = validate_signer_session(&session, &policy).unwrap_err();

        assert!(error.contains("callback URL"));
    }

    #[test]
    fn release_policy_rejects_write_shape_in_poll_url() {
        let policy = active_wallet_unlock_policy();
        let mut session = valid_signer_session();
        session.poll_url = format!(
            "{}/wallet-callback/{}/{}",
            policy.callback_base_url,
            "request12345678901234567890123456789012",
            "write1234567890123456789012345678901234"
        );

        let error = validate_signer_session(&session, &policy).unwrap_err();

        assert!(error.contains("poll URL"));
    }

    #[test]
    fn release_policy_rejects_short_callback_tokens() {
        let policy = active_wallet_unlock_policy();
        let mut session = valid_signer_session();
        session.callback_url = format!("{}/wallet-callback/short/token", policy.callback_base_url);

        let error = validate_signer_session(&session, &policy).unwrap_err();

        assert!(error.contains("callback URL"));
    }

    #[test]
    fn release_policy_rejects_arbitrary_signer_url() {
        let policy = active_wallet_unlock_policy();

        let error = require_allowed_signer_url("https://example.invalid", &policy).unwrap_err();

        assert!(error.contains("release policy"));
    }

    #[test]
    fn release_policy_rejects_lookalike_signer_url() {
        let policy = active_wallet_unlock_policy();

        let error =
            require_allowed_signer_url(&format!("{}.evil.test", policy.signer_base_url), &policy)
                .unwrap_err();

        assert!(error.contains("release policy"));
    }

    #[test]
    fn consumed_wallet_session_discards_pending_unlock() {
        let policy = active_wallet_unlock_policy();
        let pending = PendingWalletUnlockState::default();
        pending
            .insert(RegisterWalletUnlockSessionInput {
                app_encryption_request_id: "verus-notes-request".to_string(),
                app_identity_i_address: policy.app_identity_i_address.to_string(),
                chain: policy.chain.to_string(),
                cloud_attestation_expires_at: now_ms() + 60_000,
                cloud_attestation_id: "cloud-attestation-1".to_string(),
                cloud_attestation_secret: "cloud-attestation-secret-1".to_string(),
                derivation_number: policy.derivation_number,
                expires_at: now_ms() + 60_000,
                expected_app_encryption_request_id_hex: "01".to_string(),
                expected_signed_request_hash_hex: "02".to_string(),
                expected_unsigned_request_hash_hex: "03".to_string(),
                expected_wallet_signer_identity_i_address: None,
                key_version: policy.key_version,
                response_encryption_key_id: "response-key-1".to_string(),
                session_id: "session-1".to_string(),
                signer_base_url: policy.signer_base_url.to_string(),
            })
            .unwrap();

        let error = fail_consumed_wallet_unlock_session("session-1", &pending).unwrap_err();

        assert!(error.contains("retry wallet unlock"));
        assert!(pending.get_fresh_by_session_id("session-1").is_err());
    }
}
