use std::{fs, path::Path};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::crypto_vault::VaultMaterial;
use crate::local_store::{
    self, LocalEncryptedFolderRecord, LocalEncryptedNoteRecord, MergeSummary,
};

const BACKUP_FORMAT: &str = "verus-notes-backup";
const BACKUP_FORMAT_VERSION: u64 = 1;
const BACKUP_PAYLOAD_SCHEMA_VERSION: u64 = 1;
const BACKUP_ENCRYPTION_ALGORITHM: &str = "XCHACHA20-POLY1305";
const BACKUP_ARCHIVE_KEY: &str = "verus-notes/export-archive/v1";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupInspection {
    pub format: String,
    pub format_version: u64,
    pub created_at_ms: u64,
    pub encrypted: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct BackupWrapper {
    format: String,
    format_version: u64,
    created_at_ms: u64,
    encryption: BackupEncryption,
    ciphertext: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct BackupEncryption {
    algorithm: String,
    nonce: String,
    key: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct BackupPayload {
    payload_schema_version: u64,
    vault_id: String,
    export_check_hash: String,
    chain: String,
    app_identity_i_address: String,
    wallet_signer_identity_i_address: String,
    derivation_number: u64,
    folders: Vec<LocalEncryptedFolderRecord>,
    notes: Vec<LocalEncryptedNoteRecord>,
    folder_record_count: u64,
    note_record_count: u64,
}

pub fn inspect_backup_file(path: &str) -> Result<BackupInspection, String> {
    let wrapper = read_backup_wrapper(path)?;
    Ok(inspection_from_wrapper(&wrapper))
}

pub fn export_vault_backup(
    connection: &Connection,
    vault: &VaultMaterial,
    vault_id: &str,
    destination_path: &str,
    created_at_ms: u64,
) -> Result<BackupInspection, String> {
    require_vault(vault, vault_id)?;
    let local_vault =
        local_store::load_vault(connection, vault_id).map_err(|error| error.to_string())?;
    let context = vault.context();
    let payload = BackupPayload {
        payload_schema_version: BACKUP_PAYLOAD_SCHEMA_VERSION,
        vault_id: vault.vault_id().to_string(),
        export_check_hash: vault.export_check_hash(),
        chain: context.chain.clone(),
        app_identity_i_address: context.app_identity_i_address.clone(),
        wallet_signer_identity_i_address: context.wallet_signer_identity_i_address.clone(),
        derivation_number: context.derivation_number,
        folder_record_count: local_vault.folders.len() as u64,
        note_record_count: local_vault.notes.len() as u64,
        folders: local_vault.folders,
        notes: local_vault.notes,
    };
    let payload_bytes = serde_json::to_vec(&payload).map_err(|error| error.to_string())?;
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce)
        .map_err(|error| format!("backup nonce generation failed: {error}"))?;
    let ciphertext = vault
        .encrypt_archive_bytes(&payload_bytes, nonce)
        .map_err(|error| error.to_string())?;
    let wrapper = BackupWrapper {
        format: BACKUP_FORMAT.to_string(),
        format_version: BACKUP_FORMAT_VERSION,
        created_at_ms,
        encryption: BackupEncryption {
            algorithm: BACKUP_ENCRYPTION_ALGORITHM.to_string(),
            nonce: base64_url(&nonce),
            key: BACKUP_ARCHIVE_KEY.to_string(),
        },
        ciphertext,
    };
    let wrapper_bytes = serde_json::to_vec_pretty(&wrapper).map_err(|error| error.to_string())?;

    if let Some(parent) = Path::new(destination_path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
    }
    fs::write(destination_path, wrapper_bytes).map_err(|error| error.to_string())?;

    let written = read_backup_wrapper(destination_path)?;
    verify_written_backup(vault, &written)?;

    Ok(inspection_from_wrapper(&written))
}

pub fn import_vault_backup(
    connection: &Connection,
    vault: &VaultMaterial,
    vault_id: &str,
    path: &str,
) -> Result<MergeSummary, String> {
    require_vault(vault, vault_id)?;
    let wrapper = read_backup_wrapper(path)?;
    let payload = decrypt_backup_payload(vault, &wrapper)?;

    local_store::merge_import_records(connection, vault_id, &payload.notes, &payload.folders)
        .map_err(|error| error.to_string())
}

fn verify_written_backup(vault: &VaultMaterial, wrapper: &BackupWrapper) -> Result<(), String> {
    decrypt_backup_payload(vault, wrapper).map(|_| ())
}

fn decrypt_backup_payload(
    vault: &VaultMaterial,
    wrapper: &BackupWrapper,
) -> Result<BackupPayload, String> {
    let decrypted = vault
        .decrypt_archive_bytes(&wrapper.encryption.nonce, &wrapper.ciphertext)
        .map_err(|error| error.to_string())?;
    let payload: BackupPayload =
        serde_json::from_slice(&decrypted).map_err(|error| error.to_string())?;
    verify_backup_payload(vault, &payload)?;
    Ok(payload)
}

fn verify_backup_payload(vault: &VaultMaterial, payload: &BackupPayload) -> Result<(), String> {
    if payload.payload_schema_version != BACKUP_PAYLOAD_SCHEMA_VERSION {
        return Err("unsupported backup payload version".to_string());
    }

    if payload.vault_id != vault.vault_id() {
        return Err("backup vault does not match unlocked vault".to_string());
    }

    if payload.export_check_hash != vault.export_check_hash() {
        return Err("backup export check failed".to_string());
    }

    Ok(())
}

fn read_backup_wrapper(path: &str) -> Result<BackupWrapper, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let wrapper: BackupWrapper =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;

    if wrapper.format != BACKUP_FORMAT {
        return Err("not a Verus Notes backup".to_string());
    }

    if wrapper.format_version != BACKUP_FORMAT_VERSION {
        return Err("unsupported Verus Notes backup version".to_string());
    }

    if wrapper.encryption.algorithm != BACKUP_ENCRYPTION_ALGORITHM
        || wrapper.encryption.key != BACKUP_ARCHIVE_KEY
    {
        return Err("unsupported Verus Notes backup encryption".to_string());
    }

    Ok(wrapper)
}

fn inspection_from_wrapper(wrapper: &BackupWrapper) -> BackupInspection {
    BackupInspection {
        format: wrapper.format.clone(),
        format_version: wrapper.format_version,
        created_at_ms: wrapper.created_at_ms,
        encrypted: true,
    }
}

fn require_vault(vault: &VaultMaterial, vault_id: &str) -> Result<(), String> {
    if vault.vault_id() == vault_id {
        Ok(())
    } else {
        Err("backup vault does not match unlocked vault".to_string())
    }
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusqlite::Connection;

    use super::*;
    use crate::crypto_vault::{CiphertextHeader, EncryptedNote, VaultContext, VaultMaterial};
    use crate::local_store::{self, SaveLocalNoteInput, StorageMode};

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        local_store::migrate(&connection).unwrap();
        connection
    }

    fn sample_context() -> VaultContext {
        VaultContext {
            app_encryption_address:
                "zs15pu2knhknqn7dfl4u4pdmcsjssu3aqpvzphuakwhftr73k08wh9m0h874uvl76kugrg3qz9rel7"
                    .to_string(),
            app_identity_i_address: "i8LSGzcdqqzcs5XBfSVnXaXTMWt6QYjAuQ".to_string(),
            chain: "VRSCTEST".to_string(),
            derivation_number: 1,
            key_version: 1,
            wallet_signer_identity_i_address: "iLY1eeZKt2HZv6Noeidmg1EFTqaMSLejK5".to_string(),
        }
    }

    fn encrypted_note(vault_id: &str, note_id: &str, version: u64) -> EncryptedNote {
        EncryptedNote {
            header: CiphertextHeader {
                algorithm: "XCHACHA20-POLY1305".to_string(),
                content_version: version,
                key_version: 1,
                note_id: note_id.to_string(),
                schema_version: 1,
                vault_id: vault_id.to_string(),
            },
            nonce: "nonce".to_string(),
            ciphertext: "ciphertext-without-readable-title".to_string(),
        }
    }

    #[test]
    fn export_inspect_import_round_trips_encrypted_records() {
        let vault = VaultMaterial::derive([7u8; 32], sample_context(), &[3u8; 16]).unwrap();
        let source = connection();
        local_store::set_preference(&source, vault.vault_id(), StorageMode::LocalOnly, 100)
            .unwrap();
        local_store::save_note(
            &source,
            SaveLocalNoteInput {
                encrypted_note: encrypted_note(vault.vault_id(), "note-1", 1),
                created_at_ms: 100,
                updated_at_ms: 101,
                sync_state: None,
                deleted_at_ms: None,
            },
        )
        .unwrap();

        let path = temp_backup_path();
        let path_string = path.to_string_lossy().to_string();
        let exported =
            export_vault_backup(&source, &vault, vault.vault_id(), &path_string, 200).unwrap();
        let inspected = inspect_backup_file(&path_string).unwrap();

        assert_eq!(exported.format, BACKUP_FORMAT);
        assert_eq!(inspected.format_version, BACKUP_FORMAT_VERSION);
        assert!(inspected.encrypted);

        let imported = connection();
        local_store::set_preference(&imported, vault.vault_id(), StorageMode::LocalOnly, 300)
            .unwrap();
        let summary =
            import_vault_backup(&imported, &vault, vault.vault_id(), &path_string).unwrap();
        let imported_vault = local_store::load_vault(&imported, vault.vault_id()).unwrap();

        assert_eq!(summary.inserted, 1);
        assert_eq!(imported_vault.notes.len(), 1);
        assert_eq!(imported_vault.notes[0].note_id, "note-1");

        let _ = fs::remove_file(path);
    }

    fn temp_backup_path() -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "verus-notes-archive-test-{}-{suffix}.verusnotes",
            std::process::id()
        ))
    }
}
