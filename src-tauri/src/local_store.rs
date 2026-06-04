use std::{
    collections::HashSet,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};
use thiserror::Error;

use crate::crypto_vault::{
    CryptoVaultError, EncryptedFolder, EncryptedNote, FolderCiphertextHeader, VaultMaterial,
    CIPHERTEXT_SCHEMA_VERSION, MIN_CIPHERTEXT_SCHEMA_VERSION,
};
use crate::sync_merge_policy::{
    conflict_record_id, decide_merge, pending_sync_state_for_deleted, IncomingRecordSource,
    MergeDecision, MergeRecord,
};

const DATABASE_FILE_NAME: &str = "verus-notes.sqlite3";
const CIPHERTEXT_ALGORITHM: &str = "XCHACHA20-POLY1305";
const STALE_PULL_RESTORE_WINDOW_MS: u64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Debug, Error)]
pub enum LocalStoreError {
    #[error("app data directory is unavailable: {0}")]
    AppDataDir(tauri::Error),
    #[error("local store filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("local store database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("local store JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("local store crypto error: {0}")]
    Crypto(#[from] CryptoVaultError),
    #[error("local store policy violation: {0}")]
    Policy(String),
    #[error("invalid storage mode: {0}")]
    InvalidStorageMode(String),
    #[error("invalid sync state: {0}")]
    InvalidSyncState(String),
    #[error("invalid cloud sync scope: {0}")]
    InvalidCloudSyncScope(String),
    #[error("invalid sync blocked reason: {0}")]
    InvalidSyncBlockedReason(String),
    #[error("invalid remote cloud state: {0}")]
    InvalidRemoteCloudState(String),
    #[error("local encrypted {kind} record was not found")]
    MissingRecord { kind: &'static str },
}

pub type Result<T> = std::result::Result<T, LocalStoreError>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageMode {
    LocalOnly,
    SyncEnabled,
    SyncPaused,
}

impl StorageMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::LocalOnly => "local_only",
            Self::SyncEnabled => "sync_enabled",
            Self::SyncPaused => "sync_paused",
        }
    }

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "local_only" => Ok(Self::LocalOnly),
            "sync_enabled" => Ok(Self::SyncEnabled),
            "sync_paused" => Ok(Self::SyncPaused),
            other => Err(LocalStoreError::InvalidStorageMode(other.to_string())),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    NotSynced,
    PendingUpsert,
    PendingDelete,
    Synced,
    Conflict,
}

impl SyncState {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotSynced => "not_synced",
            Self::PendingUpsert => "pending_upsert",
            Self::PendingDelete => "pending_delete",
            Self::Synced => "synced",
            Self::Conflict => "conflict",
        }
    }

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "not_synced" => Ok(Self::NotSynced),
            "pending_upsert" => Ok(Self::PendingUpsert),
            "pending_delete" => Ok(Self::PendingDelete),
            "synced" => Ok(Self::Synced),
            "conflict" => Ok(Self::Conflict),
            other => Err(LocalStoreError::InvalidSyncState(other.to_string())),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudSyncScope {
    Included,
    LocalOnly,
}

impl CloudSyncScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Included => "included",
            Self::LocalOnly => "local_only",
        }
    }

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "included" => Ok(Self::Included),
            "local_only" => Ok(Self::LocalOnly),
            other => Err(LocalStoreError::InvalidCloudSyncScope(other.to_string())),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncBlockedReason {
    QuotaNoteCount,
    QuotaStorage,
    RecordTooLarge,
    SessionExpired,
    Network,
}

impl SyncBlockedReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::QuotaNoteCount => "quota_note_count",
            Self::QuotaStorage => "quota_storage",
            Self::RecordTooLarge => "record_too_large",
            Self::SessionExpired => "session_expired",
            Self::Network => "network",
        }
    }

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "quota_note_count" => Ok(Self::QuotaNoteCount),
            "quota_storage" => Ok(Self::QuotaStorage),
            "record_too_large" => Ok(Self::RecordTooLarge),
            "session_expired" => Ok(Self::SessionExpired),
            "network" => Ok(Self::Network),
            other => Err(LocalStoreError::InvalidSyncBlockedReason(other.to_string())),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteCloudState {
    Live,
    Deleted,
    RemovedFromSync,
}

impl RemoteCloudState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Deleted => "deleted",
            Self::RemovedFromSync => "removed_from_sync",
        }
    }

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "live" => Ok(Self::Live),
            "deleted" => Ok(Self::Deleted),
            "removed_from_sync" => Ok(Self::RemovedFromSync),
            other => Err(LocalStoreError::InvalidRemoteCloudState(other.to_string())),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultPreference {
    pub vault_id: String,
    pub storage_mode: StorageMode,
    pub cloud_copy_deleted_at_ms: Option<u64>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveLocalNoteInput {
    pub encrypted_note: EncryptedNote,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub sync_state: Option<SyncState>,
    pub deleted_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveLocalFolderInput {
    pub encrypted_folder: EncryptedFolder,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub sync_state: Option<SyncState>,
    pub deleted_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteNoteRecord {
    pub vault_id: String,
    pub note_id: String,
    pub header: crate::crypto_vault::CiphertextHeader,
    pub nonce: String,
    pub ciphertext: String,
    pub content_version: u64,
    pub cloud_state: Option<RemoteCloudState>,
    pub retention_expires_at_bucket_ms: Option<u64>,
    pub server_created_at_bucket_ms: u64,
    pub server_updated_at_bucket_ms: u64,
    pub server_deleted_at_bucket_ms: Option<u64>,
    pub server_removed_from_sync_at_bucket_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteFolderRecord {
    pub vault_id: String,
    pub folder_id: String,
    pub header: FolderCiphertextHeader,
    pub nonce: String,
    pub ciphertext: String,
    pub content_version: u64,
    pub cloud_state: Option<RemoteCloudState>,
    pub retention_expires_at_bucket_ms: Option<u64>,
    pub server_created_at_bucket_ms: u64,
    pub server_updated_at_bucket_ms: u64,
    pub server_deleted_at_bucket_ms: Option<u64>,
    pub server_removed_from_sync_at_bucket_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncMetadata {
    pub last_pull_at_ms: Option<u64>,
    pub last_push_at_ms: Option<u64>,
    pub restore_missing_cloud_records: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEncryptedNoteRecord {
    pub note_id: String,
    pub encrypted_note: EncryptedNote,
    pub content_version: u64,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub deleted_at_ms: Option<u64>,
    pub revision_hash: String,
    pub sync_state: SyncState,
    pub last_synced_revision_hash: Option<String>,
    pub cloud_sync_scope: CloudSyncScope,
    pub sync_blocked_reason: Option<SyncBlockedReason>,
    pub remote_cloud_state: Option<RemoteCloudState>,
    pub remote_removed_from_sync_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEncryptedFolderRecord {
    pub folder_id: String,
    pub encrypted_folder: EncryptedFolder,
    pub content_version: u64,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub deleted_at_ms: Option<u64>,
    pub revision_hash: String,
    pub sync_state: SyncState,
    pub last_synced_revision_hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalVaultData {
    pub preference: Option<VaultPreference>,
    pub sync_metadata: Option<SyncMetadata>,
    pub notes: Vec<LocalEncryptedNoteRecord>,
    pub folders: Vec<LocalEncryptedFolderRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncedRecordRef {
    pub kind: SyncedRecordKind,
    pub record_id: String,
    pub revision_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncedRecordKind {
    Note,
    Folder,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MergeSummary {
    pub inserted: u64,
    pub updated: u64,
    pub unchanged: u64,
    pub conflicts: u64,
    pub kept_local: u64,
    pub rejected: u64,
}

pub fn open_app_store(app: &AppHandle) -> Result<Connection> {
    let directory = app
        .path()
        .app_data_dir()
        .map_err(LocalStoreError::AppDataDir)?;
    fs::create_dir_all(&directory)?;
    open_store_at(directory.join(DATABASE_FILE_NAME))
}

pub fn open_store_at(path: PathBuf) -> Result<Connection> {
    let connection = Connection::open(path)?;
    migrate(&connection)?;
    Ok(connection)
}

pub fn migrate(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        r#"
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS vault_preferences (
            vault_id TEXT PRIMARY KEY NOT NULL,
            storage_mode TEXT NOT NULL,
            cloud_copy_deleted_at_ms INTEGER,
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS encrypted_notes (
            vault_id TEXT NOT NULL,
            note_id TEXT NOT NULL,
            header_json TEXT NOT NULL,
            nonce TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            content_version INTEGER NOT NULL,
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            deleted_at_ms INTEGER,
            revision_hash TEXT NOT NULL,
            sync_state TEXT NOT NULL,
            last_synced_revision_hash TEXT,
            PRIMARY KEY (vault_id, note_id)
        );

        CREATE INDEX IF NOT EXISTS encrypted_notes_by_vault_sync_state
            ON encrypted_notes (vault_id, sync_state);

        CREATE TABLE IF NOT EXISTS encrypted_folders (
            vault_id TEXT NOT NULL,
            folder_id TEXT NOT NULL,
            header_json TEXT NOT NULL,
            nonce TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            content_version INTEGER NOT NULL,
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            deleted_at_ms INTEGER,
            revision_hash TEXT NOT NULL,
            sync_state TEXT NOT NULL,
            last_synced_revision_hash TEXT,
            PRIMARY KEY (vault_id, folder_id)
        );

        CREATE INDEX IF NOT EXISTS encrypted_folders_by_vault_sync_state
            ON encrypted_folders (vault_id, sync_state);

        CREATE TABLE IF NOT EXISTS sync_metadata (
            vault_id TEXT PRIMARY KEY NOT NULL,
            backend_auth_public_key TEXT NOT NULL,
            last_pull_at_ms INTEGER,
            last_push_at_ms INTEGER,
            last_error TEXT
        );
        "#,
    )?;
    add_column_if_missing(
        connection,
        "encrypted_notes",
        "cloud_sync_scope",
        "TEXT NOT NULL DEFAULT 'included'",
    )?;
    add_column_if_missing(connection, "encrypted_notes", "sync_blocked_reason", "TEXT")?;
    add_column_if_missing(connection, "encrypted_notes", "remote_cloud_state", "TEXT")?;
    add_column_if_missing(
        connection,
        "encrypted_notes",
        "remote_removed_from_sync_at_ms",
        "INTEGER",
    )?;
    connection.execute(
        r#"
        UPDATE encrypted_notes
        SET cloud_sync_scope = 'local_only'
        WHERE cloud_sync_scope = 'included'
          AND vault_id IN (
            SELECT vault_id FROM vault_preferences WHERE storage_mode <> 'sync_enabled'
          )
        "#,
        [],
    )?;
    connection.execute(
        r#"
        UPDATE encrypted_notes
        SET sync_blocked_reason = NULL,
            sync_state = 'not_synced'
        WHERE cloud_sync_scope = 'local_only'
          AND (sync_blocked_reason IS NOT NULL OR sync_state IN ('pending_upsert', 'pending_delete'))
        "#,
        [],
    )?;
    connection.execute(
        r#"
        UPDATE encrypted_notes
        SET cloud_sync_scope = 'local_only',
            sync_blocked_reason = NULL,
            sync_state = 'not_synced'
        WHERE cloud_sync_scope = 'included'
          AND last_synced_revision_hash IS NULL
          AND sync_blocked_reason IN ('quota_note_count', 'quota_storage')
        "#,
        [],
    )?;
    Ok(())
}

pub fn get_preference(connection: &Connection, vault_id: &str) -> Result<Option<VaultPreference>> {
    connection
        .query_row(
            r#"
            SELECT vault_id, storage_mode, cloud_copy_deleted_at_ms, created_at_ms, updated_at_ms
            FROM vault_preferences
            WHERE vault_id = ?1
            "#,
            params![vault_id],
            row_to_preference,
        )
        .optional()
        .map_err(LocalStoreError::from)
}

pub fn set_preference(
    connection: &Connection,
    vault_id: &str,
    storage_mode: StorageMode,
    now_ms: u64,
) -> Result<VaultPreference> {
    let existing = get_preference(connection, vault_id)?;
    let created_at_ms = existing
        .as_ref()
        .map_or(now_ms, |preference| preference.created_at_ms);
    let cloud_copy_deleted_at_ms =
        existing.and_then(|preference| preference.cloud_copy_deleted_at_ms);

    connection.execute(
        r#"
        INSERT INTO vault_preferences (
            vault_id, storage_mode, cloud_copy_deleted_at_ms, created_at_ms, updated_at_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5)
        ON CONFLICT(vault_id) DO UPDATE SET
            storage_mode = excluded.storage_mode,
            updated_at_ms = excluded.updated_at_ms
        "#,
        params![
            vault_id,
            storage_mode.as_str(),
            cloud_copy_deleted_at_ms,
            created_at_ms,
            now_ms
        ],
    )?;

    get_preference(connection, vault_id)?.ok_or(LocalStoreError::MissingRecord {
        kind: "vault preference",
    })
}

pub fn enable_sync(
    connection: &Connection,
    vault_id: &str,
    now_ms: u64,
    included_note_ids: Option<&[String]>,
) -> Result<VaultPreference> {
    with_immediate_transaction(connection, |connection| {
        let existing = get_preference(connection, vault_id)?;
        let created_at_ms = existing
            .as_ref()
            .map_or(now_ms, |preference| preference.created_at_ms);
        let rebuild_cloud_copy = existing
            .as_ref()
            .is_some_and(|preference| preference.cloud_copy_deleted_at_ms.is_some());

        connection.execute(
            r#"
            INSERT INTO vault_preferences (
                vault_id, storage_mode, cloud_copy_deleted_at_ms, created_at_ms, updated_at_ms
            ) VALUES (?1, ?2, NULL, ?3, ?4)
            ON CONFLICT(vault_id) DO UPDATE SET
                storage_mode = excluded.storage_mode,
                cloud_copy_deleted_at_ms = NULL,
                updated_at_ms = excluded.updated_at_ms
            "#,
            params![
                vault_id,
                StorageMode::SyncEnabled.as_str(),
                created_at_ms,
                now_ms
            ],
        )?;

        if let Some(included_note_ids) = included_note_ids {
            queue_selected_records_for_sync(connection, vault_id, included_note_ids)?;
        } else {
            queue_records_for_sync(connection, vault_id, rebuild_cloud_copy)?;
        }

        Ok(())
    })?;

    get_preference(connection, vault_id)?.ok_or(LocalStoreError::MissingRecord {
        kind: "vault preference",
    })
}

fn with_immediate_transaction<T>(
    connection: &Connection,
    action: impl FnOnce(&Connection) -> Result<T>,
) -> Result<T> {
    connection.execute_batch("BEGIN IMMEDIATE TRANSACTION")?;
    match action(connection) {
        Ok(value) => {
            connection.execute_batch("COMMIT")?;
            Ok(value)
        }
        Err(error) => {
            let _ = connection.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

pub fn mark_cloud_copy_deleted(
    connection: &Connection,
    vault_id: &str,
    now_ms: u64,
) -> Result<VaultPreference> {
    let existing = get_preference(connection, vault_id)?;
    let created_at_ms = existing
        .as_ref()
        .map_or(now_ms, |preference| preference.created_at_ms);

    connection.execute(
        r#"
        INSERT INTO vault_preferences (
            vault_id, storage_mode, cloud_copy_deleted_at_ms, created_at_ms, updated_at_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5)
        ON CONFLICT(vault_id) DO UPDATE SET
            storage_mode = excluded.storage_mode,
            cloud_copy_deleted_at_ms = excluded.cloud_copy_deleted_at_ms,
            updated_at_ms = excluded.updated_at_ms
        "#,
        params![
            vault_id,
            StorageMode::LocalOnly.as_str(),
            now_ms,
            created_at_ms,
            now_ms
        ],
    )?;

    get_preference(connection, vault_id)?.ok_or(LocalStoreError::MissingRecord {
        kind: "vault preference",
    })
}

pub fn load_vault(connection: &Connection, vault_id: &str) -> Result<LocalVaultData> {
    Ok(LocalVaultData {
        preference: get_preference(connection, vault_id)?,
        sync_metadata: get_sync_metadata(connection, vault_id)?,
        folders: load_folders(connection, vault_id)?,
        notes: load_notes(connection, vault_id)?,
    })
}

pub fn list_pending_sync(connection: &Connection, vault_id: &str) -> Result<LocalVaultData> {
    Ok(LocalVaultData {
        preference: get_preference(connection, vault_id)?,
        sync_metadata: get_sync_metadata(connection, vault_id)?,
        folders: query_folders(
            connection,
            r#"
            SELECT vault_id, folder_id, header_json, nonce, ciphertext, content_version,
                created_at_ms, updated_at_ms, deleted_at_ms, revision_hash, sync_state,
                last_synced_revision_hash
            FROM encrypted_folders
            WHERE vault_id = ?1 AND sync_state IN ('pending_upsert', 'pending_delete')
            ORDER BY updated_at_ms ASC
            "#,
            params![vault_id],
        )?,
        notes: query_notes(
            connection,
            r#"
            SELECT vault_id, note_id, header_json, nonce, ciphertext, content_version,
                created_at_ms, updated_at_ms, deleted_at_ms, revision_hash, sync_state,
                last_synced_revision_hash, cloud_sync_scope, sync_blocked_reason,
                remote_cloud_state, remote_removed_from_sync_at_ms
            FROM encrypted_notes
            WHERE vault_id = ?1
              AND sync_state IN ('pending_upsert', 'pending_delete')
              AND cloud_sync_scope = 'included'
              AND sync_blocked_reason IS NULL
            ORDER BY updated_at_ms ASC
            "#,
            params![vault_id],
        )?,
    })
}

pub fn queue_cloud_replica_rebuild(
    connection: &Connection,
    vault_id: &str,
) -> Result<LocalVaultData> {
    with_immediate_transaction(connection, |connection| {
        connection.execute(
            r#"
            UPDATE encrypted_notes
            SET sync_state = 'not_synced',
                cloud_sync_scope = 'local_only',
                sync_blocked_reason = NULL
            WHERE vault_id = ?1
              AND deleted_at_ms IS NOT NULL
              AND sync_state <> 'conflict'
            "#,
            params![vault_id],
        )?;
        connection.execute(
            r#"
            UPDATE encrypted_folders
            SET sync_state = 'not_synced'
            WHERE vault_id = ?1
              AND deleted_at_ms IS NOT NULL
              AND sync_state <> 'conflict'
            "#,
            params![vault_id],
        )?;
        connection.execute(
            r#"
            UPDATE encrypted_notes
            SET sync_state = 'pending_upsert'
            WHERE vault_id = ?1
              AND deleted_at_ms IS NULL
              AND sync_state <> 'conflict'
              AND cloud_sync_scope = 'included'
              AND sync_blocked_reason IS NULL
            "#,
            params![vault_id],
        )?;
        connection.execute(
            r#"
            UPDATE encrypted_folders
            SET sync_state = 'pending_upsert'
            WHERE vault_id = ?1
              AND deleted_at_ms IS NULL
              AND sync_state <> 'conflict'
            "#,
            params![vault_id],
        )?;
        Ok(())
    })?;

    load_vault(connection, vault_id)
}

fn get_sync_metadata(connection: &Connection, vault_id: &str) -> Result<Option<SyncMetadata>> {
    let row = connection
        .query_row(
            r#"
            SELECT last_pull_at_ms, last_push_at_ms
            FROM sync_metadata
            WHERE vault_id = ?1
            "#,
            params![vault_id],
            |row| {
                Ok((
                    optional_i64_to_u64(row.get(0)?),
                    optional_i64_to_u64(row.get(1)?),
                ))
            },
        )
        .optional()?;
    let Some((last_pull_at_ms, last_push_at_ms)) = row else {
        return Ok(None);
    };
    Ok(Some(SyncMetadata {
        restore_missing_cloud_records: should_restore_missing_cloud_records(last_pull_at_ms),
        last_pull_at_ms,
        last_push_at_ms,
    }))
}

fn queue_records_for_sync(
    connection: &Connection,
    vault_id: &str,
    include_synced: bool,
) -> Result<()> {
    if include_synced {
        queue_live_records_for_cloud_copy_rebuild(connection, vault_id)?;
        return Ok(());
    }

    let state_filter = "sync_state = 'not_synced'";

    connection.execute(
        &format!(
            r#"
            UPDATE encrypted_notes
            SET sync_state = CASE
                WHEN deleted_at_ms IS NULL THEN 'pending_upsert'
                ELSE 'pending_delete'
            END,
            cloud_sync_scope = 'included',
            sync_blocked_reason = NULL
            WHERE vault_id = ?1 AND {state_filter}
            "#
        ),
        params![vault_id],
    )?;
    connection.execute(
        &format!(
            r#"
            UPDATE encrypted_folders
            SET sync_state = CASE
                WHEN deleted_at_ms IS NULL THEN 'pending_upsert'
                ELSE 'pending_delete'
            END
            WHERE vault_id = ?1 AND {state_filter}
            "#
        ),
        params![vault_id],
    )?;

    Ok(())
}

fn queue_live_records_for_cloud_copy_rebuild(
    connection: &Connection,
    vault_id: &str,
) -> Result<()> {
    connection.execute(
        r#"
        UPDATE encrypted_notes
        SET sync_state = 'pending_upsert',
            cloud_sync_scope = 'included',
            sync_blocked_reason = NULL
        WHERE vault_id = ?1
          AND sync_state <> 'conflict'
          AND deleted_at_ms IS NULL
        "#,
        params![vault_id],
    )?;
    connection.execute(
        r#"
        UPDATE encrypted_notes
        SET sync_state = 'not_synced',
            cloud_sync_scope = 'local_only',
            sync_blocked_reason = NULL
        WHERE vault_id = ?1
          AND sync_state <> 'conflict'
          AND deleted_at_ms IS NOT NULL
        "#,
        params![vault_id],
    )?;
    connection.execute(
        r#"
        UPDATE encrypted_folders
        SET sync_state = 'pending_upsert'
        WHERE vault_id = ?1
          AND sync_state <> 'conflict'
          AND deleted_at_ms IS NULL
        "#,
        params![vault_id],
    )?;
    connection.execute(
        r#"
        UPDATE encrypted_folders
        SET sync_state = 'not_synced'
        WHERE vault_id = ?1
          AND sync_state <> 'conflict'
          AND deleted_at_ms IS NOT NULL
        "#,
        params![vault_id],
    )?;

    Ok(())
}

fn queue_selected_records_for_sync(
    connection: &Connection,
    vault_id: &str,
    included_note_ids: &[String],
) -> Result<()> {
    let included_note_ids = included_note_ids
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();

    for note in load_notes(connection, vault_id)? {
        if note.sync_state == SyncState::Conflict {
            continue;
        }
        let include_note =
            note.deleted_at_ms.is_none() && included_note_ids.contains(note.note_id.as_str());
        connection.execute(
            r#"
            UPDATE encrypted_notes
            SET sync_state = ?3,
                cloud_sync_scope = ?4,
                sync_blocked_reason = NULL,
                last_synced_revision_hash = ?5,
                remote_cloud_state = NULL,
                remote_removed_from_sync_at_ms = NULL
            WHERE vault_id = ?1 AND note_id = ?2
            "#,
            params![
                vault_id,
                note.note_id,
                if include_note {
                    SyncState::PendingUpsert.as_str()
                } else {
                    SyncState::NotSynced.as_str()
                },
                if include_note {
                    CloudSyncScope::Included.as_str()
                } else {
                    CloudSyncScope::LocalOnly.as_str()
                },
                Option::<&str>::None
            ],
        )?;
    }

    connection.execute(
        r#"
        UPDATE encrypted_folders
        SET sync_state = 'pending_upsert'
        WHERE vault_id = ?1
          AND sync_state <> 'conflict'
          AND deleted_at_ms IS NULL
        "#,
        params![vault_id],
    )?;
    connection.execute(
        r#"
        UPDATE encrypted_folders
        SET sync_state = 'not_synced'
        WHERE vault_id = ?1
          AND sync_state <> 'conflict'
          AND deleted_at_ms IS NOT NULL
        "#,
        params![vault_id],
    )?;

    Ok(())
}

pub fn save_note(
    connection: &Connection,
    input: SaveLocalNoteInput,
) -> Result<LocalEncryptedNoteRecord> {
    let vault_id = input.encrypted_note.header.vault_id.clone();
    let note_id = input.encrypted_note.header.note_id.clone();
    let content_version = input.encrypted_note.header.content_version;
    let header_json = serde_json::to_string(&input.encrypted_note.header)?;
    let existing = get_note(connection, &vault_id, &note_id)?;
    let created_at_ms = existing
        .as_ref()
        .map_or(input.created_at_ms, |record| record.created_at_ms);
    let deleted_at_ms = input.deleted_at_ms;
    let cloud_sync_scope = existing.as_ref().map_or(
        default_note_cloud_sync_scope(connection, &vault_id)?,
        |record| record.cloud_sync_scope,
    );
    let sync_state = input
        .sync_state
        .unwrap_or(default_note_local_change_sync_state(
            connection,
            &vault_id,
            deleted_at_ms.is_some(),
            cloud_sync_scope,
        )?);
    let sync_blocked_reason = if cloud_sync_scope == CloudSyncScope::LocalOnly
        || matches!(
            sync_state,
            SyncState::PendingUpsert | SyncState::PendingDelete
        ) {
        None
    } else {
        existing.and_then(|record| record.sync_blocked_reason)
    };
    let revision_hash = revision_hash(
        "note",
        &note_id,
        &header_json,
        &input.encrypted_note.nonce,
        &input.encrypted_note.ciphertext,
        content_version,
        deleted_at_ms,
    );

    connection.execute(
        r#"
        INSERT INTO encrypted_notes (
            vault_id, note_id, header_json, nonce, ciphertext, content_version,
            created_at_ms, updated_at_ms, deleted_at_ms, revision_hash, sync_state,
            last_synced_revision_hash, cloud_sync_scope, sync_blocked_reason,
            remote_cloud_state, remote_removed_from_sync_at_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
        ON CONFLICT(vault_id, note_id) DO UPDATE SET
            header_json = excluded.header_json,
            nonce = excluded.nonce,
            ciphertext = excluded.ciphertext,
            content_version = excluded.content_version,
            updated_at_ms = excluded.updated_at_ms,
            deleted_at_ms = excluded.deleted_at_ms,
            revision_hash = excluded.revision_hash,
            sync_state = excluded.sync_state,
            last_synced_revision_hash = CASE
                WHEN excluded.sync_state = 'synced' THEN excluded.revision_hash
                ELSE encrypted_notes.last_synced_revision_hash
            END,
            cloud_sync_scope = excluded.cloud_sync_scope,
            sync_blocked_reason = excluded.sync_blocked_reason
        "#,
        params![
            vault_id,
            note_id,
            header_json,
            input.encrypted_note.nonce,
            input.encrypted_note.ciphertext,
            content_version,
            created_at_ms,
            input.updated_at_ms,
            deleted_at_ms,
            revision_hash,
            sync_state.as_str(),
            if sync_state == SyncState::Synced {
                Some(revision_hash.as_str())
            } else {
                None
            },
            cloud_sync_scope.as_str(),
            sync_blocked_reason.map(SyncBlockedReason::as_str),
            Option::<&str>::None,
            Option::<u64>::None
        ],
    )?;

    get_note(connection, &vault_id, &note_id)?
        .ok_or(LocalStoreError::MissingRecord { kind: "note" })
}

pub fn save_folder(
    connection: &Connection,
    input: SaveLocalFolderInput,
) -> Result<LocalEncryptedFolderRecord> {
    let vault_id = input.encrypted_folder.header.vault_id.clone();
    let folder_id = input.encrypted_folder.header.folder_id.clone();
    let content_version = input.encrypted_folder.header.content_version;
    let header_json = serde_json::to_string(&input.encrypted_folder.header)?;
    let existing = get_folder(connection, &vault_id, &folder_id)?;
    let created_at_ms = existing
        .as_ref()
        .map_or(input.created_at_ms, |record| record.created_at_ms);
    let deleted_at_ms = input.deleted_at_ms;
    let sync_state = input.sync_state.unwrap_or(default_local_change_sync_state(
        connection,
        &vault_id,
        deleted_at_ms.is_some(),
    )?);
    let revision_hash = revision_hash(
        "folder",
        &folder_id,
        &header_json,
        &input.encrypted_folder.nonce,
        &input.encrypted_folder.ciphertext,
        content_version,
        deleted_at_ms,
    );

    connection.execute(
        r#"
        INSERT INTO encrypted_folders (
            vault_id, folder_id, header_json, nonce, ciphertext, content_version,
            created_at_ms, updated_at_ms, deleted_at_ms, revision_hash, sync_state,
            last_synced_revision_hash
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        ON CONFLICT(vault_id, folder_id) DO UPDATE SET
            header_json = excluded.header_json,
            nonce = excluded.nonce,
            ciphertext = excluded.ciphertext,
            content_version = excluded.content_version,
            updated_at_ms = excluded.updated_at_ms,
            deleted_at_ms = excluded.deleted_at_ms,
            revision_hash = excluded.revision_hash,
            sync_state = excluded.sync_state,
            last_synced_revision_hash = CASE
                WHEN excluded.sync_state = 'synced' THEN excluded.revision_hash
                ELSE encrypted_folders.last_synced_revision_hash
            END
        "#,
        params![
            vault_id,
            folder_id,
            header_json,
            input.encrypted_folder.nonce,
            input.encrypted_folder.ciphertext,
            content_version,
            created_at_ms,
            input.updated_at_ms,
            deleted_at_ms,
            revision_hash,
            sync_state.as_str(),
            if sync_state == SyncState::Synced {
                Some(revision_hash.as_str())
            } else {
                None
            }
        ],
    )?;

    get_folder(connection, &vault_id, &folder_id)?
        .ok_or(LocalStoreError::MissingRecord { kind: "folder" })
}

pub fn tombstone_note(
    connection: &Connection,
    vault: &VaultMaterial,
    vault_id: &str,
    note_id: &str,
    now_ms: u64,
    nonce: [u8; 24],
) -> Result<LocalEncryptedNoteRecord> {
    require_vault_material(vault, vault_id)?;
    let mut record = get_note(connection, vault_id, note_id)?
        .ok_or(LocalStoreError::MissingRecord { kind: "note" })?;
    record.encrypted_note.header.content_version = record.content_version + 1;
    record.content_version += 1;
    record.updated_at_ms = now_ms;
    record.deleted_at_ms = Some(now_ms);
    record.sync_state =
        default_note_local_change_sync_state(connection, vault_id, true, record.cloud_sync_scope)?;
    record.sync_blocked_reason = None;
    record.encrypted_note =
        vault.encrypt_note_tombstone(record.encrypted_note.header.clone(), now_ms, nonce)?;
    let header_json = serde_json::to_string(&record.encrypted_note.header)?;
    record.revision_hash = revision_hash(
        "note",
        note_id,
        &header_json,
        &record.encrypted_note.nonce,
        &record.encrypted_note.ciphertext,
        record.content_version,
        record.deleted_at_ms,
    );

    connection.execute(
        r#"
        UPDATE encrypted_notes
            SET header_json = ?3,
            nonce = ?4,
            ciphertext = ?5,
            content_version = ?6,
            updated_at_ms = ?7,
            deleted_at_ms = ?8,
            revision_hash = ?9,
            sync_state = ?10,
            sync_blocked_reason = NULL
        WHERE vault_id = ?1 AND note_id = ?2
        "#,
        params![
            vault_id,
            note_id,
            header_json,
            record.encrypted_note.nonce,
            record.encrypted_note.ciphertext,
            record.content_version,
            now_ms,
            now_ms,
            record.revision_hash,
            record.sync_state.as_str()
        ],
    )?;

    Ok(record)
}

pub fn tombstone_folder(
    connection: &Connection,
    vault: &VaultMaterial,
    vault_id: &str,
    folder_id: &str,
    now_ms: u64,
    nonce: [u8; 24],
) -> Result<LocalEncryptedFolderRecord> {
    require_vault_material(vault, vault_id)?;
    let mut record = get_folder(connection, vault_id, folder_id)?
        .ok_or(LocalStoreError::MissingRecord { kind: "folder" })?;
    record.encrypted_folder.header.content_version = record.content_version + 1;
    record.content_version += 1;
    record.updated_at_ms = now_ms;
    record.deleted_at_ms = Some(now_ms);
    record.sync_state = default_local_change_sync_state(connection, vault_id, true)?;
    record.encrypted_folder =
        vault.encrypt_folder_tombstone(record.encrypted_folder.header.clone(), now_ms, nonce)?;
    let header_json = serde_json::to_string(&record.encrypted_folder.header)?;
    record.revision_hash = revision_hash(
        "folder",
        folder_id,
        &header_json,
        &record.encrypted_folder.nonce,
        &record.encrypted_folder.ciphertext,
        record.content_version,
        record.deleted_at_ms,
    );

    connection.execute(
        r#"
        UPDATE encrypted_folders
            SET header_json = ?3,
            nonce = ?4,
            ciphertext = ?5,
            content_version = ?6,
            updated_at_ms = ?7,
            deleted_at_ms = ?8,
            revision_hash = ?9,
            sync_state = ?10
        WHERE vault_id = ?1 AND folder_id = ?2
        "#,
        params![
            vault_id,
            folder_id,
            header_json,
            record.encrypted_folder.nonce,
            record.encrypted_folder.ciphertext,
            record.content_version,
            now_ms,
            now_ms,
            record.revision_hash,
            record.sync_state.as_str()
        ],
    )?;

    Ok(record)
}

pub fn mark_records_synced(
    connection: &Connection,
    vault_id: &str,
    records: &[SyncedRecordRef],
) -> Result<()> {
    for record in records {
        match record.kind {
            SyncedRecordKind::Note => {
                connection.execute(
                    r#"
                    UPDATE encrypted_notes
                    SET sync_state = 'synced',
                        last_synced_revision_hash = ?4,
                        cloud_sync_scope = 'included',
                        sync_blocked_reason = NULL,
                        remote_cloud_state = CASE
                            WHEN deleted_at_ms IS NULL THEN 'live'
                            ELSE 'deleted'
                        END
                    WHERE vault_id = ?1 AND note_id = ?2 AND revision_hash = ?3
                    "#,
                    params![
                        vault_id,
                        record.record_id,
                        record.revision_hash,
                        record.revision_hash
                    ],
                )?;
            }
            SyncedRecordKind::Folder => {
                connection.execute(
                    r#"
                    UPDATE encrypted_folders
                    SET sync_state = 'synced',
                        last_synced_revision_hash = ?4
                    WHERE vault_id = ?1 AND folder_id = ?2 AND revision_hash = ?3
                    "#,
                    params![
                        vault_id,
                        record.record_id,
                        record.revision_hash,
                        record.revision_hash
                    ],
                )?;
            }
        }
    }

    Ok(())
}

pub fn mark_note_sync_blocked(
    connection: &Connection,
    vault_id: &str,
    note_id: &str,
    expected_revision_hash: Option<&str>,
    reason: SyncBlockedReason,
) -> Result<LocalEncryptedNoteRecord> {
    let existing = get_note(connection, vault_id, note_id)?
        .ok_or(LocalStoreError::MissingRecord { kind: "note" })?;
    if existing.cloud_sync_scope == CloudSyncScope::LocalOnly {
        return Ok(existing);
    }
    if expected_revision_hash.is_some_and(|revision_hash| revision_hash != existing.revision_hash) {
        return Ok(existing);
    }
    let has_cloud_copy = existing.last_synced_revision_hash.is_some();
    let make_local_only = !has_cloud_copy && is_quota_block_reason(reason);
    connection.execute(
        r#"
        UPDATE encrypted_notes
        SET sync_state = ?3,
            cloud_sync_scope = ?4,
            sync_blocked_reason = ?5
        WHERE vault_id = ?1
          AND note_id = ?2
          AND cloud_sync_scope = 'included'
        "#,
        params![
            vault_id,
            note_id,
            if has_cloud_copy {
                SyncState::Synced.as_str()
            } else {
                SyncState::NotSynced.as_str()
            },
            if make_local_only {
                CloudSyncScope::LocalOnly.as_str()
            } else {
                CloudSyncScope::Included.as_str()
            },
            if make_local_only {
                Option::<&str>::None
            } else {
                Some(reason.as_str())
            }
        ],
    )?;

    get_note(connection, vault_id, note_id)?.ok_or(LocalStoreError::MissingRecord { kind: "note" })
}

fn is_quota_block_reason(reason: SyncBlockedReason) -> bool {
    matches!(
        reason,
        SyncBlockedReason::QuotaNoteCount | SyncBlockedReason::QuotaStorage
    )
}

pub fn include_note_in_cloud_sync(
    connection: &Connection,
    vault_id: &str,
    note_id: &str,
) -> Result<LocalEncryptedNoteRecord> {
    let existing = get_note(connection, vault_id, note_id)?
        .ok_or(LocalStoreError::MissingRecord { kind: "note" })?;
    let sync_state = if existing.deleted_at_ms.is_some() {
        SyncState::PendingDelete
    } else {
        SyncState::PendingUpsert
    };
    connection.execute(
        r#"
        UPDATE encrypted_notes
        SET cloud_sync_scope = 'included',
            sync_blocked_reason = NULL,
            sync_state = ?3
        WHERE vault_id = ?1 AND note_id = ?2
        "#,
        params![vault_id, note_id, sync_state.as_str()],
    )?;

    get_note(connection, vault_id, note_id)?.ok_or(LocalStoreError::MissingRecord { kind: "note" })
}

pub fn mark_note_local_only(
    connection: &Connection,
    vault_id: &str,
    note_id: &str,
    remote_state: Option<RemoteCloudState>,
    removed_from_sync_at_ms: Option<u64>,
) -> Result<LocalEncryptedNoteRecord> {
    connection.execute(
        r#"
        UPDATE encrypted_notes
        SET cloud_sync_scope = 'local_only',
            sync_blocked_reason = NULL,
            sync_state = 'not_synced',
            last_synced_revision_hash = NULL,
            remote_cloud_state = ?3,
            remote_removed_from_sync_at_ms = ?4
        WHERE vault_id = ?1 AND note_id = ?2
        "#,
        params![
            vault_id,
            note_id,
            remote_state.map(RemoteCloudState::as_str),
            removed_from_sync_at_ms
        ],
    )?;

    get_note(connection, vault_id, note_id)?.ok_or(LocalStoreError::MissingRecord { kind: "note" })
}

pub fn merge_remote_records(
    connection: &Connection,
    vault: &VaultMaterial,
    vault_id: &str,
    notes: &[RemoteNoteRecord],
    folders: &[RemoteFolderRecord],
) -> Result<MergeSummary> {
    require_vault_material(vault, vault_id)?;
    let mut summary = MergeSummary::default();

    for folder in folders {
        merge_remote_folder(connection, vault, vault_id, folder, &mut summary)?;
    }

    for note in notes {
        merge_remote_note(connection, vault, vault_id, note, &mut summary)?;
    }

    mark_sync_pulled(
        connection,
        vault_id,
        &vault.backend_auth_public_key_b64(),
        now_ms(),
    )?;

    Ok(summary)
}

fn mark_sync_pulled(
    connection: &Connection,
    vault_id: &str,
    backend_auth_public_key: &str,
    now_ms: u64,
) -> Result<()> {
    connection.execute(
        r#"
        INSERT INTO sync_metadata (
            vault_id, backend_auth_public_key, last_pull_at_ms, last_push_at_ms, last_error
        ) VALUES (?1, ?2, ?3, NULL, NULL)
        ON CONFLICT(vault_id) DO UPDATE SET
            backend_auth_public_key = excluded.backend_auth_public_key,
            last_pull_at_ms = excluded.last_pull_at_ms,
            last_error = NULL
        "#,
        params![vault_id, backend_auth_public_key, now_ms],
    )?;
    Ok(())
}

fn should_restore_missing_cloud_records(last_pull_at_ms: Option<u64>) -> bool {
    let Some(last_pull_at_ms) = last_pull_at_ms else {
        return true;
    };
    now_ms().saturating_sub(last_pull_at_ms) <= STALE_PULL_RESTORE_WINDOW_MS
}

pub fn merge_import_records(
    connection: &Connection,
    vault_id: &str,
    notes: &[LocalEncryptedNoteRecord],
    folders: &[LocalEncryptedFolderRecord],
) -> Result<MergeSummary> {
    let mut summary = MergeSummary::default();

    for folder in folders {
        merge_import_folder(connection, vault_id, folder, &mut summary)?;
    }

    for note in notes {
        merge_import_note(connection, vault_id, note, &mut summary)?;
    }

    Ok(summary)
}

fn merge_remote_note(
    connection: &Connection,
    vault: &VaultMaterial,
    vault_id: &str,
    remote: &RemoteNoteRecord,
    summary: &mut MergeSummary,
) -> Result<()> {
    if !remote_note_outer_identity_matches(vault, remote, vault_id) {
        summary.rejected += 1;
        return Ok(());
    }

    if remote.cloud_state == Some(RemoteCloudState::RemovedFromSync) {
        if get_note(connection, vault_id, &remote.note_id)?.is_some() {
            mark_note_local_only(
                connection,
                vault_id,
                &remote.note_id,
                Some(RemoteCloudState::RemovedFromSync),
                remote.server_removed_from_sync_at_bucket_ms,
            )?;
            summary.updated += 1;
        } else {
            summary.unchanged += 1;
        }
        return Ok(());
    }

    let encrypted_note = EncryptedNote {
        header: remote.header.clone(),
        nonce: remote.nonce.clone(),
        ciphertext: remote.ciphertext.clone(),
    };
    let Some(authenticated) = authenticate_remote_note(vault, remote, &encrypted_note) else {
        summary.rejected += 1;
        return Ok(());
    };
    let incoming = note_record_from_parts(
        remote.note_id.clone(),
        encrypted_note,
        remote.content_version,
        authenticated.created_at_ms,
        authenticated.updated_at_ms,
        authenticated.deleted_at_ms,
        SyncState::Synced,
        None,
    )?;
    let mut incoming = incoming;
    incoming.remote_cloud_state =
        remote
            .cloud_state
            .or(Some(if authenticated.deleted_at_ms.is_some() {
                RemoteCloudState::Deleted
            } else {
                RemoteCloudState::Live
            }));
    incoming.remote_removed_from_sync_at_ms = remote.server_removed_from_sync_at_bucket_ms;
    merge_incoming_note(
        connection,
        vault_id,
        incoming,
        IncomingRecordSource::RemoteSynced,
        summary,
    )
}

fn merge_remote_folder(
    connection: &Connection,
    vault: &VaultMaterial,
    vault_id: &str,
    remote: &RemoteFolderRecord,
    summary: &mut MergeSummary,
) -> Result<()> {
    if !remote_folder_outer_identity_matches(vault, remote, vault_id) {
        summary.rejected += 1;
        return Ok(());
    }
    if remote.cloud_state == Some(RemoteCloudState::RemovedFromSync) {
        summary.rejected += 1;
        return Ok(());
    }

    let encrypted_folder = EncryptedFolder {
        header: remote.header.clone(),
        nonce: remote.nonce.clone(),
        ciphertext: remote.ciphertext.clone(),
    };
    let Some(authenticated) = authenticate_remote_folder(vault, remote, &encrypted_folder) else {
        summary.rejected += 1;
        return Ok(());
    };
    let incoming = folder_record_from_parts(
        remote.folder_id.clone(),
        encrypted_folder,
        remote.content_version,
        authenticated.created_at_ms,
        authenticated.updated_at_ms,
        authenticated.deleted_at_ms,
        SyncState::Synced,
        None,
    )?;
    merge_incoming_folder(
        connection,
        vault_id,
        incoming,
        IncomingRecordSource::RemoteSynced,
        summary,
    )
}

fn remote_note_outer_identity_matches(
    vault: &VaultMaterial,
    remote: &RemoteNoteRecord,
    vault_id: &str,
) -> bool {
    remote.vault_id == vault_id
        && remote.header.vault_id == vault_id
        && remote.note_id == remote.header.note_id
        && remote.content_version == remote.header.content_version
        && remote.header.key_version == vault.context().key_version
        && (MIN_CIPHERTEXT_SCHEMA_VERSION..=CIPHERTEXT_SCHEMA_VERSION)
            .contains(&remote.header.schema_version)
        && remote.header.algorithm == CIPHERTEXT_ALGORITHM
        && !remote.note_id.trim().is_empty()
}

fn remote_folder_outer_identity_matches(
    vault: &VaultMaterial,
    remote: &RemoteFolderRecord,
    vault_id: &str,
) -> bool {
    remote.vault_id == vault_id
        && remote.header.vault_id == vault_id
        && remote.folder_id == remote.header.folder_id
        && remote.content_version == remote.header.content_version
        && remote.header.key_version == vault.context().key_version
        && (MIN_CIPHERTEXT_SCHEMA_VERSION..=CIPHERTEXT_SCHEMA_VERSION)
            .contains(&remote.header.schema_version)
        && remote.header.algorithm == CIPHERTEXT_ALGORITHM
        && !remote.folder_id.trim().is_empty()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthenticatedRemoteTimestamps {
    created_at_ms: u64,
    updated_at_ms: u64,
    deleted_at_ms: Option<u64>,
}

fn authenticate_remote_note(
    vault: &VaultMaterial,
    remote: &RemoteNoteRecord,
    encrypted_note: &EncryptedNote,
) -> Option<AuthenticatedRemoteTimestamps> {
    match remote_record_state(remote.cloud_state, &remote.nonce, &remote.ciphertext) {
        Some(RemoteRecordAuthState::Live) => {
            let document = vault.decrypt_note_document(encrypted_note).ok()?;
            Some(AuthenticatedRemoteTimestamps {
                created_at_ms: document.created_at_ms,
                updated_at_ms: document.updated_at_ms,
                deleted_at_ms: None,
            })
        }
        Some(RemoteRecordAuthState::Deleted) => {
            let tombstone = vault.decrypt_note_tombstone(encrypted_note).ok()?;
            Some(AuthenticatedRemoteTimestamps {
                created_at_ms: tombstone.deleted_at_ms,
                updated_at_ms: tombstone.deleted_at_ms,
                deleted_at_ms: Some(tombstone.deleted_at_ms),
            })
        }
        None => None,
    }
}

fn authenticate_remote_folder(
    vault: &VaultMaterial,
    remote: &RemoteFolderRecord,
    encrypted_folder: &EncryptedFolder,
) -> Option<AuthenticatedRemoteTimestamps> {
    match remote_record_state(remote.cloud_state, &remote.nonce, &remote.ciphertext) {
        Some(RemoteRecordAuthState::Live) => {
            let document = vault.decrypt_folder_document(encrypted_folder).ok()?;
            Some(AuthenticatedRemoteTimestamps {
                created_at_ms: document.created_at_ms,
                updated_at_ms: document.updated_at_ms,
                deleted_at_ms: None,
            })
        }
        Some(RemoteRecordAuthState::Deleted) => {
            let tombstone = vault.decrypt_folder_tombstone(encrypted_folder).ok()?;
            Some(AuthenticatedRemoteTimestamps {
                created_at_ms: tombstone.deleted_at_ms,
                updated_at_ms: tombstone.deleted_at_ms,
                deleted_at_ms: Some(tombstone.deleted_at_ms),
            })
        }
        None => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemoteRecordAuthState {
    Live,
    Deleted,
}

fn remote_record_state(
    cloud_state: Option<RemoteCloudState>,
    nonce: &str,
    ciphertext: &str,
) -> Option<RemoteRecordAuthState> {
    let has_ciphertext = !nonce.is_empty() && !ciphertext.is_empty();
    match (cloud_state, has_ciphertext) {
        (Some(RemoteCloudState::Live), true) | (None, true) => Some(RemoteRecordAuthState::Live),
        (Some(RemoteCloudState::Deleted), true) => Some(RemoteRecordAuthState::Deleted),
        _ => None,
    }
}

fn merge_import_note(
    connection: &Connection,
    vault_id: &str,
    imported: &LocalEncryptedNoteRecord,
    summary: &mut MergeSummary,
) -> Result<()> {
    if imported.encrypted_note.header.vault_id != vault_id {
        return Ok(());
    }

    let mut incoming = imported.clone();
    incoming.sync_state =
        default_local_change_sync_state(connection, vault_id, incoming.deleted_at_ms.is_some())?;
    incoming.last_synced_revision_hash = None;
    merge_incoming_note(
        connection,
        vault_id,
        incoming,
        IncomingRecordSource::ImportedLocal,
        summary,
    )
}

fn merge_import_folder(
    connection: &Connection,
    vault_id: &str,
    imported: &LocalEncryptedFolderRecord,
    summary: &mut MergeSummary,
) -> Result<()> {
    if imported.encrypted_folder.header.vault_id != vault_id {
        return Ok(());
    }

    let mut incoming = imported.clone();
    incoming.sync_state =
        default_local_change_sync_state(connection, vault_id, incoming.deleted_at_ms.is_some())?;
    incoming.last_synced_revision_hash = None;
    merge_incoming_folder(
        connection,
        vault_id,
        incoming,
        IncomingRecordSource::ImportedLocal,
        summary,
    )
}

fn merge_incoming_note(
    connection: &Connection,
    vault_id: &str,
    incoming: LocalEncryptedNoteRecord,
    source: IncomingRecordSource,
    summary: &mut MergeSummary,
) -> Result<()> {
    let existing = get_note(connection, vault_id, &incoming.note_id)?;
    let decision = decide_merge(
        existing.as_ref().map(note_merge_record),
        note_merge_record(&incoming),
        source,
    );

    match decision {
        MergeDecision::InsertIncoming => {
            upsert_note_record(connection, &incoming)?;
            summary.inserted += 1;
        }
        MergeDecision::Unchanged { mark_synced } => {
            let Some(existing) = existing else {
                return Err(LocalStoreError::MissingRecord { kind: "note" });
            };
            if mark_synced {
                mark_records_synced(
                    connection,
                    vault_id,
                    &[SyncedRecordRef {
                        kind: SyncedRecordKind::Note,
                        record_id: existing.note_id,
                        revision_hash: existing.revision_hash,
                    }],
                )?;
            }
            summary.unchanged += 1;
        }
        MergeDecision::ReplaceWithIncoming => {
            upsert_note_record(connection, &incoming)?;
            summary.updated += 1;
        }
        MergeDecision::KeepLocalAsPending { sync_state } => {
            let Some(existing) = existing else {
                return Err(LocalStoreError::MissingRecord { kind: "note" });
            };
            ensure_local_pending_if_newer(
                connection,
                vault_id,
                "note",
                &existing.note_id,
                sync_state,
            )?;
            summary.kept_local += 1;
        }
        MergeDecision::ReplaceWithIncomingAndStoreLocalConflict => {
            let Some(existing) = existing else {
                return Err(LocalStoreError::MissingRecord { kind: "note" });
            };
            insert_note_conflict(connection, vault_id, existing)?;
            upsert_note_record(connection, &incoming)?;
            summary.conflicts += 1;
            summary.updated += 1;
        }
        MergeDecision::StoreIncomingConflict => {
            insert_note_conflict(connection, vault_id, incoming)?;
            summary.conflicts += 1;
        }
    }

    Ok(())
}

fn note_merge_record(record: &LocalEncryptedNoteRecord) -> MergeRecord<'_> {
    MergeRecord {
        content_version: record.content_version,
        deleted: record.deleted_at_ms.is_some(),
        revision_hash: &record.revision_hash,
        sync_state: record.sync_state,
    }
}

fn merge_incoming_folder(
    connection: &Connection,
    vault_id: &str,
    incoming: LocalEncryptedFolderRecord,
    source: IncomingRecordSource,
    summary: &mut MergeSummary,
) -> Result<()> {
    let existing = get_folder(connection, vault_id, &incoming.folder_id)?;
    let decision = decide_merge(
        existing.as_ref().map(folder_merge_record),
        folder_merge_record(&incoming),
        source,
    );

    match decision {
        MergeDecision::InsertIncoming => {
            upsert_folder_record(connection, &incoming)?;
            summary.inserted += 1;
        }
        MergeDecision::Unchanged { mark_synced } => {
            let Some(existing) = existing else {
                return Err(LocalStoreError::MissingRecord { kind: "folder" });
            };
            if mark_synced {
                mark_records_synced(
                    connection,
                    vault_id,
                    &[SyncedRecordRef {
                        kind: SyncedRecordKind::Folder,
                        record_id: existing.folder_id,
                        revision_hash: existing.revision_hash,
                    }],
                )?;
            }
            summary.unchanged += 1;
        }
        MergeDecision::ReplaceWithIncoming => {
            upsert_folder_record(connection, &incoming)?;
            summary.updated += 1;
        }
        MergeDecision::KeepLocalAsPending { sync_state } => {
            let Some(existing) = existing else {
                return Err(LocalStoreError::MissingRecord { kind: "folder" });
            };
            ensure_local_pending_if_newer(
                connection,
                vault_id,
                "folder",
                &existing.folder_id,
                sync_state,
            )?;
            summary.kept_local += 1;
        }
        MergeDecision::ReplaceWithIncomingAndStoreLocalConflict => {
            let Some(existing) = existing else {
                return Err(LocalStoreError::MissingRecord { kind: "folder" });
            };
            insert_folder_conflict(connection, vault_id, existing)?;
            upsert_folder_record(connection, &incoming)?;
            summary.conflicts += 1;
            summary.updated += 1;
        }
        MergeDecision::StoreIncomingConflict => {
            insert_folder_conflict(connection, vault_id, incoming)?;
            summary.conflicts += 1;
        }
    }

    Ok(())
}

fn folder_merge_record(record: &LocalEncryptedFolderRecord) -> MergeRecord<'_> {
    MergeRecord {
        content_version: record.content_version,
        deleted: record.deleted_at_ms.is_some(),
        revision_hash: &record.revision_hash,
        sync_state: record.sync_state,
    }
}

fn insert_note_conflict(
    connection: &Connection,
    vault_id: &str,
    mut incoming: LocalEncryptedNoteRecord,
) -> Result<()> {
    let conflict_id = conflict_record_id("note", &incoming.note_id, &incoming.revision_hash);
    if get_note(connection, vault_id, &conflict_id)?.is_some() {
        return Ok(());
    }

    incoming.note_id = conflict_id;
    incoming.sync_state = SyncState::Conflict;
    incoming.last_synced_revision_hash = None;
    incoming.revision_hash = note_revision_hash(&incoming)?;
    upsert_note_record(connection, &incoming)
}

fn insert_folder_conflict(
    connection: &Connection,
    vault_id: &str,
    mut incoming: LocalEncryptedFolderRecord,
) -> Result<()> {
    let conflict_id = conflict_record_id("folder", &incoming.folder_id, &incoming.revision_hash);
    if get_folder(connection, vault_id, &conflict_id)?.is_some() {
        return Ok(());
    }

    incoming.folder_id = conflict_id;
    incoming.sync_state = SyncState::Conflict;
    incoming.last_synced_revision_hash = None;
    incoming.revision_hash = folder_revision_hash(&incoming)?;
    upsert_folder_record(connection, &incoming)
}

fn ensure_local_pending_if_newer(
    connection: &Connection,
    vault_id: &str,
    kind: &str,
    record_id: &str,
    sync_state: SyncState,
) -> Result<()> {
    match kind {
        "note" => {
            connection.execute(
                "UPDATE encrypted_notes SET sync_state = ?3 WHERE vault_id = ?1 AND note_id = ?2 AND sync_state = 'synced'",
                params![vault_id, record_id, sync_state.as_str()],
            )?;
        }
        "folder" => {
            connection.execute(
                "UPDATE encrypted_folders SET sync_state = ?3 WHERE vault_id = ?1 AND folder_id = ?2 AND sync_state = 'synced'",
                params![vault_id, record_id, sync_state.as_str()],
            )?;
        }
        _ => {}
    }
    Ok(())
}

fn upsert_note_record(connection: &Connection, record: &LocalEncryptedNoteRecord) -> Result<()> {
    let header_json = serde_json::to_string(&record.encrypted_note.header)?;
    connection.execute(
        r#"
        INSERT INTO encrypted_notes (
            vault_id, note_id, header_json, nonce, ciphertext, content_version,
            created_at_ms, updated_at_ms, deleted_at_ms, revision_hash, sync_state,
            last_synced_revision_hash, cloud_sync_scope, sync_blocked_reason,
            remote_cloud_state, remote_removed_from_sync_at_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
        ON CONFLICT(vault_id, note_id) DO UPDATE SET
            header_json = excluded.header_json,
            nonce = excluded.nonce,
            ciphertext = excluded.ciphertext,
            content_version = excluded.content_version,
            created_at_ms = excluded.created_at_ms,
            updated_at_ms = excluded.updated_at_ms,
            deleted_at_ms = excluded.deleted_at_ms,
            revision_hash = excluded.revision_hash,
            sync_state = excluded.sync_state,
            last_synced_revision_hash = excluded.last_synced_revision_hash,
            cloud_sync_scope = excluded.cloud_sync_scope,
            sync_blocked_reason = excluded.sync_blocked_reason,
            remote_cloud_state = excluded.remote_cloud_state,
            remote_removed_from_sync_at_ms = excluded.remote_removed_from_sync_at_ms
        "#,
        params![
            record.encrypted_note.header.vault_id,
            record.note_id,
            header_json,
            record.encrypted_note.nonce,
            record.encrypted_note.ciphertext,
            record.content_version,
            record.created_at_ms,
            record.updated_at_ms,
            record.deleted_at_ms,
            record.revision_hash,
            record.sync_state.as_str(),
            record.last_synced_revision_hash,
            record.cloud_sync_scope.as_str(),
            record.sync_blocked_reason.map(SyncBlockedReason::as_str),
            record.remote_cloud_state.map(RemoteCloudState::as_str),
            record.remote_removed_from_sync_at_ms
        ],
    )?;
    Ok(())
}

fn upsert_folder_record(
    connection: &Connection,
    record: &LocalEncryptedFolderRecord,
) -> Result<()> {
    let header_json = serde_json::to_string(&record.encrypted_folder.header)?;
    connection.execute(
        r#"
        INSERT INTO encrypted_folders (
            vault_id, folder_id, header_json, nonce, ciphertext, content_version,
            created_at_ms, updated_at_ms, deleted_at_ms, revision_hash, sync_state,
            last_synced_revision_hash
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        ON CONFLICT(vault_id, folder_id) DO UPDATE SET
            header_json = excluded.header_json,
            nonce = excluded.nonce,
            ciphertext = excluded.ciphertext,
            content_version = excluded.content_version,
            created_at_ms = excluded.created_at_ms,
            updated_at_ms = excluded.updated_at_ms,
            deleted_at_ms = excluded.deleted_at_ms,
            revision_hash = excluded.revision_hash,
            sync_state = excluded.sync_state,
            last_synced_revision_hash = excluded.last_synced_revision_hash
        "#,
        params![
            record.encrypted_folder.header.vault_id,
            record.folder_id,
            header_json,
            record.encrypted_folder.nonce,
            record.encrypted_folder.ciphertext,
            record.content_version,
            record.created_at_ms,
            record.updated_at_ms,
            record.deleted_at_ms,
            record.revision_hash,
            record.sync_state.as_str(),
            record.last_synced_revision_hash
        ],
    )?;
    Ok(())
}

fn get_note(
    connection: &Connection,
    vault_id: &str,
    note_id: &str,
) -> Result<Option<LocalEncryptedNoteRecord>> {
    connection
        .query_row(
            r#"
            SELECT vault_id, note_id, header_json, nonce, ciphertext, content_version,
                created_at_ms, updated_at_ms, deleted_at_ms, revision_hash, sync_state,
                last_synced_revision_hash, cloud_sync_scope, sync_blocked_reason,
                remote_cloud_state, remote_removed_from_sync_at_ms
            FROM encrypted_notes
            WHERE vault_id = ?1 AND note_id = ?2
            "#,
            params![vault_id, note_id],
            row_to_note,
        )
        .optional()
        .map_err(LocalStoreError::from)
}

fn get_folder(
    connection: &Connection,
    vault_id: &str,
    folder_id: &str,
) -> Result<Option<LocalEncryptedFolderRecord>> {
    connection
        .query_row(
            r#"
            SELECT vault_id, folder_id, header_json, nonce, ciphertext, content_version,
                created_at_ms, updated_at_ms, deleted_at_ms, revision_hash, sync_state,
                last_synced_revision_hash
            FROM encrypted_folders
            WHERE vault_id = ?1 AND folder_id = ?2
            "#,
            params![vault_id, folder_id],
            row_to_folder,
        )
        .optional()
        .map_err(LocalStoreError::from)
}

fn load_notes(connection: &Connection, vault_id: &str) -> Result<Vec<LocalEncryptedNoteRecord>> {
    query_notes(
        connection,
        r#"
        SELECT vault_id, note_id, header_json, nonce, ciphertext, content_version,
            created_at_ms, updated_at_ms, deleted_at_ms, revision_hash, sync_state,
            last_synced_revision_hash, cloud_sync_scope, sync_blocked_reason,
            remote_cloud_state, remote_removed_from_sync_at_ms
        FROM encrypted_notes
        WHERE vault_id = ?1
        ORDER BY updated_at_ms DESC
        "#,
        params![vault_id],
    )
}

fn load_folders(
    connection: &Connection,
    vault_id: &str,
) -> Result<Vec<LocalEncryptedFolderRecord>> {
    query_folders(
        connection,
        r#"
        SELECT vault_id, folder_id, header_json, nonce, ciphertext, content_version,
            created_at_ms, updated_at_ms, deleted_at_ms, revision_hash, sync_state,
            last_synced_revision_hash
        FROM encrypted_folders
        WHERE vault_id = ?1
        ORDER BY updated_at_ms DESC
        "#,
        params![vault_id],
    )
}

fn query_notes<P: rusqlite::Params>(
    connection: &Connection,
    sql: &str,
    params: P,
) -> Result<Vec<LocalEncryptedNoteRecord>> {
    let mut statement = connection.prepare(sql)?;
    let rows = statement.query_map(params, row_to_note)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(LocalStoreError::from)
}

fn query_folders<P: rusqlite::Params>(
    connection: &Connection,
    sql: &str,
    params: P,
) -> Result<Vec<LocalEncryptedFolderRecord>> {
    let mut statement = connection.prepare(sql)?;
    let rows = statement.query_map(params, row_to_folder)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(LocalStoreError::from)
}

fn row_to_preference(row: &rusqlite::Row<'_>) -> rusqlite::Result<VaultPreference> {
    let storage_mode: String = row.get(1)?;
    Ok(VaultPreference {
        vault_id: row.get(0)?,
        storage_mode: StorageMode::from_str(&storage_mode).map_err(to_sql_error)?,
        cloud_copy_deleted_at_ms: optional_i64_to_u64(row.get(2)?),
        created_at_ms: i64_to_u64(row.get(3)?),
        updated_at_ms: i64_to_u64(row.get(4)?),
    })
}

fn row_to_note(row: &rusqlite::Row<'_>) -> rusqlite::Result<LocalEncryptedNoteRecord> {
    let vault_id: String = row.get(0)?;
    let note_id: String = row.get(1)?;
    let header_json: String = row.get(2)?;
    let nonce: String = row.get(3)?;
    let ciphertext: String = row.get(4)?;
    let sync_state: String = row.get(10)?;
    let cloud_sync_scope: String = row.get(12)?;
    let sync_blocked_reason: Option<String> = row.get(13)?;
    let remote_cloud_state: Option<String> = row.get(14)?;

    Ok(LocalEncryptedNoteRecord {
        note_id,
        encrypted_note: EncryptedNote {
            header: serde_json::from_str(&header_json).map_err(to_sql_error)?,
            nonce,
            ciphertext,
        },
        content_version: i64_to_u64(row.get(5)?),
        created_at_ms: i64_to_u64(row.get(6)?),
        updated_at_ms: i64_to_u64(row.get(7)?),
        deleted_at_ms: optional_i64_to_u64(row.get(8)?),
        revision_hash: row.get(9)?,
        sync_state: SyncState::from_str(&sync_state).map_err(to_sql_error)?,
        last_synced_revision_hash: row.get(11)?,
        cloud_sync_scope: CloudSyncScope::from_str(&cloud_sync_scope).map_err(to_sql_error)?,
        sync_blocked_reason: sync_blocked_reason
            .map(|value| SyncBlockedReason::from_str(&value))
            .transpose()
            .map_err(to_sql_error)?,
        remote_cloud_state: remote_cloud_state
            .map(|value| RemoteCloudState::from_str(&value))
            .transpose()
            .map_err(to_sql_error)?,
        remote_removed_from_sync_at_ms: optional_i64_to_u64(row.get(15)?),
    }
    .with_vault(vault_id))
}

fn row_to_folder(row: &rusqlite::Row<'_>) -> rusqlite::Result<LocalEncryptedFolderRecord> {
    let vault_id: String = row.get(0)?;
    let folder_id: String = row.get(1)?;
    let header_json: String = row.get(2)?;
    let nonce: String = row.get(3)?;
    let ciphertext: String = row.get(4)?;
    let sync_state: String = row.get(10)?;

    Ok(LocalEncryptedFolderRecord {
        folder_id,
        encrypted_folder: EncryptedFolder {
            header: serde_json::from_str(&header_json).map_err(to_sql_error)?,
            nonce,
            ciphertext,
        },
        content_version: i64_to_u64(row.get(5)?),
        created_at_ms: i64_to_u64(row.get(6)?),
        updated_at_ms: i64_to_u64(row.get(7)?),
        deleted_at_ms: optional_i64_to_u64(row.get(8)?),
        revision_hash: row.get(9)?,
        sync_state: SyncState::from_str(&sync_state).map_err(to_sql_error)?,
        last_synced_revision_hash: row.get(11)?,
    }
    .with_vault(vault_id))
}

trait WithVault {
    fn with_vault(self, vault_id: String) -> Self;
}

impl WithVault for LocalEncryptedNoteRecord {
    fn with_vault(mut self, vault_id: String) -> Self {
        self.encrypted_note.header.vault_id = vault_id;
        self
    }
}

impl WithVault for LocalEncryptedFolderRecord {
    fn with_vault(mut self, vault_id: String) -> Self {
        self.encrypted_folder.header.vault_id = vault_id;
        self
    }
}

fn note_record_from_parts(
    note_id: String,
    encrypted_note: EncryptedNote,
    content_version: u64,
    created_at_ms: u64,
    updated_at_ms: u64,
    deleted_at_ms: Option<u64>,
    sync_state: SyncState,
    last_synced_revision_hash: Option<String>,
) -> Result<LocalEncryptedNoteRecord> {
    let header_json = serde_json::to_string(&encrypted_note.header)?;
    let revision_hash = revision_hash(
        "note",
        &note_id,
        &header_json,
        &encrypted_note.nonce,
        &encrypted_note.ciphertext,
        content_version,
        deleted_at_ms,
    );
    Ok(LocalEncryptedNoteRecord {
        note_id,
        encrypted_note,
        content_version,
        created_at_ms,
        updated_at_ms,
        deleted_at_ms,
        revision_hash: revision_hash.clone(),
        sync_state,
        last_synced_revision_hash: last_synced_revision_hash
            .or_else(|| (sync_state == SyncState::Synced).then_some(revision_hash)),
        cloud_sync_scope: CloudSyncScope::Included,
        sync_blocked_reason: None,
        remote_cloud_state: Some(if deleted_at_ms.is_some() {
            RemoteCloudState::Deleted
        } else {
            RemoteCloudState::Live
        }),
        remote_removed_from_sync_at_ms: None,
    })
}

fn folder_record_from_parts(
    folder_id: String,
    encrypted_folder: EncryptedFolder,
    content_version: u64,
    created_at_ms: u64,
    updated_at_ms: u64,
    deleted_at_ms: Option<u64>,
    sync_state: SyncState,
    last_synced_revision_hash: Option<String>,
) -> Result<LocalEncryptedFolderRecord> {
    let header_json = serde_json::to_string(&encrypted_folder.header)?;
    let revision_hash = revision_hash(
        "folder",
        &folder_id,
        &header_json,
        &encrypted_folder.nonce,
        &encrypted_folder.ciphertext,
        content_version,
        deleted_at_ms,
    );
    Ok(LocalEncryptedFolderRecord {
        folder_id,
        encrypted_folder,
        content_version,
        created_at_ms,
        updated_at_ms,
        deleted_at_ms,
        revision_hash: revision_hash.clone(),
        sync_state,
        last_synced_revision_hash: last_synced_revision_hash
            .or_else(|| (sync_state == SyncState::Synced).then_some(revision_hash)),
    })
}

fn note_revision_hash(record: &LocalEncryptedNoteRecord) -> Result<String> {
    let header_json = serde_json::to_string(&record.encrypted_note.header)?;
    Ok(revision_hash(
        "note",
        &record.note_id,
        &header_json,
        &record.encrypted_note.nonce,
        &record.encrypted_note.ciphertext,
        record.content_version,
        record.deleted_at_ms,
    ))
}

fn folder_revision_hash(record: &LocalEncryptedFolderRecord) -> Result<String> {
    let header_json = serde_json::to_string(&record.encrypted_folder.header)?;
    Ok(revision_hash(
        "folder",
        &record.folder_id,
        &header_json,
        &record.encrypted_folder.nonce,
        &record.encrypted_folder.ciphertext,
        record.content_version,
        record.deleted_at_ms,
    ))
}

fn revision_hash(
    kind: &str,
    record_id: &str,
    header_json: &str,
    nonce: &str,
    ciphertext: &str,
    content_version: u64,
    deleted_at_ms: Option<u64>,
) -> String {
    let mut hasher = Sha256::new();
    update_hash_part(&mut hasher, kind);
    update_hash_part(&mut hasher, record_id);
    update_hash_part(&mut hasher, header_json);
    update_hash_part(&mut hasher, nonce);
    update_hash_part(&mut hasher, ciphertext);
    update_hash_part(&mut hasher, &content_version.to_string());
    update_hash_part(
        &mut hasher,
        &deleted_at_ms.map_or_else(String::new, |value| value.to_string()),
    );
    hex::encode(hasher.finalize())
}

fn update_hash_part(hasher: &mut Sha256, value: &str) {
    hasher.update(value.len().to_be_bytes());
    hasher.update(value.as_bytes());
}

fn default_local_change_sync_state(
    connection: &Connection,
    vault_id: &str,
    deleted: bool,
) -> Result<SyncState> {
    let preference = get_preference(connection, vault_id)?;
    if preference
        .as_ref()
        .is_some_and(|preference| preference.storage_mode == StorageMode::SyncEnabled)
    {
        Ok(pending_sync_state_for_deleted(deleted))
    } else {
        Ok(SyncState::NotSynced)
    }
}

fn default_note_cloud_sync_scope(
    connection: &Connection,
    vault_id: &str,
) -> Result<CloudSyncScope> {
    let preference = get_preference(connection, vault_id)?;
    if preference
        .as_ref()
        .is_some_and(|preference| preference.storage_mode == StorageMode::SyncEnabled)
    {
        Ok(CloudSyncScope::Included)
    } else {
        Ok(CloudSyncScope::LocalOnly)
    }
}

fn default_note_local_change_sync_state(
    connection: &Connection,
    vault_id: &str,
    deleted: bool,
    cloud_sync_scope: CloudSyncScope,
) -> Result<SyncState> {
    if cloud_sync_scope == CloudSyncScope::LocalOnly {
        return Ok(SyncState::NotSynced);
    }

    default_local_change_sync_state(connection, vault_id, deleted)
}

fn require_vault_material(vault: &VaultMaterial, vault_id: &str) -> Result<()> {
    if vault.vault_id() == vault_id {
        Ok(())
    } else {
        Err(LocalStoreError::Policy(
            "vault material does not match local store vault".to_string(),
        ))
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn i64_to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}

fn optional_i64_to_u64(value: Option<i64>) -> Option<u64> {
    value.and_then(|inner| u64::try_from(inner).ok())
}

fn to_sql_error(error: impl std::error::Error + Send + Sync + 'static) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

fn add_column_if_missing(
    connection: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<()> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    for existing in columns {
        if existing? == column {
            return Ok(());
        }
    }

    connection.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        [],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_vault::{
        CiphertextHeader, FolderCiphertextHeader, PlaintextFolderDocument, PlaintextNoteDocument,
        VaultContext, VaultMaterial,
    };

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        migrate(&connection).unwrap();
        connection
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

    fn encrypted_folder(vault_id: &str, folder_id: &str, version: u64) -> EncryptedFolder {
        EncryptedFolder {
            header: FolderCiphertextHeader {
                algorithm: "XCHACHA20-POLY1305".to_string(),
                content_version: version,
                folder_id: folder_id.to_string(),
                key_version: 1,
                schema_version: 1,
                vault_id: vault_id.to_string(),
            },
            nonce: "folder-nonce".to_string(),
            ciphertext: "folder-ciphertext".to_string(),
        }
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

    fn sample_vault() -> VaultMaterial {
        VaultMaterial::derive([7u8; 32], sample_context(), &[3u8; 16]).unwrap()
    }

    fn real_encrypted_note(
        vault: &VaultMaterial,
        note_id: &str,
        version: u64,
        nonce_byte: u8,
    ) -> EncryptedNote {
        vault
            .encrypt_note_document(
                CiphertextHeader {
                    algorithm: "XCHACHA20-POLY1305".to_string(),
                    content_version: version,
                    key_version: 1,
                    note_id: note_id.to_string(),
                    schema_version: 1,
                    vault_id: vault.vault_id().to_string(),
                },
                &PlaintextNoteDocument {
                    body_markdown: format!("body {note_id} {version} {nonce_byte}"),
                    created_at_ms: 100,
                    folder_id: "my-notes".to_string(),
                    tags: vec![],
                    title: format!("title {note_id}"),
                    updated_at_ms: 100 + version,
                },
                [nonce_byte; 24],
            )
            .unwrap()
    }

    fn real_encrypted_folder(
        vault: &VaultMaterial,
        folder_id: &str,
        version: u64,
        nonce_byte: u8,
    ) -> EncryptedFolder {
        vault
            .encrypt_folder_document(
                FolderCiphertextHeader {
                    algorithm: "XCHACHA20-POLY1305".to_string(),
                    content_version: version,
                    folder_id: folder_id.to_string(),
                    key_version: 1,
                    schema_version: 1,
                    vault_id: vault.vault_id().to_string(),
                },
                &PlaintextFolderDocument {
                    created_at_ms: 100,
                    name: format!("folder {folder_id}"),
                    sort_order: 0,
                    updated_at_ms: 100 + version,
                },
                [nonce_byte; 24],
            )
            .unwrap()
    }

    fn remote_note_record(
        vault_id: &str,
        note_id: &str,
        encrypted: EncryptedNote,
        cloud_state: Option<RemoteCloudState>,
    ) -> RemoteNoteRecord {
        RemoteNoteRecord {
            vault_id: vault_id.to_string(),
            note_id: note_id.to_string(),
            content_version: encrypted.header.content_version,
            header: encrypted.header,
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
            cloud_state,
            retention_expires_at_bucket_ms: None,
            server_created_at_bucket_ms: 0,
            server_updated_at_bucket_ms: 0,
            server_deleted_at_bucket_ms: if cloud_state == Some(RemoteCloudState::Deleted) {
                Some(0)
            } else {
                None
            },
            server_removed_from_sync_at_bucket_ms: if cloud_state
                == Some(RemoteCloudState::RemovedFromSync)
            {
                Some(0)
            } else {
                None
            },
        }
    }

    fn remote_folder_record(
        vault_id: &str,
        folder_id: &str,
        encrypted: EncryptedFolder,
        cloud_state: Option<RemoteCloudState>,
    ) -> RemoteFolderRecord {
        RemoteFolderRecord {
            vault_id: vault_id.to_string(),
            folder_id: folder_id.to_string(),
            content_version: encrypted.header.content_version,
            header: encrypted.header,
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
            cloud_state,
            retention_expires_at_bucket_ms: None,
            server_created_at_bucket_ms: 0,
            server_updated_at_bucket_ms: 0,
            server_deleted_at_bucket_ms: if cloud_state == Some(RemoteCloudState::Deleted) {
                Some(0)
            } else {
                None
            },
            server_removed_from_sync_at_bucket_ms: if cloud_state
                == Some(RemoteCloudState::RemovedFromSync)
            {
                Some(0)
            } else {
                None
            },
        }
    }

    #[test]
    fn stores_preferences_by_vault() {
        let connection = connection();
        let preference =
            set_preference(&connection, "vault-1", StorageMode::LocalOnly, 100).unwrap();

        assert_eq!(preference.storage_mode, StorageMode::LocalOnly);
        assert_eq!(
            get_preference(&connection, "vault-1")
                .unwrap()
                .unwrap()
                .storage_mode,
            StorageMode::LocalOnly
        );
    }

    #[test]
    fn stale_pull_metadata_disables_missing_cloud_restore() {
        let connection = connection();
        let fresh_pull = now_ms();
        let stale_pull = fresh_pull - STALE_PULL_RESTORE_WINDOW_MS - 1;

        connection
            .execute(
                r#"
                INSERT INTO sync_metadata (
                    vault_id, backend_auth_public_key, last_pull_at_ms, last_push_at_ms, last_error
                ) VALUES (?1, ?2, ?3, NULL, NULL)
                "#,
                params!["fresh-vault", "backend-key", fresh_pull],
            )
            .unwrap();
        connection
            .execute(
                r#"
                INSERT INTO sync_metadata (
                    vault_id, backend_auth_public_key, last_pull_at_ms, last_push_at_ms, last_error
                ) VALUES (?1, ?2, ?3, NULL, NULL)
                "#,
                params!["stale-vault", "backend-key", stale_pull],
            )
            .unwrap();

        assert!(get_sync_metadata(&connection, "new-vault")
            .unwrap()
            .is_none());
        assert_eq!(
            get_sync_metadata(&connection, "fresh-vault")
                .unwrap()
                .unwrap()
                .restore_missing_cloud_records,
            true
        );
        assert_eq!(
            get_sync_metadata(&connection, "stale-vault")
                .unwrap()
                .unwrap()
                .restore_missing_cloud_records,
            false
        );
    }

    #[test]
    fn saves_and_loads_encrypted_records_without_plaintext_columns() {
        let connection = connection();
        set_preference(&connection, "vault-1", StorageMode::LocalOnly, 100).unwrap();

        save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: encrypted_note("vault-1", "note-1", 1),
                created_at_ms: 100,
                updated_at_ms: 101,
                sync_state: None,
                deleted_at_ms: None,
            },
        )
        .unwrap();
        save_folder(
            &connection,
            SaveLocalFolderInput {
                encrypted_folder: encrypted_folder("vault-1", "folder-1", 1),
                created_at_ms: 100,
                updated_at_ms: 101,
                sync_state: None,
                deleted_at_ms: None,
            },
        )
        .unwrap();

        let data = load_vault(&connection, "vault-1").unwrap();
        assert_eq!(data.notes.len(), 1);
        assert_eq!(data.folders.len(), 1);
        assert_eq!(data.notes[0].sync_state, SyncState::NotSynced);

        let stored_note: String = connection
            .query_row(
                "SELECT header_json || nonce || ciphertext FROM encrypted_notes WHERE vault_id = 'vault-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!stored_note.contains("Secret plaintext title"));
        assert!(!stored_note.contains("bookmark"));
    }

    #[test]
    fn tombstone_queues_delete_when_sync_enabled() {
        let vault = sample_vault();
        let vault_id = vault.vault_id();
        let connection = connection();
        set_preference(&connection, vault_id, StorageMode::SyncEnabled, 100).unwrap();
        save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: encrypted_note(vault_id, "note-1", 1),
                created_at_ms: 100,
                updated_at_ms: 101,
                sync_state: Some(SyncState::Synced),
                deleted_at_ms: None,
            },
        )
        .unwrap();

        let tombstone =
            tombstone_note(&connection, &vault, vault_id, "note-1", 200, [5u8; 24]).unwrap();

        assert_eq!(tombstone.content_version, 2);
        assert_eq!(tombstone.deleted_at_ms, Some(200));
        assert_eq!(tombstone.sync_state, SyncState::PendingDelete);
        assert_ne!(tombstone.encrypted_note.nonce, "");
        assert_ne!(tombstone.encrypted_note.ciphertext, "");
        let decrypted_tombstone = vault
            .decrypt_note_tombstone(&tombstone.encrypted_note)
            .unwrap();
        assert_eq!(decrypted_tombstone.deleted_at_ms, 200);
    }

    #[test]
    fn enable_sync_queues_existing_local_only_records() {
        let connection = connection();
        set_preference(&connection, "vault-1", StorageMode::LocalOnly, 100).unwrap();
        save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: encrypted_note("vault-1", "note-1", 1),
                created_at_ms: 100,
                updated_at_ms: 101,
                sync_state: None,
                deleted_at_ms: None,
            },
        )
        .unwrap();
        save_folder(
            &connection,
            SaveLocalFolderInput {
                encrypted_folder: encrypted_folder("vault-1", "folder-1", 1),
                created_at_ms: 100,
                updated_at_ms: 101,
                sync_state: None,
                deleted_at_ms: None,
            },
        )
        .unwrap();

        let preference = enable_sync(&connection, "vault-1", 200, None).unwrap();
        let pending = list_pending_sync(&connection, "vault-1").unwrap();

        assert_eq!(preference.storage_mode, StorageMode::SyncEnabled);
        assert_eq!(pending.notes[0].sync_state, SyncState::PendingUpsert);
        assert_eq!(pending.folders[0].sync_state, SyncState::PendingUpsert);
    }

    #[test]
    fn enable_sync_after_cloud_deletion_rebuilds_synced_records() {
        let vault = sample_vault();
        let vault_id = vault.vault_id();
        let connection = connection();
        set_preference(&connection, vault_id, StorageMode::SyncEnabled, 100).unwrap();
        save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: encrypted_note(vault_id, "note-1", 1),
                created_at_ms: 100,
                updated_at_ms: 101,
                sync_state: Some(SyncState::Synced),
                deleted_at_ms: None,
            },
        )
        .unwrap();
        save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: encrypted_note(vault_id, "note-2", 1),
                created_at_ms: 100,
                updated_at_ms: 102,
                sync_state: Some(SyncState::Synced),
                deleted_at_ms: None,
            },
        )
        .unwrap();
        tombstone_note(&connection, &vault, vault_id, "note-2", 150, [6u8; 24]).unwrap();
        save_folder(
            &connection,
            SaveLocalFolderInput {
                encrypted_folder: encrypted_folder(vault_id, "folder-1", 1),
                created_at_ms: 100,
                updated_at_ms: 103,
                sync_state: Some(SyncState::Synced),
                deleted_at_ms: None,
            },
        )
        .unwrap();
        save_folder(
            &connection,
            SaveLocalFolderInput {
                encrypted_folder: encrypted_folder(vault_id, "folder-2", 1),
                created_at_ms: 100,
                updated_at_ms: 104,
                sync_state: Some(SyncState::Synced),
                deleted_at_ms: None,
            },
        )
        .unwrap();
        tombstone_folder(&connection, &vault, vault_id, "folder-2", 160, [7u8; 24]).unwrap();
        mark_cloud_copy_deleted(&connection, vault_id, 200).unwrap();

        let preference = enable_sync(&connection, vault_id, 300, None).unwrap();
        let pending = list_pending_sync(&connection, vault_id).unwrap();

        assert_eq!(preference.storage_mode, StorageMode::SyncEnabled);
        assert_eq!(preference.cloud_copy_deleted_at_ms, None);
        assert_eq!(pending.notes.len(), 1);
        assert_eq!(pending.notes[0].note_id, "note-1");
        assert_eq!(pending.notes[0].sync_state, SyncState::PendingUpsert);
        assert_eq!(pending.folders.len(), 1);
        assert_eq!(pending.folders[0].folder_id, "folder-1");
        assert_eq!(pending.folders[0].sync_state, SyncState::PendingUpsert);

        let data = load_vault(&connection, vault_id).unwrap();
        let deleted_note = data
            .notes
            .iter()
            .find(|note| note.note_id == "note-2")
            .unwrap();
        assert_eq!(deleted_note.sync_state, SyncState::NotSynced);
        assert_eq!(deleted_note.cloud_sync_scope, CloudSyncScope::LocalOnly);
        let deleted_folder = data
            .folders
            .iter()
            .find(|folder| folder.folder_id == "folder-2")
            .unwrap();
        assert_eq!(deleted_folder.sync_state, SyncState::NotSynced);
    }

    #[test]
    fn enable_sync_with_selected_notes_queues_only_selected_live_notes() {
        let connection = connection();
        set_preference(&connection, "vault-1", StorageMode::LocalOnly, 100).unwrap();
        for index in 1..=21 {
            save_note(
                &connection,
                SaveLocalNoteInput {
                    encrypted_note: encrypted_note("vault-1", &format!("note-{index}"), 1),
                    created_at_ms: 100,
                    updated_at_ms: 100 + index,
                    sync_state: None,
                    deleted_at_ms: None,
                },
            )
            .unwrap();
        }
        save_folder(
            &connection,
            SaveLocalFolderInput {
                encrypted_folder: encrypted_folder("vault-1", "folder-1", 1),
                created_at_ms: 100,
                updated_at_ms: 130,
                sync_state: None,
                deleted_at_ms: None,
            },
        )
        .unwrap();

        let selected = (1..=20)
            .map(|index| format!("note-{index}"))
            .collect::<Vec<_>>();
        let preference = enable_sync(&connection, "vault-1", 200, Some(&selected)).unwrap();
        let pending = list_pending_sync(&connection, "vault-1").unwrap();
        let data = load_vault(&connection, "vault-1").unwrap();
        let excluded = data
            .notes
            .iter()
            .find(|note| note.note_id == "note-21")
            .unwrap();

        assert_eq!(preference.storage_mode, StorageMode::SyncEnabled);
        assert_eq!(pending.notes.len(), 20);
        assert!(pending.notes.iter().all(|note| note.note_id != "note-21"));
        assert_eq!(pending.folders.len(), 1);
        assert_eq!(excluded.cloud_sync_scope, CloudSyncScope::LocalOnly);
        assert_eq!(excluded.sync_state, SyncState::NotSynced);
        assert_eq!(excluded.sync_blocked_reason, None);
    }

    #[test]
    fn enable_sync_with_selected_notes_does_not_requeue_deleted_records() {
        let vault = sample_vault();
        let vault_id = vault.vault_id();
        let connection = connection();
        set_preference(&connection, vault_id, StorageMode::SyncEnabled, 100).unwrap();
        save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: encrypted_note(vault_id, "note-1", 1),
                created_at_ms: 100,
                updated_at_ms: 101,
                sync_state: Some(SyncState::Synced),
                deleted_at_ms: None,
            },
        )
        .unwrap();
        save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: encrypted_note(vault_id, "note-2", 1),
                created_at_ms: 100,
                updated_at_ms: 102,
                sync_state: Some(SyncState::Synced),
                deleted_at_ms: None,
            },
        )
        .unwrap();
        tombstone_note(&connection, &vault, vault_id, "note-2", 150, [8u8; 24]).unwrap();
        mark_cloud_copy_deleted(&connection, vault_id, 200).unwrap();

        let selected = vec!["note-1".to_string(), "note-2".to_string()];
        let preference = enable_sync(&connection, vault_id, 300, Some(&selected)).unwrap();
        let pending = list_pending_sync(&connection, vault_id).unwrap();
        let data = load_vault(&connection, vault_id).unwrap();
        let deleted_note = data
            .notes
            .iter()
            .find(|note| note.note_id == "note-2")
            .unwrap();

        assert_eq!(preference.storage_mode, StorageMode::SyncEnabled);
        assert_eq!(preference.cloud_copy_deleted_at_ms, None);
        assert_eq!(pending.notes.len(), 1);
        assert_eq!(pending.notes[0].note_id, "note-1");
        assert_eq!(deleted_note.cloud_sync_scope, CloudSyncScope::LocalOnly);
        assert_eq!(deleted_note.sync_state, SyncState::NotSynced);
    }

    #[test]
    fn enable_sync_with_selected_notes_preserves_conflict_records() {
        let connection = connection();
        set_preference(&connection, "vault-1", StorageMode::SyncEnabled, 100).unwrap();
        save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: encrypted_note("vault-1", "note-conflict", 1),
                created_at_ms: 100,
                updated_at_ms: 101,
                sync_state: Some(SyncState::Conflict),
                deleted_at_ms: None,
            },
        )
        .unwrap();

        let selected = vec!["note-conflict".to_string()];
        enable_sync(&connection, "vault-1", 200, Some(&selected)).unwrap();
        let conflict = get_note(&connection, "vault-1", "note-conflict")
            .unwrap()
            .unwrap();
        let pending = list_pending_sync(&connection, "vault-1").unwrap();

        assert_eq!(conflict.sync_state, SyncState::Conflict);
        assert_eq!(conflict.cloud_sync_scope, CloudSyncScope::Included);
        assert!(pending.notes.is_empty());
    }

    #[test]
    fn queue_cloud_replica_rebuild_queues_only_included_live_records() {
        let vault = sample_vault();
        let vault_id = vault.vault_id();
        let connection = connection();
        set_preference(&connection, vault_id, StorageMode::SyncEnabled, 100).unwrap();

        for (index, note_id, sync_state) in [
            (1, "note-live", SyncState::Synced),
            (2, "note-local", SyncState::Synced),
            (3, "note-deleted", SyncState::Synced),
            (4, "note-blocked", SyncState::Synced),
            (5, "note-conflict", SyncState::Conflict),
        ] {
            save_note(
                &connection,
                SaveLocalNoteInput {
                    encrypted_note: encrypted_note(vault_id, note_id, 1),
                    created_at_ms: 100,
                    updated_at_ms: 100 + index,
                    sync_state: Some(sync_state),
                    deleted_at_ms: None,
                },
            )
            .unwrap();
        }
        mark_note_local_only(
            &connection,
            vault_id,
            "note-local",
            Some(RemoteCloudState::RemovedFromSync),
            Some(200),
        )
        .unwrap();
        tombstone_note(
            &connection,
            &vault,
            vault_id,
            "note-deleted",
            210,
            [8u8; 24],
        )
        .unwrap();
        connection
            .execute(
                "UPDATE encrypted_notes SET sync_blocked_reason = 'quota_storage' WHERE vault_id = ?1 AND note_id = 'note-blocked'",
                params![vault_id],
            )
            .unwrap();

        for (index, folder_id, sync_state) in [
            (1, "folder-live", SyncState::Synced),
            (2, "folder-deleted", SyncState::Synced),
            (3, "folder-conflict", SyncState::Conflict),
        ] {
            save_folder(
                &connection,
                SaveLocalFolderInput {
                    encrypted_folder: encrypted_folder(vault_id, folder_id, 1),
                    created_at_ms: 100,
                    updated_at_ms: 130 + index,
                    sync_state: Some(sync_state),
                    deleted_at_ms: None,
                },
            )
            .unwrap();
        }
        tombstone_folder(
            &connection,
            &vault,
            vault_id,
            "folder-deleted",
            220,
            [9u8; 24],
        )
        .unwrap();

        queue_cloud_replica_rebuild(&connection, vault_id).unwrap();
        let pending = list_pending_sync(&connection, vault_id).unwrap();

        assert_eq!(pending.notes.len(), 1);
        assert_eq!(pending.notes[0].note_id, "note-live");
        assert_eq!(pending.notes[0].sync_state, SyncState::PendingUpsert);
        assert_eq!(pending.folders.len(), 1);
        assert_eq!(pending.folders[0].folder_id, "folder-live");
        assert_eq!(pending.folders[0].sync_state, SyncState::PendingUpsert);

        let data = load_vault(&connection, vault_id).unwrap();
        let local_note = data
            .notes
            .iter()
            .find(|note| note.note_id == "note-local")
            .unwrap();
        let blocked_note = data
            .notes
            .iter()
            .find(|note| note.note_id == "note-blocked")
            .unwrap();
        let conflict_note = data
            .notes
            .iter()
            .find(|note| note.note_id == "note-conflict")
            .unwrap();
        assert_eq!(local_note.cloud_sync_scope, CloudSyncScope::LocalOnly);
        assert_eq!(local_note.sync_state, SyncState::NotSynced);
        assert_eq!(blocked_note.sync_state, SyncState::Synced);
        assert_eq!(
            blocked_note.sync_blocked_reason,
            Some(SyncBlockedReason::QuotaStorage)
        );
        assert_eq!(conflict_note.sync_state, SyncState::Conflict);
    }

    #[test]
    fn stale_quota_block_does_not_override_local_only_note() {
        let connection = connection();
        set_preference(&connection, "vault-1", StorageMode::SyncEnabled, 100).unwrap();
        let saved = save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: encrypted_note("vault-1", "note-1", 1),
                created_at_ms: 100,
                updated_at_ms: 101,
                sync_state: None,
                deleted_at_ms: None,
            },
        )
        .unwrap();

        mark_note_local_only(
            &connection,
            "vault-1",
            "note-1",
            Some(RemoteCloudState::RemovedFromSync),
            Some(200),
        )
        .unwrap();
        let blocked = mark_note_sync_blocked(
            &connection,
            "vault-1",
            "note-1",
            Some(saved.revision_hash.as_str()),
            SyncBlockedReason::QuotaNoteCount,
        )
        .unwrap();

        assert_eq!(blocked.cloud_sync_scope, CloudSyncScope::LocalOnly);
        assert_eq!(blocked.sync_state, SyncState::NotSynced);
        assert_eq!(blocked.sync_blocked_reason, None);
    }

    #[test]
    fn quota_block_without_cloud_copy_becomes_local_only() {
        let connection = connection();
        set_preference(&connection, "vault-1", StorageMode::SyncEnabled, 100).unwrap();
        let saved = save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: encrypted_note("vault-1", "note-1", 1),
                created_at_ms: 100,
                updated_at_ms: 101,
                sync_state: None,
                deleted_at_ms: None,
            },
        )
        .unwrap();

        let blocked = mark_note_sync_blocked(
            &connection,
            "vault-1",
            "note-1",
            Some(saved.revision_hash.as_str()),
            SyncBlockedReason::QuotaNoteCount,
        )
        .unwrap();

        assert_eq!(blocked.cloud_sync_scope, CloudSyncScope::LocalOnly);
        assert_eq!(blocked.sync_state, SyncState::NotSynced);
        assert_eq!(blocked.sync_blocked_reason, None);
    }

    #[test]
    fn quota_block_with_cloud_copy_keeps_included_blocked_revision() {
        let connection = connection();
        set_preference(&connection, "vault-1", StorageMode::SyncEnabled, 100).unwrap();
        save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: encrypted_note("vault-1", "note-1", 1),
                created_at_ms: 100,
                updated_at_ms: 101,
                sync_state: Some(SyncState::Synced),
                deleted_at_ms: None,
            },
        )
        .unwrap();
        let local_edit = save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: encrypted_note("vault-1", "note-1", 2),
                created_at_ms: 100,
                updated_at_ms: 201,
                sync_state: None,
                deleted_at_ms: None,
            },
        )
        .unwrap();

        let blocked = mark_note_sync_blocked(
            &connection,
            "vault-1",
            "note-1",
            Some(local_edit.revision_hash.as_str()),
            SyncBlockedReason::QuotaStorage,
        )
        .unwrap();

        assert_eq!(blocked.cloud_sync_scope, CloudSyncScope::Included);
        assert_eq!(blocked.sync_state, SyncState::Synced);
        assert_eq!(
            blocked.sync_blocked_reason,
            Some(SyncBlockedReason::QuotaStorage)
        );
    }

    #[test]
    fn migration_repairs_local_only_blocked_records() {
        let connection = connection();
        set_preference(&connection, "vault-1", StorageMode::SyncEnabled, 100).unwrap();
        save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: encrypted_note("vault-1", "note-1", 1),
                created_at_ms: 100,
                updated_at_ms: 101,
                sync_state: None,
                deleted_at_ms: None,
            },
        )
        .unwrap();
        connection
            .execute(
                r#"
                UPDATE encrypted_notes
                SET cloud_sync_scope = 'local_only',
                    sync_state = 'pending_upsert',
                    sync_blocked_reason = 'quota_note_count'
                WHERE vault_id = 'vault-1' AND note_id = 'note-1'
                "#,
                [],
            )
            .unwrap();

        migrate(&connection).unwrap();
        let repaired = get_note(&connection, "vault-1", "note-1").unwrap().unwrap();

        assert_eq!(repaired.cloud_sync_scope, CloudSyncScope::LocalOnly);
        assert_eq!(repaired.sync_state, SyncState::NotSynced);
        assert_eq!(repaired.sync_blocked_reason, None);
    }

    #[test]
    fn migration_repairs_unsynced_included_quota_blocks() {
        let connection = connection();
        set_preference(&connection, "vault-1", StorageMode::SyncEnabled, 100).unwrap();
        save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: encrypted_note("vault-1", "note-1", 1),
                created_at_ms: 100,
                updated_at_ms: 101,
                sync_state: None,
                deleted_at_ms: None,
            },
        )
        .unwrap();
        connection
            .execute(
                r#"
                UPDATE encrypted_notes
                SET cloud_sync_scope = 'included',
                    sync_state = 'not_synced',
                    sync_blocked_reason = 'quota_note_count',
                    last_synced_revision_hash = NULL
                WHERE vault_id = 'vault-1' AND note_id = 'note-1'
                "#,
                [],
            )
            .unwrap();

        migrate(&connection).unwrap();
        let repaired = get_note(&connection, "vault-1", "note-1").unwrap().unwrap();

        assert_eq!(repaired.cloud_sync_scope, CloudSyncScope::LocalOnly);
        assert_eq!(repaired.sync_state, SyncState::NotSynced);
        assert_eq!(repaired.sync_blocked_reason, None);
    }

    #[test]
    fn saving_local_only_note_clears_stale_blocked_reason() {
        let connection = connection();
        set_preference(&connection, "vault-1", StorageMode::SyncEnabled, 100).unwrap();
        let saved = save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: encrypted_note("vault-1", "note-1", 1),
                created_at_ms: 100,
                updated_at_ms: 101,
                sync_state: None,
                deleted_at_ms: None,
            },
        )
        .unwrap();
        mark_note_sync_blocked(
            &connection,
            "vault-1",
            "note-1",
            Some(saved.revision_hash.as_str()),
            SyncBlockedReason::QuotaNoteCount,
        )
        .unwrap();
        mark_note_local_only(
            &connection,
            "vault-1",
            "note-1",
            Some(RemoteCloudState::RemovedFromSync),
            Some(200),
        )
        .unwrap();

        let saved_again = save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: encrypted_note("vault-1", "note-1", 2),
                created_at_ms: 100,
                updated_at_ms: 201,
                sync_state: None,
                deleted_at_ms: None,
            },
        )
        .unwrap();

        assert_eq!(saved_again.cloud_sync_scope, CloudSyncScope::LocalOnly);
        assert_eq!(saved_again.sync_state, SyncState::NotSynced);
        assert_eq!(saved_again.sync_blocked_reason, None);
    }

    #[test]
    fn stale_quota_block_does_not_override_newer_revision() {
        let connection = connection();
        set_preference(&connection, "vault-1", StorageMode::SyncEnabled, 100).unwrap();
        let first = save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: encrypted_note("vault-1", "note-1", 1),
                created_at_ms: 100,
                updated_at_ms: 101,
                sync_state: None,
                deleted_at_ms: None,
            },
        )
        .unwrap();
        let second = save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: encrypted_note("vault-1", "note-1", 2),
                created_at_ms: 100,
                updated_at_ms: 102,
                sync_state: None,
                deleted_at_ms: None,
            },
        )
        .unwrap();

        let blocked = mark_note_sync_blocked(
            &connection,
            "vault-1",
            "note-1",
            Some(first.revision_hash.as_str()),
            SyncBlockedReason::QuotaNoteCount,
        )
        .unwrap();

        assert_eq!(blocked.revision_hash, second.revision_hash);
        assert_eq!(blocked.cloud_sync_scope, CloudSyncScope::Included);
        assert_eq!(blocked.sync_state, SyncState::PendingUpsert);
        assert_eq!(blocked.sync_blocked_reason, None);
    }

    #[test]
    fn remote_merge_quarantines_pending_local_edit_when_remote_wins() {
        let vault = sample_vault();
        let vault_id = vault.vault_id();
        let connection = connection();
        set_preference(&connection, vault_id, StorageMode::SyncEnabled, 100).unwrap();
        let local_encrypted = real_encrypted_note(&vault, "note-1", 2, 9);
        let local = save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: local_encrypted,
                created_at_ms: 100,
                updated_at_ms: 200,
                sync_state: Some(SyncState::PendingUpsert),
                deleted_at_ms: None,
            },
        )
        .unwrap();
        let remote_encrypted = real_encrypted_note(&vault, "note-1", 2, 10);

        let summary = merge_remote_records(
            &connection,
            &vault,
            vault_id,
            &[remote_note_record(
                vault_id,
                "note-1",
                remote_encrypted.clone(),
                Some(RemoteCloudState::Live),
            )],
            &[],
        )
        .unwrap();

        let data = load_vault(&connection, vault_id).unwrap();
        assert_eq!(summary.conflicts, 1);
        assert_eq!(summary.updated, 1);
        assert_eq!(summary.rejected, 0);
        let canonical = data
            .notes
            .iter()
            .find(|note| note.note_id == "note-1")
            .unwrap();
        assert_eq!(canonical.encrypted_note.nonce, remote_encrypted.nonce);
        assert_eq!(canonical.sync_state, SyncState::Synced);
        let conflict = data
            .notes
            .iter()
            .find(|note| note.sync_state == SyncState::Conflict)
            .unwrap();
        assert_eq!(
            conflict.encrypted_note.ciphertext,
            local.encrypted_note.ciphertext
        );
        assert!(list_pending_sync(&connection, vault_id)
            .unwrap()
            .notes
            .is_empty());
    }

    #[test]
    fn remote_merge_rejects_mismatched_outer_note_id() {
        let vault = sample_vault();
        let vault_id = vault.vault_id();
        let connection = connection();
        set_preference(&connection, vault_id, StorageMode::SyncEnabled, 100).unwrap();
        let local = save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: real_encrypted_note(&vault, "note-1", 1, 9),
                created_at_ms: 100,
                updated_at_ms: 100,
                sync_state: Some(SyncState::Synced),
                deleted_at_ms: None,
            },
        )
        .unwrap();
        let remote_encrypted = real_encrypted_note(&vault, "note-2", 2, 10);

        let summary = merge_remote_records(
            &connection,
            &vault,
            vault_id,
            &[remote_note_record(
                vault_id,
                "note-1",
                remote_encrypted,
                Some(RemoteCloudState::Live),
            )],
            &[],
        )
        .unwrap();

        let stored = get_note(&connection, vault_id, "note-1").unwrap().unwrap();
        assert_eq!(summary.rejected, 1);
        assert_eq!(stored.revision_hash, local.revision_hash);
        assert_eq!(
            stored.encrypted_note.ciphertext,
            local.encrypted_note.ciphertext
        );
    }

    #[test]
    fn remote_merge_rejects_empty_note_tombstone() {
        let vault = sample_vault();
        let vault_id = vault.vault_id();
        let connection = connection();
        set_preference(&connection, vault_id, StorageMode::SyncEnabled, 100).unwrap();
        let local = save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: real_encrypted_note(&vault, "note-1", 1, 9),
                created_at_ms: 100,
                updated_at_ms: 100,
                sync_state: Some(SyncState::Synced),
                deleted_at_ms: None,
            },
        )
        .unwrap();
        let header = CiphertextHeader {
            content_version: 2,
            ..local.encrypted_note.header.clone()
        };

        let summary = merge_remote_records(
            &connection,
            &vault,
            vault_id,
            &[remote_note_record(
                vault_id,
                "note-1",
                EncryptedNote {
                    header,
                    nonce: "".to_string(),
                    ciphertext: "".to_string(),
                },
                Some(RemoteCloudState::Deleted),
            )],
            &[],
        )
        .unwrap();

        let stored = get_note(&connection, vault_id, "note-1").unwrap().unwrap();
        assert_eq!(summary.rejected, 1);
        assert_eq!(stored.deleted_at_ms, None);
        assert_eq!(stored.revision_hash, local.revision_hash);
    }

    #[test]
    fn remote_merge_accepts_authenticated_note_tombstone() {
        let vault = sample_vault();
        let vault_id = vault.vault_id();
        let connection = connection();
        set_preference(&connection, vault_id, StorageMode::SyncEnabled, 100).unwrap();
        save_note(
            &connection,
            SaveLocalNoteInput {
                encrypted_note: real_encrypted_note(&vault, "note-1", 1, 9),
                created_at_ms: 100,
                updated_at_ms: 100,
                sync_state: Some(SyncState::Synced),
                deleted_at_ms: None,
            },
        )
        .unwrap();
        let header = CiphertextHeader {
            algorithm: "XCHACHA20-POLY1305".to_string(),
            content_version: 2,
            key_version: 1,
            note_id: "note-1".to_string(),
            schema_version: 1,
            vault_id: vault_id.to_string(),
        };
        let tombstone = vault
            .encrypt_note_tombstone(header, 200, [11u8; 24])
            .unwrap();

        let summary = merge_remote_records(
            &connection,
            &vault,
            vault_id,
            &[remote_note_record(
                vault_id,
                "note-1",
                tombstone.clone(),
                Some(RemoteCloudState::Deleted),
            )],
            &[],
        )
        .unwrap();

        let stored = get_note(&connection, vault_id, "note-1").unwrap().unwrap();
        assert_eq!(summary.updated, 1);
        assert_eq!(summary.rejected, 0);
        assert_eq!(stored.deleted_at_ms, Some(200));
        assert_eq!(stored.encrypted_note.ciphertext, tombstone.ciphertext);
    }

    #[test]
    fn remote_merge_rejects_invalid_folder_ciphertext() {
        let vault = sample_vault();
        let vault_id = vault.vault_id();
        let connection = connection();
        set_preference(&connection, vault_id, StorageMode::SyncEnabled, 100).unwrap();
        let local = save_folder(
            &connection,
            SaveLocalFolderInput {
                encrypted_folder: real_encrypted_folder(&vault, "folder-1", 1, 4),
                created_at_ms: 100,
                updated_at_ms: 100,
                sync_state: Some(SyncState::Synced),
                deleted_at_ms: None,
            },
        )
        .unwrap();
        let mut remote = real_encrypted_folder(&vault, "folder-1", 2, 5);
        remote.ciphertext = "not-valid-authenticated-ciphertext".to_string();

        let summary = merge_remote_records(
            &connection,
            &vault,
            vault_id,
            &[],
            &[remote_folder_record(
                vault_id,
                "folder-1",
                remote,
                Some(RemoteCloudState::Live),
            )],
        )
        .unwrap();

        let stored = get_folder(&connection, vault_id, "folder-1")
            .unwrap()
            .unwrap();
        assert_eq!(summary.rejected, 1);
        assert_eq!(stored.revision_hash, local.revision_hash);
    }

    #[derive(Deserialize, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct TestArchivePayload {
        vault_id: String,
        export_check_hash: String,
        notes: Vec<LocalEncryptedNoteRecord>,
        folders: Vec<LocalEncryptedFolderRecord>,
    }

    #[test]
    fn local_first_unlock_encrypt_reload_export_import() {
        let vault = VaultMaterial::derive([7u8; 32], sample_context(), &[3u8; 16]).unwrap();
        let source_connection = connection();
        set_preference(
            &source_connection,
            vault.vault_id(),
            StorageMode::LocalOnly,
            100,
        )
        .unwrap();

        let folder = PlaintextFolderDocument {
            created_at_ms: 100,
            name: "My notes".to_string(),
            sort_order: 0,
            updated_at_ms: 101,
        };
        let encrypted_folder = vault
            .encrypt_folder_document(
                FolderCiphertextHeader {
                    algorithm: "XCHACHA20-POLY1305".to_string(),
                    content_version: 1,
                    folder_id: "my-notes".to_string(),
                    key_version: 1,
                    schema_version: 1,
                    vault_id: vault.vault_id().to_string(),
                },
                &folder,
                [4u8; 24],
            )
            .unwrap();
        save_folder(
            &source_connection,
            SaveLocalFolderInput {
                encrypted_folder,
                created_at_ms: folder.created_at_ms,
                updated_at_ms: folder.updated_at_ms,
                sync_state: None,
                deleted_at_ms: None,
            },
        )
        .unwrap();

        let note = PlaintextNoteDocument {
            body_markdown: "private body".to_string(),
            created_at_ms: 100,
            folder_id: "my-notes".to_string(),
            tags: vec!["bookmark".to_string()],
            title: "Private title".to_string(),
            updated_at_ms: 102,
        };
        let encrypted_note = vault
            .encrypt_note_document(
                CiphertextHeader {
                    algorithm: "XCHACHA20-POLY1305".to_string(),
                    content_version: 1,
                    key_version: 1,
                    note_id: "note-1".to_string(),
                    schema_version: 1,
                    vault_id: vault.vault_id().to_string(),
                },
                &note,
                [9u8; 24],
            )
            .unwrap();
        save_note(
            &source_connection,
            SaveLocalNoteInput {
                encrypted_note,
                created_at_ms: note.created_at_ms,
                updated_at_ms: note.updated_at_ms,
                sync_state: None,
                deleted_at_ms: None,
            },
        )
        .unwrap();

        let reloaded = load_vault(&source_connection, vault.vault_id()).unwrap();
        let decrypted = vault
            .decrypt_note_document(&reloaded.notes[0].encrypted_note)
            .unwrap();
        assert_eq!(decrypted.tags, vec!["bookmark"]);
        assert_eq!(decrypted.title, "Private title");

        let stored_text: String = source_connection
            .query_row(
                "SELECT group_concat(header_json || nonce || ciphertext, '') FROM encrypted_notes",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!stored_text.contains("Private title"));
        assert!(!stored_text.contains("private body"));
        assert!(!stored_text.contains("bookmark"));

        let archive = TestArchivePayload {
            vault_id: vault.vault_id().to_string(),
            export_check_hash: vault.export_check_hash(),
            notes: reloaded.notes,
            folders: reloaded.folders,
        };
        let archive_bytes = serde_json::to_vec(&archive).unwrap();
        let archive_nonce = [11u8; 24];
        let archive_nonce_b64 = {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
            URL_SAFE_NO_PAD.encode(archive_nonce)
        };
        let ciphertext = vault
            .encrypt_archive_bytes(&archive_bytes, archive_nonce)
            .unwrap();
        let decrypted_archive = vault
            .decrypt_archive_bytes(&archive_nonce_b64, &ciphertext)
            .unwrap();
        let archive_round_trip: TestArchivePayload =
            serde_json::from_slice(&decrypted_archive).unwrap();
        assert_eq!(
            archive_round_trip.export_check_hash,
            vault.export_check_hash()
        );

        let wrong_vault = VaultMaterial::derive([8u8; 32], sample_context(), &[3u8; 16]).unwrap();
        assert_ne!(
            archive_round_trip.export_check_hash,
            wrong_vault.export_check_hash()
        );

        let imported_connection = connection();
        set_preference(
            &imported_connection,
            vault.vault_id(),
            StorageMode::LocalOnly,
            200,
        )
        .unwrap();
        merge_import_records(
            &imported_connection,
            vault.vault_id(),
            &archive_round_trip.notes,
            &archive_round_trip.folders,
        )
        .unwrap();

        let imported = load_vault(&imported_connection, vault.vault_id()).unwrap();
        let imported_note = vault
            .decrypt_note_document(&imported.notes[0].encrypted_note)
            .unwrap();
        assert_eq!(imported_note.tags, vec!["bookmark"]);
    }
}
