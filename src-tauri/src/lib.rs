mod commands;
mod crypto_vault;
mod local_store;
mod sync_merge_policy;
mod vault_archive;
mod wallet_protocol;
mod wallet_response;
mod wallet_unlock_policy;

#[cfg(debug_assertions)]
use commands::unlock_encrypted_wallet_response;
use commands::{
    cancel_wallet_unlock_session, decrypt_folder, decrypt_note, enable_vault_sync, encrypt_folder,
    encrypt_note, export_markdown_note, export_vault_backup, get_cloud_auth_attestation,
    get_vault_preference, import_vault_backup, include_note_in_cloud_sync, list_pending_sync,
    load_local_vault, lock_vault, mark_cloud_copy_deleted, mark_note_local_only,
    mark_note_sync_blocked, mark_records_synced, merge_remote_records, open_external_link,
    poll_wallet_unlock_session, queue_cloud_replica_rebuild, save_local_folder, save_local_note,
    select_backup_for_import, set_vault_preference, sign_backend_challenge,
    start_wallet_unlock_session, tombstone_local_folder, tombstone_local_note, BackupImportState,
    VaultState,
};
use wallet_response::{PendingWalletUnlockState, ResponseEncryptionState};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(VaultState::default())
        .manage(BackupImportState::default())
        .manage(ResponseEncryptionState::default())
        .manage(PendingWalletUnlockState::default())
        .plugin(tauri_plugin_dialog::init())
        .plugin(
            tauri_plugin_opener::Builder::new()
                .open_js_links_on_click(false)
                .build(),
        )
        .invoke_handler(tauri::generate_handler![
            start_wallet_unlock_session,
            poll_wallet_unlock_session,
            cancel_wallet_unlock_session,
            #[cfg(debug_assertions)]
            unlock_encrypted_wallet_response,
            encrypt_note,
            decrypt_note,
            encrypt_folder,
            decrypt_folder,
            sign_backend_challenge,
            get_cloud_auth_attestation,
            lock_vault,
            get_vault_preference,
            set_vault_preference,
            enable_vault_sync,
            mark_cloud_copy_deleted,
            queue_cloud_replica_rebuild,
            load_local_vault,
            save_local_note,
            save_local_folder,
            tombstone_local_note,
            tombstone_local_folder,
            list_pending_sync,
            mark_records_synced,
            mark_note_sync_blocked,
            include_note_in_cloud_sync,
            mark_note_local_only,
            merge_remote_records,
            open_external_link,
            select_backup_for_import,
            export_vault_backup,
            export_markdown_note,
            import_vault_backup
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
