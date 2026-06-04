export type UnlockOutput = {
  vaultId: string;
  backendAuthAlgorithm: string;
  backendAuthKeyId: string;
  backendAuthPublicKey: string;
  backendAuthKeyVersion: number;
  exportCheckHash: string;
  walletSignerIdentityIAddress: string;
  walletSignerIdentityName?: string | null;
};

export type CiphertextHeader = {
  algorithm: "XCHACHA20-POLY1305";
  contentVersion: number;
  keyVersion: number;
  noteId: string;
  schemaVersion: number;
  vaultId: string;
};

export type PlaintextNoteDocument = {
  bodyMarkdown: string;
  createdAtMs: number;
  folderId: string;
  tags: string[];
  title: string;
  updatedAtMs: number;
};

export type FolderCiphertextHeader = {
  algorithm: "XCHACHA20-POLY1305";
  contentVersion: number;
  folderId: string;
  keyVersion: number;
  schemaVersion: number;
  vaultId: string;
};

export type PlaintextFolderDocument = {
  createdAtMs: number;
  name: string;
  sortOrder: number;
  updatedAtMs: number;
};

export type EncryptedNote = {
  header: CiphertextHeader;
  nonce: string;
  ciphertext: string;
};

export type EncryptedFolder = {
  header: FolderCiphertextHeader;
  nonce: string;
  ciphertext: string;
};

export type NoteDraft = {
  id: string;
  title: string;
  body: string;
  bookmarked: boolean;
  folderId: string;
  createdAtMs: number;
  updatedAtMs: number;
  cloudSyncScope?: CloudSyncScope;
  syncBlockedReason?: SyncBlockedReason | null;
  syncState?: SyncState;
  lastSyncedRevisionHash?: string | null;
  revisionHash?: string;
};

export type FolderDraft = {
  id: string;
  name: string;
  createdAtMs: number;
  sortOrder: number;
  updatedAtMs: number;
};

export type ResizablePanel = "source";
export type NoteSortMode = "updated-desc" | "updated-asc" | "title-asc";
export type SourceMode = "folders" | "search" | "bookmarks";
export type AppearanceMode = "system" | "light" | "dark";
export type VaultSettingsSectionId = "general" | "cloud" | "backup";

export type NoteTab = {
  id: string;
  noteId: string | null;
};

export type FolderContextMenu = {
  folderId: string;
  x: number;
  y: number;
};

export type UnlockInput = {
  walletSignerIdentityIAddress: string;
  walletSignerIdentityName?: string | null;
  appIdentityIAddress: string;
  chain: string;
  derivationNumber: number;
  keyVersion: number;
  appEncryptionRequestId: string;
};

export type WalletUnlockSession = {
  deeplink: string;
  expiresAt: number;
  sessionId: string;
};

export type WalletUnlockPollResponse =
  | { status: "pending" }
  | {
      status: "unlocked";
      unlockContext: UnlockInput;
      vault: UnlockOutput;
    };

export type CloudChallenge = {
  appEncryptionRequestId: string;
  appIdentityIAddress: string;
  backendAuthAlgorithm: string;
  backendAuthKeyId: string;
  backendAuthPublicKey: string;
  backendAuthKeyVersion: number;
  challenge: string;
  derivationNumber: number;
  expiresAtMs: number;
  sessionId: string;
  vaultId: string;
  walletSignerIdentityIAddress: string;
};

export type CloudSession = {
  authStrength?: "backend_key" | "signer_attested";
  expiresAtMs: number;
  sessionToken: string;
  vaultId: string;
};

export type CloudAuthAttestation =
  | {
      status: "ready";
      cloudAttestationExpiresAt: number;
      cloudAttestationId: string;
      cloudAttestationSecret: string;
      requestHashHex: string;
      signerSessionId: string;
      unlockContext: UnlockInput;
      vault: UnlockOutput;
    }
  | {
      status: "wallet_unlock_required";
      reason: string;
    };

export type StorageMode = "local_only" | "sync_enabled" | "sync_paused";
export type SyncState = "not_synced" | "pending_upsert" | "pending_delete" | "synced" | "conflict";
export type CloudSyncScope = "included" | "local_only";
export type SyncBlockedReason = "quota_note_count" | "quota_storage" | "record_too_large" | "session_expired" | "network";
export type RemoteCloudState = "live" | "deleted" | "removed_from_sync";

export type VaultPreference = {
  vaultId: string;
  storageMode: StorageMode;
  cloudCopyDeletedAtMs?: number | null;
  createdAtMs: number;
  updatedAtMs: number;
};

export type SyncMetadata = {
  lastPullAtMs?: number | null;
  lastPushAtMs?: number | null;
  restoreMissingCloudRecords: boolean;
};

export type LocalEncryptedNoteRecord = {
  noteId: string;
  encryptedNote: EncryptedNote;
  contentVersion: number;
  createdAtMs: number;
  updatedAtMs: number;
  deletedAtMs?: number | null;
  revisionHash: string;
  syncState: SyncState;
  lastSyncedRevisionHash?: string | null;
  cloudSyncScope: CloudSyncScope;
  syncBlockedReason?: SyncBlockedReason | null;
  remoteCloudState?: RemoteCloudState | null;
  remoteRemovedFromSyncAtMs?: number | null;
};

export type LocalEncryptedFolderRecord = {
  folderId: string;
  encryptedFolder: EncryptedFolder;
  contentVersion: number;
  createdAtMs: number;
  updatedAtMs: number;
  deletedAtMs?: number | null;
  revisionHash: string;
  syncState: SyncState;
  lastSyncedRevisionHash?: string | null;
};

export type LocalVaultData = {
  preference?: VaultPreference | null;
  syncMetadata?: SyncMetadata | null;
  notes: LocalEncryptedNoteRecord[];
  folders: LocalEncryptedFolderRecord[];
};

export type SyncedRecordRef = {
  kind: "note" | "folder";
  recordId: string;
  revisionHash: string;
};

export type MergeSummary = {
  inserted: number;
  updated: number;
  unchanged: number;
  conflicts: number;
  keptLocal: number;
  rejected: number;
};

export type BackupInspection = {
  format: string;
  formatVersion: number;
  createdAtMs: number;
  encrypted: boolean;
};

export type CloudNoteRow = {
  vaultId: string;
  noteId: string;
  header: CiphertextHeader;
  nonce: string;
  ciphertext: string;
  contentVersion: number;
  accountedStorageBytes?: number;
  cloudState?: RemoteCloudState;
  retentionExpiresAtBucketMs?: number;
  serverCreatedAtBucketMs: number;
  serverUpdatedAtBucketMs: number;
  serverDeletedAtBucketMs?: number;
  serverRemovedFromSyncAtBucketMs?: number;
};

export type CloudFolderRow = {
  vaultId: string;
  folderId: string;
  header: FolderCiphertextHeader;
  nonce: string;
  ciphertext: string;
  contentVersion: number;
  accountedStorageBytes?: number;
  cloudState?: RemoteCloudState;
  retentionExpiresAtBucketMs?: number;
  serverCreatedAtBucketMs: number;
  serverUpdatedAtBucketMs: number;
  serverDeletedAtBucketMs?: number;
  serverRemovedFromSyncAtBucketMs?: number;
};

export type CloudUsage = {
  vaultId: string;
  planKind: "free";
  maxSyncedNotes: number;
  maxStorageBytes: number;
  liveSyncedNoteCount: number;
  liveSyncedFolderCount: number;
  liveStorageBytes: number;
  updatedAtMs: number;
};
