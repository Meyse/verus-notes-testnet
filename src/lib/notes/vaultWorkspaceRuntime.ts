import { invoke } from "@tauri-apps/api/core";
import { ConvexHttpClient } from "convex/browser";
import {
  createCloudReplicaDiscoveryProof,
  createCloudSession as createCloudAuthSession,
  createTauriConvexCloudAuthDependencies
} from "./cloudAuthSession";
import { DEFAULT_FOLDER_ID, DEFAULT_FOLDER_NAME } from "./constants";
import { resolveFolderId as resolveFolderIdFromFolders, sanitizeFolderName, sortFolders } from "./helpers";
import type {
  CiphertextHeader,
  BackupInspection,
  CloudFolderRow,
  CloudNoteRow,
  CloudSession,
  CloudUsage,
  EncryptedFolder,
  EncryptedNote,
  FolderCiphertextHeader,
  FolderDraft,
  LocalEncryptedFolderRecord,
  LocalEncryptedNoteRecord,
  LocalVaultData,
  MergeSummary,
  NoteDraft,
  PlaintextFolderDocument,
  PlaintextNoteDocument,
  StorageMode,
  SyncBlockedReason,
  SyncedRecordRef,
  UnlockInput,
  UnlockOutput,
  VaultPreference
} from "./types";
import { api } from "../../../convex/_generated/api";

const CIPHERTEXT_SCHEMA_VERSION = 2;

export type CloudConnectionState =
  | "unconfigured"
  | "local_only"
  | "connecting"
  | "syncing"
  | "connected"
  | "error"
  | "deleted";

export type VaultWorkspaceData = {
  preference: VaultPreference | null;
  folders: FolderDraft[];
  encryptedFolders: Record<string, EncryptedFolder>;
  notes: NoteDraft[];
  encryptedNotes: Record<string, EncryptedNote>;
};

export type RuntimePatch = {
  cloudConnectionState?: CloudConnectionState;
  cloudReplica?: CloudReplicaSummary;
  cloudSession?: CloudSession | null;
  cloudStatus?: string;
  cloudUsage?: CloudUsage | null;
  data?: VaultWorkspaceData;
  status?: string;
  storagePreference?: VaultPreference | null;
};

export type CloudReplicaSummary = {
  checked: boolean;
  liveFolderCount: number;
  liveNoteCount: number;
};

export type CloudReplicaDiscovery =
  | {
      liveFolderCount: number;
      liveNoteCount: number;
      status: "found";
    }
  | {
      liveFolderCount: number;
      liveNoteCount: number;
      status: "empty";
    }
  | {
      error: string;
      liveFolderCount: 0;
      liveNoteCount: 0;
      status: "error";
    };

type RuntimeContext = {
  cloudSession: CloudSession | null;
  storagePreference: VaultPreference | null;
  unlockInput: UnlockInput;
  vault: UnlockOutput;
};

type RuntimeOptions = {
  convexUrl?: string;
};

type PaginatedRows<T> = {
  continueCursor: string;
  isDone: boolean;
  page: T[];
};

const CLOUD_PAGE_SIZE = 100;
const FREE_SYNC_MAX_NOTES = 20;
const FREE_SYNC_MAX_STORAGE_BYTES = 2 * 1024 * 1024;

export function remoteMergeWarningPatch(mergeSummary: Pick<MergeSummary, "rejected">): Pick<RuntimePatch, "cloudStatus" | "status"> | null {
  if (mergeSummary.rejected <= 0) return null;
  return {
    cloudStatus: "Some cloud records could not be verified",
    status: "Cloud sync needs review"
  };
}

type SaveFolderInput = {
  context: RuntimeContext;
  encryptedFolders: Record<string, EncryptedFolder>;
  folder: FolderDraft;
};

type SaveNoteInput = {
  context: RuntimeContext;
  encryptedNotes: Record<string, EncryptedNote>;
  folders: FolderDraft[];
  note: NoteDraft;
};

type OpenWorkspaceInput = {
  cloudSession?: CloudSession | null;
  preference: VaultPreference;
  unlockInput: UnlockInput;
  vault: UnlockOutput;
};

type CloudConnectInput = RuntimeContext & {
  syncAfterConnect?: boolean;
};

export function createVaultWorkspaceRuntime(options: RuntimeOptions) {
  const convexUrl = options.convexUrl;
  let convexClient: ConvexHttpClient | null = null;
  let syncInFlight = false;

  async function getVaultPreference(vaultId: string) {
    return await invoke<VaultPreference | null>("get_vault_preference", { vaultId });
  }

  async function setStorageModePreference(vaultId: string, storageMode: StorageMode) {
    if (storageMode === "sync_enabled") {
      return await invoke<VaultPreference>("enable_vault_sync", {
        input: { vaultId }
      });
    }

    return await invoke<VaultPreference>("set_vault_preference", {
      input: {
        storageMode,
        vaultId
      }
    });
  }

  async function openWorkspace(input: OpenWorkspaceInput): Promise<RuntimePatch & { data: VaultWorkspaceData }> {
    let data = await loadLocalVault(input.vault.vaultId, input.preference);
    let preference = data.preference ?? input.preference;
    let cloudReplica: CloudReplicaSummary | undefined;
    let cloudSession: CloudSession | null = input.cloudSession ?? null;
    let cloudStatus = convexUrl ? "Cloud disconnected" : "Cloud not configured";
    let cloudConnectionState = getInitialCloudConnectionState(convexUrl, preference);
    let status = getStorageStatusLabel({
      cloudBusy: false,
      cloudConnectionState,
      cloudSession,
      convexUrl,
      storagePreference: preference
    });

    if (preference.storageMode === "sync_enabled") {
      const cloudPatch = await connectCloud({
        cloudSession,
        storagePreference: preference,
        syncAfterConnect: true,
        unlockInput: input.unlockInput,
        vault: input.vault
      });
      cloudSession = cloudPatch.cloudSession ?? null;
      cloudStatus = cloudPatch.cloudStatus ?? cloudStatus;
      cloudConnectionState = cloudPatch.cloudConnectionState ?? cloudConnectionState;
      cloudReplica = cloudPatch.cloudReplica;
      data = cloudPatch.data ?? (await loadLocalVault(input.vault.vaultId, preference));
      preference = cloudPatch.storagePreference ?? data.preference ?? preference;
      status = cloudPatch.status ?? getStorageStatusLabel({
        cloudBusy: false,
        cloudConnectionState,
        cloudSession,
        convexUrl,
        storagePreference: preference
      });
    }

    if (shouldEnsureDefaultFolderAfterOpen(preference, cloudConnectionState, cloudReplica, data)) {
      data = await ensureDefaultFolder(input.vault, data);
    }

    return {
      cloudConnectionState,
      cloudReplica,
      cloudSession,
      cloudStatus,
      data,
      status,
      storagePreference: preference
    };
  }

  async function loadLocalVault(vaultId: string, fallbackPreference: VaultPreference | null = null): Promise<VaultWorkspaceData> {
    const localVault = await invoke<LocalVaultData>("load_local_vault", { vaultId });
    const nextEncryptedFolders: Record<string, EncryptedFolder> = {};
    const nextFolders: FolderDraft[] = [];

    for (const record of localVault.folders) {
      if (isDeletedRecord(record)) continue;

      const document = await invoke<PlaintextFolderDocument>("decrypt_folder", {
        encrypted: record.encryptedFolder
      });
      nextEncryptedFolders[record.folderId] = record.encryptedFolder;
      nextFolders.push({
        createdAtMs: document.createdAtMs,
        id: record.folderId,
        name: sanitizeFolderName(document.name) || "Untitled folder",
        sortOrder: document.sortOrder,
        updatedAtMs: document.updatedAtMs
      });
    }

    const sortedFolders = sortFolders(nextFolders);
    const nextEncryptedNotes: Record<string, EncryptedNote> = {};
    const nextNotes: NoteDraft[] = [];

    for (const record of localVault.notes) {
      if (isDeletedRecord(record)) continue;

      const document = await invoke<PlaintextNoteDocument>("decrypt_note", {
        encrypted: record.encryptedNote
      });
      nextEncryptedNotes[record.noteId] = record.encryptedNote;
      nextNotes.push({
        bookmarked: document.tags.includes("bookmark"),
        body: document.bodyMarkdown,
        cloudSyncScope: record.cloudSyncScope,
        createdAtMs: document.createdAtMs,
        folderId: resolveFolderIdFromFolders(sortedFolders, document.folderId),
        id: record.noteId,
        lastSyncedRevisionHash: record.lastSyncedRevisionHash ?? null,
        revisionHash: record.revisionHash,
        syncBlockedReason: record.syncBlockedReason ?? null,
        syncState: record.syncState,
        title: document.title,
        updatedAtMs: document.updatedAtMs
      });
    }

    return {
      encryptedFolders: nextEncryptedFolders,
      encryptedNotes: nextEncryptedNotes,
      folders: sortedFolders,
      notes: nextNotes.sort((left, right) => right.updatedAtMs - left.updatedAtMs),
      preference: localVault.preference ?? fallbackPreference
    };
  }

  async function saveFolder(input: SaveFolderInput): Promise<RuntimePatch & { encryptedFolder: EncryptedFolder }> {
    const saved = await saveFolderLocally(input.context.vault, input.folder, input.encryptedFolders);
    const syncPatch = await pushPendingSync(input.context);

    return {
      ...syncPatch,
      encryptedFolder: saved.encryptedFolder,
      status: syncPatch.status ?? "Encrypted locally"
    };
  }

  async function deleteFolder(context: RuntimeContext, folderId: string): Promise<RuntimePatch> {
    await invoke<LocalEncryptedFolderRecord>("tombstone_local_folder", {
      folderId,
      vaultId: context.vault.vaultId
    });
    const syncPatch = await pushPendingSync(context);
    return {
      ...syncPatch,
      status: syncPatch.status ?? "Folder deleted"
    };
  }

  async function saveNoteLocally(input: SaveNoteInput): Promise<{ encryptedNote: EncryptedNote; note: NoteDraft; record: LocalEncryptedNoteRecord }> {
    const note = {
      ...input.note,
      folderId: resolveFolderIdFromFolders(input.folders, input.note.folderId)
    };
    const contentVersion = input.encryptedNotes[note.id]?.header.contentVersion
      ? input.encryptedNotes[note.id].header.contentVersion + 1
      : 1;
    const header: CiphertextHeader = {
      algorithm: "XCHACHA20-POLY1305",
      contentVersion,
      keyVersion: 1,
      noteId: note.id,
      schemaVersion: CIPHERTEXT_SCHEMA_VERSION,
      vaultId: input.context.vault.vaultId
    };
    const document: PlaintextNoteDocument = {
      bodyMarkdown: note.body,
      createdAtMs: note.createdAtMs,
      folderId: note.folderId,
      tags: note.bookmarked ? ["bookmark"] : [],
      title: note.title,
      updatedAtMs: note.updatedAtMs
    };
    const encryptedNote = await invoke<EncryptedNote>("encrypt_note", { input: { document, header } });
    const record = await invoke<LocalEncryptedNoteRecord>("save_local_note", {
      input: {
        createdAtMs: note.createdAtMs,
        deletedAtMs: null,
        encryptedNote,
        syncState: null,
        updatedAtMs: note.updatedAtMs
      }
    });

    return { encryptedNote, note: noteWithSyncMetadata(note, record), record };
  }

  async function saveNote(input: SaveNoteInput): Promise<RuntimePatch & { encryptedNote: EncryptedNote; note: NoteDraft; record: LocalEncryptedNoteRecord }> {
    const saved = await saveNoteLocally(input);
    const syncPatch = await pushPendingSync(input.context);

    return {
      ...syncPatch,
      encryptedNote: saved.encryptedNote,
      note: saved.note,
      record: saved.record,
      status: syncPatch.status ?? "Encrypted locally"
    };
  }

  async function deleteNote(context: RuntimeContext, noteId: string, hasEncryptedRecord: boolean): Promise<RuntimePatch> {
    if (hasEncryptedRecord) {
      await invoke<LocalEncryptedNoteRecord>("tombstone_local_note", {
        noteId,
        vaultId: context.vault.vaultId
      });
    }
    const syncPatch = await pushPendingSync(context);
    return {
      ...syncPatch,
      status: syncPatch.status ?? "Note deleted"
    };
  }

  async function includeNoteInCloudSync(context: RuntimeContext, noteId: string): Promise<RuntimePatch> {
    await invoke<LocalEncryptedNoteRecord>("include_note_in_cloud_sync", {
      input: {
        noteId,
        vaultId: context.vault.vaultId
      }
    });
    const data = await loadLocalVault(context.vault.vaultId, context.storagePreference);
    return {
      data,
      status: "Sync queued"
    };
  }

  async function removeNoteFromCloudSync(context: RuntimeContext, noteId: string): Promise<RuntimePatch> {
    const localVault = await invoke<LocalVaultData>("load_local_vault", { vaultId: context.vault.vaultId });
    const record = localVault.notes.find((candidate) => candidate.noteId === noteId);
    if (!record) return {};

    let cloudSession = context.cloudSession;
    if (context.storagePreference?.storageMode === "sync_enabled") {
      const client = getConvexClient();
      const removedAtMs = Date.now();
      const result = await runWithRenewedCloudSession(context, cloudSession, async (renewedSession) => {
        await client.mutation(api.notes.removeFromCloudSync, {
          contentVersion: record.contentVersion,
          noteId,
          removedAtMs,
          sessionToken: renewedSession.sessionToken
        });
      });
      cloudSession = result.cloudSession;
    }

    await invoke<LocalEncryptedNoteRecord>("mark_note_local_only", {
      input: {
        noteId,
        vaultId: context.vault.vaultId
      }
    });
    const data = await loadLocalVault(context.vault.vaultId, context.storagePreference);
    const cloudUsage = cloudSession
      ? await getCloudUsageWithLocalFallback(getConvexClient(), cloudSession.sessionToken, context.vault.vaultId, context.storagePreference, data)
      : null;
    return {
      cloudConnectionState: cloudSession ? "connected" : undefined,
      cloudSession: cloudSession ?? undefined,
      cloudStatus: cloudSession ? "Cloud synced" : undefined,
      cloudUsage,
      data,
      status: "This device only"
    };
  }

  async function connectCloud(input: CloudConnectInput): Promise<RuntimePatch> {
    if (!convexUrl) {
      return {
        cloudConnectionState: "unconfigured",
        cloudStatus: "Cloud not configured"
      };
    }

    try {
      const client = getConvexClient();
      const cloudSession = input.cloudSession ?? await createCloudSession(input);

      const connectedPatch: RuntimePatch = {
        cloudConnectionState: "connected",
        cloudSession,
        cloudUsage: await getCloudUsageWithLocalFallback(client, cloudSession.sessionToken, input.vault.vaultId, input.storagePreference),
        cloudStatus: "Cloud connected"
      };

      if (!input.syncAfterConnect) return connectedPatch;

      const syncPatch = await syncWithCloudReplica({
        cloudSession,
        storagePreference: input.storagePreference,
        unlockInput: input.unlockInput,
        vault: input.vault
      });
      return {
        ...connectedPatch,
        ...syncPatch,
        cloudSession: syncPatch.cloudSession ?? cloudSession
      };
    } catch (error) {
      return {
        cloudConnectionState: "error",
        cloudSession: null,
        cloudStatus: cloudSyncErrorMessage(error)
      };
    }
  }

  async function createCloudSession(context: Pick<RuntimeContext, "unlockInput" | "vault">): Promise<CloudSession> {
    const client = getConvexClient();
    return await createCloudAuthSession(createTauriConvexCloudAuthDependencies(client), context);
  }

  async function runWithRenewedCloudSession<T>(
    context: Pick<RuntimeContext, "unlockInput" | "vault">,
    initialSession: CloudSession | null | undefined,
    operation: (cloudSession: CloudSession) => Promise<T>,
  ): Promise<{ cloudSession: CloudSession; result: T }> {
    let cloudSession = initialSession ?? await createCloudSession(context);
    let retriedAfterAuth = false;

    while (true) {
      try {
        return {
          cloudSession,
          result: await operation(cloudSession),
        };
      } catch (error) {
        if (retriedAfterAuth || !isSessionExpiredError(error)) throw error;
        cloudSession = await createCloudSession(context);
        retriedAfterAuth = true;
      }
    }
  }

  async function detectCloudReplica(vault: UnlockOutput, unlockInput: UnlockInput): Promise<CloudReplicaDiscovery> {
    if (!convexUrl) {
      return {
        error: "Cloud sync is not configured",
        liveFolderCount: 0,
        liveNoteCount: 0,
        status: "error"
      };
    }

    try {
      const client = getConvexClient();
      const proof = await createCloudReplicaDiscoveryProof(
        createTauriConvexCloudAuthDependencies(client),
        { unlockInput, vault }
      );
      const summary = await client.query(api.auth.discoverCloudReplica, proof) as {
        liveFolderCount: number;
        liveNoteCount: number;
        status: "empty" | "found";
      };

      return {
        liveFolderCount: summary.liveFolderCount,
        liveNoteCount: summary.liveNoteCount,
        status: summary.status
      };
    } catch (error) {
      return {
        error: cloudSyncErrorMessage(error),
        liveFolderCount: 0,
        liveNoteCount: 0,
        status: "error"
      };
    }
  }

  async function enableFoundCloudSync(vault: UnlockOutput, unlockInput: UnlockInput): Promise<RuntimePatch> {
    const cloudSession = await createCloudSession({ unlockInput, vault });
    const storagePreference = await invoke<VaultPreference>("enable_vault_sync", {
      input: {
        vaultId: vault.vaultId
      }
    });

    return await openWorkspace({
      cloudSession,
      preference: storagePreference,
      unlockInput,
      vault
    });
  }

  async function repairCloudSync(context: RuntimeContext): Promise<RuntimePatch> {
    if (!convexUrl || context.storagePreference?.storageMode !== "sync_enabled") {
      return {
        cloudConnectionState: convexUrl ? "local_only" : "unconfigured",
        cloudStatus: convexUrl ? "Encrypted sync is not enabled" : "Cloud not configured"
      };
    }

    const client = getConvexClient();
    let reconciled = await runWithRenewedCloudSession(
      context,
      context.cloudSession,
      (cloudSession) => reconcileCloudUsage(client, cloudSession.sessionToken)
    );
    let cloudSession = reconciled.cloudSession;

    await invoke<LocalVaultData>("queue_cloud_replica_rebuild", { vaultId: context.vault.vaultId });

    const pushPatch = await pushPendingSync({
      ...context,
      cloudSession
    });
    cloudSession = pushPatch.cloudSession ?? cloudSession;

    reconciled = await runWithRenewedCloudSession(
      context,
      cloudSession,
      (session) => reconcileCloudUsage(client, session.sessionToken)
    );
    cloudSession = reconciled.cloudSession;
    const cloudUsage = reconciled.result;
    const data = await loadLocalVault(context.vault.vaultId, context.storagePreference);

    return {
      ...pushPatch,
      cloudConnectionState: "connected",
      cloudSession,
      cloudStatus: pushPatch.cloudStatus ?? "Cloud sync repaired",
      cloudUsage,
      data,
      status: pushPatch.status ?? "Cloud sync repaired",
      storagePreference: data.preference ?? context.storagePreference
    };
  }

  async function syncWithCloudReplica(context: RuntimeContext): Promise<RuntimePatch> {
    if (!context.cloudSession || syncInFlight) return {};

    syncInFlight = true;
    let renewedSession: CloudSession | null = null;
    let workingContext = { ...context };

    try {
      const client = getConvexClient();
      let pushPatch: RuntimePatch = {};
      let cloudReplica: CloudReplicaSummary = { checked: false, liveFolderCount: 0, liveNoteCount: 0 };
      let retriedAfterAuth = false;

      while (true) {
        try {
          const sessionToken = workingContext.cloudSession?.sessionToken;
          if (!sessionToken) throw new Error("Cloud session unavailable");
          const [folderRows, noteRows] = await Promise.all([
            listAllCloudFolders(client, sessionToken),
            listAllCloudNotes(client, sessionToken)
          ]);
          cloudReplica = summarizeCloudReplicaRows(folderRows, noteRows);
          const localVaultBeforeMerge = await invoke<LocalVaultData>("load_local_vault", {
            vaultId: context.vault.vaultId
          });
          const mergeSummary = await invoke<MergeSummary>("merge_remote_records", {
            input: {
              folders: folderRows.map((row) => ({
                ciphertext: row.ciphertext,
                cloudState: row.cloudState ?? null,
                contentVersion: row.contentVersion,
                folderId: row.folderId,
                header: row.header,
                nonce: row.nonce,
                retentionExpiresAtBucketMs: row.retentionExpiresAtBucketMs ?? null,
                serverCreatedAtBucketMs: row.serverCreatedAtBucketMs,
                serverDeletedAtBucketMs: row.serverDeletedAtBucketMs ?? null,
                serverRemovedFromSyncAtBucketMs: row.serverRemovedFromSyncAtBucketMs ?? null,
                serverUpdatedAtBucketMs: row.serverUpdatedAtBucketMs,
                vaultId: row.vaultId,
              })),
              notes: noteRows.map((row) => ({
                ciphertext: row.ciphertext,
                cloudState: row.cloudState ?? null,
                contentVersion: row.contentVersion,
                header: row.header,
                nonce: row.nonce,
                noteId: row.noteId,
                retentionExpiresAtBucketMs: row.retentionExpiresAtBucketMs ?? null,
                serverCreatedAtBucketMs: row.serverCreatedAtBucketMs,
                serverDeletedAtBucketMs: row.serverDeletedAtBucketMs ?? null,
                serverRemovedFromSyncAtBucketMs: row.serverRemovedFromSyncAtBucketMs ?? null,
                serverUpdatedAtBucketMs: row.serverUpdatedAtBucketMs,
                vaultId: row.vaultId,
              })),
              vaultId: context.vault.vaultId
            }
          });
          const restored = await restoreMissingCloudRecords(
            client,
            sessionToken,
            context.vault.vaultId,
            folderRows,
            noteRows,
            localVaultBeforeMerge.syncMetadata?.restoreMissingCloudRecords ?? true
          );
          pushPatch = await pushPendingSync(workingContext, { skipBusyGuard: true });
          const warningPatch = remoteMergeWarningPatch(mergeSummary);
          if (warningPatch) {
            pushPatch = {
              ...pushPatch,
              ...warningPatch
            };
          } else if (restored.blockedCount > 0 && !pushPatch.cloudStatus) {
            pushPatch = {
              ...pushPatch,
              cloudStatus: "Some notes stayed on this device",
              status: "Saved on this device"
            };
          } else if (restored.syncedCount > 0 && !pushPatch.cloudStatus) {
            pushPatch = {
              ...pushPatch,
              cloudStatus: "Cloud synced",
              status: "Encrypted and synced"
            };
          }
          break;
        } catch (error) {
          if (retriedAfterAuth || !isSessionExpiredError(error)) throw error;
          renewedSession = await createCloudSession(workingContext);
          workingContext = { ...workingContext, cloudSession: renewedSession };
          retriedAfterAuth = true;
        }
      }

      const sessionToken = workingContext.cloudSession?.sessionToken;
      const data = await loadLocalVault(context.vault.vaultId, context.storagePreference);
      const cloudUsage = sessionToken
        ? await getCloudUsageWithLocalFallback(client, sessionToken, context.vault.vaultId, context.storagePreference, data)
        : localCloudUsageEstimate(context.vault.vaultId, data);

      return {
        cloudConnectionState: "connected",
        cloudReplica,
        cloudSession: renewedSession ?? context.cloudSession,
        cloudStatus: pushPatch.cloudStatus ?? "Cloud synced",
        cloudUsage,
        data,
        status: pushPatch.status ?? "Encrypted and synced",
        storagePreference: data.preference ?? context.storagePreference
      };
    } catch (error) {
      return {
        cloudConnectionState: "error",
        cloudSession: renewedSession ?? workingContext.cloudSession ?? context.cloudSession,
        cloudStatus: cloudSyncErrorMessage(error)
      };
    } finally {
      syncInFlight = false;
    }
  }

  async function pushPendingSync(context: RuntimeContext, options: { skipBusyGuard?: boolean } = {}): Promise<RuntimePatch> {
    if (!context.cloudSession || context.storagePreference?.storageMode !== "sync_enabled") return {};
    if (syncInFlight && !options.skipBusyGuard) return {};

    let workingContext = { ...context };
    let renewedSession: CloudSession | null = null;
    let retriedAfterAuth = false;

    try {
      while (true) {
        try {
          const pending = await invoke<LocalVaultData>("list_pending_sync", { vaultId: context.vault.vaultId });
          const sessionToken = workingContext.cloudSession?.sessionToken;
          if (!sessionToken) throw new Error("Cloud session unavailable");
          const vaultId = context.vault.vaultId;
          let blockedCount = 0;
          let syncedCount = 0;

          const client = getConvexClient();

          for (const folder of pending.folders) {
            await pushPendingFolder(client, vaultId, sessionToken, folder);
            syncedCount += 1;
          }

          for (const note of pending.notes) {
            const result = await pushPendingNote(client, vaultId, sessionToken, note);
            if (result === "blocked") {
              blockedCount += 1;
            } else {
              syncedCount += 1;
            }
          }

          if (syncedCount === 0 && blockedCount === 0) {
            const cloudUsage = await getCloudUsageWithLocalFallback(client, sessionToken, context.vault.vaultId, context.storagePreference);
            return {
              cloudConnectionState: "connected",
              cloudSession: renewedSession ?? context.cloudSession,
              cloudStatus: "Cloud synced",
              cloudUsage,
              status: "Cloud synced"
            };
          }

          const data = await loadLocalVault(context.vault.vaultId, context.storagePreference);
          const cloudUsage = await getCloudUsageWithLocalFallback(client, sessionToken, context.vault.vaultId, context.storagePreference, data);

          return {
            cloudConnectionState: "connected",
            cloudSession: renewedSession ?? context.cloudSession,
            cloudStatus: blockedCount > 0 ? "Some notes stayed on this device" : "Cloud synced",
            cloudUsage,
            data,
            status: blockedCount > 0 ? "Saved on this device" : "Encrypted and synced"
          };
        } catch (error) {
          if (retriedAfterAuth || !isSessionExpiredError(error)) throw error;
          renewedSession = await createCloudSession(workingContext);
          workingContext = { ...workingContext, cloudSession: renewedSession };
          retriedAfterAuth = true;
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!options.skipBusyGuard && message.toLowerCase().includes("stale")) {
        return await syncWithCloudReplica(context);
      }
      throw new Error(cloudSyncErrorMessage(error));
    }
  }

  async function enableEncryptedSync(
    vault: UnlockOutput,
    unlockInput: UnlockInput,
    includedNoteIds?: string[],
    existingCloudSession?: CloudSession | null
  ): Promise<RuntimePatch> {
    const client = getConvexClient();
    const localVault = await invoke<LocalVaultData>("load_local_vault", { vaultId: vault.vaultId });
    const sessionResult = await runWithRenewedCloudSession(
      { unlockInput, vault },
      existingCloudSession,
      async (cloudSession) => {
        await removeExcludedCloudNotes(client, cloudSession.sessionToken, localVault, includedNoteIds);
      }
    );
    const cloudSession = sessionResult.cloudSession;

    const storagePreference = await invoke<VaultPreference>("enable_vault_sync", {
      input: {
        includedNoteIds,
        vaultId: vault.vaultId
      }
    });

    const syncPatch = await syncWithCloudReplica({
      cloudSession,
      storagePreference,
      unlockInput,
      vault
    });

    return {
      cloudConnectionState: syncPatch.cloudConnectionState ?? "connected",
      cloudSession: syncPatch.cloudSession ?? cloudSession,
      cloudStatus: syncPatch.cloudStatus ?? "Cloud synced",
      ...syncPatch,
      storagePreference: syncPatch.storagePreference ?? storagePreference
    };
  }

  async function removeExcludedCloudNotes(
    client: ConvexHttpClient,
    sessionToken: string,
    localVault: LocalVaultData,
    includedNoteIds: string[] | undefined,
  ) {
    const excludedNotes = notesExcludedFromCloudSync(localVault.notes, includedNoteIds);
    if (excludedNotes.length === 0) return;

    const removedAtMs = Date.now();
    for (const note of excludedNotes) {
      await client.mutation(api.notes.removeFromCloudSync, {
        contentVersion: note.contentVersion,
        noteId: note.noteId,
        removedAtMs,
        sessionToken
      });
    }
  }

  async function stopSyncingThisDevice(vault: UnlockOutput): Promise<RuntimePatch> {
    const storagePreference = await invoke<VaultPreference>("set_vault_preference", {
      input: {
        storageMode: "local_only",
        vaultId: vault.vaultId
      }
    });

    return {
      cloudConnectionState: convexUrl ? "local_only" : "unconfigured",
      cloudSession: null,
      cloudStatus: convexUrl ? "Cloud disconnected" : "Cloud not configured",
      status: "This device only",
      storagePreference
    };
  }

  async function deleteCloudCopy(input: RuntimeContext): Promise<RuntimePatch> {
    if (!convexUrl || input.storagePreference?.storageMode !== "sync_enabled") {
      return {
        cloudConnectionState: convexUrl ? "local_only" : "unconfigured",
        cloudStatus: convexUrl ? "Encrypted sync is not enabled" : "Cloud not configured"
      };
    }

    let cloudSession = input.cloudSession;
    if (!cloudSession) {
      const cloudPatch = await connectCloud({
        cloudSession,
        storagePreference: input.storagePreference,
        syncAfterConnect: false,
        unlockInput: input.unlockInput,
        vault: input.vault
      });
      cloudSession = cloudPatch.cloudSession ?? null;
      if (!cloudSession) return cloudPatch;
    }

    if (!cloudSession) {
      return {
        cloudConnectionState: "error",
        cloudStatus: "Cloud session unavailable"
      };
    }

    let done = false;
    let retriedAfterAuth = false;
    while (!done) {
      try {
        const result = await getConvexClient().mutation(api.auth.deleteCloudCopy, {
          sessionToken: cloudSession.sessionToken
        }) as { done: boolean };
        done = result.done;
      } catch (error) {
        if (retriedAfterAuth || !isSessionExpiredError(error)) throw error;
        cloudSession = await createCloudSession(input);
        retriedAfterAuth = true;
      }
    }

    const storagePreference = await invoke<VaultPreference>("mark_cloud_copy_deleted", {
      vaultId: input.vault.vaultId
    });

    return {
      cloudConnectionState: "deleted",
      cloudSession: null,
      cloudStatus: "Cloud copy removed",
      status: "Cloud copy removed",
      storagePreference
    };
  }

  async function exportEncryptedBackup(vault: UnlockOutput): Promise<RuntimePatch> {
    const exported = await invoke<BackupInspection | null>("export_vault_backup", {
      input: {
        suggestedFileName: defaultBackupFileName(),
        vaultId: vault.vaultId
      }
    });
    if (!exported) return {};

    return { status: "Encrypted backup exported" };
  }

  async function exportMarkdownNote(note: NoteDraft): Promise<RuntimePatch> {
    const exported = await invoke<boolean>("export_markdown_note", {
      input: {
        markdown: buildMarkdownExport(note),
        suggestedFileName: defaultMarkdownFileName(note.title)
      }
    });
    if (!exported) return {};

    return { status: "Markdown exported" };
  }

  async function importBackup(context: RuntimeContext): Promise<RuntimePatch> {
    const selection = await invoke<{ token: string; inspection: BackupInspection } | null>("select_backup_for_import", {
      input: {
        vaultId: context.vault.vaultId
      }
    });
    if (!selection) return {};

    await invoke<MergeSummary>("import_vault_backup", {
      input: {
        token: selection.token,
        vaultId: context.vault.vaultId
      }
    });
    const data = await loadLocalVault(context.vault.vaultId, context.storagePreference);
    const syncPatch = await pushPendingSync(context);

    return {
      ...syncPatch,
      data,
      status: "Encrypted backup imported",
      storagePreference: data.preference ?? context.storagePreference
    };
  }

  async function listAllCloudFolders(client: ConvexHttpClient, sessionToken: string): Promise<CloudFolderRow[]> {
    const rows: CloudFolderRow[] = [];
    let cursor: string | null = null;

    while (true) {
      const result = await client.query(api.folders.list, {
        paginationOpts: { cursor, numItems: CLOUD_PAGE_SIZE },
        sessionToken
      }) as PaginatedRows<CloudFolderRow>;
      rows.push(...result.page);
      if (result.isDone) return rows;
      cursor = result.continueCursor;
    }
  }

  async function listAllCloudNotes(client: ConvexHttpClient, sessionToken: string): Promise<CloudNoteRow[]> {
    const rows: CloudNoteRow[] = [];
    let cursor: string | null = null;

    while (true) {
      const result = await client.query(api.notes.list, {
        paginationOpts: { cursor, numItems: CLOUD_PAGE_SIZE },
        sessionToken
      }) as PaginatedRows<CloudNoteRow>;
      rows.push(...result.page);
      if (result.isDone) return rows;
      cursor = result.continueCursor;
    }
  }

  async function getCloudUsage(client: ConvexHttpClient, sessionToken: string): Promise<CloudUsage> {
    return await client.query(api.notes.usage, { sessionToken }) as CloudUsage;
  }

  async function reconcileCloudUsage(client: ConvexHttpClient, sessionToken: string): Promise<CloudUsage> {
    return await client.mutation(api.notes.reconcileUsage, { sessionToken }) as CloudUsage;
  }

  async function tryGetCloudUsage(client: ConvexHttpClient, sessionToken: string): Promise<CloudUsage | null> {
    try {
      return await getCloudUsage(client, sessionToken);
    } catch {
      return null;
    }
  }

  async function getCloudUsageWithLocalFallback(
    client: ConvexHttpClient,
    sessionToken: string,
    vaultId: string,
    fallbackPreference: VaultPreference | null,
    fallbackData?: VaultWorkspaceData,
  ) {
    const cloudUsage = await tryGetCloudUsage(client, sessionToken);
    if (cloudUsage) return cloudUsage;

    const data = fallbackData ?? await loadLocalVault(vaultId, fallbackPreference);
    return localCloudUsageEstimate(vaultId, data);
  }

  function localCloudUsageEstimate(vaultId: string, data: VaultWorkspaceData): CloudUsage {
    const liveNotes = data.notes.filter((note) => note.cloudSyncScope !== "local_only" && !note.syncBlockedReason);
    const liveNoteIds = new Set(liveNotes.map((note) => note.id));
    const liveFolders = data.folders;
    return {
      vaultId,
      planKind: "free",
      maxSyncedNotes: FREE_SYNC_MAX_NOTES,
      maxStorageBytes: FREE_SYNC_MAX_STORAGE_BYTES,
      liveSyncedNoteCount: liveNotes.length,
      liveSyncedFolderCount: liveFolders.length,
      liveStorageBytes: [
        ...Array.from(liveNoteIds).map((noteId) => data.encryptedNotes[noteId]),
        ...liveFolders.map((folder) => data.encryptedFolders[folder.id]),
      ].reduce((sum, record) => sum + encryptedRecordByteLength(record), 0),
      updatedAtMs: Date.now(),
    };
  }

  function encryptedRecordByteLength(record: EncryptedNote | EncryptedFolder | null | undefined) {
    if (!record) return 0;
    return new TextEncoder().encode(JSON.stringify(record)).byteLength;
  }

  function summarizeCloudReplicaRows(remoteFolders: CloudFolderRow[], remoteNotes: CloudNoteRow[]): CloudReplicaSummary {
    return {
      checked: true,
      liveFolderCount: remoteFolders.filter(isLiveRemoteRecord).length,
      liveNoteCount: remoteNotes.filter(isLiveRemoteRecord).length
    };
  }

  async function restoreMissingCloudRecords(
    client: ConvexHttpClient,
    sessionToken: string,
    vaultId: string,
    remoteFolders: CloudFolderRow[],
    remoteNotes: CloudNoteRow[],
    allowMissingRestore: boolean
  ) {
    if (!allowMissingRestore) return { blockedCount: 0, syncedCount: 0 };

    const localVault = await invoke<LocalVaultData>("load_local_vault", { vaultId });
    const remoteLiveFolderIds = new Set(remoteFolders.filter(isLiveRemoteRecord).map((folder) => folder.folderId));
    const remoteLiveNoteIds = new Set(remoteNotes.filter(isLiveRemoteRecord).map((note) => note.noteId));
    let blockedCount = 0;
    let syncedCount = 0;

    for (const folder of localVault.folders) {
      if (!shouldRestoreMissingCloudFolder(folder, remoteLiveFolderIds)) continue;
      await pushPendingFolder(client, vaultId, sessionToken, folder);
      syncedCount += 1;
    }

    for (const note of localVault.notes) {
      if (!shouldRestoreMissingCloudNote(note, remoteLiveNoteIds)) continue;
      const result = await pushPendingNote(client, vaultId, sessionToken, note);
      if (result === "blocked") {
        blockedCount += 1;
      } else {
        syncedCount += 1;
      }
    }

    return { blockedCount, syncedCount };
  }

  function shouldRestoreMissingCloudFolder(folder: LocalEncryptedFolderRecord, remoteLiveFolderIds: Set<string>) {
    return folder.syncState === "synced" && !isDeletedRecord(folder) && !remoteLiveFolderIds.has(folder.folderId);
  }

  function shouldRestoreMissingCloudNote(note: LocalEncryptedNoteRecord, remoteLiveNoteIds: Set<string>) {
    return (
      note.syncState === "synced" &&
      note.cloudSyncScope === "included" &&
      !note.syncBlockedReason &&
      !isDeletedRecord(note) &&
      !remoteLiveNoteIds.has(note.noteId)
    );
  }

  function isLiveRemoteRecord(record: CloudFolderRow | CloudNoteRow) {
    if (record.cloudState === "deleted" || record.cloudState === "removed_from_sync") return false;
    return record.serverDeletedAtBucketMs === undefined && record.nonce !== "" && record.ciphertext !== "";
  }

  function isSessionExpiredError(error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    return message.toLowerCase().includes("session expired or invalid");
  }

  function cloudSyncErrorMessage(error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    const lower = message.toLowerCase();
    if (
      lower.includes("signer attestation rejected: 409") ||
      lower.includes("signer attestation rejected: 410") ||
      lower.includes("cloud attestation already consumed") ||
      lower.includes("signer session attestation expired")
    ) {
      return "Wallet unlock required to enable encrypted sync";
    }
    return message;
  }

  function getConvexClient() {
    if (!convexUrl) {
      throw new Error("PUBLIC_CONVEX_URL is not configured");
    }

    convexClient ??= new ConvexHttpClient(convexUrl);
    return convexClient;
  }

  return {
    deleteCloudCopy,
    deleteFolder,
    deleteNote,
    detectCloudReplica,
    enableFoundCloudSync,
    enableEncryptedSync,
    exportEncryptedBackup,
    exportMarkdownNote,
    getVaultPreference,
    includeNoteInCloudSync,
    importBackup,
    loadLocalVault,
    openWorkspace,
    repairCloudSync,
    saveFolder,
    saveNoteLocally,
    removeNoteFromCloudSync,
    saveNote,
    syncCloudReplica: syncWithCloudReplica,
    syncPendingRecords: pushPendingSync,
    setStorageModePreference,
    stopSyncingThisDevice
  };
}

export function notesExcludedFromCloudSync(
  notes: LocalEncryptedNoteRecord[],
  includedNoteIds: string[] | undefined,
) {
  if (!includedNoteIds) return [];

  const included = new Set(includedNoteIds);
  return notes.filter(
    (note) =>
      !included.has(note.noteId) &&
      !isDeletedRecord(note) &&
      note.syncState !== "conflict" &&
      note.remoteCloudState !== "removed_from_sync" &&
      (note.remoteCloudState === "live" || Boolean(note.lastSyncedRevisionHash)),
  );
}

export function getInitialCloudConnectionState(convexUrl: string | undefined, preference: VaultPreference): CloudConnectionState {
  if (!convexUrl) return "unconfigured";
  if (preference.cloudCopyDeletedAtMs && preference.storageMode !== "sync_enabled") return "deleted";
  if (preference.storageMode === "sync_enabled") return "connecting";
  return "local_only";
}

export function getStorageStatusLabel(input: {
  cloudBusy: boolean;
  cloudConnectionState: CloudConnectionState;
  cloudSession: CloudSession | null;
  convexUrl?: string;
  storagePreference: VaultPreference | null;
}) {
  if (!input.convexUrl && input.storagePreference?.storageMode === "sync_enabled") return "Sync unavailable";
  if (input.cloudConnectionState === "error") return "Sync error";
  if (input.storagePreference?.cloudCopyDeletedAtMs && input.storagePreference.storageMode !== "sync_enabled") {
    return "Cloud copy removed";
  }
  if (input.storagePreference?.storageMode === "sync_enabled") {
    return getActiveSyncStatusLabel(input);
  }
  if (input.storagePreference?.storageMode === "sync_paused") return "Sync paused";
  return "This device only";
}

function getActiveSyncStatusLabel(input: {
  cloudBusy: boolean;
  cloudConnectionState: CloudConnectionState;
  cloudSession: CloudSession | null;
}) {
  if (input.cloudBusy || input.cloudConnectionState === "syncing" || input.cloudConnectionState === "connecting") return "Syncing";
  if (input.cloudConnectionState === "connected" && input.cloudSession) return "Encrypted sync on";
  return "Sync disconnected";
}

function shouldEnsureDefaultFolderAfterOpen(
  preference: VaultPreference,
  cloudConnectionState: CloudConnectionState,
  cloudReplica: CloudReplicaSummary | undefined,
  data: VaultWorkspaceData
) {
  if (data.encryptedFolders[DEFAULT_FOLDER_ID]) return false;
  if (preference.storageMode !== "sync_enabled") return true;
  if (cloudConnectionState !== "connected") return false;
  return cloudReplica?.checked === true;
}

async function ensureDefaultFolder(vault: UnlockOutput, data: VaultWorkspaceData) {
  if (data.encryptedFolders[DEFAULT_FOLDER_ID]) return data;

  const defaultFolder = createDefaultFolder();
  const savedFolder = await saveFolderLocally(vault, defaultFolder, data.encryptedFolders);
  return {
    ...data,
    encryptedFolders: {
      ...data.encryptedFolders,
      [defaultFolder.id]: savedFolder.encryptedFolder
    },
    folders: sortFolders([defaultFolder, ...data.folders])
  };
}

function createDefaultFolder(): FolderDraft {
  const now = Date.now();
  return {
    createdAtMs: now,
    id: DEFAULT_FOLDER_ID,
    name: DEFAULT_FOLDER_NAME,
    sortOrder: 0,
    updatedAtMs: now
  };
}

async function saveFolderLocally(vault: UnlockOutput, folder: FolderDraft, encryptedFolders: Record<string, EncryptedFolder>) {
  const contentVersion = encryptedFolders[folder.id]?.header.contentVersion
    ? encryptedFolders[folder.id].header.contentVersion + 1
    : 1;
  const header: FolderCiphertextHeader = {
    algorithm: "XCHACHA20-POLY1305",
    contentVersion,
    folderId: folder.id,
    keyVersion: 1,
    schemaVersion: CIPHERTEXT_SCHEMA_VERSION,
    vaultId: vault.vaultId
  };
  const document: PlaintextFolderDocument = {
    createdAtMs: folder.createdAtMs,
    name: folder.name,
    sortOrder: folder.sortOrder,
    updatedAtMs: folder.updatedAtMs
  };
  const encryptedFolder = await invoke<EncryptedFolder>("encrypt_folder", { input: { document, header } });
  const record = await invoke<LocalEncryptedFolderRecord>("save_local_folder", {
    input: {
      createdAtMs: folder.createdAtMs,
      deletedAtMs: null,
      encryptedFolder,
      syncState: null,
      updatedAtMs: folder.updatedAtMs
    }
  });

  return { encryptedFolder, record };
}

function noteWithSyncMetadata(note: NoteDraft, record: LocalEncryptedNoteRecord): NoteDraft {
  return {
    ...note,
    cloudSyncScope: record.cloudSyncScope,
    lastSyncedRevisionHash: record.lastSyncedRevisionHash ?? null,
    revisionHash: record.revisionHash,
    syncBlockedReason: record.syncBlockedReason ?? null,
    syncState: record.syncState
  };
}

async function pushPendingFolder(
  client: ConvexHttpClient,
  vaultId: string,
  sessionToken: string,
  folder: LocalEncryptedFolderRecord
) {
  if (isDeletedRecord(folder)) {
    await client.mutation(api.folders.remove, {
      deletedAtMs: folder.deletedAtMs,
      encryptedFolder: folder.encryptedFolder,
      sessionToken
    });
  } else {
    await client.mutation(api.folders.upsert, {
      encryptedFolder: folder.encryptedFolder,
      sessionToken
    });
  }

  await markSyncedRecord(vaultId, {
    kind: "folder",
    recordId: folder.folderId,
    revisionHash: folder.revisionHash
  });
}

async function pushPendingNote(
  client: ConvexHttpClient,
  vaultId: string,
  sessionToken: string,
  note: LocalEncryptedNoteRecord,
): Promise<"blocked" | "synced"> {
  try {
    if (isDeletedRecord(note)) {
      await client.mutation(api.notes.remove, {
        deletedAtMs: note.deletedAtMs,
        encryptedNote: note.encryptedNote,
        sessionToken
      });
    } else {
      await client.mutation(api.notes.upsert, {
        encryptedNote: note.encryptedNote,
        sessionToken
      });
    }
  } catch (error) {
    const blockedReason = syncBlockedReasonFromError(error);
    if (!blockedReason) throw error;
    await markNoteSyncBlockedForRecord(vaultId, note, blockedReason);
    return "blocked";
  }

  await markSyncedRecord(vaultId, {
    kind: "note",
    recordId: note.noteId,
    revisionHash: note.revisionHash
  });
  return "synced";
}

async function markNoteSyncBlockedForRecord(vaultId: string, note: LocalEncryptedNoteRecord, reason: SyncBlockedReason) {
  await invoke<LocalEncryptedNoteRecord>("mark_note_sync_blocked", {
    input: {
      expectedRevisionHash: note.revisionHash,
      noteId: note.noteId,
      reason,
      vaultId
    }
  });
}

function syncBlockedReasonFromError(error: unknown): SyncBlockedReason | null {
  const message = error instanceof Error ? error.message : String(error);
  if (message.includes("quota_note_count_exceeded")) return "quota_note_count";
  if (message.includes("quota_storage_exceeded")) return "quota_storage";
  if (message.includes("record_too_large") || message.includes("ciphertext is too large")) {
    return "record_too_large";
  }
  return null;
}

async function markSyncedRecord(vaultId: string, record: SyncedRecordRef) {
  await invoke("mark_records_synced", {
    input: {
      syncedRecordRefs: [record],
      vaultId
    }
  });
}

function defaultBackupFileName() {
  const today = new Date().toISOString().slice(0, 10);
  return `Verus Notes Backup ${today}.verusnotes`;
}

function defaultMarkdownFileName(title: string) {
  const stem = (title.trim() || "Untitled")
    .replace(/[\\/:*?"<>|]+/g, "-")
    .replace(/\s+/g, " ")
    .slice(0, 80)
    .trim();
  return `${stem || "Untitled"}.md`;
}

function buildMarkdownExport(note: NoteDraft) {
  const title = escapeMarkdownHeadingText(note.title.trim() || "Untitled");
  const body = note.body.trim();
  return body ? `# ${title}\n\n${body}\n` : `# ${title}\n`;
}

function escapeMarkdownHeadingText(value: string) {
  return value.replace(/([\\`*])/g, "\\$1");
}

function isDeletedRecord<T extends { deletedAtMs?: number | null }>(record: T): record is T & { deletedAtMs: number } {
  return record.deletedAtMs !== null && record.deletedAtMs !== undefined;
}
