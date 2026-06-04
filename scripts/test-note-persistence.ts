import assert from "node:assert/strict";
import { createNotePersistenceController } from "../src/lib/notes/notePersistence.svelte";
import type { EncryptedNote, FolderDraft, NoteDraft, StorageMode, VaultPreference } from "../src/lib/notes/types";
import type { NotesRuntime, RuntimeContext } from "../src/lib/notes/workspaceTypes";

declare global {
  var $state: <T>(value: T) => T;
}

globalThis.$state = <T>(value: T) => value;

let timerId = 0;
const queuedTimers = new Map<number, () => void>();
Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: {
  clearTimeout(id: number | undefined) {
    if (id === undefined) return;
    queuedTimers.delete(id);
  },
  setTimeout(callback: () => void) {
    timerId += 1;
    queuedTimers.set(timerId, callback);
    return timerId;
  }
  }
});

const vault = {
  backendAuthAlgorithm: "ed25519-v1",
  backendAuthKeyId: "backend-key-id",
  backendAuthPublicKey: "backend-key",
  backendAuthKeyVersion: 1,
  exportCheckHash: "export-check",
  vaultId: "vault-1",
  walletSignerIdentityIAddress: "wallet-i"
};
const unlockInput = {
  appEncryptionRequestId: "request-1",
  appIdentityIAddress: "app-i",
  chain: "VRSCTEST",
  derivationNumber: 1,
  keyVersion: 1,
  walletSignerIdentityIAddress: "wallet-i"
};
const localPreference: VaultPreference = {
  createdAtMs: 1,
  storageMode: "local_only",
  updatedAtMs: 1,
  vaultId: vault.vaultId
};
const folder: FolderDraft = {
  createdAtMs: 1,
  id: "folder-1",
  name: "Notes",
  sortOrder: 0,
  updatedAtMs: 1
};

function note(): NoteDraft {
  return {
    body: "Body",
    bookmarked: false,
    createdAtMs: 1,
    folderId: folder.id,
    id: "note-1",
    title: "Title",
    updatedAtMs: 1
  };
}

function encryptedNote(version: number): EncryptedNote {
  return {
    ciphertext: `ciphertext-${version}`,
    header: {
      algorithm: "XCHACHA20-POLY1305",
      contentVersion: version,
      keyVersion: 1,
      noteId: "note-1",
      schemaVersion: 1,
      vaultId: vault.vaultId
    },
    nonce: `nonce-${version}`
  };
}

function createHarness(input: {
  deactivateBeforeSyncReturns?: boolean;
  notePatch?: Partial<NoteDraft>;
  saveFails?: boolean;
  storageMode?: StorageMode;
  syncFails?: boolean;
  syncReturnsData?: boolean;
} = {}) {
  let notes = [{ ...note(), ...input.notePatch }];
  let encryptedNotes: Record<string, EncryptedNote> = {};
  let status = "";
  let cloudStatus = "";
  let cloudConnectionState = input.storageMode === "sync_enabled" ? "connected" : "local_only";
  let cloudBusy = false;
  let contextActive = true;
  let appliedWorkspaceData = false;
  let saveCount = 0;
  let syncCount = 0;
  const preference = {
    ...localPreference,
    storageMode: input.storageMode ?? localPreference.storageMode
  };
  const context: RuntimeContext = {
    cloudSession:
      input.storageMode === "sync_enabled"
        ? {
            expiresAtMs: 9_999,
            sessionToken: "session-token",
            vaultId: vault.vaultId
          }
        : null,
    storagePreference: preference,
    unlockInput,
    vault
  };
  const runtime = {
    async saveNoteLocally({ note }: { note: NoteDraft }) {
      saveCount += 1;
      if (input.saveFails) throw new Error("local save failed");
      const saved = {
        ...note,
        cloudSyncScope: input.storageMode === "sync_enabled" ? "included" : undefined,
        revisionHash: `revision-${saveCount}`,
        syncState: input.storageMode === "sync_enabled" ? "pending_upsert" : "not_synced"
      } satisfies NoteDraft;
      return {
        encryptedNote: encryptedNote(saveCount),
        note: saved
      };
    },
    async syncPendingRecords() {
      syncCount += 1;
      if (input.syncFails) throw new Error("cloud sync failed");
      if (input.deactivateBeforeSyncReturns) contextActive = false;
      if (input.syncReturnsData) {
        return {
          cloudConnectionState: "connected",
          cloudStatus: "Cloud synced",
          data: {
            encryptedFolders: {},
            encryptedNotes: {},
            folders: [{ ...folder, id: "synced-folder" }],
            notes: [{ ...note(), id: "synced-note" }],
            preference
          },
          status: "Encrypted and synced"
        };
      }
      return {
        cloudConnectionState: "connected",
        cloudStatus: "Cloud synced",
        status: "Encrypted and synced"
      };
    }
  } as Pick<NotesRuntime, "saveNoteLocally" | "syncPendingRecords">;

  const controller = createNotePersistenceController({
    applyRuntimePatch(patch) {
      if (patch.data) {
        appliedWorkspaceData = true;
        notes = patch.data.notes;
        encryptedNotes = patch.data.encryptedNotes;
      }
      if (patch.cloudStatus) cloudStatus = patch.cloudStatus;
      if (patch.cloudConnectionState) cloudConnectionState = patch.cloudConnectionState;
      if (patch.status) status = patch.status;
    },
    getActiveNote: () => notes[0] ?? null,
    getCloudConnectionState: () => cloudConnectionState,
    getCloudSession: () => context.cloudSession,
    getCloudStatus: () => cloudStatus,
    getEncryptedFolders: () => ({}),
    getEncryptedNotes: () => encryptedNotes,
    getFolders: () => [folder],
    getNotes: () => notes,
    getRuntimeContext: () => (contextActive ? context : null),
    getStoragePreference: () => preference,
    isRuntimeContextCurrent: (candidate) => contextActive && candidate === context,
    isWalletUnlockRequiredSyncError: (message) => Boolean(message?.includes("wallet unlock required")),
    resolveFolderId: (folderId) => folderId ?? folder.id,
    runtime,
    setCloudBusy: (value) => (cloudBusy = value),
    setCloudConnectionState: (value) => (cloudConnectionState = value),
    setCloudStatus: (value) => (cloudStatus = value),
    setEncryptedNotes: (value) => (encryptedNotes = value),
    setNotes: (value) => (notes = value),
    setStatus: (value) => (status = value)
  });

  return {
    controller,
    get cloudBusy() {
      return cloudBusy;
    },
    get cloudConnectionState() {
      return cloudConnectionState;
    },
    get cloudStatus() {
      return cloudStatus;
    },
    get encryptedNotes() {
      return encryptedNotes;
    },
    get appliedWorkspaceData() {
      return appliedWorkspaceData;
    },
    get notes() {
      return notes;
    },
    get saveCount() {
      return saveCount;
    },
    get syncCount() {
      return syncCount;
    },
    get status() {
      return status;
    },
    deactivateContext() {
      contextActive = false;
    }
  };
}

async function dirtyNoteSavesLocally() {
  const harness = createHarness();
  harness.controller.markNoteDirty("note-1");
  const saved = await harness.controller.flushNoteAutosave("note-1", { force: true });

  assert.equal(saved, true);
  assert.equal(harness.saveCount, 1);
  assert.equal(harness.encryptedNotes["note-1"]?.header.contentVersion, 1);
  assert.equal(harness.controller.getNoteSaveState("note-1").dirty, false);
  assert.equal(harness.controller.getNoteSaveState("note-1").localError, null);
  assert.equal(harness.notes[0]?.revisionHash, "revision-1");
}

async function failedSaveKeepsNoteDirty() {
  const harness = createHarness({ saveFails: true });
  harness.controller.markNoteDirty("note-1");
  const saved = await harness.controller.flushNoteAutosave("note-1", { force: true });
  const state = harness.controller.getNoteSaveState("note-1");

  assert.equal(saved, false);
  assert.equal(state.dirty, true);
  assert.equal(state.localSaving, false);
  assert.equal(state.localError, "local save failed");
  assert.equal(harness.status, "Save failed");
}

async function cloudSyncErrorLeavesLocalSaveIntact() {
  const harness = createHarness({ storageMode: "sync_enabled", syncFails: true });
  harness.controller.markNoteDirty("note-1");
  const saved = await harness.controller.flushNoteAutosave("note-1", { force: true });

  assert.equal(saved, true);
  assert.equal(harness.encryptedNotes["note-1"]?.header.contentVersion, 1);

  await harness.controller.runQueuedCloudSync();
  const state = harness.controller.getNoteSaveState("note-1");

  assert.equal(state.localError, null);
  assert.equal(state.syncError, "cloud sync failed");
  assert.equal(state.syncPending, true);
  assert.equal(state.syncing, false);
  assert.equal(harness.cloudConnectionState, "error");
  assert.equal(harness.cloudBusy, false);
}

async function staleCloudSyncResultDoesNotApplyWorkspaceData() {
  const harness = createHarness({
    deactivateBeforeSyncReturns: true,
    storageMode: "sync_enabled",
    syncReturnsData: true
  });

  harness.controller.scheduleCloudSync("note-1");
  await harness.controller.runQueuedCloudSync();

  assert.equal(harness.appliedWorkspaceData, false);
  assert.equal(harness.notes[0]?.id, "note-1");
  assert.equal(harness.cloudBusy, false);
}

async function queuedCloudSyncUsesPendingStoreWithoutTrackedNote() {
  const harness = createHarness({ storageMode: "sync_enabled" });

  await harness.controller.runQueuedCloudSync();

  assert.equal(harness.syncCount, 1);
  assert.equal(harness.cloudConnectionState, "connected");
  assert.equal(harness.cloudBusy, false);
}

async function activeNoteStatusShowsPersistedPendingUpsertAfterRelaunch() {
  const harness = createHarness({
    notePatch: {
      cloudSyncScope: "included",
      revisionHash: "revision-current",
      syncState: "pending_upsert"
    },
    storageMode: "sync_enabled"
  });
  harness.controller.resetSavedStates(harness.notes);

  const status = harness.controller.activeNoteSaveStatus;

  assert.equal(status.compactLabel, "Queued");
  assert.equal(status.displayLabel, "Sync queued");
}

async function activeNoteStatusShowsPersistedPendingDeleteAfterRelaunch() {
  const harness = createHarness({
    notePatch: {
      cloudSyncScope: "included",
      revisionHash: "revision-current",
      syncState: "pending_delete"
    },
    storageMode: "sync_enabled"
  });
  harness.controller.resetSavedStates(harness.notes);

  const status = harness.controller.activeNoteSaveStatus;

  assert.equal(status.compactLabel, "Queued");
  assert.equal(status.displayLabel, "Sync queued");
}

async function activeNoteStatusShowsExactSyncedRevisionHash() {
  const harness = createHarness({
    notePatch: {
      cloudSyncScope: "included",
      lastSyncedRevisionHash: "revision-current",
      revisionHash: "revision-current",
      syncState: "synced"
    },
    storageMode: "sync_enabled"
  });
  harness.controller.resetSavedStates(harness.notes);

  const status = harness.controller.activeNoteSaveStatus;

  assert.equal(status.compactLabel, "Synced");
  assert.equal(status.displayLabel, "Cloud synced");
}

async function activeNoteStatusRequiresMatchingSyncedRevisionHash() {
  const harness = createHarness({
    notePatch: {
      cloudSyncScope: "included",
      lastSyncedRevisionHash: "revision-previous",
      revisionHash: "revision-current",
      syncState: "synced"
    },
    storageMode: "sync_enabled"
  });
  harness.controller.resetSavedStates(harness.notes);

  const status = harness.controller.activeNoteSaveStatus;

  assert.equal(status.compactLabel, "Local");
  assert.equal(status.displayLabel, "Local device");
}

await dirtyNoteSavesLocally();
await failedSaveKeepsNoteDirty();
await cloudSyncErrorLeavesLocalSaveIntact();
await staleCloudSyncResultDoesNotApplyWorkspaceData();
await queuedCloudSyncUsesPendingStoreWithoutTrackedNote();
await activeNoteStatusShowsPersistedPendingUpsertAfterRelaunch();
await activeNoteStatusShowsPersistedPendingDeleteAfterRelaunch();
await activeNoteStatusShowsExactSyncedRevisionHash();
await activeNoteStatusRequiresMatchingSyncedRevisionHash();

console.log("note persistence tests passed");
