import type { CloudSession, EncryptedFolder, EncryptedNote, FolderDraft, NoteDraft, VaultPreference } from "./types";
import type { RuntimePatch } from "./vaultWorkspaceRuntime";
import { getDocumentNoteById } from "./workspaceDocument";
import type { NoteSaveState, NoteSaveStatus, NotesRuntime, RuntimeContext } from "./workspaceTypes";

const NOTE_AUTOSAVE_IDLE_MS = 850;
const NOTE_AUTOSAVE_MAX_WAIT_MS = 3000;
const CLOUD_SYNC_IDLE_MS = 6000;
const LOCAL_STATUS_LABEL = "Local device";
const LOCAL_STATUS_COMPACT_LABEL = "Local";

type NotePersistenceOptions = {
  applyRuntimePatch(patch: RuntimePatch): void;
  getActiveNote(): NoteDraft | null;
  getCloudConnectionState(): string;
  getCloudSession(): CloudSession | null;
  getCloudStatus(): string;
  getEncryptedFolders(): Record<string, EncryptedFolder>;
  getEncryptedNotes(): Record<string, EncryptedNote>;
  getFolders(): FolderDraft[];
  getNotes(): NoteDraft[];
  getRuntimeContext(): RuntimeContext | null;
  getStoragePreference(): VaultPreference | null;
  isRuntimeContextCurrent(context: RuntimeContext): boolean;
  isWalletUnlockRequiredSyncError(message: string | null | undefined): boolean;
  resolveFolderId(folderId: string | undefined): string;
  runtime: Pick<NotesRuntime, "saveNoteLocally" | "syncPendingRecords">;
  setCloudBusy(value: boolean): void;
  setCloudConnectionState(value: "syncing" | "error"): void;
  setCloudStatus(value: string): void;
  setEncryptedNotes(value: Record<string, EncryptedNote>): void;
  setNotes(value: NoteDraft[]): void;
  setStatus(value: string): void;
};

export function createNotePersistenceController(options: NotePersistenceOptions) {
  let noteSaveStates = $state<Record<string, NoteSaveState>>({});
  let saving = $state(false);
  let cloudSyncTimer: number | null = null;
  let cloudSyncRunning = false;
  let cloudSyncQueued = false;
  const noteAutosaveTimers = new Map<string, number>();
  const noteAutosaveMaxTimers = new Map<string, number>();
  const noteSaveQueues = new Map<string, Promise<boolean>>();
  const cloudSyncNoteIds = new Set<string>();

  function createDefaultNoteSaveState(): NoteSaveState {
    return {
      dirty: false,
      localError: null,
      localSavedAtMs: null,
      localSaving: false,
      snapshotOrdinal: 0,
      syncError: null,
      syncPending: false,
      syncing: false
    };
  }

  function createSavedNoteState(savedAtMs: number): NoteSaveState {
    return {
      ...createDefaultNoteSaveState(),
      localSavedAtMs: savedAtMs
    };
  }

  function resetSavedStates(notes: NoteDraft[]) {
    noteSaveStates = Object.fromEntries(
      notes.map((note) => [
        note.id,
        createSavedNoteState(note.updatedAtMs)
      ])
    );
    refreshSavingState();
  }

  function getNoteSaveState(noteId: string) {
    return noteSaveStates[noteId] ?? createDefaultNoteSaveState();
  }

  function updateNoteSaveState(noteId: string, patch: Partial<NoteSaveState>) {
    const nextState = {
      ...getNoteSaveState(noteId),
      ...patch
    };
    noteSaveStates = {
      ...noteSaveStates,
      [noteId]: nextState
    };
    refreshSavingState();
  }

  function removeNoteSaveState(noteId: string) {
    const nextStates = { ...noteSaveStates };
    delete nextStates[noteId];
    noteSaveStates = nextStates;
    refreshSavingState();
  }

  function refreshSavingState() {
    saving = Object.values(noteSaveStates).some((state) => state.localSaving);
  }

  function markNoteDirty(noteId: string) {
    const current = getNoteSaveState(noteId);
    updateNoteSaveState(noteId, {
      dirty: true,
      localError: null,
      snapshotOrdinal: current.snapshotOrdinal + 1
    });
  }

  function scheduleNoteAutosave(noteId: string, delayMs = NOTE_AUTOSAVE_IDLE_MS) {
    if (!options.getRuntimeContext()) return;

    markNoteDirty(noteId);
    const existingTimer = noteAutosaveTimers.get(noteId);
    if (existingTimer !== undefined) window.clearTimeout(existingTimer);

    noteAutosaveTimers.set(
      noteId,
      window.setTimeout(() => {
        noteAutosaveTimers.delete(noteId);
        void flushNoteAutosave(noteId);
      }, delayMs)
    );

    if (!noteAutosaveMaxTimers.has(noteId)) {
      noteAutosaveMaxTimers.set(
        noteId,
        window.setTimeout(() => {
          noteAutosaveMaxTimers.delete(noteId);
          void flushNoteAutosave(noteId);
        }, NOTE_AUTOSAVE_MAX_WAIT_MS)
      );
    }
  }

  function clearNoteAutosaveTimers(noteId: string) {
    const idleTimer = noteAutosaveTimers.get(noteId);
    if (idleTimer !== undefined) window.clearTimeout(idleTimer);
    noteAutosaveTimers.delete(noteId);

    const maxTimer = noteAutosaveMaxTimers.get(noteId);
    if (maxTimer !== undefined) window.clearTimeout(maxTimer);
    noteAutosaveMaxTimers.delete(noteId);
  }

  function clearAllAutosaveTimers() {
    for (const timer of noteAutosaveTimers.values()) window.clearTimeout(timer);
    for (const timer of noteAutosaveMaxTimers.values()) window.clearTimeout(timer);
    noteAutosaveTimers.clear();
    noteAutosaveMaxTimers.clear();
  }

  function clearCloudSyncTimer() {
    if (cloudSyncTimer !== null) window.clearTimeout(cloudSyncTimer);
    cloudSyncTimer = null;
  }

  function scheduleQueuedCloudSyncRun() {
    clearCloudSyncTimer();
    cloudSyncTimer = window.setTimeout(() => {
      cloudSyncTimer = null;
      void runQueuedCloudSync();
    }, CLOUD_SYNC_IDLE_MS);
  }

  async function flushNoteAutosave(noteId: string, options: { force?: boolean } = {}) {
    clearNoteAutosaveTimers(noteId);
    const previous = noteSaveQueues.get(noteId) ?? Promise.resolve(true);
    const queued = previous
      .catch(() => false)
      .then(() => saveNoteSnapshotLocally(noteId, Boolean(options.force)));
    noteSaveQueues.set(noteId, queued);

    try {
      return await queued;
    } finally {
      if (noteSaveQueues.get(noteId) === queued) {
        noteSaveQueues.delete(noteId);
      }
    }
  }

  async function waitForNoteSave(noteId: string) {
    const queued = noteSaveQueues.get(noteId);
    if (queued) await queued.catch(() => false);
  }

  async function saveNoteSnapshotLocally(noteId: string, force: boolean) {
    const runtimeContext = options.getRuntimeContext();
    const note = getDocumentNoteById(options.getNotes(), noteId);
    if (!runtimeContext || !note) return false;

    const stateAtStart = getNoteSaveState(noteId);
    if (!stateAtStart.dirty && !force) return true;
    if (!stateAtStart.dirty && force && options.getEncryptedNotes()[noteId]) {
      updateNoteSaveState(noteId, {
        localError: null,
        localSavedAtMs: Date.now()
      });
      return true;
    }

    const snapshotOrdinal = stateAtStart.snapshotOrdinal;
    const savedNote = { ...note, folderId: options.resolveFolderId(note.folderId), updatedAtMs: Date.now() };
    updateNoteSaveState(noteId, {
      dirty: false,
      localError: null,
      localSaving: true
    });

    try {
      const result = await options.runtime.saveNoteLocally({
        context: runtimeContext,
        encryptedNotes: options.getEncryptedNotes(),
        folders: options.getFolders(),
        note: savedNote
      });
      if (!options.isRuntimeContextCurrent(runtimeContext)) return false;

      options.setEncryptedNotes({ ...options.getEncryptedNotes(), [savedNote.id]: result.encryptedNote });

      const latestState = getNoteSaveState(noteId);
      const hasNewerSnapshot = latestState.snapshotOrdinal !== snapshotOrdinal;
      if (!hasNewerSnapshot) {
        options.setNotes(
          options.getNotes().map((candidate) =>
            candidate.id === savedNote.id
              ? {
                  ...candidate,
                  cloudSyncScope: result.note.cloudSyncScope,
                  folderId: savedNote.folderId,
                  lastSyncedRevisionHash: result.note.lastSyncedRevisionHash,
                  revisionHash: result.note.revisionHash,
                  syncBlockedReason: result.note.syncBlockedReason,
                  syncState: result.note.syncState,
                  updatedAtMs: savedNote.updatedAtMs
                }
              : candidate
          )
        );
      }

      updateNoteSaveState(noteId, {
        dirty: hasNewerSnapshot,
        localError: null,
        localSavedAtMs: Date.now(),
        localSaving: false,
        syncError: null
      });

      if (runtimeContext.storagePreference?.storageMode === "sync_enabled") {
        scheduleCloudSync(noteId);
      }
      if (hasNewerSnapshot) {
        scheduleNoteAutosave(noteId, 0);
      }
      return true;
    } catch (error) {
      if (!options.isRuntimeContextCurrent(runtimeContext)) return false;

      const message = error instanceof Error ? error.message : String(error);
      updateNoteSaveState(noteId, {
        dirty: true,
        localError: message,
        localSaving: false
      });
      options.setStatus("Save failed");
      return false;
    }
  }

  function scheduleCloudSync(noteId: string) {
    const runtimeContext = options.getRuntimeContext();
    if (runtimeContext?.storagePreference?.storageMode !== "sync_enabled") return;

    cloudSyncQueued = true;
    cloudSyncNoteIds.add(noteId);
    updateNoteSaveState(noteId, {
      syncError: null,
      syncPending: true
    });

    if (!runtimeContext.cloudSession) return;
    scheduleQueuedCloudSyncRun();
  }

  async function runQueuedCloudSync() {
    if (cloudSyncRunning) return;
    const runtimeContext = options.getRuntimeContext();
    if (!runtimeContext?.cloudSession || runtimeContext.storagePreference?.storageMode !== "sync_enabled") return;

    const noteIds = Array.from(cloudSyncNoteIds);
    cloudSyncNoteIds.clear();
    cloudSyncQueued = false;

    cloudSyncRunning = true;
    options.setCloudBusy(true);
    options.setCloudConnectionState("syncing");
    for (const noteId of noteIds) {
      updateNoteSaveState(noteId, {
        syncError: null,
        syncPending: false,
        syncing: true
      });
    }

    try {
      const result = await options.runtime.syncPendingRecords(runtimeContext);
      if (!options.isRuntimeContextCurrent(runtimeContext)) return;

      if (result.data && Object.values(noteSaveStates).some((state) => state.dirty || state.localSaving)) {
        const statusPatch = { ...result };
        delete statusPatch.data;
        options.applyRuntimePatch(statusPatch);
      } else {
        options.applyRuntimePatch(result);
      }
      for (const noteId of noteIds) {
        updateNoteSaveState(noteId, {
          syncError: null,
          syncPending: false,
          syncing: false
        });
      }
    } catch (error) {
      if (!options.isRuntimeContextCurrent(runtimeContext)) return;

      const message = error instanceof Error ? error.message : String(error);
      options.setCloudStatus(message);
      options.setCloudConnectionState("error");
      for (const noteId of noteIds) {
        updateNoteSaveState(noteId, {
          syncError: message,
          syncPending: true,
          syncing: false
        });
        cloudSyncNoteIds.add(noteId);
      }
      if (noteIds.length > 0) cloudSyncQueued = true;
    } finally {
      options.setCloudBusy(false);
      cloudSyncRunning = false;
      if (options.isRuntimeContextCurrent(runtimeContext) && cloudSyncQueued) {
        scheduleQueuedCloudSyncRun();
      }
    }
  }

  async function flushDirtyNotes() {
    const noteIds = Object.entries(noteSaveStates)
      .filter(([, state]) => state.dirty || state.localSaving)
      .map(([noteId]) => noteId);
    const results = await Promise.all(noteIds.map((noteId) => flushNoteAutosave(noteId, { force: true })));
    return results.every(Boolean);
  }

  async function saveNote(note: NoteDraft) {
    options.setNotes(options.getNotes().map((candidate) => (candidate.id === note.id ? note : candidate)));
    markNoteDirty(note.id);
    await flushNoteAutosave(note.id, { force: true });
  }

  function removeCloudSyncNoteId(noteId: string) {
    cloudSyncNoteIds.delete(noteId);
  }

  function clear() {
    noteSaveStates = {};
    noteSaveQueues.clear();
    cloudSyncNoteIds.clear();
    cloudSyncQueued = false;
    clearAllAutosaveTimers();
    clearCloudSyncTimer();
    refreshSavingState();
  }

  function getActiveNoteSaveStatus(): NoteSaveStatus {
    const activeNote = options.getActiveNote();
    if (!activeNote) return getWorkspaceSaveStatus();

    const noteState = noteSaveStates[activeNote.id] ?? null;
    if (noteState?.localError) {
      return {
        compactLabel: "Save failed",
        displayLabel: LOCAL_STATUS_LABEL,
        icon: "error",
        label: "Save failed",
        tone: "error",
        title: `Autosave failed: ${noteState.localError}`
      };
    }
    if (noteState?.localSaving) {
      return {
        compactLabel: "Saving",
        displayLabel: LOCAL_STATUS_LABEL,
        icon: "spinner",
        label: "Saving on this device",
        tone: "local",
        title: "Encrypting and saving on this device"
      };
    }
    if (noteState?.dirty) {
      return {
        compactLabel: "Saving",
        displayLabel: LOCAL_STATUS_LABEL,
        icon: "spinner",
        label: "Autosave scheduled",
        tone: "local",
        title: "Autosave is scheduled"
      };
    }
    if (noteState?.syncError) {
      if (options.isWalletUnlockRequiredSyncError(noteState.syncError)) {
        return {
          compactLabel: "Paused",
          displayLabel: "Sync paused",
          icon: "error",
          label: "Needs new wallet unlock",
          tone: "error",
          title: "Cloud sync needs new wallet unlock. Changes are saved on this device."
        };
      }

      return {
        compactLabel: "Failed",
        displayLabel: "Sync failed",
        icon: "error",
        label: "Sync failed",
        tone: "error",
        title: `Encrypted sync failed: ${noteState.syncError}`
      };
    }
    if (noteState?.syncing) {
      return {
        compactLabel: "Syncing",
        displayLabel: "Syncing",
        icon: "spinner",
        label: "Syncing encrypted changes",
        tone: "cloud",
        title: "Uploading encrypted changes"
      };
    }
    if (noteState?.syncPending) {
      return getSyncQueuedStatus();
    }
    const cloudScopeStatus = getNoteCloudScopeStatus(activeNote);
    if (cloudScopeStatus) return cloudScopeStatus;
    if (options.getEncryptedNotes()[activeNote.id] || noteState?.localSavedAtMs) {
      return {
        compactLabel: LOCAL_STATUS_COMPACT_LABEL,
        displayLabel: LOCAL_STATUS_LABEL,
        icon: "check",
        label: "Saved on this device",
        tone: "local",
        title: "Encrypted before local storage"
      };
    }
    return {
      compactLabel: "Saving",
      displayLabel: LOCAL_STATUS_LABEL,
      icon: "spinner",
      label: "Autosave scheduled",
      tone: "local",
      title: "Autosave is scheduled"
    };
  }

  function getSyncQueuedStatus(): NoteSaveStatus {
    return {
      compactLabel: "Queued",
      displayLabel: "Sync queued",
      icon: "spinner",
      label: "Cloud sync queued",
      tone: "cloud",
      title: "Saved on this device and queued for encrypted sync"
    };
  }

  function getNoteCloudScopeStatus(note: NoteDraft | null): NoteSaveStatus | null {
    if (!note || options.getStoragePreference()?.storageMode !== "sync_enabled") return null;

    if (note.cloudSyncScope === "local_only") {
      return {
        compactLabel: "Local only",
        displayLabel: "This device only",
        icon: "check",
        label: "Saved on this device",
        tone: "local",
        title: "This note is not included in encrypted cloud sync."
      };
    }

    if (note.syncBlockedReason) {
      if (note.syncBlockedReason === "record_too_large") {
        return {
          compactLabel: "Too large",
          displayLabel: "Too large to sync",
          icon: "error",
          label: "Too large to sync",
          tone: "error",
          title: "This note is saved on this device, but it is too large for cloud sync."
        };
      }

      if (note.lastSyncedRevisionHash && note.revisionHash && note.lastSyncedRevisionHash !== note.revisionHash) {
        return {
          compactLabel: "Out of date",
          displayLabel: "Cloud out of date",
          icon: "error",
          label: "Cloud out of date",
          tone: "error",
          title: "Latest changes are saved on this device, but they have not synced."
        };
      }

      return {
        compactLabel: "Sync full",
        displayLabel: "Sync limit reached",
        icon: "error",
        label: "Sync limit reached",
        tone: "error",
        title: "This note is saved on this device, but the free cloud sync limit is full."
      };
    }

    if (note.syncState === "pending_upsert" || note.syncState === "pending_delete") {
      return getSyncQueuedStatus();
    }

    if (note.syncState === "synced" && note.revisionHash && note.lastSyncedRevisionHash === note.revisionHash) {
      return {
        compactLabel: "Synced",
        displayLabel: "Cloud synced",
        icon: "check",
        label: "Encrypted changes synced",
        tone: "cloud",
        title: "Encrypted changes are synced"
      };
    }

    return null;
  }

  function getWorkspaceSaveStatus(): NoteSaveStatus {
    if (
      options.getStoragePreference()?.storageMode === "sync_enabled" &&
      options.getCloudConnectionState() === "error" &&
      options.isWalletUnlockRequiredSyncError(options.getCloudStatus())
    ) {
      return {
        compactLabel: "Paused",
        displayLabel: "Sync paused",
        icon: "error",
        label: "Needs new wallet unlock",
        tone: "error",
        title: "Cloud sync needs new wallet unlock. Changes are saved on this device."
      };
    }

    if (options.getStoragePreference()?.storageMode === "sync_enabled" && options.getCloudConnectionState() === "connected" && options.getCloudSession()) {
      return {
        compactLabel: "Synced",
        displayLabel: "Cloud synced",
        icon: "check",
        label: "Encrypted sync on",
        tone: "cloud",
        title: "Encrypted cloud sync is on"
      };
    }

    return {
      compactLabel: LOCAL_STATUS_COMPACT_LABEL,
      displayLabel: LOCAL_STATUS_LABEL,
      icon: "check",
      label: "Saved on this device",
      tone: "local",
      title: "Notes save on this device"
    };
  }

  return {
    clear,
    clearAllAutosaveTimers,
    clearCloudSyncTimer,
    clearNoteAutosaveTimers,
    flushDirtyNotes,
    flushNoteAutosave,
    get activeNoteSaveStatus() {
      return getActiveNoteSaveStatus();
    },
    get saving() {
      return saving;
    },
    getNoteSaveState,
    markNoteDirty,
    removeCloudSyncNoteId,
    removeNoteSaveState,
    resetSavedStates,
    runQueuedCloudSync,
    saveNote,
    scheduleCloudSync,
    scheduleNoteAutosave,
    updateNoteSaveState,
    waitForNoteSave
  };
}
