import { invoke } from "@tauri-apps/api/core";
import { tick } from "svelte";
import {
  APPEARANCE_MODE_STORAGE_KEY,
  DEFAULT_FOLDER_ID,
  DEFAULT_SOURCE_PANEL_WIDTH,
  MAX_SOURCE_PANEL_WIDTH,
  MIN_EDITOR_PANEL_WIDTH,
  MIN_SOURCE_PANEL_WIDTH,
  NOTE_PICKER_RESULT_LIMIT,
  RESIZE_KEY_STEP,
  SOURCE_PANEL_STORAGE_KEY,
  WALLET_SUCCESS_DELAY_MS
} from "./constants";
import {
  clamp,
  delay,
  formatEditorDate,
  getFolderName as getFolderNameFromFolders,
  getNoteTitle,
  sortFolders
} from "./helpers";
import {
  buildCloudSyncSelection,
  encryptedRecordByteLength,
  FREE_SYNC_MAX_NOTES,
  FREE_SYNC_MAX_STORAGE_BYTES,
  updateCloudSyncSelection,
  type CloudSyncSelection
} from "./cloudSyncPreflight";
import { isCloudDiscoveryRunCurrent } from "./cloudDiscoveryRunGuard";
import { shouldSeedInitialNoteAfterOpen as shouldSeedInitialNoteAfterOpenPolicy } from "./cloudBootstrapPolicy";
import { createNotePersistenceController } from "./notePersistence.svelte";
import {
  bookmarkedDocumentNotes,
  canCreateNoteFromPicker as canCreatePickerNote,
  clampPickerIndex,
  countNotesByFolder,
  createFolderMutation,
  createNoteMutation,
  deleteFolderMutation,
  duplicateNoteMutation,
  ensureActiveFolderId,
  ensureInitialNote as ensureInitialDocumentNote,
  ensureWorkspaceTabs as ensureDocumentWorkspaceTabs,
  filteredDocumentNotes,
  getDocumentNoteById,
  moveNoteToFolderMutation,
  notePatchChangesPersistedFields,
  openNoteInActiveTab as openDocumentNoteInActiveTab,
  openNoteInNewTab as openDocumentNoteInNewTab,
  removeNoteFromDocumentTabs,
  renameFolderMutation,
  renameNoteMutation,
  resolveDocumentFolderId,
  searchDocumentNotes,
  toggleBookmarkMutation,
  updateNoteMutation
} from "./workspaceDocument";
import {
  getStorageStatusLabel as getRuntimeStorageStatusLabel,
  type CloudConnectionState,
  type RuntimePatch,
  type VaultWorkspaceData
} from "./vaultWorkspaceRuntime";
import type {
  AppearanceMode,
  CloudSession,
  CloudUsage,
  EncryptedFolder,
  EncryptedNote,
  FolderContextMenu,
  FolderDraft,
  NoteDraft,
  NoteSortMode,
  NoteTab,
  ResizablePanel,
  SourceMode,
  StorageMode,
  UnlockInput,
  UnlockOutput,
  VaultPreference
} from "./types";
import type {
  NotesRuntime,
  LockedAccessViewModel,
  RuntimeContext,
  StorageCloudDiscoveryState,
  StorageOnboardingCommands,
  StorageOnboardingViewModel,
  WorkspaceCommands,
  WorkspaceViewModel
} from "./workspaceTypes";

type WorkspaceControllerOptions = {
  clearWalletSession(): void;
  convexUrl?: string;
  requestWalletUnlock(): void | Promise<void>;
  runtime: NotesRuntime;
};

type CloudSyncSelectionSource = "onboarding" | "settings";
type CloudDownloadState = "idle" | "downloading" | "downloaded";

export function createWorkspaceController(options: WorkspaceControllerOptions) {
  const convexUrl = options.convexUrl;
  const runtime = options.runtime;
  let unlocked = $state(false);
  let vault = $state<UnlockOutput | null>(null);
  let activeFolderId = $state(DEFAULT_FOLDER_ID);
  let sourceMode = $state<SourceMode>("folders");
  let noteTabs = $state<NoteTab[]>([]);
  let activeTabId = $state<string | null>(null);
  let sourceSearchQuery = $state("");
  let notePickerOpen = $state(false);
  let notePickerQuery = $state("");
  let notePickerIndex = $state(0);
  let folders = $state<FolderDraft[]>([]);
  let encryptedFolders = $state<Record<string, EncryptedFolder>>({});
  let notes = $state<NoteDraft[]>([]);
  let encryptedNotes = $state<Record<string, EncryptedNote>>({});
  let titleSelectionNoteId = $state<string | null>(null);
  let sourcePanelWidth = $state(DEFAULT_SOURCE_PANEL_WIDTH);
  let resizingPanel = $state<ResizablePanel | null>(null);
  let status = $state("Vault locked");
  let cloudSession = $state<CloudSession | null>(null);
  let cloudStatus = $state(convexUrl ? "Cloud disconnected" : "Cloud not configured");
  let cloudConnectionState = $state<CloudConnectionState>(convexUrl ? "local_only" : "unconfigured");
  let cloudUsage = $state<CloudUsage | null>(null);
  let cloudBusy = $state(false);
  let storagePreference = $state<VaultPreference | null>(null);
  let storageOnboardingOpen = $state(false);
  let storageBusy = $state(false);
  let cloudDiscovery = $state<StorageCloudDiscoveryState>({ status: "idle" });
  let cloudDownloadState = $state<CloudDownloadState>("idle");
  let cloudDiscoveryRunId = 0;
  let lastUnlockInput = $state<UnlockInput | null>(null);
  let appearanceMode = $state<AppearanceMode>("system");
  let notesShell = $state<HTMLElement | null>(null);
  let editingFolderId = $state<string | null>(null);
  let editingFolderName = $state("");
  let folderContextMenu = $state<FolderContextMenu | null>(null);
  let noteSortMode = $state<NoteSortMode>("updated-desc");
  let cloudSyncSelection = $state<CloudSyncSelection | null>(null);
  let cloudSyncSelectionSource = $state<CloudSyncSelectionSource | null>(null);
  const localOnlyNoteOverrides = new Set<string>();

  const contextMenuFolder = $derived.by(() => {
    const menu = folderContextMenu;
    return menu ? folders.find((folder) => folder.id === menu.folderId) ?? null : null;
  });
  const folderNoteCounts = $derived(countNotesByFolder(folders, notes));
  const canDeleteContextFolder = $derived(
    Boolean(
      contextMenuFolder &&
        contextMenuFolder.id !== DEFAULT_FOLDER_ID &&
        folders.length > 1 &&
        (folderNoteCounts[contextMenuFolder.id] ?? 0) === 0
    )
  );
  const filteredNotes = $derived(
    filteredDocumentNotes({ activeFolderId, folders, notes, sortMode: noteSortMode })
  );
  const sourceSearchResults = $derived(
    searchDocumentNotes({ folders, notes, query: sourceSearchQuery, sortMode: noteSortMode })
  );
  const bookmarkedNotes = $derived(bookmarkedDocumentNotes(notes, noteSortMode));
  const activeTab = $derived(noteTabs.find((tab) => tab.id === activeTabId) ?? null);
  const activeNoteId = $derived(activeTab?.noteId ?? null);
  const activeNote = $derived(notes.find((note) => note.id === activeNoteId) ?? null);
  const activeEditorDate = $derived(activeNote ? formatEditorDate(activeNote.updatedAtMs) : "");
  const notePickerResults = $derived(
    searchDocumentNotes({ folders, notes, query: notePickerQuery, sortMode: noteSortMode }).slice(0, NOTE_PICKER_RESULT_LIMIT)
  );
  const notePickerCanCreate = $derived(canCreatePickerNote(notes, notePickerQuery));
  const panelGridStyle = $derived(`--source-panel-width: ${sourcePanelWidth}px;`);
  const cloudSyncNeedsNewWalletUnlock = $derived(
    storagePreference?.storageMode === "sync_enabled" &&
      cloudConnectionState === "error" &&
      isWalletUnlockRequiredSyncError(cloudStatus)
  );
  const localCloudSyncNoteCount = $derived(
    storagePreference?.storageMode === "sync_enabled"
      ? notes.filter((note) => note.cloudSyncScope !== "local_only" && !note.syncBlockedReason).length
      : 0
  );
  const localCloudSyncStorageBytes = $derived.by(() => {
    if (storagePreference?.storageMode !== "sync_enabled") return 0;

    const syncedNoteIds = new Set(
      notes
        .filter((note) => note.cloudSyncScope !== "local_only" && !note.syncBlockedReason)
        .map((note) => note.id)
    );
    const noteBytes = Array.from(syncedNoteIds).reduce((sum, noteId) => sum + encryptedRecordByteLength(encryptedNotes[noteId]), 0);
    const folderBytes = folders.reduce((sum, folder) => sum + encryptedRecordByteLength(encryptedFolders[folder.id]), 0);
    return noteBytes + folderBytes;
  });
  const storageStatusLabel = $derived(getStorageStatusLabel());
  const storageLockedAccessView = $derived.by((): LockedAccessViewModel | null => {
    if (!storageOnboardingOpen) return null;

    if (cloudDownloadState === "downloading") {
      return blockingLockedAccessView("Downloading encrypted notes");
    }

    if (cloudDownloadState === "downloaded") {
      return blockingLockedAccessView("Encrypted notes downloaded", true);
    }

    if (cloudDiscovery.status === "checking") {
      return blockingLockedAccessView("Checking encrypted cloud sync");
    }

    return null;
  });

  $effect(() => {
    if (!notePickerOpen) return;

    const nextIndex = clampPickerIndex(notePickerIndex, notePickerResults.length);
    if (nextIndex !== notePickerIndex) {
      notePickerIndex = nextIndex;
    }
  });

  const persistence = createNotePersistenceController({
    applyRuntimePatch,
    getActiveNote: () => activeNote,
    getCloudConnectionState: () => cloudConnectionState,
    getCloudSession: () => cloudSession,
    getCloudStatus: () => cloudStatus,
    getEncryptedFolders: () => encryptedFolders,
    getEncryptedNotes: () => encryptedNotes,
    getFolders: () => folders,
    getNotes: () => notes,
    getRuntimeContext,
    getStoragePreference: () => storagePreference,
    isRuntimeContextCurrent,
    isWalletUnlockRequiredSyncError,
    resolveFolderId,
    runtime,
    setCloudBusy: (value) => (cloudBusy = value),
    setCloudConnectionState: (value) => (cloudConnectionState = value),
    setCloudStatus: (value) => (cloudStatus = value),
    setEncryptedNotes: (value) => (encryptedNotes = value),
    setNotes: (value) => (notes = value),
    setStatus: (value) => (status = value)
  });

  function blockingLockedAccessView(message: string, succeeded = false): LockedAccessViewModel {
    return {
      unlocking: false,
      walletCountdownLabel: "",
      walletFlowStarted: true,
      walletHasError: false,
      walletOpeningWorkspace: !succeeded,
      walletQrDataUrl: "",
      walletQrPending: false,
      walletSessionExpired: false,
      walletSessionStarting: false,
      walletStatusMessage: message,
      walletSuccessMessage: message,
      walletUnlockSucceeded: succeeded
    };
  }

  function mount() {
    appearanceMode = readStoredAppearanceMode();
    applyAppearanceMode(appearanceMode);
    sourcePanelWidth = readStoredPanelWidth(SOURCE_PANEL_STORAGE_KEY, DEFAULT_SOURCE_PANEL_WIDTH, MIN_SOURCE_PANEL_WIDTH, MAX_SOURCE_PANEL_WIDTH);
    window.addEventListener("pointermove", resizeActivePanel);
    window.addEventListener("pointerup", stopPanelResize);
    window.addEventListener("click", closeFolderContextMenu);
    window.addEventListener("contextmenu", suppressUnhandledContextMenu);
    window.addEventListener("keydown", handleWindowKeydown);
    window.addEventListener("resize", closeFolderContextMenu);
  }

  function destroy() {
    window.removeEventListener("pointermove", resizeActivePanel);
    window.removeEventListener("pointerup", stopPanelResize);
    window.removeEventListener("click", closeFolderContextMenu);
    window.removeEventListener("contextmenu", suppressUnhandledContextMenu);
    window.removeEventListener("keydown", handleWindowKeydown);
    window.removeEventListener("resize", closeFolderContextMenu);
    persistence.clear();
    document.body.classList.remove("resizing-panels");
  }

  async function acceptWalletUnlock(unlockedVault: UnlockOutput, unlockContext: UnlockInput) {
    vault = unlockedVault;
    lastUnlockInput = unlockContext;
    status = "Vault unlocked";
    storagePreference = await runtime.getVaultPreference(unlockedVault.vaultId);
    return storagePreference;
  }

  function nextCloudDiscoveryRunId() {
    cloudDiscoveryRunId += 1;
    return cloudDiscoveryRunId;
  }

  function invalidateCloudDiscoveryRun() {
    cloudDiscoveryRunId += 1;
  }

  function cloudDiscoveryRunIsCurrent(runId: number, discoveryVault: UnlockOutput, discoveryUnlockInput: UnlockInput) {
    return isCloudDiscoveryRunCurrent(
      {
        runId,
        unlockInput: discoveryUnlockInput,
        vault: discoveryVault
      },
      {
        runId: cloudDiscoveryRunId,
        storageOnboardingOpen,
        unlockInput: lastUnlockInput,
        vault
      }
    );
  }

  async function showStorageOnboarding() {
    storageOnboardingOpen = true;
    await startCloudDiscovery();
  }

  function discardAcceptedWalletUnlock() {
    invalidateCloudDiscoveryRun();
    vault = null;
    storagePreference = null;
    lastUnlockInput = null;
    storageOnboardingOpen = false;
    cloudDownloadState = "idle";
    cloudDiscovery = { status: "idle" };
  }

  async function startCloudDiscovery() {
    cloudDownloadState = "idle";

    if (!vault || !lastUnlockInput || !convexUrl) {
      invalidateCloudDiscoveryRun();
      cloudDiscovery = { status: "idle" };
      status = "Choose encrypted storage";
      return;
    }

    const discoveryVault = vault;
    const discoveryUnlockInput = lastUnlockInput;
    const runId = nextCloudDiscoveryRunId();
    cloudDiscovery = { status: "checking" };
    storageBusy = true;
    status = "Checking encrypted cloud sync";

    try {
      const result = await runtime.detectCloudReplica(discoveryVault, discoveryUnlockInput);
      if (!cloudDiscoveryRunIsCurrent(runId, discoveryVault, discoveryUnlockInput)) return;
      if (result.status === "found") {
        cloudDiscovery = {
          liveFolderCount: result.liveFolderCount,
          liveNoteCount: result.liveNoteCount,
          status: "found"
        };
        status = "Encrypted cloud sync found";
        return;
      }

      if (result.status === "empty") {
        cloudDiscovery = { status: "empty" };
        status = "Choose encrypted storage";
        return;
      }

      cloudDiscovery = {
        error: result.error,
        status: "error"
      };
      status = "Cloud sync could not be checked";
    } catch (error) {
      if (!cloudDiscoveryRunIsCurrent(runId, discoveryVault, discoveryUnlockInput)) return;
      cloudDiscovery = {
        error: error instanceof Error ? error.message : String(error),
        status: "error"
      };
      status = "Cloud sync could not be checked";
    } finally {
      if (cloudDiscoveryRunIsCurrent(runId, discoveryVault, discoveryUnlockInput)) {
        storageBusy = false;
      }
    }
  }

  async function chooseStorageMode(storageMode: StorageMode) {
    if (!vault || !lastUnlockInput) return;
    if (storageMode === "sync_enabled" && !convexUrl) {
      cloudConnectionState = "unconfigured";
      cloudStatus = "Cloud not configured";
      status = "Cloud sync is not configured";
      return;
    }

    if (storageMode === "sync_enabled") {
      await startEnableEncryptedSync("onboarding");
      return;
    }

    await chooseLocalStorageMode(storageMode);
  }

  async function enableFoundCloudSync() {
    if (!vault || !lastUnlockInput) return;

    storageBusy = true;
    cloudDownloadState = "downloading";
    status = "Downloading encrypted notes";

    try {
      const result = await runtime.enableFoundCloudSync(vault, lastUnlockInput);
      applyRuntimePatch(result);
      cloudDownloadState = "downloaded";
      status = "Encrypted notes downloaded";
      await delay(WALLET_SUCCESS_DELAY_MS);
      const initialNoteId = ensureInitialNoteAfterOpen(result);
      unlocked = true;
      if (initialNoteId) persistence.scheduleNoteAutosave(initialNoteId);
      invalidateCloudDiscoveryRun();
      storageOnboardingOpen = false;
      cloudDiscovery = { status: "idle" };
      cloudDownloadState = "idle";
      status = result.status ?? getStorageStatusLabel();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      cloudDiscovery = {
        error: message,
        status: "error"
      };
      status = "Cloud sync could not be downloaded";
      cloudDownloadState = "idle";
    } finally {
      storageBusy = false;
    }
  }

  async function chooseLocalStorageMode(storageMode: StorageMode) {
    if (!vault || !lastUnlockInput) return;
    storageBusy = true;
    cloudDownloadState = "idle";
    status = "Preparing encrypted storage";

    try {
      storagePreference = await runtime.setStorageModePreference(vault.vaultId, storageMode);
      await openUnlockedWorkspace(lastUnlockInput, vault, storagePreference);
      invalidateCloudDiscoveryRun();
      storageOnboardingOpen = false;
      cloudDiscovery = { status: "idle" };
    } catch (error) {
      status = error instanceof Error ? error.message : String(error);
    } finally {
      storageBusy = false;
    }
  }

  async function openUnlockedWorkspace(input: UnlockInput, unlockedVault: UnlockOutput, preference: VaultPreference) {
    status = "Loading encrypted local notes";
    const result = await runtime.openWorkspace({ preference, unlockInput: input, vault: unlockedVault });
    applyRuntimePatch(result);
    const initialNoteId = ensureInitialNoteAfterOpen(result);
    unlocked = true;
    if (initialNoteId) persistence.scheduleNoteAutosave(initialNoteId);
    status = result.status ?? getStorageStatusLabel();
  }

  function applyRuntimePatch(patch: RuntimePatch, preferredNoteId: string | null = activeNoteId) {
    if ("storagePreference" in patch) storagePreference = patch.storagePreference ?? null;
    if ("cloudSession" in patch) cloudSession = patch.cloudSession ?? null;
    if ("cloudUsage" in patch) cloudUsage = patch.cloudUsage ?? null;
    if (patch.cloudStatus !== undefined) cloudStatus = patch.cloudStatus;
    if (patch.cloudConnectionState !== undefined) cloudConnectionState = patch.cloudConnectionState;
    if (patch.data) applyWorkspaceData(applyLocalOnlyOverrides(patch.data), preferredNoteId);
    if (patch.status !== undefined) status = patch.status;
  }

  function applyLocalOnlyOverrides(data: VaultWorkspaceData) {
    if (localOnlyNoteOverrides.size === 0) return data;

    let changed = false;
    const nextNotes = data.notes.map((note) => {
      if (!localOnlyNoteOverrides.has(note.id)) return note;
      changed = true;
      return {
        ...note,
        cloudSyncScope: "local_only" as const,
        lastSyncedRevisionHash: null,
        syncBlockedReason: null,
        syncState: "not_synced" as const
      };
    });

    return changed ? { ...data, notes: nextNotes } : data;
  }

  function applyWorkspaceData(data: VaultWorkspaceData, preferredNoteId: string | null = activeNoteId) {
    storagePreference = data.preference ?? storagePreference;
    folders = data.folders;
    encryptedFolders = data.encryptedFolders;
    ensureActiveFolder();
    notes = data.notes;
    encryptedNotes = data.encryptedNotes;
    persistence.resetSavedStates(data.notes);
    const preferred =
      preferredNoteId && notes.some((note) => note.id === preferredNoteId)
        ? preferredNoteId
        : notes.find((note) => resolveFolderId(note.folderId) === activeFolderId)?.id ?? notes[0]?.id ?? null;
    ensureWorkspaceTabs(preferred);
  }

  function getRuntimeContext(): RuntimeContext | null {
    if (!vault || !lastUnlockInput) return null;

    return {
      cloudSession,
      storagePreference,
      unlockInput: lastUnlockInput,
      vault
    };
  }

  function isRuntimeContextCurrent(context: RuntimeContext) {
    const current = getRuntimeContext();
    return Boolean(current && current.vault === context.vault && current.unlockInput === context.unlockInput);
  }

  function ensureInitialNote() {
    if (notes.length !== 0) {
      ensureWorkspaceTabs(notes[0]?.id ?? null);
      return null;
    }

    const result = ensureInitialDocumentNote({
      activeFolderId,
      createNoteId: createRandomId,
      createTabId: createRandomId,
      notes,
      now: Date.now()
    });
    if (!result) return null;
    notes = result.notes;
    noteTabs = result.noteTabs;
    activeTabId = result.activeTabId;
    return result.note.id;
  }

  function ensureInitialNoteAfterOpen(result: RuntimePatch) {
    if (shouldSeedInitialNote(result)) return ensureInitialNote();

    ensureWorkspaceTabs(notes[0]?.id ?? null);
    return null;
  }

  function shouldSeedInitialNote(result: RuntimePatch) {
    return shouldSeedInitialNoteAfterOpenPolicy({
      cloudReplica: result.cloudReplica,
      noteCount: notes.length,
      storageMode: storagePreference?.storageMode
    });
  }

  async function lockVault() {
    closeFolderContextMenu();
    closeNotePicker();
    cancelFolderRename();

    const flushed = await persistence.flushDirtyNotes();
    if (!flushed) {
      status = "Save failed";
      return;
    }

    try {
      await invoke("lock_vault");
    } catch (error) {
      status = error instanceof Error ? error.message : String(error);
      return;
    }

    persistence.clear();
    resetWorkspaceState();
    options.clearWalletSession();
    status = "Vault locked";
  }

  async function reconnectCloudSync() {
    if (!unlocked) return;

    status = "Preparing new wallet unlock";
    await lockVault();
    if (unlocked) return;

    await tick();
    await options.requestWalletUnlock();
  }

  async function retryCloudSync() {
    const runtimeContext = getRuntimeContext();
    if (!runtimeContext) return;
    if (!runtimeContext.cloudSession) {
      await enableEncryptedSync();
      return;
    }

    cloudBusy = true;
    cloudStatus = "Syncing";
    cloudConnectionState = "syncing";

    try {
      const result = await runtime.syncCloudReplica(runtimeContext);
      applyRuntimePatch(result);
    } catch (error) {
      cloudStatus = error instanceof Error ? error.message : String(error);
      cloudConnectionState = "error";
    } finally {
      cloudBusy = false;
    }
  }

  async function repairCloudSync() {
    const runtimeContext = getRuntimeContext();
    if (!runtimeContext) return;

    cloudBusy = true;
    cloudStatus = "Repairing cloud sync";
    cloudConnectionState = "syncing";
    status = "Repairing cloud sync";

    try {
      const flushed = await flushWorkspaceForCloudSync();
      if (!flushed) {
        status = "Save failed";
        return;
      }

      const result = await runtime.repairCloudSync(runtimeContext);
      applyRuntimePatch(result);
    } catch (error) {
      cloudStatus = error instanceof Error ? error.message : String(error);
      cloudConnectionState = "error";
    } finally {
      cloudBusy = false;
    }
  }

  function setNotesShell(element: HTMLElement | null) {
    notesShell = element;
  }

  function getFolderName(folderId: string) {
    return getFolderNameFromFolders(folders, folderId);
  }

  function createRandomId() {
    return crypto.randomUUID();
  }

  function ensureWorkspaceTabs(preferredNoteId: string | null = null) {
    const result = ensureDocumentWorkspaceTabs({
      activeTabId,
      createTabId: createRandomId,
      noteTabs,
      notes,
      preferredNoteId
    });
    noteTabs = result.noteTabs;
    activeTabId = result.activeTabId;
  }

  function createBlankTab() {
    const tab: NoteTab = { id: createRandomId(), noteId: null };
    noteTabs = [...noteTabs, tab];
    activeTabId = tab.id;
    closeNotePicker();
  }

  async function activateTab(tabId: string) {
    if (!noteTabs.some((tab) => tab.id === tabId)) return;
    if (activeTabId === tabId) return;

    if (activeNoteId) await persistence.flushNoteAutosave(activeNoteId);
    activeTabId = tabId;
    closeNotePicker();
  }

  function handleTabKeydown(event: KeyboardEvent, tabId: string) {
    if (event.key !== "Enter" && event.key !== " ") return;

    event.preventDefault();
    void activateTab(tabId);
  }

  async function closeTab(tabId: string) {
    const tabIndex = noteTabs.findIndex((tab) => tab.id === tabId);
    if (tabIndex === -1) return;

    const closingNoteId = noteTabs[tabIndex]?.noteId ?? null;
    if (closingNoteId) await persistence.flushNoteAutosave(closingNoteId);

    const closingActiveTab = activeTabId === tabId;
    const nextTabs = noteTabs.filter((tab) => tab.id !== tabId);

    if (nextTabs.length === 0) {
      const tab: NoteTab = { id: createRandomId(), noteId: null };
      noteTabs = [tab];
      activeTabId = tab.id;
      closeNotePicker();
      return;
    }

    noteTabs = nextTabs;

    if (closingActiveTab) {
      activeTabId = nextTabs[Math.min(tabIndex, nextTabs.length - 1)]?.id ?? nextTabs[0]?.id ?? null;
    }

    closeNotePicker();
  }

  function closeActiveTab() {
    if (!activeTabId) return;
    void closeTab(activeTabId);
  }

  function getTabTitle(tab: NoteTab) {
    if (!tab.noteId) return "New tab";

    const note = getDocumentNoteById(notes, tab.noteId);
    return getNoteTitle(note);
  }

  async function openNoteInActiveTab(noteId: string) {
    if (activeNoteId && activeNoteId !== noteId) {
      await persistence.flushNoteAutosave(activeNoteId);
    }

    const result = openDocumentNoteInActiveTab({
      activeTabId,
      createTabId: createRandomId,
      folders,
      noteId,
      notes,
      noteTabs
    });
    if (!result) return;

    noteTabs = result.noteTabs;
    activeTabId = result.activeTabId;
    activeFolderId = result.activeFolderId;
    closeNotePicker();
  }

  async function openNoteInNewTab(noteId: string) {
    if (activeNoteId && activeNoteId !== noteId) {
      await persistence.flushNoteAutosave(activeNoteId);
    }

    const result = openDocumentNoteInNewTab({
      createTabId: createRandomId,
      folders,
      noteId,
      notes,
      noteTabs
    });
    if (!result) return;

    noteTabs = result.noteTabs;
    activeTabId = result.activeTabId;
    activeFolderId = result.activeFolderId;
    closeNotePicker();
  }

  function removeNoteFromTabs(noteId: string) {
    const result = removeNoteFromDocumentTabs({
      activeTabId,
      createTabId: createRandomId,
      noteId,
      notes,
      noteTabs
    });
    noteTabs = result.noteTabs;
    activeTabId = result.activeTabId;
  }

  function setSourceMode(mode: SourceMode) {
    sourceMode = mode;
    closeFolderContextMenu();
  }

  function isNoteBookmarked(noteId: string) {
    return Boolean(getDocumentNoteById(notes, noteId)?.bookmarked);
  }

  async function toggleBookmark(noteId: string) {
    const result = toggleBookmarkMutation(notes, noteId, Date.now());
    if (!result) return;

    notes = result.notes;
    await persistence.saveNote(result.note);
  }

  async function renameNote(noteId: string, title: string) {
    const result = renameNoteMutation(notes, noteId, title, Date.now());
    if (!result) return;

    notes = result.notes;
    await persistence.saveNote(result.note);
  }

  function openNotePicker() {
    if (!unlocked) return;

    notePickerOpen = true;
    notePickerQuery = "";
    notePickerIndex = 0;
  }

  function closeNotePicker() {
    notePickerOpen = false;
    notePickerQuery = "";
    notePickerIndex = 0;
  }

  function setNotePickerQuery(query: string) {
    notePickerQuery = query;
    notePickerIndex = clampPickerIndex(notePickerIndex, notePickerResults.length);
  }

  function setNotePickerIndex(index: number) {
    notePickerIndex = clampPickerIndex(index, notePickerResults.length);
  }

  function createNoteFromPicker() {
    const title = notePickerQuery.trim();
    createNote(title || "Untitled", { autosave: true });
    closeNotePicker();
  }

  function handleNotePickerKeydown(event: KeyboardEvent) {
    if (event.key === "Escape") {
      event.preventDefault();
      closeNotePicker();
      return;
    }

    if (event.key === "ArrowDown") {
      event.preventDefault();
      notePickerIndex = Math.min(notePickerIndex + 1, Math.max(0, notePickerResults.length - 1));
      return;
    }

    if (event.key === "ArrowUp") {
      event.preventDefault();
      notePickerIndex = Math.max(0, notePickerIndex - 1);
      return;
    }

    if (event.key !== "Enter") return;

    event.preventDefault();
    const note = notePickerResults[notePickerIndex];
    if (note) {
      void openNoteInActiveTab(note.id);
      return;
    }

    if (notePickerCanCreate) {
      createNoteFromPicker();
    }
  }

  function readStoredPanelWidth(storageKey: string, fallback: number, min: number, max: number) {
    const stored = Number(localStorage.getItem(storageKey));
    return Number.isFinite(stored) ? clamp(stored, min, max) : fallback;
  }

  function readStoredAppearanceMode(): AppearanceMode {
    const stored = localStorage.getItem(APPEARANCE_MODE_STORAGE_KEY);
    if (stored === "light" || stored === "dark" || stored === "system") return stored;
    return "system";
  }

  function setAppearanceMode(mode: AppearanceMode) {
    appearanceMode = mode;
    applyAppearanceMode(mode);
    localStorage.setItem(APPEARANCE_MODE_STORAGE_KEY, mode);
  }

  function applyAppearanceMode(mode: AppearanceMode) {
    if (mode === "system") {
      document.documentElement.removeAttribute("data-theme");
      return;
    }

    document.documentElement.dataset.theme = mode;
  }

  function persistPanelWidths() {
    localStorage.setItem(SOURCE_PANEL_STORAGE_KEY, String(Math.round(sourcePanelWidth)));
  }

  function getResizeBounds(_panel: ResizablePanel) {
    const shellWidth = notesShell?.getBoundingClientRect().width ?? 0;
    const maxByShell = shellWidth - MIN_EDITOR_PANEL_WIDTH;
    return {
      min: MIN_SOURCE_PANEL_WIDTH,
      max: Math.max(MIN_SOURCE_PANEL_WIDTH, Math.min(MAX_SOURCE_PANEL_WIDTH, maxByShell))
    };
  }

  function setPanelWidth(panel: ResizablePanel, width: number) {
    const bounds = getResizeBounds(panel);
    const nextWidth = clamp(width, bounds.min, bounds.max);

    sourcePanelWidth = nextWidth;

    persistPanelWidths();
  }

  function startPanelResize(panel: ResizablePanel, event: PointerEvent) {
    event.preventDefault();
    resizingPanel = panel;
    document.body.classList.add("resizing-panels");
    event.currentTarget instanceof HTMLElement && event.currentTarget.setPointerCapture(event.pointerId);
  }

  function resizeActivePanel(event: PointerEvent) {
    if (!resizingPanel || !notesShell) return;

    const shellLeft = notesShell.getBoundingClientRect().left;

    setPanelWidth("source", event.clientX - shellLeft);
  }

  function stopPanelResize() {
    if (!resizingPanel) return;

    resizingPanel = null;
    document.body.classList.remove("resizing-panels");
  }

  function resizePanelWithKeyboard(panel: ResizablePanel, event: KeyboardEvent) {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;

    event.preventDefault();
    const direction = event.key === "ArrowRight" ? 1 : -1;
    const step = event.shiftKey ? RESIZE_KEY_STEP * 3 : RESIZE_KEY_STEP;
    setPanelWidth(panel, sourcePanelWidth + direction * step);
  }

  function ensureActiveFolder() {
    activeFolderId = ensureActiveFolderId(folders, activeFolderId);
  }

  function resolveFolderId(folderId: string | undefined) {
    return resolveDocumentFolderId(folders, folderId);
  }

  function selectFolder(folderId: string) {
    closeFolderContextMenu();
    activeFolderId = folderId;
    sourceMode = "folders";
  }

  function beginFolderRename(folderId: string) {
    const folder = folders.find((candidate) => candidate.id === folderId);
    if (!folder) return;

    closeFolderContextMenu();
    activeFolderId = folder.id;
    editingFolderName = folder.name;
    editingFolderId = folder.id;
  }

  function cancelFolderRename() {
    editingFolderId = null;
    editingFolderName = "";
  }

  async function finishFolderRename() {
    const result = renameFolderMutation({
      editingName: editingFolderName,
      folderId: editingFolderId,
      folders,
      now: Date.now()
    });

    cancelFolderRename();

    if (result.status !== "ok") return;

    folders = result.folders;

    try {
      await saveFolder(result.folder);
    } catch (error) {
      status = error instanceof Error ? error.message : String(error);
    }
  }

  function setEditingFolderName(name: string) {
    editingFolderName = name;
  }

  function handleFolderRenameKeydown(event: KeyboardEvent) {
    event.stopPropagation();

    if (event.key === "Enter") {
      event.preventDefault();
      void finishFolderRename();
      return;
    }

    if (event.key === "Escape") {
      event.preventDefault();
      cancelFolderRename();
    }
  }

  function handleFolderRowKeydown(event: KeyboardEvent, folderId: string) {
    if (event.key !== "Enter" && event.key !== " ") return;

    event.preventDefault();
    selectFolder(folderId);
  }

  function openFolderContextMenu(event: MouseEvent, folderId: string) {
    event.preventDefault();
    event.stopPropagation();
    document.getSelection()?.removeAllRanges();

    selectFolder(folderId);

    const menuWidth = 188;
    const menuHeight = 166;
    folderContextMenu = {
      folderId,
      x: clamp(event.clientX, 8, window.innerWidth - menuWidth - 8),
      y: clamp(event.clientY, 8, window.innerHeight - menuHeight - 8)
    };
  }

  function closeFolderContextMenu() {
    folderContextMenu = null;
  }

  function suppressUnhandledContextMenu(event: MouseEvent) {
    if (isNativeTextContextMenuTarget(event.target)) {
      closeFolderContextMenu();
      return;
    }

    event.preventDefault();
    closeFolderContextMenu();
    document.getSelection()?.removeAllRanges();
  }

  function isNativeTextContextMenuTarget(target: EventTarget | null) {
    const element = target instanceof Element ? target : target instanceof Node ? target.parentElement : null;
    return Boolean(element?.closest('input:not([type="button"]), textarea, [contenteditable="true"], [contenteditable="plaintext-only"]'));
  }

  function handleWindowKeydown(event: KeyboardEvent) {
    if (event.key === "Escape" && notePickerOpen) {
      closeNotePicker();
      return;
    }

    if (event.key === "Escape") {
      closeFolderContextMenu();
      return;
    }

    if (!unlocked || !event.metaKey || event.altKey || event.ctrlKey) return;

    const key = event.key.toLowerCase();

    if (key === "n") {
      event.preventDefault();
      createNote();
      return;
    }

    if (key === "o") {
      event.preventDefault();
      openNotePicker();
      return;
    }

    if (key === "s") {
      event.preventDefault();
      void saveActiveNote();
      return;
    }

    if (key === "w") {
      event.preventDefault();
      closeActiveTab();
    }
  }

  function createFolderFromContextMenu() {
    closeFolderContextMenu();
    void createFolder();
  }

  function deleteFolderFromContextMenu() {
    const folder = contextMenuFolder;
    if (!folder) return;

    closeFolderContextMenu();
    void deleteFolder(folder.id);
  }

  function setNoteSortMode(mode: NoteSortMode) {
    noteSortMode = mode;
    closeFolderContextMenu();
  }

  async function createFolder(editAfterCreate = true) {
    if (!vault) return;

    const result = createFolderMutation({
      folders,
      id: createRandomId(),
      now: Date.now()
    });
    if (result.status !== "ok") return;

    folders = result.folders;
    activeFolderId = result.folder.id;
    sourceMode = "folders";

    try {
      await saveFolder(result.folder);
      if (editAfterCreate) beginFolderRename(result.folder.id);
    } catch (error) {
      status = error instanceof Error ? error.message : String(error);
    }
  }

  async function deleteFolder(folderId: string) {
    const runtimeContext = getRuntimeContext();
    if (!runtimeContext) return;

    const result = deleteFolderMutation({
      activeFolderId,
      folderId,
      folders,
      notes
    });

    if (result.status === "default-folder") {
      status = "Default folder cannot be deleted";
      return;
    }
    if (result.status === "folder-has-notes") {
      status = "Move notes before deleting this folder";
      return;
    }
    if (result.status !== "ok") return;

    try {
      const patch = await runtime.deleteFolder(runtimeContext, folderId);
      folders = folders.filter((folder) => folder.id !== folderId);
      activeFolderId = ensureActiveFolderId(folders, activeFolderId);
      const nextEncryptedFolders = { ...encryptedFolders };
      delete nextEncryptedFolders[folderId];
      encryptedFolders = nextEncryptedFolders;
      applyRuntimePatch(patch);
    } catch (error) {
      status = error instanceof Error ? error.message : String(error);
    }
  }

  async function saveFolder(folder: FolderDraft) {
    const runtimeContext = getRuntimeContext();
    if (!runtimeContext) return;

    const result = await runtime.saveFolder({
      context: runtimeContext,
      encryptedFolders,
      folder
    });
    encryptedFolders = { ...encryptedFolders, [folder.id]: result.encryptedFolder };
    applyRuntimePatch(result);
  }

  function createNote(title = "Untitled", options: { autosave?: boolean } = {}) {
    if (!unlocked) return;

    const result = createNoteMutation({
      activeFolderId,
      id: createRandomId(),
      notes,
      now: Date.now(),
      title
    });
    notes = result.notes;
    if (result.shouldSelectTitle) titleSelectionNoteId = result.note.id;
    void openNoteInActiveTab(result.note.id);

    persistence.scheduleNoteAutosave(result.note.id, options.autosave ? 0 : undefined);
  }

  function clearTitleSelectionRequest(noteId: string) {
    if (titleSelectionNoteId === noteId) titleSelectionNoteId = null;
  }

  async function duplicateNote(noteId: string) {
    if (!unlocked) return;

    const result = duplicateNoteMutation({
      id: createRandomId(),
      noteId,
      notes,
      now: Date.now(),
      folders
    });
    if (!result) return;

    notes = result.notes;
    await persistence.saveNote(result.note);
  }

  async function deleteNote(noteId: string) {
    const runtimeContext = getRuntimeContext();
    if (!runtimeContext) return;

    try {
      persistence.clearNoteAutosaveTimers(noteId);
      await persistence.waitForNoteSave(noteId);
      const result = await runtime.deleteNote(runtimeContext, noteId, Boolean(encryptedNotes[noteId]));
      notes = notes.filter((note) => note.id !== noteId);
      const nextEncrypted = { ...encryptedNotes };
      delete nextEncrypted[noteId];
      encryptedNotes = nextEncrypted;
      localOnlyNoteOverrides.delete(noteId);
      persistence.removeNoteSaveState(noteId);
      persistence.removeCloudSyncNoteId(noteId);
      removeNoteFromTabs(noteId);
      applyRuntimePatch(result);
    } catch (error) {
      status = error instanceof Error ? error.message : String(error);
    }
  }

  function updateActiveNote(patch: Partial<NoteDraft>) {
    if (!activeNote || !notePatchChangesPersistedFields(activeNote, patch)) return;

    const result = updateNoteMutation({
      activeNoteId,
      notes,
      now: Date.now(),
      patch
    });
    notes = result.notes;

    if (result.updatedNoteId) {
      persistence.scheduleNoteAutosave(result.updatedNoteId);
    }
  }

  async function includeNoteInCloudSync(noteId: string) {
    const runtimeContext = getRuntimeContext();
    if (!runtimeContext) return;
    localOnlyNoteOverrides.delete(noteId);
    await persistence.waitForNoteSave(noteId);
    const result = await runtime.includeNoteInCloudSync(runtimeContext, noteId);
    applyRuntimePatch(result);
    persistence.scheduleCloudSync(noteId);
    await persistence.runQueuedCloudSync();
  }

  async function removeNoteFromCloudSync(noteId: string) {
    const runtimeContext = getRuntimeContext();
    if (!runtimeContext) return;
    localOnlyNoteOverrides.add(noteId);
    persistence.removeCloudSyncNoteId(noteId);
    try {
      await persistence.flushNoteAutosave(noteId, { force: true });
      const result = await runtime.removeNoteFromCloudSync(runtimeContext, noteId);
      applyRuntimePatch(result);
      persistence.updateNoteSaveState(noteId, {
        syncError: null,
        syncPending: false,
        syncing: false
      });
    } catch (error) {
      localOnlyNoteOverrides.delete(noteId);
      status = error instanceof Error ? error.message : String(error);
    }
  }

  async function retryNoteSync(noteId: string) {
    await includeNoteInCloudSync(noteId);
  }

  async function saveActiveNote() {
    if (!activeNote) return;
    await persistence.flushNoteAutosave(activeNote.id, { force: true });
  }

  async function exportActiveNoteMarkdown() {
    if (!activeNote) return;

    try {
      const result = await runtime.exportMarkdownNote(activeNote);
      applyRuntimePatch(result);
    } catch (error) {
      status = error instanceof Error ? error.message : String(error);
    }
  }

  async function saveNote(note: NoteDraft) {
    await persistence.saveNote(note);
  }

  async function moveActiveNoteToFolder(folderId: string) {
    const result = moveNoteToFolderMutation({
      activeNote,
      folderId,
      folders,
      notes,
      now: Date.now()
    });
    if (!result) return;

    notes = result.notes;
    activeFolderId = folderId;
    await saveNote(result.note);
  }

  async function enableEncryptedSync() {
    await startEnableEncryptedSync("settings");
  }

  async function startEnableEncryptedSync(source: CloudSyncSelectionSource) {
    if (!vault || !lastUnlockInput) return;
    if (!convexUrl) {
      cloudConnectionState = "unconfigured";
      cloudStatus = "Cloud not configured";
      status = "Cloud sync is not configured";
      return;
    }

    setCloudSyncBusy(source, true);
    status = "Saving notes before cloud sync";

    try {
      const data = await currentWorkspaceDataForCloudPreflight();
      status = "Checking cloud sync quota";
      const selection = buildCloudSyncSelection({
        encryptedFolders: data.encryptedFolders,
        encryptedNotes: data.encryptedNotes,
        folders: data.folders,
        maxNotes: cloudUsage?.maxSyncedNotes ?? FREE_SYNC_MAX_NOTES,
        maxStorageBytes: cloudUsage?.maxStorageBytes ?? FREE_SYNC_MAX_STORAGE_BYTES,
        notes: data.notes
      });

      if (selection.requiresReview) {
        cloudSyncSelection = selection;
        cloudSyncSelectionSource = source;
        status = "Choose notes to sync";
        return;
      }

      await performEnableEncryptedSync(selection.selectedNoteIds, source);
    } catch (error) {
      status = error instanceof Error ? error.message : String(error);
    } finally {
      setCloudSyncBusy(source, false);
    }
  }

  async function currentWorkspaceDataForCloudPreflight(): Promise<VaultWorkspaceData> {
    if (!vault) {
      return {
        encryptedFolders,
        encryptedNotes,
        folders,
        notes,
        preference: storagePreference
      };
    }

    if (unlocked) {
      const flushed = await flushWorkspaceForCloudSync();
      if (!flushed) throw new Error("Save failed");
    }

    return await runtime.loadLocalVault(vault.vaultId, storagePreference);
  }

  async function flushWorkspaceForCloudSync() {
    if (!unlocked) return true;
    for (const note of notes) {
      if (!encryptedNotes[note.id]) {
        persistence.markNoteDirty(note.id);
      }
    }
    return await persistence.flushDirtyNotes();
  }

  async function performEnableEncryptedSync(includedNoteIds: string[], source: CloudSyncSelectionSource) {
    if (!vault || !lastUnlockInput) return;

    cloudBusy = true;
    cloudStatus = "Saving notes";

    try {
      const flushed = await flushWorkspaceForCloudSync();
      if (!flushed) {
        status = "Save failed";
        return;
      }

      cloudStatus = "Connecting cloud";
      cloudConnectionState = "connecting";
      const result = await runtime.enableEncryptedSync(
        vault,
        lastUnlockInput,
        includedNoteIds
      );
      applyRuntimePatch(result);
      if (source === "onboarding" && result.data) {
        const initialNoteId = ensureInitialNoteAfterOpen(result);
        unlocked = true;
        if (initialNoteId) persistence.scheduleNoteAutosave(initialNoteId);
        invalidateCloudDiscoveryRun();
        storageOnboardingOpen = false;
        cloudDiscovery = { status: "idle" };
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      cloudConnectionState = "error";
      cloudStatus = message;
      status = message;
    } finally {
      cloudBusy = false;
    }
  }

  async function confirmCloudSyncSelection() {
    if (!cloudSyncSelection || !cloudSyncSelectionSource) return;
    const selectedNoteIds = [...cloudSyncSelection.selectedNoteIds];
    const source = cloudSyncSelectionSource;
    cloudSyncSelection = null;
    cloudSyncSelectionSource = null;
    setCloudSyncBusy(source, true);
    try {
      await performEnableEncryptedSync(selectedNoteIds, source);
    } finally {
      setCloudSyncBusy(source, false);
    }
  }

  async function keepCloudSyncSelectionLocal() {
    const source = cloudSyncSelectionSource;
    cloudSyncSelection = null;
    cloudSyncSelectionSource = null;
    if (source === "onboarding") {
      await chooseLocalStorageMode("local_only");
      return;
    }
    status = "This device only";
  }

  function cancelCloudSyncSelection() {
    cloudSyncSelection = null;
    cloudSyncSelectionSource = null;
  }

  function toggleCloudSyncSelectionNote(noteId: string, selected: boolean) {
    if (!cloudSyncSelection) return;
    cloudSyncSelection = updateCloudSyncSelection(cloudSyncSelection, noteId, selected);
  }

  function setCloudSyncBusy(source: CloudSyncSelectionSource, value: boolean) {
    if (source === "onboarding") {
      storageBusy = value;
    } else {
      cloudBusy = value;
    }
  }

  async function stopSyncingThisDevice() {
    if (!vault) return;

    try {
      const result = await runtime.stopSyncingThisDevice(vault);
      applyRuntimePatch(result);
    } catch (error) {
      status = error instanceof Error ? error.message : String(error);
    }
  }

  async function deleteCloudCopy() {
    const runtimeContext = getRuntimeContext();
    if (!runtimeContext) return;

    cloudBusy = true;
    cloudConnectionState = "syncing";
    try {
      const result = await runtime.deleteCloudCopy(runtimeContext);
      applyRuntimePatch(result);
    } catch (error) {
      cloudStatus = error instanceof Error ? error.message : String(error);
      cloudConnectionState = "error";
    } finally {
      cloudBusy = false;
    }
  }

  async function exportEncryptedBackup() {
    if (!vault) return;

    try {
      const result = await runtime.exportEncryptedBackup(vault);
      applyRuntimePatch(result);
    } catch (error) {
      status = error instanceof Error ? error.message : String(error);
    }
  }

  async function importBackup() {
    const runtimeContext = getRuntimeContext();
    if (!runtimeContext) return;

    try {
      const result = await runtime.importBackup(runtimeContext);
      applyRuntimePatch(result);
    } catch (error) {
      status = error instanceof Error ? error.message : String(error);
    }
  }

  function getStorageStatusLabel() {
    if (cloudSyncNeedsNewWalletUnlock) return "Needs new wallet unlock";

    return getRuntimeStorageStatusLabel({
      cloudBusy,
      cloudConnectionState,
      cloudSession,
      convexUrl,
      storagePreference
    });
  }

  function isWalletUnlockRequiredSyncError(message: string | null | undefined) {
    const lower = message?.toLowerCase();
    return Boolean(
      lower?.includes("wallet unlock required") ||
        lower?.includes("signer attestation rejected: 409") ||
        lower?.includes("signer attestation rejected: 410") ||
        lower?.includes("cloud attestation already consumed") ||
        lower?.includes("signer session attestation expired")
    );
  }

  function resetWorkspaceState() {
    invalidateCloudDiscoveryRun();
    unlocked = false;
    vault = null;
    cloudSession = null;
    cloudUsage = null;
    cloudStatus = convexUrl ? "Cloud disconnected" : "Cloud not configured";
    cloudConnectionState = convexUrl ? "local_only" : "unconfigured";
    storagePreference = null;
    storageOnboardingOpen = false;
    storageBusy = false;
    cloudDiscovery = { status: "idle" };
    cloudDownloadState = "idle";
    cloudSyncSelection = null;
    cloudSyncSelectionSource = null;
    lastUnlockInput = null;
    activeFolderId = DEFAULT_FOLDER_ID;
    sourceMode = "folders";
    noteTabs = [];
    activeTabId = null;
    titleSelectionNoteId = null;
    sourceSearchQuery = "";
    folders = [];
    encryptedFolders = {};
    notes = [];
    encryptedNotes = {};
    localOnlyNoteOverrides.clear();
    folderContextMenu = null;
    editingFolderId = null;
    editingFolderName = "";
    notePickerOpen = false;
    notePickerQuery = "";
    notePickerIndex = 0;
  }

  function returnToOnboarding(shouldLockVault: boolean) {
    invalidateCloudDiscoveryRun();
    storageOnboardingOpen = false;
    storageBusy = false;
    cloudDiscovery = { status: "idle" };
    cloudDownloadState = "idle";
    cloudSyncSelection = null;
    cloudSyncSelectionSource = null;
    storagePreference = null;
    lastUnlockInput = null;
    titleSelectionNoteId = null;
    status = "Vault locked";

    if (shouldLockVault) {
      vault = null;
      void invoke("lock_vault").catch(() => undefined);
    }
  }

  function setStatus(message: string) {
    status = message;
  }

  const storageView: StorageOnboardingViewModel = {
    get busy() {
      return storageBusy;
    },
    get cloudDiscovery() {
      return cloudDiscovery;
    },
    get cloudSyncSelection() {
      return cloudSyncSelection;
    },
    get status() {
      return status;
    },
    get canUseCloud() {
      return Boolean(convexUrl);
    },
    get connectedVerusIdAddress() {
      return lastUnlockInput?.walletSignerIdentityIAddress ?? "";
    },
    get connectedVerusIdName() {
      return lastUnlockInput?.walletSignerIdentityName ?? null;
    }
  };

  const storageCommands: StorageOnboardingCommands = {
    cancelCloudSyncSelection,
    cancelStorageOnboarding: () => returnToOnboarding(Boolean(vault)),
    chooseStorageMode,
    confirmCloudSyncSelection,
    enableFoundCloudSync,
    keepCloudSyncSelectionLocal,
    retryCloudDiscovery: startCloudDiscovery,
    toggleCloudSyncSelectionNote
  };

  const workspaceView: WorkspaceViewModel = {
    get panelGridStyle() {
      return panelGridStyle;
    },
    get sourceMode() {
      return sourceMode;
    },
    get noteTabs() {
      return noteTabs;
    },
    get activeTabId() {
      return activeTabId;
    },
    get activeNote() {
      return activeNote;
    },
    get activeNoteId() {
      return activeNoteId;
    },
    get selectTitleForNoteId() {
      return titleSelectionNoteId;
    },
    get activeEditorDate() {
      return activeEditorDate;
    },
    get activeNoteSaveStatus() {
      return persistence.activeNoteSaveStatus;
    },
    get saving() {
      return persistence.saving;
    },
    get notes() {
      return notes;
    },
    get folders() {
      return folders;
    },
    get activeFolderId() {
      return activeFolderId;
    },
    get editingFolderId() {
      return editingFolderId;
    },
    get editingFolderName() {
      return editingFolderName;
    },
    get folderNoteCounts() {
      return folderNoteCounts;
    },
    get filteredNotes() {
      return filteredNotes;
    },
    get sourceSearchQuery() {
      return sourceSearchQuery;
    },
    get sourceSearchResults() {
      return sourceSearchResults;
    },
    get bookmarkedNotes() {
      return bookmarkedNotes;
    },
    get unlocked() {
      return unlocked;
    },
    get notePickerOpen() {
      return notePickerOpen;
    },
    get notePickerQuery() {
      return notePickerQuery;
    },
    get notePickerIndex() {
      return notePickerIndex;
    },
    get notePickerResults() {
      return notePickerResults;
    },
    get notePickerCanCreate() {
      return notePickerCanCreate;
    },
    get folderContextMenu() {
      return folderContextMenu;
    },
    get contextMenuFolder() {
      return contextMenuFolder;
    },
    get canDeleteContextFolder() {
      return canDeleteContextFolder;
    },
    get noteSortMode() {
      return noteSortMode;
    },
    get appearanceMode() {
      return appearanceMode;
    },
    get storageStatusLabel() {
      return storageStatusLabel;
    },
    get storageMode() {
      return storagePreference?.storageMode ?? null;
    },
    get cloudCopyDeleted() {
      return Boolean(storagePreference?.cloudCopyDeletedAtMs);
    },
    get cloudBusy() {
      return cloudBusy;
    },
    get cloudStatus() {
      return cloudStatus;
    },
    get cloudUsage() {
      return cloudUsage;
    },
    get cloudSyncSelection() {
      return cloudSyncSelection;
    },
    get cloudSyncNeedsNewWalletUnlock() {
      return cloudSyncNeedsNewWalletUnlock;
    },
    get localCloudSyncNoteCount() {
      return localCloudSyncNoteCount;
    },
    get localCloudSyncStorageBytes() {
      return localCloudSyncStorageBytes;
    },
    get canUseCloud() {
      return Boolean(convexUrl);
    },
    get connectedVerusIdAddress() {
      return lastUnlockInput?.walletSignerIdentityIAddress ?? "";
    },
    get connectedVerusIdName() {
      return lastUnlockInput?.walletSignerIdentityName ?? null;
    }
  };

  const workspaceCommands: WorkspaceCommands = {
    activateTab,
    beginFolderRename,
    closeActiveTab,
    closeFolderContextMenu,
    closeNotePicker,
    closeTab,
    createBlankTab,
    createFolder,
    createFolderFromContextMenu,
    createNote,
    createNoteFromPicker,
    deleteCloudCopy,
    deleteFolder,
    deleteFolderFromContextMenu,
    deleteNote,
    duplicateNote,
    enableEncryptedSync,
    cancelCloudSyncSelection,
    confirmCloudSyncSelection,
    exportActiveNoteMarkdown,
    exportEncryptedBackup,
    finishFolderRename,
    getFolderName,
    getNoteTitle,
    getTabTitle,
    handleFolderRenameKeydown,
    handleFolderRowKeydown,
    handleNotePickerKeydown,
    handleTabKeydown,
    importBackup,
    includeNoteInCloudSync,
    isNoteBookmarked,
    lockVault,
    onTitleSelectionHandled: clearTitleSelectionRequest,
    openFolderContextMenu,
    openNoteInActiveTab,
    openNoteInNewTab,
    openNotePicker,
    reconnectCloudSync,
    repairCloudSync,
    removeNoteFromCloudSync,
    renameNote,
    resizePanelWithKeyboard,
    retryCloudSync,
    retryNoteSync,
    selectFolder,
    setAppearanceMode,
    setEditingFolderName,
    setNotePickerIndex,
    setNotePickerQuery,
    setNoteSortMode,
    setNotesShell,
    setSourceMode,
    setSourceSearchQuery: (query) => (sourceSearchQuery = query),
    startPanelResize,
    stopSyncingThisDevice,
    keepCloudSyncSelectionLocal,
    toggleCloudSyncSelectionNote,
    toggleBookmark,
    updateActiveNote
  };

  return {
    acceptWalletUnlock,
    destroy,
    discardAcceptedWalletUnlock,
    get hasVault() {
      return Boolean(vault);
    },
    get isStorageOnboardingOpen() {
      return storageOnboardingOpen;
    },
    get lockedAccessView() {
      return storageLockedAccessView;
    },
    get isUnlocked() {
      return unlocked;
    },
    mount,
    openUnlockedWorkspace,
    returnToOnboarding,
    setStatus,
    showStorageOnboarding,
    storageCommands,
    storageView,
    workspaceCommands,
    workspaceView
  };
}
