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
import type { CloudSyncSelection } from "./cloudSyncPreflight";
import type {
  CloudConnectionState,
  CloudReplicaDiscovery,
  RuntimePatch,
  VaultWorkspaceData
} from "./vaultWorkspaceRuntime";

export type NoteSaveState = {
  dirty: boolean;
  localError: string | null;
  localSavedAtMs: number | null;
  localSaving: boolean;
  snapshotOrdinal: number;
  syncError: string | null;
  syncPending: boolean;
  syncing: boolean;
};

export type NoteSaveStatusIcon = "check" | "error" | "spinner";
export type NoteSaveStatusTone = "cloud" | "error" | "local";

export type NoteSaveStatus = {
  compactLabel: string;
  displayLabel: string;
  icon: NoteSaveStatusIcon;
  label: string;
  title: string;
  tone: NoteSaveStatusTone;
};

export type RuntimeContext = {
  cloudSession: CloudSession | null;
  storagePreference: VaultPreference | null;
  unlockInput: UnlockInput;
  vault: UnlockOutput;
};

export type NotesRuntime = {
  deleteCloudCopy(input: RuntimeContext): Promise<RuntimePatch>;
  deleteFolder(context: RuntimeContext, folderId: string): Promise<RuntimePatch>;
  deleteNote(context: RuntimeContext, noteId: string, hasEncryptedRecord: boolean): Promise<RuntimePatch>;
  detectCloudReplica(vault: UnlockOutput, unlockInput: UnlockInput): Promise<CloudReplicaDiscovery>;
  enableFoundCloudSync(vault: UnlockOutput, unlockInput: UnlockInput): Promise<RuntimePatch>;
  enableEncryptedSync(vault: UnlockOutput, unlockInput: UnlockInput, includedNoteIds?: string[], cloudSession?: CloudSession | null): Promise<RuntimePatch>;
  exportEncryptedBackup(vault: UnlockOutput): Promise<RuntimePatch>;
  exportMarkdownNote(note: NoteDraft): Promise<RuntimePatch>;
  getVaultPreference(vaultId: string): Promise<VaultPreference | null>;
  includeNoteInCloudSync(context: RuntimeContext, noteId: string): Promise<RuntimePatch>;
  importBackup(context: RuntimeContext): Promise<RuntimePatch>;
  loadLocalVault(vaultId: string, fallbackPreference?: VaultPreference | null): Promise<VaultWorkspaceData>;
  openWorkspace(input: {
    preference: VaultPreference;
    cloudSession?: CloudSession | null;
    unlockInput: UnlockInput;
    vault: UnlockOutput;
  }): Promise<RuntimePatch & { data: VaultWorkspaceData }>;
  repairCloudSync(context: RuntimeContext): Promise<RuntimePatch>;
  removeNoteFromCloudSync(context: RuntimeContext, noteId: string): Promise<RuntimePatch>;
  saveFolder(input: {
    context: RuntimeContext;
    encryptedFolders: Record<string, EncryptedFolder>;
    folder: FolderDraft;
  }): Promise<RuntimePatch & { encryptedFolder: EncryptedFolder }>;
  saveNoteLocally(input: {
    context: RuntimeContext;
    encryptedNotes: Record<string, EncryptedNote>;
    folders: FolderDraft[];
    note: NoteDraft;
  }): Promise<{ encryptedNote: EncryptedNote; note: NoteDraft }>;
  setStorageModePreference(vaultId: string, storageMode: StorageMode): Promise<VaultPreference>;
  stopSyncingThisDevice(vault: UnlockOutput): Promise<RuntimePatch>;
  syncCloudReplica(context: RuntimeContext): Promise<RuntimePatch>;
  syncPendingRecords(context: RuntimeContext): Promise<RuntimePatch>;
};

export type StorageCloudDiscoveryState =
  | {
      status: "idle" | "checking" | "empty";
    }
  | {
      liveFolderCount: number;
      liveNoteCount: number;
      status: "found";
    }
  | {
      error: string;
      status: "error";
    };

export type LockedAccessViewModel = {
  walletFlowStarted: boolean;
  walletUnlockSucceeded: boolean;
  walletHasError: boolean;
  walletQrDataUrl: string;
  walletSessionExpired: boolean;
  walletQrPending: boolean;
  unlocking: boolean;
  walletOpeningWorkspace: boolean;
  walletStatusMessage: string;
  walletSuccessMessage: string;
  walletCountdownLabel: string;
  walletSessionStarting: boolean;
};

export type LockedAccessCommands = {
  startWalletSession(): void | Promise<void>;
  returnToOnboarding(): void;
};

export type StorageOnboardingViewModel = {
  busy: boolean;
  cloudDiscovery: StorageCloudDiscoveryState;
  cloudSyncSelection: CloudSyncSelection | null;
  status: string;
  canUseCloud: boolean;
  connectedVerusIdAddress: string;
  connectedVerusIdName: string | null;
};

export type StorageOnboardingCommands = {
  cancelCloudSyncSelection(): void;
  cancelStorageOnboarding(): void;
  chooseStorageMode(mode: StorageMode): void | Promise<void>;
  confirmCloudSyncSelection(): void | Promise<void>;
  enableFoundCloudSync(): void | Promise<void>;
  keepCloudSyncSelectionLocal(): void | Promise<void>;
  retryCloudDiscovery(): void | Promise<void>;
  toggleCloudSyncSelectionNote(noteId: string, selected: boolean): void;
};

export type WorkspaceViewModel = {
  panelGridStyle: string;
  sourceMode: SourceMode;
  noteTabs: NoteTab[];
  activeTabId: string | null;
  activeNote: NoteDraft | null;
  activeNoteId: string | null;
  selectTitleForNoteId: string | null;
  activeEditorDate: string;
  activeNoteSaveStatus: NoteSaveStatus;
  saving: boolean;
  notes: NoteDraft[];
  folders: FolderDraft[];
  activeFolderId: string;
  editingFolderId: string | null;
  editingFolderName: string;
  folderNoteCounts: Record<string, number>;
  filteredNotes: NoteDraft[];
  sourceSearchQuery: string;
  sourceSearchResults: NoteDraft[];
  bookmarkedNotes: NoteDraft[];
  unlocked: boolean;
  notePickerOpen: boolean;
  notePickerQuery: string;
  notePickerIndex: number;
  notePickerResults: NoteDraft[];
  notePickerCanCreate: boolean;
  folderContextMenu: FolderContextMenu | null;
  contextMenuFolder: FolderDraft | null;
  canDeleteContextFolder: boolean;
  noteSortMode: NoteSortMode;
  appearanceMode: AppearanceMode;
  storageStatusLabel: string;
  storageMode: StorageMode | null;
  cloudCopyDeleted: boolean;
  cloudBusy: boolean;
  cloudStatus: string;
  cloudUsage: CloudUsage | null;
  cloudSyncSelection: CloudSyncSelection | null;
  cloudSyncNeedsNewWalletUnlock: boolean;
  localCloudSyncNoteCount: number;
  localCloudSyncStorageBytes: number;
  canUseCloud: boolean;
  connectedVerusIdAddress: string;
  connectedVerusIdName: string | null;
};

export type WorkspaceCommands = {
  setNotesShell(element: HTMLElement | null): void;
  getTabTitle(tab: NoteTab): string;
  activateTab(tabId: string): void | Promise<void>;
  handleTabKeydown(event: KeyboardEvent, tabId: string): void;
  closeTab(tabId: string): void | Promise<void>;
  createBlankTab(): void;
  isNoteBookmarked(noteId: string): boolean;
  toggleBookmark(noteId: string): void | Promise<void>;
  exportActiveNoteMarkdown(): void | Promise<void>;
  deleteNote(noteId: string): void | Promise<void>;
  lockVault(): void | Promise<void>;
  setSourceMode(mode: SourceMode): void;
  createFolder(): void | Promise<void>;
  deleteFolder(folderId: string): void | Promise<void>;
  createNote(title?: string): void;
  openFolderContextMenu(event: MouseEvent, folderId: string): void;
  closeFolderContextMenu(): void;
  selectFolder(folderId: string): void;
  beginFolderRename(folderId: string): void;
  finishFolderRename(): void | Promise<void>;
  setEditingFolderName(name: string): void;
  handleFolderRenameKeydown(event: KeyboardEvent): void;
  handleFolderRowKeydown(event: KeyboardEvent, folderId: string): void;
  openNoteInActiveTab(noteId: string): void | Promise<void>;
  openNoteInNewTab(noteId: string): void | Promise<void>;
  setSourceSearchQuery(query: string): void;
  getNoteTitle(note: NoteDraft | null | undefined): string;
  getFolderName(folderId: string): string;
  startPanelResize(panel: ResizablePanel, event: PointerEvent): void;
  resizePanelWithKeyboard(panel: ResizablePanel, event: KeyboardEvent): void;
  updateActiveNote(patch: Partial<NoteDraft>): void;
  onTitleSelectionHandled(noteId: string): void;
  openNotePicker(): void;
  closeActiveTab(): void;
  closeNotePicker(): void;
  handleNotePickerKeydown(event: KeyboardEvent): void;
  setNotePickerQuery(query: string): void;
  setNotePickerIndex(index: number): void;
  createNoteFromPicker(): void;
  deleteFolderFromContextMenu(): void;
  createFolderFromContextMenu(): void;
  setNoteSortMode(mode: NoteSortMode): void;
  duplicateNote(noteId: string): void | Promise<void>;
  renameNote(noteId: string, title: string): void | Promise<void>;
  includeNoteInCloudSync(noteId: string): void | Promise<void>;
  removeNoteFromCloudSync(noteId: string): void | Promise<void>;
  retryNoteSync(noteId: string): void | Promise<void>;
  setAppearanceMode(mode: AppearanceMode): void;
  enableEncryptedSync(): void | Promise<void>;
  cancelCloudSyncSelection(): void;
  confirmCloudSyncSelection(): void | Promise<void>;
  keepCloudSyncSelectionLocal(): void | Promise<void>;
  toggleCloudSyncSelectionNote(noteId: string, selected: boolean): void;
  reconnectCloudSync(): void | Promise<void>;
  repairCloudSync(): void | Promise<void>;
  retryCloudSync(): void | Promise<void>;
  stopSyncingThisDevice(): void | Promise<void>;
  deleteCloudCopy(): void | Promise<void>;
  exportEncryptedBackup(): void | Promise<void>;
  importBackup(): void | Promise<void>;
};
