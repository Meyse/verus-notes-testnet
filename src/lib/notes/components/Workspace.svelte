<script lang="ts">
  import {
    ArrowDownUp,
    Bookmark,
    Bold,
    Braces,
    Check,
    ChevronRight,
    CircleAlert,
    Code,
    Cloud,
    CloudOff,
    Copy,
    Ellipsis,
    FileDown,
    FolderPlus,
    Heading1,
    Heading2,
    Italic,
    LoaderCircle,
    Pencil,
    Pilcrow,
    Plus,
    Settings,
    SquarePen,
    Trash2,
    RefreshCw
  } from "@lucide/svelte";
  import ConfirmPopover from "./ConfirmPopover.svelte";
  import CloudSyncSelectionModal from "./CloudSyncSelectionModal.svelte";
  import MarkdownEditor from "./MarkdownEditor.svelte";
  import VaultSettings from "./VaultSettings.svelte";
  import WorkspaceNotePicker from "./WorkspaceNotePicker.svelte";
  import WorkspaceSourceSidebar from "./WorkspaceSourceSidebar.svelte";
  import WorkspaceTopbar from "./WorkspaceTopbar.svelte";
  import {
    getCaretRangeFromPoint,
    placeCursorAtNearestEditorBlockEdge,
    selectRange,
    type MarkdownEditorToolbarState
  } from "$lib/notes/markdownEditor";
	import type {
	  FolderDraft,
	  NoteDraft,
	  NoteTab,
	  VaultSettingsSectionId
	} from "$lib/notes/types";
  import type { WorkspaceCommands, WorkspaceViewModel } from "$lib/notes/workspaceTypes";

  type Props = {
    commands: WorkspaceCommands;
    view: WorkspaceViewModel;
  };

  type PendingConfirmation = {
    body: string;
    confirmLabel: string;
    heading: string;
    headingId: string;
    onConfirm: () => void | Promise<void>;
  };

  let {
    commands,
    view
  }: Props = $props();

  let notesShell = $state<HTMLElement | null>(null);
  const panelGridStyle = $derived(view.panelGridStyle);
  const sourceMode = $derived(view.sourceMode);
  const noteTabs = $derived(view.noteTabs);
  const activeTabId = $derived(view.activeTabId);
  const activeNote = $derived(view.activeNote);
  const activeNoteId = $derived(view.activeNoteId);
  const selectTitleForNoteId = $derived(view.selectTitleForNoteId);
  const activeEditorDate = $derived(view.activeEditorDate);
  const activeNoteSaveStatusCompactLabel = $derived(view.activeNoteSaveStatus.compactLabel);
  const activeNoteSaveStatusDisplayLabel = $derived(view.activeNoteSaveStatus.displayLabel);
  const activeNoteSaveStatusIcon = $derived(view.activeNoteSaveStatus.icon);
  const activeNoteSaveStatusLabel = $derived(view.activeNoteSaveStatus.label);
  const activeNoteSaveStatusTitle = $derived(view.activeNoteSaveStatus.title);
  const activeNoteSaveStatusTooltip = $derived(activeNoteSaveStatusTitle || activeNoteSaveStatusLabel);
  const activeNoteSaveStatusTone = $derived(view.activeNoteSaveStatus.tone);
  const saving = $derived(view.saving);
  const notes = $derived(view.notes);
  const folders = $derived(view.folders);
  const activeFolderId = $derived(view.activeFolderId);
  const editingFolderId = $derived(view.editingFolderId);
  const editingFolderName = $derived(view.editingFolderName);
  const folderNoteCounts = $derived(view.folderNoteCounts);
  const filteredNotes = $derived(view.filteredNotes);
  const sourceSearchQuery = $derived(view.sourceSearchQuery);
  const sourceSearchResults = $derived(view.sourceSearchResults);
  const bookmarkedNotes = $derived(view.bookmarkedNotes);
  const unlocked = $derived(view.unlocked);
  const notePickerOpen = $derived(view.notePickerOpen);
  const notePickerQuery = $derived(view.notePickerQuery);
  const notePickerIndex = $derived(view.notePickerIndex);
  const notePickerResults = $derived(view.notePickerResults);
  const notePickerCanCreate = $derived(view.notePickerCanCreate);
  const folderContextMenu = $derived(view.folderContextMenu);
  const contextMenuFolder = $derived(view.contextMenuFolder);
  const canDeleteContextFolder = $derived(view.canDeleteContextFolder);
  const noteSortMode = $derived(view.noteSortMode);
  const appearanceMode = $derived(view.appearanceMode);
  const storageStatusLabel = $derived(view.storageStatusLabel);
  const storageMode = $derived(view.storageMode);
  const cloudCopyDeleted = $derived(view.cloudCopyDeleted);
  const cloudBusy = $derived(view.cloudBusy);
  const cloudStatus = $derived(view.cloudStatus);
  const cloudUsage = $derived(view.cloudUsage);
  const cloudSyncSelection = $derived(view.cloudSyncSelection);
  const cloudSyncNeedsNewWalletUnlock = $derived(view.cloudSyncNeedsNewWalletUnlock);
  const localCloudSyncNoteCount = $derived(view.localCloudSyncNoteCount);
  const localCloudSyncStorageBytes = $derived(view.localCloudSyncStorageBytes);
  const canUseCloud = $derived(view.canUseCloud);
  const connectedVerusIdAddress = $derived(view.connectedVerusIdAddress);
  const connectedVerusIdName = $derived(view.connectedVerusIdName);

  // svelte-ignore state_referenced_locally
  const {
    getTabTitle,
    activateTab,
    handleTabKeydown,
    closeTab,
    createBlankTab,
    isNoteBookmarked,
    toggleBookmark,
    exportActiveNoteMarkdown,
    deleteNote,
    lockVault,
    setSourceMode,
    createFolder,
    createNote,
    openFolderContextMenu,
    closeFolderContextMenu,
    selectFolder,
    beginFolderRename,
    finishFolderRename,
    setEditingFolderName,
    handleFolderRenameKeydown,
    handleFolderRowKeydown,
    openNoteInActiveTab,
    openNoteInNewTab,
    setSourceSearchQuery,
    getNoteTitle,
    getFolderName,
    startPanelResize,
    resizePanelWithKeyboard,
    updateActiveNote,
    onTitleSelectionHandled,
    openNotePicker,
    closeActiveTab,
    closeNotePicker,
    handleNotePickerKeydown,
    setNotePickerQuery,
    setNotePickerIndex,
    createNoteFromPicker,
    createFolderFromContextMenu,
    setNoteSortMode,
    duplicateNote,
    renameNote,
    deleteFolder,
    includeNoteInCloudSync,
    removeNoteFromCloudSync,
    retryNoteSync,
    cancelCloudSyncSelection,
    confirmCloudSyncSelection,
    keepCloudSyncSelectionLocal,
    toggleCloudSyncSelectionNote,
    setAppearanceMode,
    enableEncryptedSync,
    reconnectCloudSync,
    retryCloudSync,
    stopSyncingThisDevice,
    deleteCloudCopy,
    exportEncryptedBackup,
    importBackup
  } = commands;

  let editorScrollElement = $state<HTMLElement | null>(null);
  let titleInput = $state<HTMLInputElement | null>(null);
  let noteActionsMenuButton = $state<HTMLButtonElement | null>(null);
  let noteActionsMenu = $state<{ x: number; y: number } | null>(null);
  let sourceContextMenu = $state<{ x: number; y: number } | null>(null);
  let noteContextMenu = $state<{ noteId: string; x: number; y: number } | null>(null);
  let pendingConfirmation = $state<PendingConfirmation | null>(null);
  let editingNoteId = $state<string | null>(null);
  let editingNoteTitle = $state("");
  let bodyEditorElement = $state<HTMLElement | null>(null);
  let settingsOpen = $state(false);
  let settingsInitialSection = $state<VaultSettingsSectionId>("general");
  let settingsSyncNotesModalOpen = $state(false);
  let markdownToolbar = $state<MarkdownEditorToolbarState | null>(null);
  const contextMenuNote = $derived.by(() => {
    if (!noteContextMenu) return null;
    return findSourceNote(noteContextMenu.noteId);
  });

  $effect(() => {
    commands.setNotesShell(notesShell);
  });

  $effect(() => {
    if (!selectTitleForNoteId || activeNoteId !== selectTitleForNoteId || !titleInput) return;

    titleInput.focus();
    titleInput.select();
    onTitleSelectionHandled(selectTitleForNoteId);
  });

  $effect(() => {
    const scrollElement = editorScrollElement;
    if (!scrollElement) return;

    scrollElement.addEventListener("mousedown", handleEditorScrollMousedown);
    return () => scrollElement.removeEventListener("mousedown", handleEditorScrollMousedown);
  });

  function closeSettings() {
    settingsOpen = false;
    settingsSyncNotesModalOpen = false;
  }

  function openSettings(section: VaultSettingsSectionId = "general") {
    settingsInitialSection = section;
    settingsSyncNotesModalOpen = false;
    settingsOpen = true;
  }

  function openSyncNotesSettings(event?: MouseEvent) {
    event?.preventDefault();
    event?.stopPropagation();
    settingsInitialSection = "cloud";
    settingsSyncNotesModalOpen = true;
    settingsOpen = true;
  }

  function openSyncNotesModal() {
    settingsSyncNotesModalOpen = true;
  }

  function closeSyncNotesModal() {
    settingsSyncNotesModalOpen = false;
  }

  function isBlockedSyncLabel(label: string) {
    return label === "Sync limit reached" || label === "Cloud out of date" || label === "Too large to sync" || label === "Sync failed";
  }

  function blockedSyncBannerCopy(label: string) {
    if (label === "Cloud out of date") {
      return "Your latest changes are saved on this device. Free cloud sync space to upload this revision.";
    }
    if (label === "Too large to sync") {
      return "This note is saved on this device, but it is too large for cloud sync on this plan.";
    }
    if (label === "Sync failed") {
      return activeNoteSaveStatusTitle || "Your encrypted changes are saved on this device.";
    }
    return "This note is saved on this device. Remove another synced note to include it in cloud sync.";
  }

  function noteCanIncludeInCloudSync(note: NoteDraft | null) {
    return Boolean(note && storageMode === "sync_enabled" && note.cloudSyncScope === "local_only" && !note.syncBlockedReason && cloudQuotaHasSpace());
  }

  function noteNeedsQuotaBeforeInclude(note: NoteDraft | null) {
    return Boolean(note && storageMode === "sync_enabled" && note.cloudSyncScope === "local_only" && !note.syncBlockedReason && !cloudQuotaHasSpace());
  }

  function noteCanRemoveFromCloudSync(note: NoteDraft | null) {
    return Boolean(note && storageMode === "sync_enabled" && note.cloudSyncScope === "included" && note.lastSyncedRevisionHash && !note.syncBlockedReason);
  }

  function noteCanKeepLocalOnly(note: NoteDraft | null) {
    return Boolean(note && storageMode === "sync_enabled" && note.cloudSyncScope !== "local_only" && note.syncBlockedReason);
  }

  function noteCanRetrySync(note: NoteDraft | null) {
    return Boolean(
      note &&
        storageMode === "sync_enabled" &&
        note.cloudSyncScope !== "local_only" &&
        (note.syncState === "pending_upsert" ||
          ((note.syncBlockedReason === "quota_note_count" || note.syncBlockedReason === "quota_storage") && cloudQuotaHasSpace()) ||
          note.syncBlockedReason === "session_expired" ||
          note.syncBlockedReason === "network")
    );
  }

  function cloudQuotaHasSpace() {
    const maxNotes = cloudUsage?.maxSyncedNotes ?? 20;
    const maxStorageBytes = cloudUsage?.maxStorageBytes ?? 2 * 1024 * 1024;
    const syncedNoteCount = Math.max(cloudUsage?.liveSyncedNoteCount ?? 0, localCloudSyncNoteCount);
    const syncedStorageBytes = Math.max(cloudUsage?.liveStorageBytes ?? 0, localCloudSyncStorageBytes);
    return syncedNoteCount < maxNotes && syncedStorageBytes < maxStorageBytes;
  }

  function toggleNoteActionsMenu(event: MouseEvent) {
    event.stopPropagation();

    if (noteActionsMenu) {
      noteActionsMenu = null;
      return;
    }

    const button = noteActionsMenuButton;
    if (!button) return;

    closeSourceContextMenu();

    const rect = button.getBoundingClientRect();
    const menuWidth = 188;
    const menuHeight = 62;
    noteActionsMenu = {
      x: Math.round(Math.min(Math.max(rect.right - menuWidth, 8), window.innerWidth - menuWidth - 8)),
      y: Math.round(Math.min(Math.max(rect.bottom + 8, 8), window.innerHeight - menuHeight - 8))
    };
  }

  function closeNoteActionsMenu() {
    noteActionsMenu = null;
  }

  function closeNoteContextMenu() {
    noteContextMenu = null;
  }

  function closeSourceContextMenu() {
    sourceContextMenu = null;
  }

  function closeSourceMenus() {
    closeNoteActionsMenu();
    closeSourceContextMenu();
    closeNoteContextMenu();
    closeFolderContextMenu();
  }

  function handleNoteActionsWindowKeydown(event: KeyboardEvent) {
    if (event.key === "Escape" && pendingConfirmation) {
      cancelPendingConfirmation();
      return;
    }

    if (event.key === "Escape") {
      closeSourceMenus();
      cancelNoteRename();
    }
  }

  function runNoteAction(action: () => void | Promise<void>) {
    closeNoteActionsMenu();
    void action();
  }

  function findSourceNote(noteId: string) {
    return (
      filteredNotes.find((note) => note.id === noteId) ??
      sourceSearchResults.find((note) => note.id === noteId) ??
      bookmarkedNotes.find((note) => note.id === noteId) ??
      (activeNote?.id === noteId ? activeNote : null)
    );
  }

  function openNoteContextMenu(event: MouseEvent, note: NoteDraft) {
    event.preventDefault();
    event.stopPropagation();
    document.getSelection()?.removeAllRanges();

    closeNoteActionsMenu();
    closeSourceContextMenu();
    closeFolderContextMenu();

    const menuWidth = 188;
    const menuHeight = 158;
    noteContextMenu = {
      noteId: note.id,
      x: Math.round(Math.min(Math.max(event.clientX, 8), window.innerWidth - menuWidth - 8)),
      y: Math.round(Math.min(Math.max(event.clientY, 8), window.innerHeight - menuHeight - 8))
    };
  }

  function openSourceContextMenu(event: MouseEvent) {
    if (isNativeTextContextMenuTarget(event.target) || isInteractiveSourceContextTarget(event.target)) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();
    document.getSelection()?.removeAllRanges();

    closeNoteActionsMenu();
    closeNoteContextMenu();
    closeFolderContextMenu();

    const menuWidth = 188;
    const menuHeight = 62;
    sourceContextMenu = {
      x: Math.round(Math.min(Math.max(event.clientX, 8), window.innerWidth - menuWidth - 8)),
      y: Math.round(Math.min(Math.max(event.clientY, 8), window.innerHeight - menuHeight - 8))
    };
  }

  function isNativeTextContextMenuTarget(target: EventTarget | null) {
    const element = target instanceof Element ? target : target instanceof Node ? target.parentElement : null;
    return Boolean(element?.closest('input:not([type="button"]), textarea, [contenteditable="true"], [contenteditable="plaintext-only"]'));
  }

  function isInteractiveSourceContextTarget(target: EventTarget | null) {
    const element = target instanceof Element ? target : target instanceof Node ? target.parentElement : null;
    return Boolean(element?.closest("button, [role='button'], a, label, select, summary"));
  }

  function runSourceContextAction(action: () => void | Promise<void>) {
    closeSourceContextMenu();
    void action();
  }

  function runNoteContextAction(action: () => void | Promise<void>) {
    void action();
    closeNoteContextMenu();
  }

  function beginNoteRename(note: NoteDraft) {
    closeNoteContextMenu();
    editingNoteId = note.id;
    editingNoteTitle = getNoteTitle(note);
  }

  function requestDeleteNote(note: NoteDraft) {
    closeSourceMenus();
    const noteId = note.id;
    pendingConfirmation = {
      body: `"${getNoteTitle(note)}" will be deleted. This can't be undone.`,
      confirmLabel: "Delete",
      heading: "Delete note?",
      headingId: "delete-note-heading",
      onConfirm: () => deleteNote(noteId)
    };
  }

  function requestDeleteFolder(folder: FolderDraft) {
    closeSourceMenus();
    const folderId = folder.id;
    pendingConfirmation = {
      body: `"${getFolderName(folderId)}" will be deleted. This can't be undone.`,
      confirmLabel: "Delete",
      heading: "Delete folder?",
      headingId: "delete-folder-heading",
      onConfirm: () => deleteFolder(folderId)
    };
  }

  function cancelPendingConfirmation() {
    pendingConfirmation = null;
  }

  function confirmPendingAction() {
    const confirmation = pendingConfirmation;
    pendingConfirmation = null;
    if (confirmation) void confirmation.onConfirm();
  }

  function cancelNoteRename() {
    editingNoteId = null;
    editingNoteTitle = "";
  }

  function finishNoteRename() {
    const noteId = editingNoteId;
    const title = editingNoteTitle.trim() || "Untitled";
    const note = noteId ? findSourceNote(noteId) : null;

    cancelNoteRename();
    if (!note || title === note.title) return;
    void renameNote(note.id, title);
  }

  function handleNoteRenameKeydown(event: KeyboardEvent) {
    event.stopPropagation();

    if (event.key === "Enter") {
      event.preventDefault();
      finishNoteRename();
      return;
    }

    if (event.key === "Escape") {
      event.preventDefault();
      cancelNoteRename();
    }
  }

  function handleNoteRowKeydown(event: KeyboardEvent, noteId: string) {
    if (editingNoteId || (event.key !== "Enter" && event.key !== " ")) return;

    event.preventDefault();
    void openNoteInActiveTab(noteId);
  }

  function handleTitleKeydown(event: KeyboardEvent) {
    if (event.key !== "Enter") return;

    event.preventDefault();
    focusBodyEditor();
  }

  function handleEditorScrollMousedown(event: MouseEvent) {
    if (event.defaultPrevented) return;
    if (!activeNote || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    if (isNativeTextContextMenuTarget(event.target) || isInteractiveSourceContextTarget(event.target)) return;

    const titleRect = titleInput?.getBoundingClientRect();
    if (titleInput && titleRect && event.clientY >= titleRect.top && event.clientY <= titleRect.bottom) {
      event.preventDefault();
      focusTitleFromGutter(event.clientX, titleRect);
      return;
    }

    const editor = bodyEditorElement;
    const editorRect = editor?.getBoundingClientRect();
    if (!editor || !editorRect || event.clientY < editorRect.top || event.clientY > editorRect.bottom) return;

    event.preventDefault();
    placeEditorCaretFromPoint(editor, event.clientX, event.clientY);
  }

  function focusTitleFromGutter(clientX: number, titleRect: DOMRect) {
    const offset = clientX < titleRect.left + titleRect.width / 2 ? 0 : titleInput?.value.length ?? 0;
    titleInput?.focus();
    titleInput?.setSelectionRange(offset, offset);
  }

  function placeEditorCaretFromPoint(editor: HTMLElement, clientX: number, clientY: number) {
    const editorRect = editor.getBoundingClientRect();
    const adjustedX = Math.min(Math.max(clientX, editorRect.left + 1), editorRect.right - 1);
    const range = getCaretRangeFromPoint(adjustedX, clientY);

    editor.focus();
    if (range && editor.contains(range.commonAncestorContainer)) {
      selectRange(range);
      return;
    }

    placeCursorAtNearestEditorBlockEdge(editor, clientY, clientX < editorRect.left);
  }

  function focusBodyEditor() {
    const editor = bodyEditorElement;
    if (!editor) return;

    editor.focus();
    const target = editor.querySelector<HTMLElement>("p, h1, h2, pre code, pre") ?? editor;
    const selection = window.getSelection();
    if (!selection) return;

    const range = document.createRange();
    range.selectNodeContents(target);
    range.collapse(false);
    selection.removeAllRanges();
    selection.addRange(range);
  }
</script>

<svelte:window
  onclick={closeSourceMenus}
  oncontextmenu={closeSourceMenus}
  onkeydown={handleNoteActionsWindowKeydown}
  onresize={closeSourceMenus}
/>

<main class="notes-shell" bind:this={notesShell} style={panelGridStyle}>
  <WorkspaceTopbar
    {activeTabId}
    {activateTab}
    {closeTab}
    {createBlankTab}
    {getTabTitle}
    {handleTabKeydown}
    {noteTabs}
    {setSourceMode}
    {sourceMode}
  />

  <WorkspaceSourceSidebar
    {activeFolderId}
    {activeNoteId}
    {beginFolderRename}
    {bookmarkedNotes}
    {closeFolderContextMenu}
    {closeSourceMenus}
    {createFolder}
    {createNote}
    {editingFolderId}
    {editingFolderName}
    {editingNoteId}
    {editingNoteTitle}
    {filteredNotes}
    {finishFolderRename}
    {finishNoteRename}
    {folderNoteCounts}
    {folders}
    {getFolderName}
    {getNoteTitle}
    {handleFolderRenameKeydown}
    {handleFolderRowKeydown}
    {handleNoteRenameKeydown}
    {handleNoteRowKeydown}
    {lockVault}
    {openFolderContextMenu}
    {openNoteContextMenu}
    {openNoteInActiveTab}
    {openSourceContextMenu}
    {selectFolder}
    {setEditingFolderName}
    setEditingNoteTitle={(title) => (editingNoteTitle = title)}
    {setSourceSearchQuery}
    {settingsOpen}
    {sourceMode}
    {sourceSearchQuery}
    {sourceSearchResults}
    {unlocked}
    openSettings={() => openSettings()}
  />

  <button
    class="panel-resizer source-resizer"
    aria-label="Resize vault list"
    title="Resize vault list"
    type="button"
    onpointerdown={(event) => startPanelResize("source", event)}
    onkeydown={(event) => resizePanelWithKeyboard("source", event)}
  ></button>

  <section class:has-sync-banner={Boolean(activeNote && isBlockedSyncLabel(activeNoteSaveStatusDisplayLabel))} class="editor-pane" aria-busy={saving}>
    {#if activeNote}
      <div class="note-editor-chrome">
        <div class="editor-format-toolbar" aria-label="Formatting">
          <button
            class:active={markdownToolbar?.activeBlock === "body"}
            class="format-button"
            type="button"
            title="Body"
            aria-label="Body"
            aria-pressed={markdownToolbar?.activeBlock === "body"}
            disabled={!markdownToolbar}
            onmousedown={(event) => event.preventDefault()}
            onclick={() => markdownToolbar?.setBlock("body")}
          >
            <Pilcrow size={16} />
          </button>
          <button
            class:active={markdownToolbar?.activeBlock === "h1"}
            class="format-button"
            type="button"
            title="Heading 1"
            aria-label="Heading 1"
            aria-pressed={markdownToolbar?.activeBlock === "h1"}
            disabled={!markdownToolbar}
            onmousedown={(event) => event.preventDefault()}
            onclick={() => markdownToolbar?.setBlock("h1")}
          >
            <Heading1 size={16} />
          </button>
          <button
            class:active={markdownToolbar?.activeBlock === "h2"}
            class="format-button"
            type="button"
            title="Heading 2"
            aria-label="Heading 2"
            aria-pressed={markdownToolbar?.activeBlock === "h2"}
            disabled={!markdownToolbar}
            onmousedown={(event) => event.preventDefault()}
            onclick={() => markdownToolbar?.setBlock("h2")}
          >
            <Heading2 size={16} />
          </button>
          <span class="format-divider" aria-hidden="true"></span>
          <button
            class:active={markdownToolbar?.activeBold}
            class="format-button"
            type="button"
            title="Bold"
            aria-label="Bold"
            aria-pressed={markdownToolbar?.activeBold}
            disabled={!markdownToolbar}
            onmousedown={(event) => event.preventDefault()}
            onclick={() => markdownToolbar?.toggleBold()}
          >
            <Bold size={16} />
          </button>
          <button
            class:active={markdownToolbar?.activeItalic}
            class="format-button"
            type="button"
            title="Italic"
            aria-label="Italic"
            aria-pressed={markdownToolbar?.activeItalic}
            disabled={!markdownToolbar}
            onmousedown={(event) => event.preventDefault()}
            onclick={() => markdownToolbar?.toggleItalic()}
          >
            <Italic size={16} />
          </button>
          <button
            class:active={markdownToolbar?.activeCode}
            class="format-button"
            type="button"
            title="Inline code"
            aria-label="Inline code"
            aria-pressed={markdownToolbar?.activeCode}
            disabled={!markdownToolbar}
            onmousedown={(event) => event.preventDefault()}
            onclick={() => markdownToolbar?.toggleInlineCode()}
          >
            <Code size={16} />
          </button>
          <button
            class:active={markdownToolbar?.activeBlock === "codeBlock"}
            class="format-button"
            type="button"
            title="Code block"
            aria-label="Code block"
            aria-pressed={markdownToolbar?.activeBlock === "codeBlock"}
            disabled={!markdownToolbar}
            onmousedown={(event) => event.preventDefault()}
            onclick={() => markdownToolbar?.toggleCodeBlock()}
          >
            <Braces size={16} />
          </button>
        </div>
        <time class="editor-date">{activeEditorDate}</time>
        <div class="note-editor-actions" aria-label="Note actions">
          <button
            class:active={Boolean(activeNote && isNoteBookmarked(activeNote.id))}
            class="topbar-icon-button bookmark-action-button"
            type="button"
            title={activeNote && isNoteBookmarked(activeNote.id) ? "Remove bookmark" : "Bookmark note"}
            aria-label={activeNote && isNoteBookmarked(activeNote.id) ? "Remove bookmark" : "Bookmark note"}
            onclick={() => activeNote && void toggleBookmark(activeNote.id)}
          >
            <Bookmark size={17} />
          </button>
          <button
            bind:this={noteActionsMenuButton}
            class:active={Boolean(noteActionsMenu)}
            class="topbar-icon-button"
            type="button"
            title="More note actions"
            aria-label="More note actions"
            aria-expanded={Boolean(noteActionsMenu)}
            aria-haspopup="menu"
            onclick={toggleNoteActionsMenu}
          >
            <Ellipsis size={18} />
          </button>
        </div>
      </div>
      {#if isBlockedSyncLabel(activeNoteSaveStatusDisplayLabel)}
        <div class="note-sync-banner" role="status">
          <CircleAlert size={16} aria-hidden="true" />
          <div class="note-sync-banner-copy">
            <strong>{activeNoteSaveStatusDisplayLabel}</strong>
            <p>{blockedSyncBannerCopy(activeNoteSaveStatusDisplayLabel)}</p>
          </div>
          <div class="note-sync-banner-actions">
            <button class="secondary-button compact" type="button" onclick={openSyncNotesSettings}>Manage synced notes</button>
            {#if activeNote && noteCanKeepLocalOnly(activeNote)}
              <button class="secondary-button compact" type="button" onclick={() => removeNoteFromCloudSync(activeNote.id)}>
                Keep local only
              </button>
            {/if}
          </div>
        </div>
      {/if}
      <article class="editor-scroll" bind:this={editorScrollElement}>
        <input
          bind:this={titleInput}
          class="title-input"
          value={activeNote.title}
          oninput={(event) => updateActiveNote({ title: event.currentTarget.value })}
          onkeydown={handleTitleKeydown}
          aria-label="Note title"
        />
        <MarkdownEditor
          value={activeNote.body}
          onChange={(body) => updateActiveNote({ body })}
          onEditorElementChange={(element) => (bodyEditorElement = element)}
          onToolbarChange={(state) => (markdownToolbar = state)}
        />
      </article>
    {:else}
      <div class="new-tab-empty">
        <button class="new-tab-action" type="button" onclick={() => createNote()}>
          <span>Create new note (⌘ N)</span>
        </button>
        <button class="new-tab-action" type="button" onclick={openNotePicker}>
          <span>Go to file (⌘ O)</span>
        </button>
        <button class="new-tab-action subtle" type="button" onclick={closeActiveTab}>
          <span>Close</span>
        </button>
      </div>
    {/if}
  </section>

  <div class="storage-status-dock">
    <div
      class="storage-status-indicator"
      class:cloud-storage={activeNoteSaveStatusTone === "cloud"}
      class:error={activeNoteSaveStatusTone === "error"}
      class:spinning={activeNoteSaveStatusIcon === "spinner"}
      role="status"
      aria-live="polite"
      aria-label={`${activeNoteSaveStatusDisplayLabel}: ${activeNoteSaveStatusLabel}`}
    >
      <span class="storage-status-icon" aria-hidden="true">
        {#if activeNoteSaveStatusIcon === "error"}
          <CircleAlert size={14} />
        {:else if activeNoteSaveStatusIcon === "spinner"}
          <LoaderCircle size={14} />
        {:else}
          <Check size={14} />
        {/if}
      </span>
      <span class="storage-status-label">{activeNoteSaveStatusCompactLabel}</span>
      <span class="storage-status-tooltip" aria-hidden="true">{activeNoteSaveStatusTooltip}</span>
    </div>
  </div>

  {#if settingsOpen}
    <VaultSettings
      initialSection={settingsInitialSection}
      syncNotesModalOpen={settingsSyncNotesModalOpen}
      {canUseCloud}
      {cloudBusy}
      {cloudCopyDeleted}
      {cloudStatus}
      {cloudUsage}
      {cloudSyncNeedsNewWalletUnlock}
      {localCloudSyncNoteCount}
      {localCloudSyncStorageBytes}
      {appearanceMode}
      {notes}
      {connectedVerusIdAddress}
      {connectedVerusIdName}
      {getNoteTitle}
      {getFolderName}
      {closeSyncNotesModal}
      {deleteCloudCopy}
      {enableEncryptedSync}
      {includeNoteInCloudSync}
      {openSyncNotesModal}
      {removeNoteFromCloudSync}
      {reconnectCloudSync}
      {retryCloudSync}
      {retryNoteSync}
      {exportEncryptedBackup}
      {importBackup}
      {setAppearanceMode}
      {stopSyncingThisDevice}
      {storageMode}
      {storageStatusLabel}
      closeSettings={closeSettings}
    />
  {/if}

  {#if cloudSyncSelection}
    <CloudSyncSelectionModal
      busy={cloudBusy}
      selection={cloudSyncSelection}
      cancel={cancelCloudSyncSelection}
      confirm={confirmCloudSyncSelection}
      keepLocal={keepCloudSyncSelectionLocal}
      toggleNote={toggleCloudSyncSelectionNote}
    />
  {/if}

  <WorkspaceNotePicker
    open={notePickerOpen}
    query={notePickerQuery}
    index={notePickerIndex}
    results={notePickerResults}
    canCreate={notePickerCanCreate}
    close={closeNotePicker}
    createNote={createNoteFromPicker}
    {getFolderName}
    {getNoteTitle}
    handleKeydown={handleNotePickerKeydown}
    openNote={openNoteInActiveTab}
    setIndex={setNotePickerIndex}
    setQuery={setNotePickerQuery}
  />

  {#if noteActionsMenu && activeNote}
    <div
      class="note-actions-menu"
      role="menu"
      tabindex="-1"
      aria-label="Note actions"
      style={`left: ${noteActionsMenu.x}px; top: ${noteActionsMenu.y}px;`}
      onclick={(event) => event.stopPropagation()}
      onkeydown={(event) => event.stopPropagation()}
    >
      <button class="context-menu-item" type="button" role="menuitem" onclick={() => runNoteAction(exportActiveNoteMarkdown)}>
        <FileDown size={17} />
        <span>Export Markdown</span>
      </button>
      <button class="context-menu-item" type="button" role="menuitem" onclick={() => activeNote && requestDeleteNote(activeNote)}>
        <Trash2 size={17} />
        <span>Delete Note</span>
      </button>
    </div>
  {/if}

  {#if sourceContextMenu}
    <div
      class="source-context-menu"
      role="menu"
      tabindex="-1"
      aria-label="Source context menu"
      style={`left: ${sourceContextMenu.x}px; top: ${sourceContextMenu.y}px;`}
      onclick={(event) => event.stopPropagation()}
      oncontextmenu={(event) => {
        event.preventDefault();
        event.stopPropagation();
      }}
      onkeydown={(event) => event.stopPropagation()}
    >
      <button class="context-menu-item" type="button" role="menuitem" onclick={() => runSourceContextAction(() => createNote())} disabled={!unlocked}>
        <SquarePen size={17} />
        <span>New Note</span>
      </button>
      <button class="context-menu-item" type="button" role="menuitem" onclick={() => runSourceContextAction(createFolder)} disabled={!unlocked}>
        <FolderPlus size={17} />
        <span>New Folder</span>
      </button>
    </div>
  {/if}

  {#if noteContextMenu && contextMenuNote}
    <div
      class="note-context-menu"
      role="menu"
      tabindex="-1"
      aria-label="Note context menu"
      style={`left: ${noteContextMenu.x}px; top: ${noteContextMenu.y}px;`}
      onclick={(event) => event.stopPropagation()}
      oncontextmenu={(event) => {
        event.preventDefault();
        event.stopPropagation();
      }}
      onkeydown={(event) => event.stopPropagation()}
    >
      <button class="context-menu-item" type="button" role="menuitem" onclick={() => runNoteContextAction(() => openNoteInNewTab(contextMenuNote.id))}>
        <Plus size={17} />
        <span>Open in New Tab</span>
      </button>
      <button class="context-menu-item" type="button" role="menuitem" onclick={() => beginNoteRename(contextMenuNote)}>
        <Pencil size={17} />
        <span>Rename</span>
      </button>
      <button class="context-menu-item" type="button" role="menuitem" onclick={() => runNoteContextAction(() => duplicateNote(contextMenuNote.id))}>
        <Copy size={17} />
        <span>Duplicate</span>
      </button>
      <button class="context-menu-item" type="button" role="menuitem" onclick={() => runNoteContextAction(() => toggleBookmark(contextMenuNote.id))}>
        <Bookmark size={17} />
        <span>{contextMenuNote.bookmarked ? "Remove Bookmark" : "Bookmark"}</span>
      </button>

      {#if storageMode === "sync_enabled"}
        <div class="context-menu-separator"></div>

	        {#if noteCanIncludeInCloudSync(contextMenuNote)}
	          <button class="context-menu-item" type="button" role="menuitem" onclick={() => runNoteContextAction(() => includeNoteInCloudSync(contextMenuNote.id))}>
	            <Cloud size={17} />
	            <span>Include in cloud sync</span>
	          </button>
        {:else if noteNeedsQuotaBeforeInclude(contextMenuNote)}
          <button class="context-menu-item" type="button" role="menuitem" onclick={() => runNoteContextAction(() => openSyncNotesSettings())}>
            <Settings size={17} />
            <span>Manage synced notes</span>
          </button>
	        {/if}
        {#if noteCanRemoveFromCloudSync(contextMenuNote)}
          <button class="context-menu-item" type="button" role="menuitem" onclick={() => runNoteContextAction(() => removeNoteFromCloudSync(contextMenuNote.id))}>
            <CloudOff size={17} />
            <span>Remove from cloud sync</span>
          </button>
        {/if}
        {#if contextMenuNote.syncBlockedReason}
          <button class="context-menu-item" type="button" role="menuitem" onclick={() => runNoteContextAction(() => openSyncNotesSettings())}>
            <Settings size={17} />
            <span>Manage synced notes</span>
          </button>
          <button class="context-menu-item" type="button" role="menuitem" onclick={() => runNoteContextAction(() => removeNoteFromCloudSync(contextMenuNote.id))}>
            <CloudOff size={17} />
            <span>Keep local only</span>
          </button>
        {/if}
        {#if noteCanRetrySync(contextMenuNote)}
          <button class="context-menu-item" type="button" role="menuitem" onclick={() => runNoteContextAction(() => retryNoteSync(contextMenuNote.id))}>
            <RefreshCw size={17} />
            <span>Retry sync</span>
          </button>
        {/if}
      {/if}

      <div class="context-menu-separator"></div>

      <button class="context-menu-item" type="button" role="menuitem" onclick={() => requestDeleteNote(contextMenuNote)}>
        <Trash2 size={17} />
        <span>Delete</span>
      </button>
    </div>
  {/if}

  {#if pendingConfirmation}
    <ConfirmPopover
      body={pendingConfirmation.body}
      cancel={cancelPendingConfirmation}
      confirm={confirmPendingAction}
      confirmLabel={pendingConfirmation.confirmLabel}
      danger
      heading={pendingConfirmation.heading}
      headingId={pendingConfirmation.headingId}
    />
  {/if}

  {#if folderContextMenu && contextMenuFolder}
    <div
      class="folder-context-menu"
      role="menu"
      tabindex="-1"
      style={`left: ${folderContextMenu.x}px; top: ${folderContextMenu.y}px;`}
      onclick={(event) => event.stopPropagation()}
      onkeydown={(event) => event.stopPropagation()}
    >
      <button class="context-menu-item" type="button" role="menuitem" onclick={() => beginFolderRename(contextMenuFolder.id)}>
        <Pencil size={17} />
        <span>Rename Folder</span>
      </button>
      <button
        class="context-menu-item"
        type="button"
        role="menuitem"
        onclick={() => requestDeleteFolder(contextMenuFolder)}
        disabled={!canDeleteContextFolder}
      >
        <Trash2 size={17} />
        <span>Delete Folder</span>
      </button>

      <div class="context-menu-separator"></div>

      <button class="context-menu-item" type="button" role="menuitem" onclick={createFolderFromContextMenu}>
        <FolderPlus size={17} />
        <span>New Folder</span>
      </button>

      <div class="context-menu-separator"></div>

      <div class="context-menu-item context-menu-parent" role="menuitem" tabindex="0">
        <ArrowDownUp size={17} />
        <span>Sort By</span>
        <ChevronRight size={17} />
        <div class="context-submenu" role="menu" tabindex="-1">
          <button class="context-menu-item" type="button" role="menuitem" onclick={() => setNoteSortMode("updated-desc")}>
            <Check class={noteSortMode === "updated-desc" ? "context-menu-check active" : "context-menu-check"} size={15} />
            <span>Newest First</span>
          </button>
          <button class="context-menu-item" type="button" role="menuitem" onclick={() => setNoteSortMode("updated-asc")}>
            <Check class={noteSortMode === "updated-asc" ? "context-menu-check active" : "context-menu-check"} size={15} />
            <span>Oldest First</span>
          </button>
          <button class="context-menu-item" type="button" role="menuitem" onclick={() => setNoteSortMode("title-asc")}>
            <Check class={noteSortMode === "title-asc" ? "context-menu-check active" : "context-menu-check"} size={15} />
            <span>Title</span>
          </button>
        </div>
      </div>
    </div>
  {/if}
</main>
