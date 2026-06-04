<script lang="ts">
  import { Folder, FolderOpen, FolderPlus, Lock, Search, Settings, SquarePen } from "@lucide/svelte";
  import { flip } from "svelte/animate";
  import SourceNoteRow from "./SourceNoteRow.svelte";
  import type { FolderDraft, NoteDraft, SourceMode } from "$lib/notes/types";

  type Props = {
    activeFolderId: string;
    activeNoteId: string | null;
    beginFolderRename: (folderId: string) => void;
    bookmarkedNotes: NoteDraft[];
    closeFolderContextMenu: () => void;
    closeSourceMenus: () => void;
    createFolder: () => void | Promise<void>;
    createNote: (title?: string) => void;
    editingFolderId: string | null;
    editingFolderName: string;
    editingNoteId: string | null;
    editingNoteTitle: string;
    filteredNotes: NoteDraft[];
    finishFolderRename: () => void | Promise<void>;
    finishNoteRename: () => void;
    folderNoteCounts: Record<string, number>;
    folders: FolderDraft[];
    getFolderName: (folderId: string) => string;
    getNoteTitle: (note: NoteDraft | null | undefined) => string;
    handleFolderRenameKeydown: (event: KeyboardEvent) => void;
    handleFolderRowKeydown: (event: KeyboardEvent, folderId: string) => void;
    handleNoteRenameKeydown: (event: KeyboardEvent) => void;
    handleNoteRowKeydown: (event: KeyboardEvent, noteId: string) => void;
    lockVault: () => void | Promise<void>;
    openFolderContextMenu: (event: MouseEvent, folderId: string) => void;
    openNoteContextMenu: (event: MouseEvent, note: NoteDraft) => void;
    openNoteInActiveTab: (noteId: string) => void | Promise<void>;
    openSettings: () => void;
    openSourceContextMenu: (event: MouseEvent) => void;
    selectFolder: (folderId: string) => void;
    setEditingFolderName: (name: string) => void;
    setEditingNoteTitle: (title: string) => void;
    setSourceSearchQuery: (query: string) => void;
    settingsOpen: boolean;
    sourceMode: SourceMode;
    sourceSearchQuery: string;
    sourceSearchResults: NoteDraft[];
    unlocked: boolean;
  };

  let {
    activeFolderId,
    activeNoteId,
    beginFolderRename,
    bookmarkedNotes,
    closeFolderContextMenu,
    closeSourceMenus,
    createFolder,
    createNote,
    editingFolderId,
    editingFolderName,
    editingNoteId,
    editingNoteTitle,
    filteredNotes,
    finishFolderRename,
    finishNoteRename,
    folderNoteCounts,
    folders,
    getFolderName,
    getNoteTitle,
    handleFolderRenameKeydown,
    handleFolderRowKeydown,
    handleNoteRenameKeydown,
    handleNoteRowKeydown,
    lockVault,
    openFolderContextMenu,
    openNoteContextMenu,
    openNoteInActiveTab,
    openSettings,
    openSourceContextMenu,
    selectFolder,
    setEditingFolderName,
    setEditingNoteTitle,
    setSourceSearchQuery,
    settingsOpen,
    sourceMode,
    sourceSearchQuery,
    sourceSearchResults,
    unlocked
  }: Props = $props();

  let editingFolderInput = $state<HTMLInputElement | null>(null);
  let editingNoteInput = $state<HTMLInputElement | null>(null);
  let sourceScrollViewport = $state<HTMLElement | null>(null);
  let activeFolderElement = $state<HTMLElement | null>(null);
  let sourceScrolling = $state(false);
  let sourceScrollIdleTimer: ReturnType<typeof setTimeout> | null = null;
  const sourceListFlip = { duration: () => (prefersReducedMotion() ? 0 : 120) };

  $effect(() => {
    if (!editingFolderId || !editingFolderInput) return;

    editingFolderInput.focus();
    editingFolderInput.select();
  });

  $effect(() => {
    if (!editingNoteId || !editingNoteInput) return;

    editingNoteInput.focus();
    editingNoteInput.select();
  });

  $effect(() => {
    activeFolderId;
    if (!sourceScrollViewport || !activeFolderElement) return;

    requestAnimationFrame(() => {
      if (!sourceScrollViewport || !activeFolderElement) return;

      const viewportRect = sourceScrollViewport.getBoundingClientRect();
      const folderRect = activeFolderElement.getBoundingClientRect();
      const isAboveViewport = folderRect.top < viewportRect.top + 8;
      const isBelowViewport = folderRect.bottom > viewportRect.bottom - 8;

      if (isAboveViewport || isBelowViewport) {
        activeFolderElement.scrollIntoView({ block: "nearest" });
      }
    });
  });

  $effect(() => {
    return () => {
      if (sourceScrollIdleTimer) clearTimeout(sourceScrollIdleTimer);
    };
  });

  function prefersReducedMotion() {
    return typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  function showSourceScrollbar() {
    sourceScrolling = true;

    if (sourceScrollIdleTimer) {
      clearTimeout(sourceScrollIdleTimer);
    }

    sourceScrollIdleTimer = setTimeout(() => {
      sourceScrolling = false;
      sourceScrollIdleTimer = null;
    }, 760);
  }

  function activeFolderAnchor(node: HTMLElement, active: boolean) {
    if (active) activeFolderElement = node;

    return {
      update(nextActive: boolean) {
        if (nextActive) {
          activeFolderElement = node;
        } else if (activeFolderElement === node) {
          activeFolderElement = null;
        }
      },
      destroy() {
        if (activeFolderElement === node) activeFolderElement = null;
      }
    };
  }
</script>

<aside class="source-sidebar" oncontextmenu={openSourceContextMenu}>
  {#if sourceMode === "folders"}
    <section class="source-sidebar-main" aria-label="Vault folders">
      <div class="source-section-heading actions-only">
        <div class="source-heading-actions">
          <button
            class="icon-button"
            type="button"
            title="New folder"
            aria-label="New folder"
            onclick={() => void createFolder()}
            disabled={!unlocked}
          >
            <FolderPlus size={17} />
          </button>
          <button class="icon-button" type="button" title="New note" aria-label="New note" onclick={() => createNote()} disabled={!unlocked}>
            <SquarePen size={17} />
          </button>
        </div>
      </div>
      <div
        bind:this={sourceScrollViewport}
        class:scrolling={sourceScrolling}
        class="source-scroll-viewport source-folder-scroll"
        aria-label="Folders and notes"
        onscroll={showSourceScrollbar}
      >
        <div class="source-section source-folder-section">
          {#each folders as folder (folder.id)}
            <div class:active={folder.id === activeFolderId} class="source-folder-block" animate:flip={sourceListFlip}>
              <div
                use:activeFolderAnchor={folder.id === activeFolderId}
                class:selected={folder.id === activeFolderId}
                class="source-row"
                role="button"
                tabindex="0"
                aria-current={folder.id === activeFolderId ? "page" : undefined}
                aria-expanded={folder.id === activeFolderId}
                oncontextmenu={(event) => {
                  closeSourceMenus();
                  openFolderContextMenu(event, folder.id);
                }}
                onclick={() => selectFolder(folder.id)}
                ondblclick={() => beginFolderRename(folder.id)}
                onkeydown={(event) => handleFolderRowKeydown(event, folder.id)}
              >
                {#if folder.id === activeFolderId}
                  <FolderOpen size={18} />
                {:else}
                  <Folder size={18} />
                {/if}
                {#if editingFolderId === folder.id}
                  <input
                    bind:this={editingFolderInput}
                    class="folder-name-input"
                    value={editingFolderName}
                    aria-label="Folder name"
                    onblur={() => void finishFolderRename()}
                    onclick={(event) => event.stopPropagation()}
                    ondblclick={(event) => event.stopPropagation()}
                    oncontextmenu={(event) => event.stopPropagation()}
                    oninput={(event) => setEditingFolderName(event.currentTarget.value)}
                    onkeydown={handleFolderRenameKeydown}
                  />
                {:else}
                  <span>{folder.name}</span>
                {/if}
                <strong>{folderNoteCounts[folder.id] ?? 0}</strong>
              </div>

              {#if folder.id === activeFolderId}
                {#key folder.id}
                  <div class="folder-note-list" aria-label={`${folder.name} notes`}>
                    {#if filteredNotes.length > 0}
                      {#each filteredNotes as note (note.id)}
                        <SourceNoteRow
                          bind:editingNoteInput
                          editing={editingNoteId === note.id}
                          editingTitle={editingNoteTitle}
                          {getNoteTitle}
                          handleRenameKeydown={handleNoteRenameKeydown}
                          handleRowKeydown={handleNoteRowKeydown}
                          {note}
                          openContextMenu={openNoteContextMenu}
                          openNote={openNoteInActiveTab}
                          rowClass="folder-note-row"
                          selected={note.id === activeNoteId}
                          setEditingTitle={setEditingNoteTitle}
                          finishRename={finishNoteRename}
                        />
                      {/each}
                    {:else}
                      <p class="folder-note-empty">No notes</p>
                    {/if}
                  </div>
                {/key}
              {/if}
            </div>
          {/each}
        </div>
      </div>
    </section>
  {:else if sourceMode === "search"}
    <section class="source-sidebar-main source-search-section" aria-label="Search notes">
      <div class="source-section-heading">
        <p>Search</p>
      </div>
      <label class="source-search-field">
        <Search size={16} aria-hidden="true" />
        <input value={sourceSearchQuery} placeholder="Search notes" oninput={(event) => setSourceSearchQuery(event.currentTarget.value)} />
      </label>
      <div
        class:scrolling={sourceScrolling}
        class="source-scroll-viewport source-results-scroll"
        aria-label="Search results"
        onscroll={showSourceScrollbar}
      >
        <div class="source-note-results">
          {#if sourceSearchResults.length > 0}
            {#each sourceSearchResults as note (note.id)}
              <SourceNoteRow
                bind:editingNoteInput
                editing={editingNoteId === note.id}
                editingTitle={editingNoteTitle}
                folderName={getFolderName(note.folderId)}
                {getNoteTitle}
                handleRenameKeydown={handleNoteRenameKeydown}
                handleRowKeydown={handleNoteRowKeydown}
                {note}
                openContextMenu={openNoteContextMenu}
                openNote={openNoteInActiveTab}
                rowClass="source-note-row"
                setEditingTitle={setEditingNoteTitle}
                finishRename={finishNoteRename}
              />
            {/each}
          {:else}
            <p class="source-empty">No notes found</p>
          {/if}
        </div>
      </div>
    </section>
  {:else}
    <section class="source-sidebar-main" aria-label="Bookmarked notes">
      <div class="source-section-heading">
        <p>Bookmarks</p>
      </div>
      <div
        class:scrolling={sourceScrolling}
        class="source-scroll-viewport source-results-scroll"
        aria-label="Bookmarked notes"
        onscroll={showSourceScrollbar}
      >
        <div class="source-note-results">
          {#if bookmarkedNotes.length > 0}
            {#each bookmarkedNotes as note (note.id)}
              <SourceNoteRow
                bind:editingNoteInput
                editing={editingNoteId === note.id}
                editingTitle={editingNoteTitle}
                folderName={getFolderName(note.folderId)}
                {getNoteTitle}
                handleRenameKeydown={handleNoteRenameKeydown}
                handleRowKeydown={handleNoteRowKeydown}
                {note}
                openContextMenu={openNoteContextMenu}
                openNote={openNoteInActiveTab}
                rowClass="source-note-row"
                setEditingTitle={setEditingNoteTitle}
                finishRename={finishNoteRename}
              />
            {/each}
          {:else}
            <p class="source-empty">No bookmarks</p>
          {/if}
        </div>
      </div>
    </section>
  {/if}
  <footer class="source-sidebar-footer" aria-label="Vault actions">
    <button
      class:active={settingsOpen}
      class="sidebar-footer-button"
      type="button"
      title="Settings"
      aria-label="Settings"
      onclick={openSettings}
    >
      <Settings size={18} />
    </button>
    <button class="sidebar-footer-button" type="button" title="Lock vault" aria-label="Lock vault" onclick={lockVault}>
      <Lock size={17} />
    </button>
  </footer>
</aside>
