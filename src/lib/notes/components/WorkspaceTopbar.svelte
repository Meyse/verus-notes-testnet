<script lang="ts">
  import { Bookmark, Folder, Plus, Search, X } from "@lucide/svelte";
  import type { NoteTab, SourceMode } from "$lib/notes/types";

  type Props = {
    activeTabId: string | null;
    activateTab: (tabId: string) => void | Promise<void>;
    closeTab: (tabId: string) => void | Promise<void>;
    createBlankTab: () => void;
    getTabTitle: (tab: NoteTab) => string;
    handleTabKeydown: (event: KeyboardEvent, tabId: string) => void;
    noteTabs: NoteTab[];
    setSourceMode: (mode: SourceMode) => void;
    sourceMode: SourceMode;
  };

  let {
    activeTabId,
    activateTab,
    closeTab,
    createBlankTab,
    getTabTitle,
    handleTabKeydown,
    noteTabs,
    setSourceMode,
    sourceMode
  }: Props = $props();
</script>

<header class="workspace-topbar" data-tauri-drag-region="deep">
  <nav class="topbar-source-controls" aria-label="Workspace views">
    <span class="traffic-light-spacer" aria-hidden="true"></span>
    <button
      class:active={sourceMode === "folders"}
      class="topbar-icon-button"
      type="button"
      title="Folders"
      aria-label="Folders"
      aria-pressed={sourceMode === "folders"}
      onclick={() => setSourceMode("folders")}
    >
      <Folder size={18} />
    </button>
    <button
      class:active={sourceMode === "search"}
      class="topbar-icon-button"
      type="button"
      title="Search"
      aria-label="Search"
      aria-pressed={sourceMode === "search"}
      onclick={() => setSourceMode("search")}
    >
      <Search size={18} />
    </button>
    <button
      class:active={sourceMode === "bookmarks"}
      class="topbar-icon-button"
      type="button"
      title="Bookmarks"
      aria-label="Bookmarks"
      aria-pressed={sourceMode === "bookmarks"}
      onclick={() => setSourceMode("bookmarks")}
    >
      <Bookmark size={17} />
    </button>
  </nav>

  <div class="topbar-tab-area">
    <div class="tab-strip" role="tablist" aria-label="Open notes">
      {#each noteTabs as tab}
        <div
          class:active={tab.id === activeTabId}
          class:empty={!tab.noteId}
          class="note-tab"
          role="tab"
          aria-selected={tab.id === activeTabId}
          tabindex={tab.id === activeTabId ? 0 : -1}
          onclick={() => void activateTab(tab.id)}
          onkeydown={(event) => handleTabKeydown(event, tab.id)}
        >
          <span>{getTabTitle(tab)}</span>
          <button
            class="tab-close-button"
            type="button"
            title="Close tab"
            aria-label={`Close ${getTabTitle(tab)}`}
            onclick={(event) => {
              event.stopPropagation();
              void closeTab(tab.id);
            }}
          >
            <X size={14} />
          </button>
        </div>
      {/each}
      <button class="topbar-icon-button new-tab-button" type="button" title="New tab" aria-label="New tab" onclick={createBlankTab}>
        <Plus size={18} />
      </button>
    </div>
  </div>
</header>
