<script lang="ts">
  import type { NoteDraft } from "$lib/notes/types";

  type Props = {
    editing: boolean;
    editingNoteInput?: HTMLInputElement | null;
    editingTitle: string;
    folderName?: string | null;
    getNoteTitle: (note: NoteDraft | null | undefined) => string;
    handleRenameKeydown: (event: KeyboardEvent) => void;
    handleRowKeydown: (event: KeyboardEvent, noteId: string) => void;
    note: NoteDraft;
    openContextMenu: (event: MouseEvent, note: NoteDraft) => void;
    openNote: (noteId: string) => void | Promise<void>;
    rowClass: "folder-note-row" | "source-note-row";
    selected?: boolean;
    setEditingTitle: (title: string) => void;
    finishRename: () => void;
  };

  let {
    editing,
    editingNoteInput = $bindable<HTMLInputElement | null>(null),
    editingTitle,
    folderName = null,
    getNoteTitle,
    handleRenameKeydown,
    handleRowKeydown,
    note,
    openContextMenu,
    openNote,
    rowClass,
    selected = false,
    setEditingTitle,
    finishRename
  }: Props = $props();

</script>

<div
  class:selected={selected}
  class={rowClass}
  role="button"
  tabindex="0"
  oncontextmenu={(event) => openContextMenu(event, note)}
  onclick={() => !editing && openNote(note.id)}
  onkeydown={(event) => handleRowKeydown(event, note.id)}
>
  {#if editing}
    <input
      bind:this={editingNoteInput}
      class="note-name-input"
      value={editingTitle}
      aria-label="Note name"
      onblur={finishRename}
      onclick={(event) => event.stopPropagation()}
      ondblclick={(event) => event.stopPropagation()}
      oncontextmenu={(event) => event.stopPropagation()}
      oninput={(event) => setEditingTitle(event.currentTarget.value)}
      onkeydown={handleRenameKeydown}
    />
  {:else}
    <span>{getNoteTitle(note)}</span>
  {/if}

  {#if folderName}
    <small>{folderName}</small>
  {/if}

</div>
