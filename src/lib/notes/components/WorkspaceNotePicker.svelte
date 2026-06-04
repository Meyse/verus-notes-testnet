<script lang="ts">
  import { Plus, Search, X } from "@lucide/svelte";
  import type { NoteDraft } from "$lib/notes/types";

  type Props = {
    canCreate: boolean;
    close: () => void;
    createNote: () => void;
    getFolderName: (folderId: string) => string;
    getNoteTitle: (note: NoteDraft | null | undefined) => string;
    handleKeydown: (event: KeyboardEvent) => void;
    index: number;
    open: boolean;
    openNote: (noteId: string) => void | Promise<void>;
    query: string;
    results: NoteDraft[];
    setIndex: (index: number) => void;
    setQuery: (query: string) => void;
  };

  let {
    canCreate,
    close,
    createNote,
    getFolderName,
    getNoteTitle,
    handleKeydown,
    index,
    open,
    openNote,
    query,
    results,
    setIndex,
    setQuery
  }: Props = $props();

  let inputElement = $state<HTMLInputElement | null>(null);

  $effect(() => {
    if (!open || !inputElement) return;

    inputElement.focus();
    inputElement.select();
  });
</script>

{#if open}
  <div class="note-picker-layer" role="presentation" onclick={close}>
    <div
      class="note-picker"
      role="dialog"
      tabindex="-1"
      aria-modal="true"
      aria-label="Open note"
      onclick={(event) => event.stopPropagation()}
      onkeydown={(event) => event.stopPropagation()}
    >
      <label class="note-picker-search">
        <Search size={17} aria-hidden="true" />
        <input
          bind:this={inputElement}
          value={query}
          placeholder="Open note"
          oninput={(event) => setQuery(event.currentTarget.value)}
          onkeydown={handleKeydown}
        />
        <button class="note-picker-close" type="button" title="Close" aria-label="Close" onclick={close}>
          <X size={15} />
        </button>
      </label>

      <div class="note-picker-results">
        {#if results.length > 0}
          {#each results as note, resultIndex}
            <button
              class:selected={resultIndex === index}
              class="note-picker-row"
              type="button"
              onmouseenter={() => setIndex(resultIndex)}
              onclick={() => void openNote(note.id)}
            >
              <span>{getNoteTitle(note)}</span>
              <small>{getFolderName(note.folderId)}</small>
            </button>
          {/each}
        {/if}

        {#if canCreate}
          <button class="note-picker-row create" type="button" onclick={createNote}>
            <Plus size={15} />
            <span>Create "{query.trim()}"</span>
          </button>
        {:else if results.length === 0}
          <p class="note-picker-empty">No notes found</p>
        {/if}
      </div>
    </div>
  </div>
{/if}
