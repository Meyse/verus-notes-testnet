<script lang="ts">
  import { Cloud, HardDrive, X } from "@lucide/svelte";
  import type { CloudSyncSelection, CloudSyncSelectionEntry } from "$lib/notes/cloudSyncPreflight";

  type Props = {
    busy: boolean;
    cancel: () => void;
    confirm: () => void | Promise<void>;
    keepLocal: () => void | Promise<void>;
    selection: CloudSyncSelection;
    toggleNote: (noteId: string, selected: boolean) => void;
  };

  let { busy, cancel, confirm, keepLocal, selection, toggleNote }: Props = $props();
  const selectedNoteIds = $derived(new Set(selection.selectedNoteIds));
  const selectedCount = $derived(selection.selectedNoteIds.length);
  const selectedStorageBytes = $derived(selection.selectedStorageBytes);

  function canSelect(entry: CloudSyncSelectionEntry) {
    if (selectedNoteIds.has(entry.note.id)) return true;
    if (entry.unavailableReason) return false;
    if (selectedCount >= selection.maxNotes) return false;
    return selectedStorageBytes + entry.noteStorageBytes <= selection.maxStorageBytes;
  }

  function formatStorageBytes(bytes: number) {
    if (bytes >= 1024 * 1024) return `${formatCompactNumber(bytes / (1024 * 1024))} MB`;
    if (bytes >= 1024) return `${formatCompactNumber(bytes / 1024)} KB`;
    return `${bytes} B`;
  }

  function formatCompactNumber(value: number) {
    return Number.isInteger(value) ? value.toString() : value.toFixed(1);
  }

  function noteStatus(entry: CloudSyncSelectionEntry) {
    if (entry.unavailableReason === "storage") return "Too large";
    return selectedNoteIds.has(entry.note.id) ? "Selected" : "This device only";
  }
</script>

<div class="settings-modal-layer cloud-sync-selection-layer" role="presentation" onclick={cancel}>
  <div
    class="settings-sync-modal cloud-sync-selection-modal"
    role="dialog"
    tabindex="-1"
    aria-modal="true"
    aria-labelledby="cloud-sync-selection-title"
    onclick={(event) => event.stopPropagation()}
    onkeydown={(event) => event.stopPropagation()}
  >
    <header class="settings-sync-modal-header">
      <div>
        <h2 id="cloud-sync-selection-title">Choose notes to sync</h2>
        <p>{selectedCount} of {selection.maxNotes} notes selected</p>
      </div>
      <button class="settings-sync-modal-close" type="button" title="Close" aria-label="Close note selection" onclick={cancel}>
        <X size={18} aria-hidden="true" />
      </button>
    </header>

    <div class="settings-sync-modal-body cloud-sync-selection-body">
      <div class="cloud-sync-selection-summary" role="status">
        <Cloud size={16} aria-hidden="true" />
        <div>
          <strong>Free cloud sync includes 20 notes and 2 MB of encrypted data.</strong>
          <p>We selected your previous synced notes first. You can change this before syncing.</p>
        </div>
      </div>

      <div class="cloud-sync-selection-usage">
        <span>
          <Cloud size={14} aria-hidden="true" />
          {selectedCount} of {selection.maxNotes} notes
        </span>
        <span>
          <HardDrive size={14} aria-hidden="true" />
          {formatStorageBytes(selectedStorageBytes)} of {formatStorageBytes(selection.maxStorageBytes)}
        </span>
      </div>

      <div class="settings-sync-note-list cloud-sync-selection-list" aria-label="Notes available for encrypted cloud sync">
        {#each selection.entries as entry}
          <label class:unavailable={entry.unavailableReason} class="settings-sync-note-row cloud-sync-selection-row">
            <input
              type="checkbox"
              checked={selectedNoteIds.has(entry.note.id)}
              disabled={busy || !canSelect(entry)}
              onchange={(event) => toggleNote(entry.note.id, event.currentTarget.checked)}
            />
            <span class="settings-sync-note-copy">
              <strong title={entry.note.title || "Untitled"}>{entry.note.title || "Untitled"}</strong>
              <span class="settings-sync-note-meta">
                <span class="settings-sync-note-folder" title={entry.folderName}>{entry.folderName}</span>
                <span class={selectedNoteIds.has(entry.note.id) ? "cloud" : entry.unavailableReason ? "warning" : "local"}>{noteStatus(entry)}</span>
              </span>
            </span>
          </label>
        {/each}
      </div>
    </div>

    <footer class="settings-sync-modal-footer cloud-sync-selection-footer">
      <button class="secondary-button" type="button" disabled={busy} onclick={keepLocal}>Keep all notes local</button>
      <button class="primary-button" type="button" disabled={busy || selectedCount === 0} onclick={confirm}>Sync selected notes</button>
    </footer>
  </div>
</div>
