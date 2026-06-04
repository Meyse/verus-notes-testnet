import type { EncryptedFolder, EncryptedNote, FolderDraft, NoteDraft } from "./types";

export const FREE_SYNC_MAX_NOTES = 20;
export const FREE_SYNC_MAX_STORAGE_BYTES = 2 * 1024 * 1024;

export type CloudSyncSelectionEntry = {
  folderName: string;
  note: NoteDraft;
  noteStorageBytes: number;
  previouslyIncluded: boolean;
  unavailableReason: "storage" | null;
};

export type CloudSyncSelection = {
  entries: CloudSyncSelectionEntry[];
  folderStorageBytes: number;
  maxNotes: number;
  maxStorageBytes: number;
  requiresReview: boolean;
  selectedNoteIds: string[];
  selectedStorageBytes: number;
  totalLiveNotes: number;
};

type CloudSyncPreflightInput = {
  encryptedFolders: Record<string, EncryptedFolder>;
  encryptedNotes: Record<string, EncryptedNote>;
  folders: FolderDraft[];
  maxNotes?: number;
  maxStorageBytes?: number;
  notes: NoteDraft[];
};

export function buildCloudSyncSelection(input: CloudSyncPreflightInput): CloudSyncSelection {
  const maxNotes = input.maxNotes ?? FREE_SYNC_MAX_NOTES;
  const maxStorageBytes = input.maxStorageBytes ?? FREE_SYNC_MAX_STORAGE_BYTES;
  const folderStorageBytes = input.folders.reduce(
    (sum, folder) => sum + encryptedRecordByteLength(input.encryptedFolders[folder.id]),
    0,
  );
  const entries = input.notes.map((note) => {
    const noteStorageBytes = encryptedRecordByteLength(input.encryptedNotes[note.id]);
    const folderName = input.folders.find((folder) => folder.id === note.folderId)?.name ?? "My notes";
    return {
      folderName,
      note,
      noteStorageBytes,
      previouslyIncluded: note.cloudSyncScope === "included" || Boolean(note.lastSyncedRevisionHash),
      unavailableReason: folderStorageBytes + noteStorageBytes > maxStorageBytes ? "storage" as const : null,
    };
  });

  const selectedNoteIds: string[] = [];
  let selectedStorageBytes = folderStorageBytes;

  for (const entry of [...entries].sort(compareDefaultSelectionEntry)) {
    if (entry.unavailableReason) continue;
    if (selectedNoteIds.length >= maxNotes) continue;
    if (selectedStorageBytes + entry.noteStorageBytes > maxStorageBytes) continue;
    selectedNoteIds.push(entry.note.id);
    selectedStorageBytes += entry.noteStorageBytes;
  }

  return {
    entries,
    folderStorageBytes,
    maxNotes,
    maxStorageBytes,
    requiresReview: selectedNoteIds.length !== entries.length,
    selectedNoteIds,
    selectedStorageBytes,
    totalLiveNotes: entries.length,
  };
}

export function updateCloudSyncSelection(
  selection: CloudSyncSelection,
  noteId: string,
  selected: boolean,
): CloudSyncSelection {
  const current = new Set(selection.selectedNoteIds);
  const entry = selection.entries.find((candidate) => candidate.note.id === noteId);
  if (!entry || entry.unavailableReason) return selection;

  if (!selected) {
    current.delete(noteId);
    return selectionWithSelectedIds(selection, current);
  }

  if (current.has(noteId)) return selection;
  if (current.size >= selection.maxNotes) return selection;
  const nextStorageBytes = selectedStorageBytes(selection, current) + entry.noteStorageBytes;
  if (nextStorageBytes > selection.maxStorageBytes) return selection;
  current.add(noteId);
  return selectionWithSelectedIds(selection, current);
}

export function canSelectCloudSyncNote(selection: CloudSyncSelection, noteId: string) {
  if (selection.selectedNoteIds.includes(noteId)) return true;
  const entry = selection.entries.find((candidate) => candidate.note.id === noteId);
  if (!entry || entry.unavailableReason) return false;
  if (selection.selectedNoteIds.length >= selection.maxNotes) return false;
  return selection.selectedStorageBytes + entry.noteStorageBytes <= selection.maxStorageBytes;
}

export function encryptedRecordByteLength(record: EncryptedNote | EncryptedFolder | null | undefined) {
  if (!record) return 0;
  return new TextEncoder().encode(JSON.stringify(record)).byteLength;
}

function selectionWithSelectedIds(selection: CloudSyncSelection, selectedNoteIds: Set<string>) {
  const nextSelectedNoteIds = selection.entries
    .map((entry) => entry.note.id)
    .filter((noteId) => selectedNoteIds.has(noteId));
  return {
    ...selection,
    selectedNoteIds: nextSelectedNoteIds,
    selectedStorageBytes: selectedStorageBytes(selection, selectedNoteIds),
  };
}

function selectedStorageBytes(selection: CloudSyncSelection, selectedNoteIds: Set<string>) {
  return selection.entries.reduce(
    (sum, entry) => sum + (selectedNoteIds.has(entry.note.id) ? entry.noteStorageBytes : 0),
    selection.folderStorageBytes,
  );
}

function compareDefaultSelectionEntry(left: CloudSyncSelectionEntry, right: CloudSyncSelectionEntry) {
  if (left.previouslyIncluded !== right.previouslyIncluded) {
    return left.previouslyIncluded ? -1 : 1;
  }
  if (left.note.updatedAtMs !== right.note.updatedAtMs) {
    return right.note.updatedAtMs - left.note.updatedAtMs;
  }
  if (left.note.createdAtMs !== right.note.createdAtMs) {
    return right.note.createdAtMs - left.note.createdAtMs;
  }
  return left.note.id.localeCompare(right.note.id);
}
