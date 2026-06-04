import type { FolderDraft, NoteDraft, NoteSortMode } from "./types";
import { DEFAULT_FOLDER_ID, DEFAULT_FOLDER_NAME } from "./constants";

const editorDateFormatter = new Intl.DateTimeFormat(undefined, {
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  month: "long",
  year: "numeric"
});

export function formatEditorDate(timestampMs: number) {
  return editorDateFormatter.format(new Date(timestampMs)).replace(",", " at");
}

export function getNoteTitle(note: NoteDraft | null | undefined) {
  return note?.title.trim() || "Untitled";
}

export function normalizeSearchQuery(value: string) {
  return value.trim().toLowerCase();
}

export function sortNotes(noteRows: NoteDraft[], sortMode: NoteSortMode) {
  return [...noteRows].sort((left, right) => {
    if (sortMode === "title-asc") {
      const titleOrder = (left.title || "Untitled").localeCompare(right.title || "Untitled");
      return titleOrder !== 0 ? titleOrder : right.updatedAtMs - left.updatedAtMs;
    }

    if (sortMode === "updated-asc") {
      return left.updatedAtMs - right.updatedAtMs;
    }

    return right.updatedAtMs - left.updatedAtMs;
  });
}

export function getFolderName(folders: FolderDraft[], folderId: string) {
  return folders.find((folder) => folder.id === resolveFolderId(folders, folderId))?.name ?? DEFAULT_FOLDER_NAME;
}

export function filterNotesByQuery(noteRows: NoteDraft[], value: string, folders: FolderDraft[]) {
  const needle = normalizeSearchQuery(value);
  if (!needle) return noteRows;

  return noteRows.filter((note) => {
    return (
      note.title.toLowerCase().includes(needle) ||
      note.body.toLowerCase().includes(needle) ||
      getFolderName(folders, note.folderId).toLowerCase().includes(needle)
    );
  });
}

export function resolveFolderId(folders: FolderDraft[], folderId: string | undefined) {
  if (folderId && folders.some((folder) => folder.id === folderId)) {
    return folderId;
  }

  return DEFAULT_FOLDER_ID;
}

export function sortFolders(folderRows: FolderDraft[]) {
  return [...folderRows].sort((left, right) => {
    if (left.sortOrder !== right.sortOrder) return left.sortOrder - right.sortOrder;
    return left.name.localeCompare(right.name);
  });
}

export function sanitizeFolderName(name: string) {
  return name.trim().replace(/\s+/g, " ").slice(0, 80);
}

export function clamp(value: number, min: number, max: number) {
  return Math.min(Math.max(value, min), max);
}

export function delay(ms: number) {
  return new Promise<void>((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

export function formatCountdown(totalSeconds: number) {
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes.toString().padStart(2, "0")}:${seconds.toString().padStart(2, "0")}`;
}

export function formatErrorBody(body: string) {
  if (!body) return "";

  try {
    const parsed = JSON.parse(body) as { error?: unknown; message?: unknown };
    if (typeof parsed.message === "string") return parsed.message;
    if (typeof parsed.error === "string") return parsed.error;
  } catch {
    // Fall back to the raw response body below.
  }

  return body;
}
