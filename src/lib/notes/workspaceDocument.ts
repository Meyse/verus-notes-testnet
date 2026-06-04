import { DEFAULT_FOLDER_ID } from "./constants";
import {
  filterNotesByQuery,
  getNoteTitle,
  resolveFolderId as resolveFolderIdFromFolders,
  sanitizeFolderName,
  sortFolders,
  sortNotes
} from "./helpers";
import {
  createNoteDraft,
  duplicateNote as duplicateNoteInList,
  getNoteById,
  openNoteInActiveTabState,
  openNoteInNewTabState,
  removeNoteFromTabs as detachNoteFromTabs,
  renameNote as renameNoteInList,
  toggleNoteBookmark
} from "./noteCommands";
import type { FolderDraft, NoteDraft, NoteSortMode, NoteTab, SourceMode } from "./types";

const INITIAL_NOTE_BODY = [
  "This is your first encrypted note. Unlock your vault with your Verus wallet, then write normally.",
  "Verus Notes saves encrypted changes on this device. If you enable encrypted cloud sync, you can conveniently access your notes from any device. You can also always easily export and import your encrypted notes locally.",
  "Use this space for drafts, research, plans, project notes, and anything you want to keep out of plaintext cloud documents.",
  "Inline code can look like `a short code line`.",
  [
    "```",
    "Code blocks keep line breaks.",
    "They are useful for commands, snippets, logs,",
    "or any text where spacing matters.",
    "```"
  ].join("\n"),
  "When this note stops being useful, replace it with something yours."
].join("\n\n");

export type WorkspaceDocumentState = {
  activeFolderId: string;
  activeTabId: string | null;
  folders: FolderDraft[];
  notePickerIndex: number;
  notePickerOpen: boolean;
  notePickerQuery: string;
  notes: NoteDraft[];
  noteSortMode: NoteSortMode;
  noteTabs: NoteTab[];
  sourceMode: SourceMode;
  sourceSearchQuery: string;
  titleSelectionNoteId: string | null;
};

export type NoteListMutation = {
  note: NoteDraft;
  notes: NoteDraft[];
};

export type FolderMutation =
  | { status: "ok"; folder: FolderDraft; folders: FolderDraft[] }
  | { status: "invalid" }
  | { status: "unchanged" };

export type DeleteFolderMutation =
  | { status: "ok"; activeFolderId: string; folders: FolderDraft[] }
  | { status: "default-folder" }
  | { status: "folder-has-notes" }
  | { status: "not-found" };

export function createEmptyDocumentState(): WorkspaceDocumentState {
  return {
    activeFolderId: DEFAULT_FOLDER_ID,
    activeTabId: null,
    folders: [],
    notePickerIndex: 0,
    notePickerOpen: false,
    notePickerQuery: "",
    notes: [],
    noteSortMode: "updated-desc",
    noteTabs: [],
    sourceMode: "folders",
    sourceSearchQuery: "",
    titleSelectionNoteId: null
  };
}

export function createNoteTab(id: string, noteId: string | null = null): NoteTab {
  return { id, noteId };
}

export function ensureActiveFolderId(folders: FolderDraft[], activeFolderId: string) {
  if (folders.some((folder) => folder.id === activeFolderId)) return activeFolderId;
  return folders.find((folder) => folder.id === DEFAULT_FOLDER_ID)?.id ?? folders[0]?.id ?? DEFAULT_FOLDER_ID;
}

export function resolveDocumentFolderId(folders: FolderDraft[], folderId: string | undefined) {
  return resolveFolderIdFromFolders(folders, folderId);
}

export function countNotesByFolder(folders: FolderDraft[], notes: NoteDraft[]) {
  return Object.fromEntries(
    folders.map((folder) => [
      folder.id,
      notes.filter((note) => resolveDocumentFolderId(folders, note.folderId) === folder.id).length
    ])
  );
}

export function filteredDocumentNotes(input: {
  activeFolderId: string;
  folders: FolderDraft[];
  notes: NoteDraft[];
  sortMode: NoteSortMode;
}) {
  return sortNotes(
    input.notes.filter((note) => resolveDocumentFolderId(input.folders, note.folderId) === input.activeFolderId),
    input.sortMode
  );
}

export function searchDocumentNotes(input: {
  folders: FolderDraft[];
  notes: NoteDraft[];
  query: string;
  sortMode: NoteSortMode;
}) {
  return sortNotes(filterNotesByQuery(input.notes, input.query, input.folders), input.sortMode);
}

export function bookmarkedDocumentNotes(notes: NoteDraft[], sortMode: NoteSortMode) {
  return sortNotes(notes.filter((note) => note.bookmarked), sortMode);
}

export function clampPickerIndex(index: number, resultCount: number) {
  return Math.min(Math.max(index, 0), Math.max(0, resultCount - 1));
}

export function canCreateNoteFromPicker(notes: NoteDraft[], query: string) {
  const title = query.trim();
  if (!title) return false;
  return !notes.some((note) => getNoteTitle(note).toLowerCase() === title.toLowerCase());
}

export function getNextFolderSortOrder(folders: FolderDraft[]) {
  return folders.reduce((max, folder) => Math.max(max, folder.sortOrder), 0) + 1000;
}

export function getAvailableFolderName(folders: FolderDraft[], baseName: string) {
  const existingNames = new Set(folders.map((folder) => folder.name.toLowerCase()));
  let candidate = baseName;
  let suffix = 2;

  while (existingNames.has(candidate.toLowerCase())) {
    candidate = `${baseName} ${suffix}`;
    suffix += 1;
  }

  return candidate;
}

export function createFolderMutation(input: {
  folders: FolderDraft[];
  id: string;
  name?: string;
  now: number;
}): FolderMutation {
  const folder = {
    createdAtMs: input.now,
    id: input.id,
    name: input.name ?? getAvailableFolderName(input.folders, "New folder"),
    sortOrder: getNextFolderSortOrder(input.folders),
    updatedAtMs: input.now
  };

  return {
    status: "ok",
    folder,
    folders: sortFolders([...input.folders, folder])
  };
}

export function renameFolderMutation(input: {
  editingName: string;
  folderId: string | null;
  folders: FolderDraft[];
  now: number;
}): FolderMutation {
  const folder = input.folders.find((candidate) => candidate.id === input.folderId);
  const name = sanitizeFolderName(input.editingName);
  if (!folder || !name) return { status: "invalid" };
  if (name === folder.name) return { status: "unchanged" };

  const updated = { ...folder, name, updatedAtMs: input.now };
  return {
    status: "ok",
    folder: updated,
    folders: sortFolders(input.folders.map((candidate) => (candidate.id === updated.id ? updated : candidate)))
  };
}

export function deleteFolderMutation(input: {
  activeFolderId: string;
  folderId: string;
  folders: FolderDraft[];
  notes: NoteDraft[];
}): DeleteFolderMutation {
  const folder = input.folders.find((candidate) => candidate.id === input.folderId);
  if (!folder) return { status: "not-found" };
  if (folder.id === DEFAULT_FOLDER_ID || input.folders.length === 1) return { status: "default-folder" };
  if ((countNotesByFolder(input.folders, input.notes)[folder.id] ?? 0) > 0) return { status: "folder-has-notes" };

  const folders = input.folders.filter((candidate) => candidate.id !== folder.id);
  return {
    status: "ok",
    activeFolderId: ensureActiveFolderId(folders, input.activeFolderId),
    folders
  };
}

export function ensureWorkspaceTabs(input: {
  activeTabId: string | null;
  createTabId: () => string;
  noteTabs: NoteTab[];
  notes: NoteDraft[];
  preferredNoteId?: string | null;
}) {
  const existingNoteIds = new Set(input.notes.map((note) => note.id));
  const sanitizedTabs = input.noteTabs.map((tab) => ({
    ...tab,
    noteId: tab.noteId && existingNoteIds.has(tab.noteId) ? tab.noteId : null
  }));

  if (sanitizedTabs.length === 0) {
    const tab = createNoteTab(
      input.createTabId(),
      input.preferredNoteId && existingNoteIds.has(input.preferredNoteId) ? input.preferredNoteId : null
    );
    return {
      activeTabId: tab.id,
      noteTabs: [tab]
    };
  }

  return {
    activeTabId:
      input.activeTabId && sanitizedTabs.some((tab) => tab.id === input.activeTabId)
        ? input.activeTabId
        : sanitizedTabs[0]?.id ?? null,
    noteTabs: sanitizedTabs
  };
}

export function ensureInitialNote(input: {
  activeFolderId: string;
  createNoteId: () => string;
  createTabId: () => string;
  notes: NoteDraft[];
  now: number;
}) {
  if (input.notes.length !== 0) return null;

  const note = {
    id: input.createNoteId(),
    title: "Welcome to Verus Notes",
    body: INITIAL_NOTE_BODY,
    bookmarked: false,
    folderId: input.activeFolderId,
    createdAtMs: input.now,
    updatedAtMs: input.now
  };
  const tab = createNoteTab(input.createTabId(), note.id);
  return {
    activeTabId: tab.id,
    note,
    noteTabs: [tab],
    notes: [note]
  };
}

export function createNoteMutation(input: {
  activeFolderId: string;
  id: string;
  notes: NoteDraft[];
  now: number;
  title?: string;
}) {
  const title = input.title?.trim() || "Untitled";
  const note = createNoteDraft({
    activeFolderId: input.activeFolderId,
    id: input.id,
    now: input.now,
    title
  });

  return {
    note,
    notes: [note, ...input.notes],
    shouldSelectTitle: title === "Untitled"
  };
}

export function openNoteInActiveTab(input: {
  activeTabId: string | null;
  createTabId: () => string;
  folders: FolderDraft[];
  noteId: string;
  notes: NoteDraft[];
  noteTabs: NoteTab[];
}) {
  return openNoteInActiveTabState({
    activeTabId: input.activeTabId,
    createNoteTab: (noteId) => createNoteTab(input.createTabId(), noteId),
    noteId: input.noteId,
    notes: input.notes,
    noteTabs: input.noteTabs,
    resolveFolderId: (folderId) => resolveDocumentFolderId(input.folders, folderId)
  });
}

export function openNoteInNewTab(input: {
  createTabId: () => string;
  folders: FolderDraft[];
  noteId: string;
  notes: NoteDraft[];
  noteTabs: NoteTab[];
}) {
  return openNoteInNewTabState({
    createNoteTab: (noteId) => createNoteTab(input.createTabId(), noteId),
    noteId: input.noteId,
    notes: input.notes,
    noteTabs: input.noteTabs,
    resolveFolderId: (folderId) => resolveDocumentFolderId(input.folders, folderId)
  });
}

export function removeNoteFromDocumentTabs(input: {
  activeTabId: string | null;
  createTabId: () => string;
  noteId: string;
  notes: NoteDraft[];
  noteTabs: NoteTab[];
}) {
  return ensureWorkspaceTabs({
    activeTabId: input.activeTabId,
    createTabId: input.createTabId,
    noteTabs: detachNoteFromTabs(input.noteTabs, input.noteId),
    notes: input.notes
  });
}

export function toggleBookmarkMutation(notes: NoteDraft[], noteId: string, now: number): NoteListMutation | null {
  return toggleNoteBookmark(notes, noteId, now);
}

export function renameNoteMutation(notes: NoteDraft[], noteId: string, title: string, now: number): NoteListMutation | null {
  return renameNoteInList(notes, noteId, title, now);
}

export function duplicateNoteMutation(input: {
  id: string;
  noteId: string;
  notes: NoteDraft[];
  now: number;
  folders: FolderDraft[];
}): NoteListMutation | null {
  return duplicateNoteInList({
    id: input.id,
    noteId: input.noteId,
    notes: input.notes,
    now: input.now,
    resolveFolderId: (folderId) => resolveDocumentFolderId(input.folders, folderId)
  });
}

export function updateNoteMutation(input: {
  activeNoteId: string | null;
  notes: NoteDraft[];
  now: number;
  patch: Partial<NoteDraft>;
}) {
  let updatedNoteId: string | null = null;
  const notes = input.notes.map((note) => {
    if (note.id !== input.activeNoteId) return note;
    if (!notePatchChangesPersistedFields(note, input.patch)) return note;

    updatedNoteId = note.id;
    return { ...note, ...input.patch, updatedAtMs: input.patch.updatedAtMs ?? input.now };
  });

  return {
    notes: updatedNoteId ? notes : input.notes,
    updatedNoteId
  };
}

export function notePatchChangesPersistedFields(note: NoteDraft, patch: Partial<NoteDraft>) {
  return Object.entries(patch).some(([key, value]) => note[key as keyof NoteDraft] !== value);
}

export function moveNoteToFolderMutation(input: {
  activeNote: NoteDraft | null;
  folders: FolderDraft[];
  folderId: string;
  notes: NoteDraft[];
  now: number;
}): NoteListMutation | null {
  if (!input.activeNote || !input.folders.some((folder) => folder.id === input.folderId)) return null;
  if (input.activeNote.folderId === input.folderId) return null;

  const note = { ...input.activeNote, folderId: input.folderId, updatedAtMs: input.now };
  return {
    note,
    notes: input.notes.map((candidate) => (candidate.id === note.id ? note : candidate))
  };
}

export function getDocumentNoteById(notes: NoteDraft[], noteId: string | null | undefined) {
  return getNoteById(notes, noteId);
}
