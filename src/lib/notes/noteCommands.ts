import type { NoteDraft, NoteTab } from "./types";
import { getNoteTitle } from "./helpers";

type NoteListMutation = {
  note: NoteDraft;
  notes: NoteDraft[];
};

type NoteTabSelection = {
  activeFolderId: string;
  activeTabId: string;
  noteTabs: NoteTab[];
};

type CreateNoteTab = (noteId: string | null) => NoteTab;
type ResolveFolderId = (folderId: string | undefined) => string;

export function getNoteById(notes: NoteDraft[], noteId: string | null | undefined) {
  if (!noteId) return null;
  return notes.find((note) => note.id === noteId) ?? null;
}

export function createNoteDraft(input: {
  activeFolderId: string;
  id: string;
  now: number;
  title?: string;
}): NoteDraft {
  return {
    id: input.id,
    title: input.title ?? "Untitled",
    body: "",
    bookmarked: false,
    folderId: input.activeFolderId,
    createdAtMs: input.now,
    updatedAtMs: input.now
  };
}

export function openNoteInActiveTabState(input: {
  activeTabId: string | null;
  createNoteTab: CreateNoteTab;
  noteId: string;
  notes: NoteDraft[];
  noteTabs: NoteTab[];
  resolveFolderId: ResolveFolderId;
}): NoteTabSelection | null {
  const note = getNoteById(input.notes, input.noteId);
  if (!note) return null;

  const existingTab = input.noteTabs.find((tab) => tab.noteId === input.noteId);
  if (existingTab) {
    return selectNoteTab(input.noteTabs, existingTab.id, note, input.resolveFolderId);
  }

  if (input.activeTabId && input.noteTabs.some((tab) => tab.id === input.activeTabId)) {
    const noteTabs = input.noteTabs.map((tab) =>
      tab.id === input.activeTabId ? { ...tab, noteId: input.noteId } : tab
    );
    return selectNoteTab(noteTabs, input.activeTabId, note, input.resolveFolderId);
  }

  const tab = input.createNoteTab(input.noteId);
  return selectNoteTab([...input.noteTabs, tab], tab.id, note, input.resolveFolderId);
}

export function openNoteInNewTabState(input: {
  createNoteTab: CreateNoteTab;
  noteId: string;
  notes: NoteDraft[];
  noteTabs: NoteTab[];
  resolveFolderId: ResolveFolderId;
}): NoteTabSelection | null {
  const note = getNoteById(input.notes, input.noteId);
  if (!note) return null;

  const tab = input.createNoteTab(input.noteId);
  return selectNoteTab([...input.noteTabs, tab], tab.id, note, input.resolveFolderId);
}

export function removeNoteFromTabs(noteTabs: NoteTab[], noteId: string) {
  return noteTabs.map((tab) => (tab.noteId === noteId ? { ...tab, noteId: null } : tab));
}

export function toggleNoteBookmark(notes: NoteDraft[], noteId: string, now: number): NoteListMutation | null {
  const note = getNoteById(notes, noteId);
  if (!note) return null;

  const updated = { ...note, bookmarked: !note.bookmarked, updatedAtMs: now };
  return replaceNote(notes, updated);
}

export function renameNote(notes: NoteDraft[], noteId: string, title: string, now: number): NoteListMutation | null {
  const note = getNoteById(notes, noteId);
  if (!note) return null;

  const nextTitle = title.trim() || "Untitled";
  if (nextTitle === note.title) return null;

  return replaceNote(notes, { ...note, title: nextTitle, updatedAtMs: now });
}

export function duplicateNote(input: {
  id: string;
  noteId: string;
  notes: NoteDraft[];
  now: number;
  resolveFolderId: ResolveFolderId;
}): NoteListMutation | null {
  const note = getNoteById(input.notes, input.noteId);
  if (!note) return null;

  const duplicate = {
    ...note,
    id: input.id,
    title: getDuplicateNoteTitle(input.notes, note.title),
    bookmarked: false,
    folderId: input.resolveFolderId(note.folderId),
    createdAtMs: input.now,
    updatedAtMs: input.now
  };

  return {
    note: duplicate,
    notes: [duplicate, ...input.notes]
  };
}

export function getDuplicateNoteTitle(notes: NoteDraft[], title: string) {
  const baseTitle = (title.trim() || "Untitled").replace(/\s+\(\d+\)$/, "");
  const existingTitles = new Set(notes.map((note) => getNoteTitle(note)));

  let copyNumber = 2;
  while (existingTitles.has(`${baseTitle} (${copyNumber})`)) {
    copyNumber += 1;
  }
  return `${baseTitle} (${copyNumber})`;
}

function selectNoteTab(
  noteTabs: NoteTab[],
  activeTabId: string,
  note: NoteDraft,
  resolveFolderId: ResolveFolderId
): NoteTabSelection {
  return {
    activeFolderId: resolveFolderId(note.folderId),
    activeTabId,
    noteTabs
  };
}

function replaceNote(notes: NoteDraft[], note: NoteDraft): NoteListMutation {
  return {
    note,
    notes: notes.map((candidate) => (candidate.id === note.id ? note : candidate))
  };
}
