import assert from "node:assert/strict";
import { shouldSeedInitialNoteAfterOpen } from "../src/lib/notes/cloudBootstrapPolicy";
import { DEFAULT_FOLDER_ID, DEFAULT_FOLDER_NAME } from "../src/lib/notes/constants";
import {
  bookmarkedDocumentNotes,
  canCreateNoteFromPicker,
  countNotesByFolder,
  createFolderMutation,
  createNoteMutation,
  deleteFolderMutation,
  duplicateNoteMutation,
  ensureActiveFolderId,
  ensureInitialNote,
  ensureWorkspaceTabs,
  filteredDocumentNotes,
  notePatchChangesPersistedFields,
  openNoteInActiveTab,
  removeNoteFromDocumentTabs,
  renameFolderMutation,
  renameNoteMutation,
  searchDocumentNotes,
  toggleBookmarkMutation,
  updateNoteMutation
} from "../src/lib/notes/workspaceDocument";
import type { FolderDraft, NoteDraft, NoteTab } from "../src/lib/notes/types";

const NOW = 1_700_000_000_000;

const defaultFolder: FolderDraft = {
  id: DEFAULT_FOLDER_ID,
  name: DEFAULT_FOLDER_NAME,
  createdAtMs: NOW,
  sortOrder: 0,
  updatedAtMs: NOW
};

const archiveFolder: FolderDraft = {
  id: "folder-archive",
  name: "Archive",
  createdAtMs: NOW,
  sortOrder: 1000,
  updatedAtMs: NOW
};

function note(input: Partial<NoteDraft> & Pick<NoteDraft, "id" | "title">): NoteDraft {
  return {
    body: "",
    bookmarked: false,
    createdAtMs: NOW,
    folderId: DEFAULT_FOLDER_ID,
    updatedAtMs: NOW,
    ...input
  };
}

function idFactory(prefix: string) {
  let count = 0;
  return () => `${prefix}-${++count}`;
}

function folderRules() {
  const folders = [defaultFolder, archiveFolder];
  const notes = [note({ id: "note-1", title: "A", folderId: archiveFolder.id })];

  assert.equal(ensureActiveFolderId(folders, "missing"), DEFAULT_FOLDER_ID);
  assert.deepEqual(countNotesByFolder(folders, notes), {
    [DEFAULT_FOLDER_ID]: 0,
    [archiveFolder.id]: 1
  });

  assert.equal(
    deleteFolderMutation({ activeFolderId: DEFAULT_FOLDER_ID, folderId: DEFAULT_FOLDER_ID, folders, notes }).status,
    "default-folder"
  );
  assert.equal(
    deleteFolderMutation({ activeFolderId: DEFAULT_FOLDER_ID, folderId: archiveFolder.id, folders, notes }).status,
    "folder-has-notes"
  );

  const emptyFolder = { ...archiveFolder, id: "empty-folder", name: "Empty" };
  const deleteResult = deleteFolderMutation({
    activeFolderId: emptyFolder.id,
    folderId: emptyFolder.id,
    folders: [defaultFolder, emptyFolder],
    notes: []
  });
  assert.equal(deleteResult.status, "ok");
  assert.equal(deleteResult.status === "ok" && deleteResult.activeFolderId, DEFAULT_FOLDER_ID);

  const createResult = createFolderMutation({ folders, id: "new-folder", now: NOW + 1 });
  assert.equal(createResult.status, "ok");
  assert.equal(createResult.status === "ok" && createResult.folder.name, "New folder");

  const renameResult = renameFolderMutation({
    editingName: "  Renamed   Folder  ",
    folderId: archiveFolder.id,
    folders,
    now: NOW + 2
  });
  assert.equal(renameResult.status, "ok");
  assert.equal(renameResult.status === "ok" && renameResult.folder.name, "Renamed Folder");
}

function noteRules() {
  const folders = [defaultFolder, archiveFolder];
  const notes = [
    note({ id: "note-1", title: "Zebra", body: "wallet", folderId: DEFAULT_FOLDER_ID, updatedAtMs: NOW + 3 }),
    note({ id: "note-2", title: "Alpha", body: "sync", folderId: archiveFolder.id, updatedAtMs: NOW + 2 }),
    note({ id: "note-3", title: "Alpha (2)", body: "bookmark", bookmarked: true, folderId: DEFAULT_FOLDER_ID, updatedAtMs: NOW + 1 })
  ];

  assert.deepEqual(filteredDocumentNotes({ activeFolderId: DEFAULT_FOLDER_ID, folders, notes, sortMode: "title-asc" }).map((row) => row.id), [
    "note-3",
    "note-1"
  ]);
  assert.deepEqual(searchDocumentNotes({ folders, notes, query: "archive", sortMode: "updated-desc" }).map((row) => row.id), [
    "note-2"
  ]);
  assert.deepEqual(bookmarkedDocumentNotes(notes, "updated-desc").map((row) => row.id), ["note-3"]);
  assert.equal(canCreateNoteFromPicker(notes, "Alpha"), false);
  assert.equal(canCreateNoteFromPicker(notes, "New idea"), true);

  const createResult = createNoteMutation({
    activeFolderId: archiveFolder.id,
    id: "note-4",
    notes,
    now: NOW + 4,
    title: "  "
  });
  assert.equal(createResult.note.title, "Untitled");
  assert.equal(createResult.shouldSelectTitle, true);
  assert.equal(createResult.note.folderId, archiveFolder.id);

  const renameResult = renameNoteMutation(notes, "note-1", "  Updated  ", NOW + 5);
  assert.equal(renameResult?.note.title, "Updated");

  const duplicateResult = duplicateNoteMutation({
    folders,
    id: "note-copy",
    noteId: "note-1",
    notes,
    now: NOW + 6
  });
  assert.equal(duplicateResult?.note.title, "Zebra (2)");
  assert.equal(duplicateResult?.note.bookmarked, false);

  const bookmarkResult = toggleBookmarkMutation(notes, "note-1", NOW + 7);
  assert.equal(bookmarkResult?.note.bookmarked, true);

  const unchangedBodyResult = updateNoteMutation({
    activeNoteId: "note-1",
    notes,
    now: NOW + 8,
    patch: { body: "wallet" }
  });
  assert.equal(unchangedBodyResult.updatedNoteId, null);
  assert.equal(unchangedBodyResult.notes, notes);

  const unchangedTitleResult = updateNoteMutation({
    activeNoteId: "note-1",
    notes,
    now: NOW + 9,
    patch: { title: "Zebra" }
  });
  assert.equal(unchangedTitleResult.updatedNoteId, null);
  assert.equal(unchangedTitleResult.notes[0]?.updatedAtMs, NOW + 3);

  const changedBodyResult = updateNoteMutation({
    activeNoteId: "note-1",
    notes,
    now: NOW + 10,
    patch: { body: "updated wallet" }
  });
  assert.equal(changedBodyResult.updatedNoteId, "note-1");
  assert.equal(changedBodyResult.notes[0]?.body, "updated wallet");
  assert.equal(changedBodyResult.notes[0]?.updatedAtMs, NOW + 10);

  assert.equal(notePatchChangesPersistedFields(notes[0]!, { body: "wallet" }), false);
  assert.equal(notePatchChangesPersistedFields(notes[0]!, { bookmarked: true }), true);
}

function tabRules() {
  const notes = [note({ id: "note-1", title: "One" }), note({ id: "note-2", title: "Two" })];
  const tabs: NoteTab[] = [
    { id: "tab-1", noteId: "note-1" },
    { id: "tab-2", noteId: "missing" }
  ];

  const ensured = ensureWorkspaceTabs({
    activeTabId: "missing-tab",
    createTabId: idFactory("tab"),
    noteTabs: tabs,
    notes
  });
  assert.equal(ensured.activeTabId, "tab-1");
  assert.deepEqual(ensured.noteTabs[1], { id: "tab-2", noteId: null });

  const opened = openNoteInActiveTab({
    activeTabId: "tab-1",
    createTabId: idFactory("new-tab"),
    folders: [defaultFolder],
    noteId: "note-2",
    notes,
    noteTabs: tabs
  });
  assert.equal(opened?.activeTabId, "tab-1");
  assert.equal(opened?.activeFolderId, DEFAULT_FOLDER_ID);
  assert.equal(opened?.noteTabs[0]?.noteId, "note-2");

  const removed = removeNoteFromDocumentTabs({
    activeTabId: "tab-1",
    createTabId: idFactory("tab"),
    noteId: "note-1",
    notes: notes.filter((row) => row.id !== "note-1"),
    noteTabs: tabs
  });
  assert.equal(removed.noteTabs[0]?.noteId, null);

  const initial = ensureInitialNote({
    activeFolderId: DEFAULT_FOLDER_ID,
    createNoteId: idFactory("note"),
    createTabId: idFactory("tab"),
    notes: [],
    now: NOW
  });
  assert.equal(initial?.note.title, "Welcome to Verus Notes");
  assert.match(initial?.note.body ?? "", /This is your first encrypted note\./);
  assert.match(initial?.note.body ?? "", /If you enable encrypted cloud sync/);
  assert.match(initial?.note.body ?? "", /`a short code line`/);
  assert.match(initial?.note.body ?? "", /```\nCode blocks keep line breaks\./);
  assert.equal(initial?.noteTabs[0]?.noteId, initial?.note.id);
}

function cloudBootstrapRules() {
  assert.equal(
    shouldSeedInitialNoteAfterOpen({
      cloudReplica: undefined,
      noteCount: 0,
      storageMode: "sync_enabled"
    }),
    false
  );
  assert.equal(
    shouldSeedInitialNoteAfterOpen({
      cloudReplica: { checked: true, liveFolderCount: 0, liveNoteCount: 0 },
      noteCount: 0,
      storageMode: "sync_enabled"
    }),
    true
  );
  assert.equal(
    shouldSeedInitialNoteAfterOpen({
      cloudReplica: { checked: true, liveFolderCount: 1, liveNoteCount: 1 },
      noteCount: 0,
      storageMode: "sync_enabled"
    }),
    false
  );
  assert.equal(
    shouldSeedInitialNoteAfterOpen({
      noteCount: 0,
      storageMode: "local_only"
    }),
    true
  );
}

folderRules();
noteRules();
tabRules();
cloudBootstrapRules();

console.log("workspace document tests passed");
