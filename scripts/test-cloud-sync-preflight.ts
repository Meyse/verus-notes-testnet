import assert from "node:assert/strict";

import {
  buildCloudSyncSelection,
  FREE_SYNC_MAX_NOTES,
  updateCloudSyncSelection,
} from "../src/lib/notes/cloudSyncPreflight";
import { notesExcludedFromCloudSync, remoteMergeWarningPatch } from "../src/lib/notes/vaultWorkspaceRuntime";
import type {
  EncryptedFolder,
  EncryptedNote,
  FolderDraft,
  LocalEncryptedNoteRecord,
  NoteDraft,
} from "../src/lib/notes/types";

const folder: FolderDraft = {
  createdAtMs: 1,
  id: "folder-1",
  name: "Notes",
  sortOrder: 0,
  updatedAtMs: 1,
};

function note(input: Partial<NoteDraft> & Pick<NoteDraft, "id">): NoteDraft {
  return {
    body: "Body",
    bookmarked: false,
    cloudSyncScope: "local_only",
    createdAtMs: 1,
    folderId: folder.id,
    title: input.id,
    updatedAtMs: 1,
    ...input,
  };
}

function encryptedNote(noteId: string, bytes = 24): EncryptedNote {
  return {
    ciphertext: Buffer.alloc(bytes, 1).toString("base64url"),
    header: {
      algorithm: "XCHACHA20-POLY1305",
      contentVersion: 1,
      keyVersion: 1,
      noteId,
      schemaVersion: 1,
      vaultId: "vault-1",
    },
    nonce: Buffer.alloc(24, 2).toString("base64url"),
  };
}

function encryptedFolder(folderId: string): EncryptedFolder {
  return {
    ciphertext: Buffer.alloc(24, 3).toString("base64url"),
    header: {
      algorithm: "XCHACHA20-POLY1305",
      contentVersion: 1,
      folderId,
      keyVersion: 1,
      schemaVersion: 1,
      vaultId: "vault-1",
    },
    nonce: Buffer.alloc(24, 4).toString("base64url"),
  };
}

function encryptedNotesFor(notes: NoteDraft[]) {
  return Object.fromEntries(notes.map((candidate) => [candidate.id, encryptedNote(candidate.id)]));
}

function localRecord(
  noteId: string,
  input: Partial<LocalEncryptedNoteRecord> = {},
): LocalEncryptedNoteRecord {
  return {
    cloudSyncScope: "included",
    contentVersion: 1,
    createdAtMs: 1,
    encryptedNote: encryptedNote(noteId),
    lastSyncedRevisionHash: "revision-1",
    noteId,
    revisionHash: "revision-1",
    syncState: "synced",
    updatedAtMs: 1,
    ...input,
  };
}

function skipsReviewWhenVaultFits() {
  const notes = [note({ id: "note-1" }), note({ id: "note-2" })];
  const selection = buildCloudSyncSelection({
    encryptedFolders: { [folder.id]: encryptedFolder(folder.id) },
    encryptedNotes: encryptedNotesFor(notes),
    folders: [folder],
    notes,
  });

  assert.equal(selection.requiresReview, false);
  assert.deepEqual(selection.selectedNoteIds, ["note-1", "note-2"]);
}

function preservesPreviousSelectionThenUsesRecentNotes() {
  const notes = Array.from({ length: FREE_SYNC_MAX_NOTES + 1 }, (_, index) => {
    const noteNumber = index + 1;
    return note({
      cloudSyncScope: noteNumber === 21 ? "included" : "local_only",
      id: `note-${noteNumber}`,
      updatedAtMs: noteNumber,
    });
  });
  const selection = buildCloudSyncSelection({
    encryptedFolders: { [folder.id]: encryptedFolder(folder.id) },
    encryptedNotes: encryptedNotesFor(notes),
    folders: [folder],
    notes,
  });

  assert.equal(selection.requiresReview, true);
  assert.equal(selection.selectedNoteIds.length, FREE_SYNC_MAX_NOTES);
  assert(selection.selectedNoteIds.includes("note-21"));
  assert(!selection.selectedNoteIds.includes("note-1"));
}

function excludesNotesThatWouldExceedStorage() {
  const notes = [note({ id: "small-note" }), note({ id: "large-note", updatedAtMs: 2 })];
  const encryptedNotes = {
    "large-note": encryptedNote("large-note", 200),
    "small-note": encryptedNote("small-note", 8),
  };
  const selection = buildCloudSyncSelection({
    encryptedFolders: { [folder.id]: encryptedFolder(folder.id) },
    encryptedNotes,
    folders: [folder],
    maxStorageBytes: 500,
    notes,
  });

  assert.equal(selection.requiresReview, true);
  assert.deepEqual(selection.selectedNoteIds, ["small-note"]);
  assert.equal(
    selection.entries.find((entry) => entry.note.id === "large-note")?.unavailableReason,
    "storage",
  );
}

function manualSelectionCannotOverfillQuota() {
  const notes = [note({ id: "note-1" }), note({ id: "note-2", updatedAtMs: 2 })];
  let selection = buildCloudSyncSelection({
    encryptedFolders: { [folder.id]: encryptedFolder(folder.id) },
    encryptedNotes: encryptedNotesFor(notes),
    folders: [folder],
    maxNotes: 1,
    notes,
  });

  assert.deepEqual(selection.selectedNoteIds, ["note-2"]);
  selection = updateCloudSyncSelection(selection, "note-1", true);
  assert.deepEqual(selection.selectedNoteIds, ["note-2"]);
  selection = updateCloudSyncSelection(selection, "note-2", false);
  selection = updateCloudSyncSelection(selection, "note-1", true);
  assert.deepEqual(selection.selectedNoteIds, ["note-1"]);
}

function cloudBackedExcludedNotesNeedRemoteRemoval() {
  const records = [
    localRecord("selected-note"),
    localRecord("excluded-cloud-note", { remoteCloudState: "live" }),
    localRecord("local-only-note", {
      cloudSyncScope: "local_only",
      lastSyncedRevisionHash: null,
      remoteCloudState: null,
      syncState: "not_synced",
    }),
    localRecord("deleted-note", { deletedAtMs: 2 }),
    localRecord("conflict-note", { syncState: "conflict" }),
    localRecord("already-removed-note", {
      remoteCloudState: "removed_from_sync",
      remoteRemovedFromSyncAtMs: 2,
    }),
  ];

  assert.deepEqual(
    notesExcludedFromCloudSync(records, ["selected-note"]).map((candidate) => candidate.noteId),
    ["excluded-cloud-note"],
  );
  assert.deepEqual(notesExcludedFromCloudSync(records, undefined), []);
}

function rejectedRemoteRowsProduceWarningStatus() {
  assert.deepEqual(remoteMergeWarningPatch({ rejected: 1 }), {
    cloudStatus: "Some cloud records could not be verified",
    status: "Cloud sync needs review",
  });
  assert.equal(remoteMergeWarningPatch({ rejected: 0 }), null);
}

skipsReviewWhenVaultFits();
preservesPreviousSelectionThenUsesRecentNotes();
excludesNotesThatWouldExceedStorage();
manualSelectionCannotOverfillQuota();
cloudBackedExcludedNotesNeedRemoteRemoval();
rejectedRemoteRowsProduceWarningStatus();

console.log("cloud sync preflight tests passed");
