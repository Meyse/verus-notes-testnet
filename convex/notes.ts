import { v } from "convex/values";
import { paginationOptsValidator } from "convex/server";

import type { Id } from "./_generated/dataModel";
import { type MutationCtx, type QueryCtx, mutation, query } from "./_generated/server";
import { requireSession } from "./lib/backendAuth";
import {
  type EncryptedRecordWriteAdapter,
  encryptedRecordCiphertextFields,
  encryptedRecordHeaderFields,
  encryptedRecordStorageBytes,
  FREE_SYNC_MAX_NOTES,
  FREE_SYNC_MAX_STORAGE_BYTES,
  isLiveCloudRecord,
  removeEncryptedRecordFromCloudSync,
  tombstoneEncryptedRecord,
  upsertEncryptedRecord,
} from "./lib/encryptedRecords";

const ciphertextHeader = v.object({
  ...encryptedRecordHeaderFields,
  noteId: v.string(),
});

const encryptedNote = v.object({
  header: ciphertextHeader,
  ...encryptedRecordCiphertextFields,
});

const WRITE_LIMIT_PER_MINUTE = 120;
const WRITE_WINDOW_MS = 60_000;

const noteWriteAdapter: EncryptedRecordWriteAdapter<"noteId", Id<"notes">> = {
  countField: "liveSyncedNoteCount",
  deleteLogName: "convex_note_delete",
  getExisting: async (ctx, vaultId, noteId) => {
    return await ctx.db
      .query("notes")
      .withIndex("by_vault_note", (q) => q.eq("vaultId", vaultId).eq("noteId", noteId))
      .unique();
  },
  getUsage: async (ctx, vaultId) => {
    return await ctx.db
      .query("vaultUsage")
      .withIndex("by_vault_id", (q) => q.eq("vaultId", vaultId))
      .unique();
  },
  idField: "noteId",
  insert: async (ctx, row) => await ctx.db.insert("notes", row),
  insertUsage: async (ctx, row) => await ctx.db.insert("vaultUsage", row),
  kind: "note",
  maxRecordsPerVault: FREE_SYNC_MAX_NOTES,
  patch: async (ctx, noteId, row) => {
    await ctx.db.patch(noteId, row);
  },
  patchUsage: async (ctx, usageId, row) => {
    await ctx.db.patch(usageId as Id<"vaultUsage">, row);
  },
  rateLimitKeyPrefix: "write:note",
  writeLimit: WRITE_LIMIT_PER_MINUTE,
  writeLogName: "convex_note_write",
  writeWindowMs: WRITE_WINDOW_MS,
};

export const list = query({
  args: {
    paginationOpts: paginationOptsValidator,
    sessionToken: v.string(),
  },
  handler: async (ctx, args) => {
    const session = await requireSession(ctx, args.sessionToken);

    return await ctx.db
      .query("notes")
      .withIndex("by_vault_updated", (q) => q.eq("vaultId", session.vaultId))
      .paginate(args.paginationOpts);
  },
});

export const upsert = mutation({
  args: {
    sessionToken: v.string(),
    encryptedNote,
  },
  handler: async (ctx, args) => {
    return await upsertEncryptedRecord(ctx, {
      adapter: noteWriteAdapter,
      encryptedRecord: args.encryptedNote,
      sessionToken: args.sessionToken,
    });
  },
});

export const remove = mutation({
  args: {
    encryptedNote,
    sessionToken: v.string(),
    deletedAtMs: v.number(),
  },
  handler: async (ctx, args) => {
    return await tombstoneEncryptedRecord(ctx, {
      adapter: noteWriteAdapter,
      deletedAtMs: args.deletedAtMs,
      encryptedRecord: args.encryptedNote,
      sessionToken: args.sessionToken,
    });
  },
});

export const removeFromCloudSync = mutation({
  args: {
    sessionToken: v.string(),
    noteId: v.string(),
    contentVersion: v.number(),
    removedAtMs: v.number(),
  },
  handler: async (ctx, args) => {
    return await removeEncryptedRecordFromCloudSync(ctx, {
      adapter: noteWriteAdapter,
      contentVersion: args.contentVersion,
      recordId: args.noteId,
      removedAtMs: args.removedAtMs,
      sessionToken: args.sessionToken,
    });
  },
});

export const usage = query({
  args: {
    sessionToken: v.string(),
  },
  handler: async (ctx, args) => {
    const session = await requireSession(ctx, args.sessionToken);
    return await usageSnapshot(ctx, session.vaultId);
  },
});

export const reconcileUsage = mutation({
  args: {
    sessionToken: v.string(),
  },
  handler: async (ctx, args) => {
    const session = await requireSession(ctx, args.sessionToken);
    return await reconcileUsageForVault(ctx, session.vaultId);
  },
});

async function usageSnapshot(ctx: QueryCtx | MutationCtx, vaultId: string) {
  const [storedUsage, noteRows, folderRows] = await Promise.all([
    ctx.db
      .query("vaultUsage")
      .withIndex("by_vault_id", (q) => q.eq("vaultId", vaultId))
      .unique(),
    ctx.db
      .query("notes")
      .withIndex("by_vault_updated", (q) => q.eq("vaultId", vaultId))
      .collect(),
    ctx.db
      .query("folders")
      .withIndex("by_vault_updated", (q) => q.eq("vaultId", vaultId))
      .collect(),
  ]);
  const liveNotes = noteRows.filter(isLiveCloudRecord);
  const liveFolders = folderRows.filter(isLiveCloudRecord);
  const nowMs = Date.now();

  return {
    vaultId,
    planKind: "free" as const,
    maxSyncedNotes: storedUsage?.maxSyncedNotes ?? FREE_SYNC_MAX_NOTES,
    maxStorageBytes: storedUsage?.maxStorageBytes ?? FREE_SYNC_MAX_STORAGE_BYTES,
    liveSyncedNoteCount: liveNotes.length,
    liveSyncedFolderCount: liveFolders.length,
    liveStorageBytes: [...liveNotes, ...liveFolders].reduce(
      (sum, row) => sum + Math.max(0, row.accountedStorageBytes ?? encryptedRecordStorageBytes(row)),
      0,
    ),
    updatedAtMs: storedUsage?.updatedAtMs ?? nowMs,
  };
}

export async function reconcileUsageForVault(ctx: MutationCtx, vaultId: string) {
  const snapshot = await usageSnapshot(ctx, vaultId);
  const storedUsage = await ctx.db
    .query("vaultUsage")
    .withIndex("by_vault_id", (q) => q.eq("vaultId", vaultId))
    .unique();
  const updatedAtMs = Date.now();
  const patch = {
    liveSyncedNoteCount: snapshot.liveSyncedNoteCount,
    liveSyncedFolderCount: snapshot.liveSyncedFolderCount,
    liveStorageBytes: snapshot.liveStorageBytes,
    maxStorageBytes: snapshot.maxStorageBytes,
    maxSyncedNotes: snapshot.maxSyncedNotes,
    planKind: snapshot.planKind,
    updatedAtMs,
  };

  if (storedUsage) {
    await ctx.db.patch(storedUsage._id, patch);
  } else {
    await ctx.db.insert("vaultUsage", {
      vaultId,
      ...patch,
    });
  }

  return {
    ...snapshot,
    updatedAtMs,
  };
}
