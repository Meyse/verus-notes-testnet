import { v } from "convex/values";
import { paginationOptsValidator } from "convex/server";

import type { Id } from "./_generated/dataModel";
import { mutation, query } from "./_generated/server";
import { requireSession } from "./lib/backendAuth";
import {
  type EncryptedRecordWriteAdapter,
  encryptedRecordCiphertextFields,
  encryptedRecordHeaderFields,
  tombstoneEncryptedRecord,
  upsertEncryptedRecord,
} from "./lib/encryptedRecords";

const folderCiphertextHeader = v.object({
  ...encryptedRecordHeaderFields,
  folderId: v.string(),
});

const encryptedFolder = v.object({
  header: folderCiphertextHeader,
  ...encryptedRecordCiphertextFields,
});

const MAX_FOLDERS_PER_VAULT = 500;
const WRITE_LIMIT_PER_MINUTE = 120;
const WRITE_WINDOW_MS = 60_000;

const folderWriteAdapter: EncryptedRecordWriteAdapter<"folderId", Id<"folders">> = {
  countField: "liveSyncedFolderCount",
  deleteLogName: "convex_folder_delete",
  getExisting: async (ctx, vaultId, folderId) => {
    return await ctx.db
      .query("folders")
      .withIndex("by_vault_folder", (q) =>
        q.eq("vaultId", vaultId).eq("folderId", folderId),
      )
      .unique();
  },
  getUsage: async (ctx, vaultId) => {
    return await ctx.db
      .query("vaultUsage")
      .withIndex("by_vault_id", (q) => q.eq("vaultId", vaultId))
      .unique();
  },
  idField: "folderId",
  insert: async (ctx, row) => await ctx.db.insert("folders", row),
  insertUsage: async (ctx, row) => await ctx.db.insert("vaultUsage", row),
  kind: "folder",
  maxRecordsPerVault: MAX_FOLDERS_PER_VAULT,
  patch: async (ctx, folderId, row) => {
    await ctx.db.patch(folderId, row);
  },
  patchUsage: async (ctx, usageId, row) => {
    await ctx.db.patch(usageId as Id<"vaultUsage">, row);
  },
  rateLimitKeyPrefix: "write:folder",
  writeLimit: WRITE_LIMIT_PER_MINUTE,
  writeLogName: "convex_folder_write",
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
      .query("folders")
      .withIndex("by_vault_updated", (q) => q.eq("vaultId", session.vaultId))
      .paginate(args.paginationOpts);
  },
});

export const upsert = mutation({
  args: {
    sessionToken: v.string(),
    encryptedFolder,
  },
  handler: async (ctx, args) => {
    return await upsertEncryptedRecord(ctx, {
      adapter: folderWriteAdapter,
      encryptedRecord: args.encryptedFolder,
      sessionToken: args.sessionToken,
    });
  },
});

export const remove = mutation({
  args: {
    encryptedFolder,
    sessionToken: v.string(),
    deletedAtMs: v.number(),
  },
  handler: async (ctx, args) => {
    return await tombstoneEncryptedRecord(ctx, {
      adapter: folderWriteAdapter,
      deletedAtMs: args.deletedAtMs,
      encryptedRecord: args.encryptedFolder,
      sessionToken: args.sessionToken,
    });
  },
});
