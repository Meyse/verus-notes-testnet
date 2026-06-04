import { getDocumentSize, v } from "convex/values";

import type { MutationCtx } from "../_generated/server";
import { consumeRateLimit, requireSession } from "./backendAuth";
import { decodeBase64Url } from "./encoding";

export const MAX_CIPHERTEXT_BYTES = 512 * 1024;
export const MAX_PADDED_CIPHERTEXT_BYTES = MAX_CIPHERTEXT_BYTES + 16;
export const MAX_CONTENT_VERSION = 1_000_000_000;
export const MAX_RECORD_ID_LENGTH = 80;
export const MAX_TIMESTAMP_SKEW_MS = 24 * 60 * 60 * 1000;
export const XCHACHA20_POLY1305_NONCE_BYTES = 24;
export const FREE_PLAN_KIND = "free" as const;
export const FREE_SYNC_MAX_NOTES = 20;
export const FREE_SYNC_MAX_STORAGE_BYTES = 2 * 1024 * 1024;
export const SERVER_TIMESTAMP_BUCKET_MS = 24 * 60 * 60 * 1000;
export const TOMBSTONE_RETENTION_MS = 30 * SERVER_TIMESTAMP_BUCKET_MS;
export const REMOVED_FROM_SYNC_RETENTION_MS = 7 * SERVER_TIMESTAMP_BUCKET_MS;

const SUPPORTED_CIPHERTEXT_SCHEMA_VERSIONS = new Set([1, 2]);
const PADDED_PLAINTEXT_BUCKET_BYTES = new Set([1024, 4096, 16_384, 65_536, 262_144, 524_288]);

export const encryptedRecordHeaderFields = {
  algorithm: v.literal("XCHACHA20-POLY1305"),
  contentVersion: v.number(),
  keyVersion: v.number(),
  schemaVersion: v.number(),
  vaultId: v.string(),
};

export const encryptedRecordCiphertextFields = {
  nonce: v.string(),
  ciphertext: v.string(),
};

type RecordIdField = "folderId" | "noteId";

type EncryptedRecordHeaderBase = {
  algorithm: "XCHACHA20-POLY1305";
  contentVersion: number;
  keyVersion: number;
  schemaVersion: number;
  vaultId: string;
};

type EncryptedRecordHeader<IdField extends RecordIdField> = EncryptedRecordHeaderBase & {
  [K in IdField]: string;
};

type EncryptedRecordValue<IdField extends RecordIdField> = {
  header: EncryptedRecordHeader<IdField>;
  nonce: string;
  ciphertext: string;
};

type StoredEncryptedRecordValue<IdField extends RecordIdField> = EncryptedRecordValue<IdField> &
  Partial<Record<RecordIdField, string>> & {
  accountedStorageBytes?: number;
  cloudState?: CloudRecordState;
  contentVersion: number;
  retentionExpiresAtBucketMs?: number;
  serverCreatedAtBucketMs?: number;
  serverDeletedAtBucketMs?: number;
  serverRemovedFromSyncAtBucketMs?: number;
  serverUpdatedAtBucketMs?: number;
  vaultId?: string;
};

type TombstoneRecordValue<Header extends EncryptedRecordHeaderBase = EncryptedRecordHeaderBase> = {
  accountedStorageBytes?: number;
  cloudState?: CloudRecordState;
  header: Header;
  nonce: string;
  ciphertext: string;
  contentVersion: number;
  retentionExpiresAtBucketMs?: number;
  serverDeletedAtBucketMs?: number;
  serverRemovedFromSyncAtBucketMs?: number;
};

type CloudRecordState = "live" | "deleted" | "removed_from_sync";

type VaultUsageRow = {
  _id: unknown;
  vaultId: string;
  planKind: typeof FREE_PLAN_KIND;
  maxSyncedNotes: number;
  maxStorageBytes: number;
  liveSyncedNoteCount: number;
  liveSyncedFolderCount: number;
  liveStorageBytes: number;
  updatedAtMs: number;
};

type RecordPolicyInput<IdField extends RecordIdField> = {
  encryptedRecord: EncryptedRecordValue<IdField>;
  idField: IdField;
  kind: string;
  vaultId: string;
};

type ExistingEncryptedRecord<IdField extends RecordIdField, RowId> = StoredEncryptedRecordValue<IdField> & {
  _id: RowId;
};

type LiveEncryptedRecordRow<IdField extends RecordIdField> = {
  [K in IdField]: string;
} & {
  accountedStorageBytes: number;
  cloudState: "live";
  vaultId: string;
  header: EncryptedRecordHeader<IdField>;
  nonce: string;
  ciphertext: string;
  contentVersion: number;
  retentionExpiresAtBucketMs: undefined;
  serverDeletedAtBucketMs: undefined;
  serverRemovedFromSyncAtBucketMs: undefined;
  serverUpdatedAtBucketMs: number;
};

type NewLiveEncryptedRecordRow<IdField extends RecordIdField> =
  LiveEncryptedRecordRow<IdField> & {
    serverCreatedAtBucketMs: number;
  };

export type EncryptedRecordWriteAdapter<IdField extends RecordIdField, RowId> = {
  countField: "liveSyncedNoteCount" | "liveSyncedFolderCount";
  deleteLogName: string;
  getExisting(
    ctx: MutationCtx,
    vaultId: string,
    recordId: string,
  ): Promise<ExistingEncryptedRecord<IdField, RowId> | null>;
  getUsage(ctx: MutationCtx, vaultId: string): Promise<VaultUsageRow | null>;
  idField: IdField;
  insert(ctx: MutationCtx, row: NewLiveEncryptedRecordRow<IdField>): Promise<RowId>;
  insertUsage(ctx: MutationCtx, row: Omit<VaultUsageRow, "_id">): Promise<unknown>;
  kind: string;
  maxRecordsPerVault: number;
  patch(ctx: MutationCtx, rowId: RowId, row: object): Promise<void>;
  patchUsage(ctx: MutationCtx, rowId: unknown, row: object): Promise<void>;
  rateLimitKeyPrefix: string;
  writeLimit: number;
  writeLogName: string;
  writeWindowMs: number;
};

export async function upsertEncryptedRecord<IdField extends RecordIdField, RowId>(
  ctx: MutationCtx,
  input: {
    adapter: EncryptedRecordWriteAdapter<IdField, RowId>;
    encryptedRecord: EncryptedRecordValue<IdField>;
    now?: number;
    sessionToken: string;
  },
) {
  const { adapter, encryptedRecord } = input;
  const session = await requireSession(ctx, input.sessionToken);
  const now = input.now ?? Date.now();
  await consumeRecordWriteRateLimit(ctx, adapter, session.vaultId, now);
  const recordId = requireEncryptedRecordForVault({
    encryptedRecord,
    idField: adapter.idField,
    kind: adapter.kind,
    vaultId: session.vaultId,
  });
  const existing = await adapter.getExisting(ctx, session.vaultId, recordId);

  if (
    existing &&
    !shouldWriteLiveRecord(existing, encryptedRecord, {
      idField: adapter.idField,
      kind: adapter.kind,
    })
  ) {
    return existing._id;
  }

	  const row = liveRecordRow(
	    adapter.idField,
	    recordId,
	    session.vaultId,
	    encryptedRecord,
	    now,
	    existing?.serverCreatedAtBucketMs ?? serverTimestampBucket(now),
	  );
  const usage = await requireUsage(ctx, adapter, session.vaultId, now);
  const { currentUsage, nextUsage } = await checkedNextUsageAfterLiveWrite(
    ctx,
    adapter,
    usage,
    existing,
    row,
  );

  if (existing) {
    await adapter.patch(ctx, existing._id, row);
    await patchUsage(ctx, adapter, currentUsage, nextUsage);
    console.log(adapter.writeLogName, { kind: "update" });
    return existing._id;
  }

  console.log(adapter.writeLogName, { kind: "insert" });
	  const rowId = await adapter.insert(ctx, {
	    ...row,
	    serverCreatedAtBucketMs: serverTimestampBucket(now),
	  });
  await patchUsage(ctx, adapter, currentUsage, nextUsage);
  return rowId;
}

export async function tombstoneEncryptedRecord<IdField extends RecordIdField, RowId>(
  ctx: MutationCtx,
  input: {
    adapter: EncryptedRecordWriteAdapter<IdField, RowId>;
    deletedAtMs: number;
    encryptedRecord: EncryptedRecordValue<IdField>;
    now?: number;
    sessionToken: string;
  },
) {
  const { adapter } = input;
  const session = await requireSession(ctx, input.sessionToken);
  const now = input.now ?? Date.now();
  await consumeRecordWriteRateLimit(ctx, adapter, session.vaultId, now);
  const recordId = requireEncryptedRecordForVault({
    encryptedRecord: input.encryptedRecord,
    idField: adapter.idField,
    kind: adapter.kind,
    vaultId: session.vaultId,
  });

  const existing = await adapter.getExisting(ctx, session.vaultId, recordId);
  if (!existing) return null;
  validateTombstoneTimestamp(input.deletedAtMs, adapter.kind, now);

  if (
    !shouldWriteTombstone(
      existing,
      input.encryptedRecord,
      input.deletedAtMs,
      adapter.idField,
      adapter.kind,
    )
  ) {
    return existing._id;
  }

  await adapter.patch(
    ctx,
    existing._id,
    tombstoneRecord(adapter.idField, recordId, input.encryptedRecord, input.deletedAtMs, now),
  );
  const usage = await requireUsage(ctx, adapter, session.vaultId, now);
  await patchUsage(ctx, adapter, usage, nextUsageAfterInactiveWrite(adapter, usage, existing));

  console.log(adapter.deleteLogName, { kind: "delete" });
  return existing._id;
}

export async function removeEncryptedRecordFromCloudSync<IdField extends RecordIdField, RowId>(
  ctx: MutationCtx,
  input: {
    adapter: EncryptedRecordWriteAdapter<IdField, RowId>;
    contentVersion: number;
    now?: number;
    recordId: string;
    removedAtMs: number;
    sessionToken: string;
  },
) {
  const { adapter } = input;
  const session = await requireSession(ctx, input.sessionToken);
  const now = input.now ?? Date.now();
  await consumeRecordWriteRateLimit(ctx, adapter, session.vaultId, now);
  validateTombstoneRecordIdentity(input.contentVersion, input.recordId, adapter.kind);

  const existing = await adapter.getExisting(ctx, session.vaultId, input.recordId);
  if (!existing) return null;
  validateTombstoneTimestamp(input.removedAtMs, adapter.kind, now);

  if (!shouldWriteRemovedFromSync(existing, input.contentVersion, input.removedAtMs, adapter.kind)) {
    return existing._id;
  }

  await adapter.patch(
    ctx,
    existing._id,
    removedFromSyncRecord(existing, input.contentVersion, input.removedAtMs, now),
  );
  const usage = await requireUsage(ctx, adapter, session.vaultId, now);
  await patchUsage(ctx, adapter, usage, nextUsageAfterInactiveWrite(adapter, usage, existing));

  console.log(adapter.deleteLogName, { kind: "remove_from_sync" });
  return existing._id;
}

export async function cleanupExpiredEncryptedRecordMarkers(
  ctx: MutationCtx,
  input: { batchSize: number; now?: number },
) {
  const expiresBeforeBucket = serverTimestampBucket(input.now ?? Date.now()) + SERVER_TIMESTAMP_BUCKET_MS;
  const deletedNotes = await ctx.db
    .query("notes")
    .withIndex("by_retention_expiry")
    .filter((q) => q.lt(q.field("retentionExpiresAtBucketMs"), expiresBeforeBucket))
    .filter((q) => q.eq(q.field("cloudState"), "deleted"))
    .take(input.batchSize);
  const remainingNoteBatch = Math.max(0, input.batchSize - deletedNotes.length);
  const removedNotes = remainingNoteBatch > 0
    ? await ctx.db
      .query("notes")
      .withIndex("by_retention_expiry")
      .filter((q) => q.lt(q.field("retentionExpiresAtBucketMs"), expiresBeforeBucket))
      .filter((q) => q.eq(q.field("cloudState"), "removed_from_sync"))
      .take(remainingNoteBatch)
    : [];
  const notes = [...deletedNotes, ...removedNotes].filter((record) =>
    isExpiredInactiveRecordMarker(record, expiresBeforeBucket)
  );
  for (const note of notes) {
    await ctx.db.delete(note._id);
  }

  const remainingBatch = Math.max(0, input.batchSize - notes.length);
  const deletedFolders = remainingBatch > 0
    ? await ctx.db
      .query("folders")
      .withIndex("by_retention_expiry")
      .filter((q) => q.lt(q.field("retentionExpiresAtBucketMs"), expiresBeforeBucket))
      .filter((q) => q.eq(q.field("cloudState"), "deleted"))
      .take(remainingBatch)
    : [];
  const remainingFolderBatch = Math.max(0, remainingBatch - deletedFolders.length);
  const removedFolders = remainingFolderBatch > 0
    ? await ctx.db
      .query("folders")
      .withIndex("by_retention_expiry")
      .filter((q) => q.lt(q.field("retentionExpiresAtBucketMs"), expiresBeforeBucket))
      .filter((q) => q.eq(q.field("cloudState"), "removed_from_sync"))
      .take(remainingFolderBatch)
    : [];
  const folders = [...deletedFolders, ...removedFolders].filter((record) =>
    isExpiredInactiveRecordMarker(record, expiresBeforeBucket)
  );
  for (const folder of folders) {
    await ctx.db.delete(folder._id);
  }

  const result = { folders: folders.length, notes: notes.length };
  if (result.folders || result.notes) {
    console.log("convex_record_marker_cleanup", result);
  }
  return result;
}

function isExpiredInactiveRecordMarker(record: {
  cloudState?: CloudRecordState;
  retentionExpiresAtBucketMs?: number;
}, expiresBeforeBucket: number) {
  return (
    (record.cloudState === "deleted" || record.cloudState === "removed_from_sync") &&
    typeof record.retentionExpiresAtBucketMs === "number" &&
    record.retentionExpiresAtBucketMs < expiresBeforeBucket
  );
}

export function requireEncryptedRecordForVault<IdField extends RecordIdField>({
  encryptedRecord,
  idField,
  kind,
  vaultId,
}: RecordPolicyInput<IdField>) {
  if (encryptedRecord.header.vaultId !== vaultId) {
    throw new Error(`${kind} vault does not match session`);
  }

  const recordId = encryptedRecord.header[idField];
  validateRecordId(recordId, `${kind} ID`);
  validateEncryptedRecordShape(encryptedRecord, kind);

  return recordId;
}

export function validateTombstoneInput(input: {
  contentVersion: number;
  deletedAtMs: number;
  kind: string;
  recordId: string;
  now: number;
}) {
  validateTombstoneRecordIdentity(input.contentVersion, input.recordId, input.kind);
  validateTombstoneTimestamp(input.deletedAtMs, input.kind, input.now);
}

function validateTombstoneRecordIdentity(contentVersion: number, recordId: string, kind: string) {
  validateRecordId(recordId, `${kind} ID`);
  validateContentVersion(contentVersion, `${kind} content version`);
}

function validateTombstoneTimestamp(timestampMs: number, kind: string, now: number) {
  validateTimestampSkew(timestampMs, `${kind} delete timestamp`, now);
}

export function shouldWriteLiveRecord<IdField extends RecordIdField>(
  existing: StoredEncryptedRecordValue<IdField>,
  next: EncryptedRecordValue<IdField>,
  options: { idField: IdField; kind: string },
) {
  if (next.header.contentVersion < existing.contentVersion) {
    throw new Error(`stale ${options.kind} revision`);
  }

  if (next.header.contentVersion === existing.contentVersion) {
    if (existing.cloudState === "removed_from_sync") return true;
    if (isSameLiveRecord(existing, next, options.idField)) return false;
    throw new Error(`stale ${options.kind} revision`);
  }

  return true;
}

export function shouldWriteTombstone<IdField extends RecordIdField>(
  existing: TombstoneRecordValue<EncryptedRecordHeader<IdField>>,
  encryptedRecord: EncryptedRecordValue<IdField>,
  deletedAtMs: number,
  idField: IdField,
  kind: string,
) {
  const contentVersion = encryptedRecord.header.contentVersion;
  if (contentVersion < existing.contentVersion) {
    throw new Error(`stale ${kind} tombstone`);
  }

  if (contentVersion === existing.contentVersion) {
    if (isSameTombstone(existing, encryptedRecord, deletedAtMs, idField)) return false;
    throw new Error(`stale ${kind} tombstone`);
  }

  return true;
}

export function shouldWriteRemovedFromSync(
  existing: TombstoneRecordValue,
  contentVersion: number,
  _removedAtMs: number,
  kind: string,
) {
  if (isRemovedFromSyncRecord(existing)) return false;

  if (contentVersion < existing.contentVersion) {
    throw new Error(`stale ${kind} cloud sync removal`);
  }

  if (contentVersion === existing.contentVersion) {
    if (isLiveCloudRecord(existing)) return true;
    throw new Error(`stale ${kind} cloud sync removal`);
  }

  return true;
}

export function tombstoneRecord<IdField extends RecordIdField>(
  idField: IdField,
  recordId: string,
  encryptedRecord: EncryptedRecordValue<IdField>,
  _deletedAtMs: number,
  updatedAtMs: number,
) {
  return {
    [idField]: recordId,
    accountedStorageBytes: 0,
    cloudState: "deleted" as const,
    header: encryptedRecord.header,
    nonce: encryptedRecord.nonce,
    ciphertext: encryptedRecord.ciphertext,
    contentVersion: encryptedRecord.header.contentVersion,
    retentionExpiresAtBucketMs: serverTimestampBucket(updatedAtMs + TOMBSTONE_RETENTION_MS),
    serverDeletedAtBucketMs: serverTimestampBucket(updatedAtMs),
    serverRemovedFromSyncAtBucketMs: undefined,
    serverUpdatedAtBucketMs: serverTimestampBucket(updatedAtMs),
  };
}

export function removedFromSyncRecord<Header extends EncryptedRecordHeaderBase>(
  existing: TombstoneRecordValue<Header>,
  contentVersion: number,
  _removedAtMs: number,
  updatedAtMs: number,
) {
  return {
    accountedStorageBytes: 0,
    cloudState: "removed_from_sync" as const,
    header: {
      ...existing.header,
      contentVersion,
    },
    nonce: "",
    ciphertext: "",
    contentVersion,
    retentionExpiresAtBucketMs: serverTimestampBucket(updatedAtMs + REMOVED_FROM_SYNC_RETENTION_MS),
    serverDeletedAtBucketMs: undefined,
    serverRemovedFromSyncAtBucketMs: serverTimestampBucket(updatedAtMs),
    serverUpdatedAtBucketMs: serverTimestampBucket(updatedAtMs),
  };
}

function liveRecordRow<IdField extends RecordIdField>(
  idField: IdField,
  recordId: string,
  vaultId: string,
  encryptedRecord: EncryptedRecordValue<IdField>,
  now: number,
  createdAtMs: number,
): LiveEncryptedRecordRow<IdField> {
  const row = {
    [idField]: recordId,
    accountedStorageBytes: 0,
    cloudState: "live",
    vaultId,
    header: encryptedRecord.header,
    nonce: encryptedRecord.nonce,
    ciphertext: encryptedRecord.ciphertext,
    contentVersion: encryptedRecord.header.contentVersion,
    retentionExpiresAtBucketMs: undefined,
    serverDeletedAtBucketMs: undefined,
    serverRemovedFromSyncAtBucketMs: undefined,
    serverUpdatedAtBucketMs: serverTimestampBucket(now),
  } as LiveEncryptedRecordRow<IdField>;
  row.accountedStorageBytes = getAccountedDocumentSize({
    ...row,
    serverCreatedAtBucketMs: createdAtMs,
  });
  return row;
}

async function consumeRecordWriteRateLimit<IdField extends RecordIdField, RowId>(
  ctx: MutationCtx,
  adapter: EncryptedRecordWriteAdapter<IdField, RowId>,
  vaultId: string,
  now: number,
) {
  await consumeRateLimit(
    ctx,
    `${adapter.rateLimitKeyPrefix}:${vaultId}`,
    adapter.writeLimit,
    adapter.writeWindowMs,
    now,
  );
}

async function requireUsage<IdField extends RecordIdField, RowId>(
  ctx: MutationCtx,
  adapter: EncryptedRecordWriteAdapter<IdField, RowId>,
  vaultId: string,
  now: number,
) {
  const existing = await adapter.getUsage(ctx, vaultId);
  if (existing) return normalizeUsageRow(existing);

  const row = {
    vaultId,
    planKind: FREE_PLAN_KIND,
    maxSyncedNotes: FREE_SYNC_MAX_NOTES,
    maxStorageBytes: FREE_SYNC_MAX_STORAGE_BYTES,
    liveSyncedNoteCount: 0,
    liveSyncedFolderCount: 0,
    liveStorageBytes: 0,
    updatedAtMs: now,
  };
  const _id = await adapter.insertUsage(ctx, row);
  return { _id, ...row };
}

function normalizeUsageRow(row: VaultUsageRow): VaultUsageRow {
  return {
    ...row,
    liveSyncedNoteCount: Math.max(0, row.liveSyncedNoteCount),
    liveSyncedFolderCount: Math.max(0, row.liveSyncedFolderCount),
    liveStorageBytes: Math.max(0, row.liveStorageBytes),
  };
}

function nextUsageAfterLiveWrite<IdField extends RecordIdField>(
  adapter: Pick<EncryptedRecordWriteAdapter<IdField, unknown>, "countField">,
  usage: VaultUsageRow,
  existing: StoredEncryptedRecordValue<IdField> | null,
  row: LiveEncryptedRecordRow<IdField>,
) {
  const existingLive = existing ? isLiveCloudRecord(existing) : false;
  const existingStorageBytes =
    existing && existingLive ? existing.accountedStorageBytes ?? encryptedRecordStorageBytes(existing) : 0;
  return {
    ...usage,
    [adapter.countField]: usage[adapter.countField] + (existingLive ? 0 : 1),
    liveStorageBytes: Math.max(0, usage.liveStorageBytes - existingStorageBytes + row.accountedStorageBytes),
  };
}

async function checkedNextUsageAfterLiveWrite<IdField extends RecordIdField, RowId>(
  ctx: MutationCtx,
  adapter: EncryptedRecordWriteAdapter<IdField, RowId>,
  usage: VaultUsageRow,
  existing: StoredEncryptedRecordValue<IdField> | null,
  row: LiveEncryptedRecordRow<IdField>,
) {
  const nextUsage = nextUsageAfterLiveWrite(adapter, usage, existing, row);
  const limitError = usageLimitError(adapter, nextUsage);
  if (!limitError) return { currentUsage: usage, nextUsage };

  const reconciledUsage = await reconcileUsage(ctx, usage);
  if (!usageCountsDiffer(usage, reconciledUsage)) {
    throw new Error(limitError);
  }

  await patchUsage(ctx, adapter, usage, reconciledUsage);
  const reconciledNextUsage = nextUsageAfterLiveWrite(adapter, reconciledUsage, existing, row);
  const reconciledLimitError = usageLimitError(adapter, reconciledNextUsage);
  if (reconciledLimitError) {
    throw new Error(reconciledLimitError);
  }

  return { currentUsage: reconciledUsage, nextUsage: reconciledNextUsage };
}

function nextUsageAfterInactiveWrite<IdField extends RecordIdField>(
  adapter: Pick<EncryptedRecordWriteAdapter<IdField, unknown>, "countField">,
  usage: VaultUsageRow,
  existing: StoredEncryptedRecordValue<IdField>,
) {
  if (!isLiveCloudRecord(existing)) return usage;

  return {
    ...usage,
    [adapter.countField]: Math.max(0, usage[adapter.countField] - 1),
    liveStorageBytes: Math.max(
      0,
      usage.liveStorageBytes - (existing.accountedStorageBytes ?? encryptedRecordStorageBytes(existing)),
    ),
  };
}

function validateUsageLimits<IdField extends RecordIdField>(
  adapter: Pick<EncryptedRecordWriteAdapter<IdField, unknown>, "countField" | "kind" | "maxRecordsPerVault">,
  usage: VaultUsageRow,
) {
  const error = usageLimitError(adapter, usage);
  if (error) throw new Error(error);
}

function usageLimitError<IdField extends RecordIdField>(
  adapter: Pick<EncryptedRecordWriteAdapter<IdField, unknown>, "countField" | "kind" | "maxRecordsPerVault">,
  usage: VaultUsageRow,
) {
  if (adapter.countField === "liveSyncedNoteCount" && usage.liveSyncedNoteCount > usage.maxSyncedNotes) {
    return "quota_note_count_exceeded";
  }

  if (usage[adapter.countField] > adapter.maxRecordsPerVault) {
    return `${adapter.kind} limit exceeded`;
  }

  if (usage.liveStorageBytes > usage.maxStorageBytes) {
    return "quota_storage_exceeded";
  }

  return null;
}

async function patchUsage<IdField extends RecordIdField, RowId>(
  ctx: MutationCtx,
  adapter: EncryptedRecordWriteAdapter<IdField, RowId>,
  existing: VaultUsageRow,
  next: VaultUsageRow,
) {
  if (
    existing.liveSyncedNoteCount === next.liveSyncedNoteCount &&
    existing.liveSyncedFolderCount === next.liveSyncedFolderCount &&
    existing.liveStorageBytes === next.liveStorageBytes
  ) {
    return;
  }

  const normalizedNext = normalizeUsageRow(next);
  await adapter.patchUsage(ctx, existing._id, {
    liveSyncedNoteCount: normalizedNext.liveSyncedNoteCount,
    liveSyncedFolderCount: normalizedNext.liveSyncedFolderCount,
    liveStorageBytes: normalizedNext.liveStorageBytes,
    updatedAtMs: Date.now(),
  });
}

export function isLiveCloudRecord(record: {
  ciphertext: string;
  cloudState?: CloudRecordState;
  nonce: string;
  serverDeletedAtBucketMs?: number;
}) {
  if (record.cloudState === "deleted" || record.cloudState === "removed_from_sync") return false;
  return record.serverDeletedAtBucketMs === undefined && record.nonce !== "" && record.ciphertext !== "";
}

async function reconcileUsage(ctx: MutationCtx, usage: VaultUsageRow): Promise<VaultUsageRow> {
	  const [noteRows, folderRows] = await Promise.all([
	    ctx.db
	      .query("notes")
	      .withIndex("by_vault_updated", (q) => q.eq("vaultId", usage.vaultId))
      .collect(),
    ctx.db
      .query("folders")
      .withIndex("by_vault_updated", (q) => q.eq("vaultId", usage.vaultId))
      .collect(),
  ]);
  const liveNotes = noteRows.filter(isLiveCloudRecord);
  const liveFolders = folderRows.filter(isLiveCloudRecord);

  return {
    ...usage,
    liveSyncedNoteCount: liveNotes.length,
    liveSyncedFolderCount: liveFolders.length,
    liveStorageBytes: [...liveNotes, ...liveFolders].reduce(
      (sum, row) => sum + Math.max(0, row.accountedStorageBytes ?? encryptedRecordStorageBytes(row)),
      0,
    ),
  };
}

function usageCountsDiffer(left: VaultUsageRow, right: VaultUsageRow) {
  return (
    left.liveSyncedNoteCount !== right.liveSyncedNoteCount ||
    left.liveSyncedFolderCount !== right.liveSyncedFolderCount ||
    left.liveStorageBytes !== right.liveStorageBytes
  );
}

export function encryptedRecordStorageBytes(record: {
  accountedStorageBytes?: number;
  ciphertext: string;
  cloudState?: CloudRecordState;
  contentVersion: number;
  folderId?: string;
  header: EncryptedRecordHeaderBase & Partial<Record<RecordIdField, string>>;
  nonce: string;
  noteId?: string;
  retentionExpiresAtBucketMs?: number;
  serverCreatedAtBucketMs?: number;
  serverDeletedAtBucketMs?: number;
  serverRemovedFromSyncAtBucketMs?: number;
  serverUpdatedAtBucketMs?: number;
  vaultId?: string;
}) {
  return getAccountedDocumentSize({
    ...recordIdFields(record),
    accountedStorageBytes: record.accountedStorageBytes ?? 0,
    cloudState: record.cloudState ?? (record.serverDeletedAtBucketMs === undefined ? "live" : "deleted"),
    contentVersion: record.contentVersion,
    ciphertext: record.ciphertext,
    header: record.header,
    nonce: record.nonce,
    retentionExpiresAtBucketMs: record.retentionExpiresAtBucketMs,
    serverCreatedAtBucketMs: record.serverCreatedAtBucketMs,
    serverDeletedAtBucketMs: record.serverDeletedAtBucketMs,
    serverRemovedFromSyncAtBucketMs: record.serverRemovedFromSyncAtBucketMs,
    serverUpdatedAtBucketMs: record.serverUpdatedAtBucketMs,
    vaultId: record.vaultId ?? record.header.vaultId,
  });
}

function recordIdFields(record: {
  folderId?: string;
  header: EncryptedRecordHeaderBase & Partial<Record<RecordIdField, string>>;
  noteId?: string;
}) {
  if (record.header.noteId) return { noteId: record.noteId ?? record.header.noteId };
  if (record.header.folderId) return { folderId: record.folderId ?? record.header.folderId };
  return {};
}

function getAccountedDocumentSize(value: object) {
  const firstPass = getConvexDocumentSize({ ...value, accountedStorageBytes: 0 });
  return getConvexDocumentSize({ ...value, accountedStorageBytes: firstPass });
}

function getConvexDocumentSize(value: object) {
  return getDocumentSize(JSON.parse(JSON.stringify(value)));
}

function isSameLiveRecord<IdField extends RecordIdField>(
  existing: StoredEncryptedRecordValue<IdField>,
  next: EncryptedRecordValue<IdField>,
  idField: IdField,
) {
  return (
    existing.serverDeletedAtBucketMs === undefined &&
    existing.header.algorithm === next.header.algorithm &&
    existing.header.contentVersion === next.header.contentVersion &&
    existing.header[idField] === next.header[idField] &&
    existing.header.keyVersion === next.header.keyVersion &&
    existing.header.schemaVersion === next.header.schemaVersion &&
    existing.header.vaultId === next.header.vaultId &&
    existing.nonce === next.nonce &&
    existing.ciphertext === next.ciphertext
  );
}

function isSameTombstone<IdField extends RecordIdField>(
  existing: TombstoneRecordValue<EncryptedRecordHeader<IdField>>,
  next: EncryptedRecordValue<IdField>,
  _deletedAtMs: number,
  idField: IdField,
) {
  return (
    (existing.cloudState === undefined || existing.cloudState === "deleted") &&
    existing.header.algorithm === next.header.algorithm &&
    existing.header.contentVersion === next.header.contentVersion &&
    existing.header.keyVersion === next.header.keyVersion &&
    existing.header.schemaVersion === next.header.schemaVersion &&
    existing.header.vaultId === next.header.vaultId &&
    existing.header[idField] === next.header[idField] &&
    existing.nonce === next.nonce &&
    existing.ciphertext === next.ciphertext
  );
}

function isRemovedFromSyncRecord(existing: TombstoneRecordValue) {
  return (
    existing.cloudState === "removed_from_sync" &&
    existing.nonce === "" &&
    existing.ciphertext === ""
  );
}

function validateEncryptedRecordShape<IdField extends RecordIdField>(
  encryptedRecord: EncryptedRecordValue<IdField>,
  kind: string,
) {
  const { header } = encryptedRecord;

  validateContentVersion(header.contentVersion, `${kind} header content version`);
  validateSafeInteger(header.keyVersion, `${kind} key version`);
  validateSafeInteger(header.schemaVersion, `${kind} schema version`);

  if (header.keyVersion < 1 || header.keyVersion > 100) {
    throw new Error(`${kind} key version is unsupported`);
  }

  if (!SUPPORTED_CIPHERTEXT_SCHEMA_VERSIONS.has(header.schemaVersion)) {
    throw new Error(`${kind} schema version is unsupported`);
  }

  decodeBase64Url(`${kind} nonce`, encryptedRecord.nonce, XCHACHA20_POLY1305_NONCE_BYTES);
  validateCiphertextSize(encryptedRecord.ciphertext, kind, header.schemaVersion);
}

function validateCiphertextSize(ciphertext: string, kind: string, schemaVersion: number) {
  if (ciphertext.length === 0) {
    throw new Error(`${kind} ciphertext is required`);
  }

  const maxBytes = schemaVersion >= 2 ? MAX_PADDED_CIPHERTEXT_BYTES : MAX_CIPHERTEXT_BYTES;
  const maxBase64UrlChars = Math.ceil(maxBytes / 3) * 4;
  if (ciphertext.length > maxBase64UrlChars) {
    throw new Error(`${kind} ciphertext is too large`);
  }

  const bytes = decodeBase64Url(`${kind} ciphertext`, ciphertext);
  if (bytes.length > maxBytes) {
    throw new Error(`${kind} ciphertext is too large`);
  }
  if (schemaVersion >= 2 && !isPaddedCiphertextLength(bytes.length)) {
    throw new Error(`${kind} ciphertext padding bucket is unsupported`);
  }
}

function validateRecordId(recordId: string, label: string) {
  if (recordId.trim() === "") {
    throw new Error(`${label} is required`);
  }

  if (recordId.length > MAX_RECORD_ID_LENGTH || !/^[A-Za-z0-9_-]+$/.test(recordId)) {
    throw new Error(`${label} is malformed`);
  }
}

function validateContentVersion(value: number, label: string) {
  validateSafeInteger(value, label);
  if (value < 1 || value > MAX_CONTENT_VERSION) {
    throw new Error(`${label} is out of range`);
  }
}

function validateTimestampSkew(value: number, label: string, now: number) {
  validateSafeInteger(value, label);
  if (value - now > MAX_TIMESTAMP_SKEW_MS) {
    throw new Error(`${label} is outside the allowed clock skew`);
  }
}

function validateSafeInteger(value: number, label: string) {
  if (!Number.isSafeInteger(value)) {
    throw new Error(`${label} must be a safe integer`);
  }
}

function serverTimestampBucket(timestampMs: number) {
  validateSafeInteger(timestampMs, "server timestamp");
  return Math.floor(timestampMs / SERVER_TIMESTAMP_BUCKET_MS) * SERVER_TIMESTAMP_BUCKET_MS;
}

function isPaddedCiphertextLength(byteLength: number) {
  const plaintextLength = byteLength - 16;
  return plaintextLength > 0 && PADDED_PLAINTEXT_BUCKET_BYTES.has(plaintextLength);
}
