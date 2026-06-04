import assert from "node:assert/strict";

import type { MutationCtx } from "../convex/_generated/server";
import { sessionTokenHash } from "../convex/lib/backendAuth";
import {
  MAX_CIPHERTEXT_BYTES,
  MAX_TIMESTAMP_SKEW_MS,
  FREE_SYNC_MAX_NOTES,
  FREE_SYNC_MAX_STORAGE_BYTES,
  cleanupExpiredEncryptedRecordMarkers,
  type EncryptedRecordWriteAdapter,
  removeEncryptedRecordFromCloudSync,
  tombstoneEncryptedRecord,
  upsertEncryptedRecord,
} from "../convex/lib/encryptedRecords";
import { reconcileUsage, reconcileUsageForVault } from "../convex/notes";

const NOW = 1_779_720_000_000;
const SESSION_TOKEN = "session-token";
const VAULT_ID = "vault-1";
const BACKEND_AUTH_ALGORITHM = "ed25519-v1";
const BACKEND_AUTH_KEY_ID = "backend-key-id";
const BACKEND_AUTH_PUBLIC_KEY = "backend-key";
const BACKEND_AUTH_KEY_VERSION = 1;
const SERVER_TIMESTAMP_BUCKET_MS = 24 * 60 * 60 * 1000;

type CapturedLog = Parameters<typeof console.log>;

type TestNoteHeader = {
  algorithm: "XCHACHA20-POLY1305";
  contentVersion: number;
  keyVersion: number;
  noteId: string;
  schemaVersion: number;
  vaultId: string;
};

type TestEncryptedNote = {
  header: TestNoteHeader;
  nonce: string;
  ciphertext: string;
};

type TestNoteRow = TestEncryptedNote & {
  _id: string;
  accountedStorageBytes?: number;
  cloudState?: "live" | "deleted" | "removed_from_sync";
  contentVersion: number;
  noteId: string;
  retentionExpiresAtBucketMs?: number;
  serverCreatedAtBucketMs: number;
  serverDeletedAtBucketMs?: number;
  serverRemovedFromSyncAtBucketMs?: number;
  serverUpdatedAtBucketMs: number;
  vaultId: string;
};

type TestUsageRow = {
  _id: string;
  vaultId: string;
  planKind: "free";
  maxSyncedNotes: number;
  maxStorageBytes: number;
  liveSyncedNoteCount: number;
  liveSyncedFolderCount: number;
  liveStorageBytes: number;
  updatedAtMs: number;
};

type RateLimitRow = {
  _id: string;
  count: number;
  key: string;
  updatedAtMs: number;
  windowStartedAtMs: number;
};

type TestMutationHandler<Args> = {
  _handler: (ctx: MutationCtx, args: Args) => Promise<unknown>;
};

class FakeQuery {
  private filters: Array<{ field: string; value: unknown }> = [];
  private upperBounds: Array<{ field: string; value: number }> = [];

  constructor(private readonly rows: Record<string, unknown>[]) {}

  withIndex(
    _name: string,
    build?: (q: { eq: (field: string, value: unknown) => unknown; lt: (field: string, value: number) => unknown }) => unknown,
  ) {
    const query = {
      eq: (field: string, value: unknown) => {
        this.filters.push({ field, value });
        return query;
      },
      lt: (field: string, value: number) => {
        this.upperBounds.push({ field, value });
        return query;
      },
    };
    build?.(query);
    return this;
  }

  filter(
    build: (q: {
      field: (field: string) => { field: string };
      eq: (field: { field: string }, value: unknown) => unknown;
      lt: (field: { field: string }, value: number) => unknown;
    }) => unknown,
  ) {
    const query = {
      field: (field: string) => ({ field }),
      eq: (field: { field: string }, value: unknown) => {
        this.filters.push({ field: field.field, value });
        return query;
      },
      lt: (field: { field: string }, value: number) => {
        this.upperBounds.push({ field: field.field, value });
        return query;
      },
    };
    build(query);
    return this;
  }

  async unique() {
    const matches = this.matchingRows();
    return matches[0] ?? null;
  }

  async take(count: number) {
    return this.matchingRows().slice(0, count);
  }

  async collect() {
    return this.matchingRows();
  }

  private matchingRows() {
    return this.rows.filter((row) =>
      this.filters.every((filter) => row[filter.field] === filter.value) &&
      this.upperBounds.every((filter) => {
        const value = row[filter.field];
        return value === undefined || (typeof value === "number" && value < filter.value);
      }),
    );
  }
}

class FakeDb {
  readonly rateLimits: RateLimitRow[] = [];
  readonly sessions = [
    {
      _id: "session-1",
      sessionTokenHash: sessionTokenHash(SESSION_TOKEN),
      vaultId: VAULT_ID,
      backendAuthAlgorithm: BACKEND_AUTH_ALGORITHM,
      backendAuthKeyId: BACKEND_AUTH_KEY_ID,
      backendAuthPublicKey: BACKEND_AUTH_PUBLIC_KEY,
      backendAuthKeyVersion: BACKEND_AUTH_KEY_VERSION,
      createdAtMs: NOW - 1_000,
      expiresAtMs: Number.MAX_SAFE_INTEGER,
      lastSeenAtMs: NOW - 1_000,
    },
  ];
  readonly vaults = [
    {
      _id: "vault-1-row",
      vaultId: VAULT_ID,
      backendAuthAlgorithm: BACKEND_AUTH_ALGORITHM,
      backendAuthKeyId: BACKEND_AUTH_KEY_ID,
      backendAuthPublicKey: BACKEND_AUTH_PUBLIC_KEY,
      backendAuthKeyVersion: BACKEND_AUTH_KEY_VERSION,
      createdAtMs: NOW - 1_000,
      updatedAtMs: NOW - 1_000,
    },
  ];
  readonly folders: TestNoteRow[] = [];
  readonly notes: TestNoteRow[] = [];
  readonly vaultUsage: TestUsageRow[] = [];
  private nextId = 1;

  query(table: "folders" | "notes" | "rateLimits" | "sessions" | "vaultUsage" | "vaults") {
    return new FakeQuery(this[table]);
  }

  async insert(table: "rateLimits", row: Omit<RateLimitRow, "_id">): Promise<string>;
  async insert(table: "vaultUsage", row: Omit<TestUsageRow, "_id">): Promise<string>;
  async insert(
    table: "rateLimits" | "vaultUsage",
    row: Omit<RateLimitRow, "_id"> | Omit<TestUsageRow, "_id">,
  ) {
    const _id = `${table}-${this.nextId++}`;
    if (table === "rateLimits") {
      this.rateLimits.push({ _id, ...(row as Omit<RateLimitRow, "_id">) });
    } else {
      this.vaultUsage.push({ _id, ...(row as Omit<TestUsageRow, "_id">) });
    }
    return _id;
  }

  async patch(rowId: string, patch: Partial<RateLimitRow> | Partial<TestUsageRow> | Partial<TestNoteRow>) {
    const row = [...this.rateLimits, ...this.vaultUsage, ...this.notes, ...this.folders].find((candidate) => candidate._id === rowId);
    if (!row) throw new Error(`missing fake row ${rowId}`);
    Object.assign(row, patch);
  }

  async delete(rowId: string) {
    for (const rows of [this.notes, this.folders, this.rateLimits, this.sessions, this.vaultUsage, this.vaults]) {
      const index = rows.findIndex((candidate) => candidate._id === rowId);
      if (index >= 0) {
        rows.splice(index, 1);
        return;
      }
    }
    throw new Error(`missing fake row ${rowId}`);
  }
}

function createHarness(
  input: {
    maxRecords?: number;
    maxStorageBytes?: number;
    maxSyncedNotes?: number;
    records?: TestNoteRow[];
    usage?: Partial<TestUsageRow>;
  } = {},
) {
  const db = new FakeDb();
  const ctx = { db } as unknown as MutationCtx;
  db.notes.push(...(input.records ? input.records.map(cloneRow) : []));
  const records = db.notes;
  db.vaultUsage.push({
    _id: "usage-1",
    vaultId: VAULT_ID,
    planKind: "free",
    maxSyncedNotes: input.maxSyncedNotes ?? FREE_SYNC_MAX_NOTES,
    maxStorageBytes: input.maxStorageBytes ?? FREE_SYNC_MAX_STORAGE_BYTES,
    liveSyncedNoteCount: records.filter(isLiveRecord).length,
    liveSyncedFolderCount: 0,
    liveStorageBytes: records.reduce((sum, row) => sum + (isLiveRecord(row) ? row.accountedStorageBytes ?? 0 : 0), 0),
    updatedAtMs: NOW - 1_000,
    ...input.usage,
  });
  let nextId = records.length + 1;
  let patchCount = 0;
  const adapter: EncryptedRecordWriteAdapter<"noteId", string> = {
    countField: "liveSyncedNoteCount",
    deleteLogName: "test_note_delete",
    getExisting: async (_ctx, vaultId, noteId) => {
      return cloneRow(records.find((row) => row.vaultId === vaultId && row.noteId === noteId) ?? null);
    },
    getUsage: async (_ctx, vaultId) => {
      return cloneRow(db.vaultUsage.find((row) => row.vaultId === vaultId) ?? null);
    },
    idField: "noteId",
    insert: async (_ctx, row) => {
      const _id = `note-${nextId++}`;
      records.push({ _id, ...cloneRow(row) });
      return _id;
    },
    insertUsage: async (_ctx, row) => await db.insert("vaultUsage", row),
    kind: "note",
    maxRecordsPerVault: input.maxRecords ?? 5,
    patch: async (_ctx, rowId, patch) => {
      patchCount += 1;
      const row = records.find((candidate) => candidate._id === rowId);
      if (!row) throw new Error(`missing record ${rowId}`);
      applyPatch(row, patch);
    },
    rateLimitKeyPrefix: "write:note",
    patchUsage: async (_ctx, rowId, patch) => {
      await db.patch(rowId as string, patch as Partial<TestUsageRow>);
    },
    writeLimit: 120,
    writeLogName: "test_note_write",
    writeWindowMs: 60_000,
  };

  return {
    adapter,
    ctx,
    db,
    get patchCount() {
      return patchCount;
    },
    records,
  };
}

function encryptedNote(input: {
  ciphertext?: string;
  contentVersion?: number;
  noteId?: string;
  schemaVersion?: number;
  vaultId?: string;
} = {}): TestEncryptedNote {
  const contentVersion = input.contentVersion ?? 1;
  const noteId = input.noteId ?? "note-1";
  const schemaVersion = input.schemaVersion ?? 2;
  const vaultId = input.vaultId ?? VAULT_ID;
  return {
    header: {
      algorithm: "XCHACHA20-POLY1305",
      contentVersion,
      keyVersion: 1,
      noteId,
      schemaVersion,
      vaultId,
    },
    nonce: Buffer.alloc(24, 1).toString("base64url"),
    ciphertext:
      input.ciphertext ??
      (schemaVersion >= 2
        ? paddedCiphertext(contentVersion)
        : Buffer.from(`ciphertext-${contentVersion}`).toString("base64url")),
  };
}

function rowFromEncrypted(encrypted: TestEncryptedNote, overrides: Partial<TestNoteRow> = {}): TestNoteRow {
  return {
    _id: "note-1",
    noteId: encrypted.header.noteId,
    vaultId: encrypted.header.vaultId,
    header: encrypted.header,
    nonce: encrypted.nonce,
    ciphertext: encrypted.ciphertext,
    contentVersion: encrypted.header.contentVersion,
    serverCreatedAtBucketMs: serverBucket(NOW - 1_000),
    serverUpdatedAtBucketMs: serverBucket(NOW - 1_000),
    ...overrides,
  };
}

async function insertLiveRecord() {
  const harness = createHarness();

  const rowId = await upsertEncryptedRecord(harness.ctx, {
    adapter: harness.adapter,
    encryptedRecord: encryptedNote(),
    now: NOW,
    sessionToken: SESSION_TOKEN,
  });

  assert.equal(rowId, "note-1");
  assert.equal(harness.records.length, 1);
  assert.equal(harness.records[0].contentVersion, 1);
  assert.equal(harness.records[0].cloudState, "live");
  assert.equal(harness.db.vaultUsage[0].liveSyncedNoteCount, 1);
  assert.equal(harness.db.vaultUsage[0].liveStorageBytes, harness.records[0].accountedStorageBytes);
  assert.equal(harness.db.rateLimits[0].key, "write:note:vault-1");
  assert.equal(harness.db.rateLimits[0].count, 1);
}

async function updateNewerVersion() {
  const existing = rowFromEncrypted(encryptedNote({ contentVersion: 1 }));
  const harness = createHarness({ records: [existing] });

  const rowId = await upsertEncryptedRecord(harness.ctx, {
    adapter: harness.adapter,
    encryptedRecord: encryptedNote({ contentVersion: 2 }),
    now: NOW,
    sessionToken: SESSION_TOKEN,
  });

  assert.equal(rowId, existing._id);
  assert.equal(harness.records[0].contentVersion, 2);
  assert.equal(harness.records[0].serverCreatedAtBucketMs, serverBucket(NOW - 1_000));
}

async function sameVersionIdenticalLiveWriteIsNoop() {
  const existing = rowFromEncrypted(encryptedNote({ contentVersion: 1 }));
  const harness = createHarness({ records: [existing] });

  const rowId = await upsertEncryptedRecord(harness.ctx, {
    adapter: harness.adapter,
    encryptedRecord: encryptedNote({ contentVersion: 1 }),
    now: NOW,
    sessionToken: SESSION_TOKEN,
  });

  assert.equal(rowId, existing._id);
  assert.equal(harness.patchCount, 0);
}

async function conflictingOrStaleLiveWritesFail() {
  const conflictHarness = createHarness({ records: [rowFromEncrypted(encryptedNote())] });
  await assert.rejects(
    () =>
      upsertEncryptedRecord(conflictHarness.ctx, {
        adapter: conflictHarness.adapter,
        encryptedRecord: encryptedNote({
          ciphertext: paddedCiphertext(99),
          contentVersion: 1,
        }),
        now: NOW,
        sessionToken: SESSION_TOKEN,
      }),
    /stale note revision/,
  );

  const harness = createHarness({ records: [rowFromEncrypted(encryptedNote({ contentVersion: 2 }))] });
  await assert.rejects(
    () =>
      upsertEncryptedRecord(harness.ctx, {
        adapter: harness.adapter,
        encryptedRecord: encryptedNote({ contentVersion: 1 }),
        now: NOW,
        sessionToken: SESSION_TOKEN,
      }),
    /stale note revision/,
  );
}

async function validationFailuresAreCentralized() {
  const harness = createHarness();

  await assert.rejects(
    () =>
      upsertEncryptedRecord(harness.ctx, {
        adapter: harness.adapter,
        encryptedRecord: encryptedNote({ vaultId: "other-vault" }),
        now: NOW,
        sessionToken: SESSION_TOKEN,
      }),
    /note vault does not match session/,
  );
  await assert.rejects(
    () =>
      upsertEncryptedRecord(harness.ctx, {
        adapter: harness.adapter,
        encryptedRecord: encryptedNote({ noteId: "bad id" }),
        now: NOW,
        sessionToken: SESSION_TOKEN,
      }),
    /note ID is malformed/,
  );
  await assert.rejects(
    () =>
      upsertEncryptedRecord(harness.ctx, {
        adapter: harness.adapter,
        encryptedRecord: encryptedNote({
          ciphertext: Buffer.alloc(MAX_CIPHERTEXT_BYTES + 1).toString("base64url"),
          schemaVersion: 1,
        }),
        now: NOW,
        sessionToken: SESSION_TOKEN,
      }),
    /note ciphertext is too large/,
  );
}

async function capacityAppliesOnlyToInserts() {
  const existing = rowFromEncrypted(encryptedNote());
  const fullHarness = createHarness({ maxRecords: 1, records: [existing] });

  await assert.rejects(
    () =>
      upsertEncryptedRecord(fullHarness.ctx, {
        adapter: fullHarness.adapter,
        encryptedRecord: encryptedNote({ noteId: "note-2" }),
        now: NOW,
        sessionToken: SESSION_TOKEN,
      }),
    /note limit exceeded/,
  );

  const harness = createHarness({ maxRecords: 1, records: [existing] });
  await upsertEncryptedRecord(harness.ctx, {
    adapter: harness.adapter,
    encryptedRecord: encryptedNote({ contentVersion: 2 }),
    now: NOW,
    sessionToken: SESSION_TOKEN,
  });
  assert.equal(harness.records[0].contentVersion, 2);
}

async function freeQuotaLimitsAreEnforced() {
  const fullHarness = createHarness({
    records: Array.from({ length: FREE_SYNC_MAX_NOTES }, (_, index) =>
      rowFromEncrypted(encryptedNote({ noteId: `note-${index + 1}` }), {
        _id: `note-${index + 1}`,
      }),
    ),
  });

  await assert.rejects(
    () =>
      upsertEncryptedRecord(fullHarness.ctx, {
        adapter: fullHarness.adapter,
        encryptedRecord: encryptedNote({ noteId: "note-21" }),
        now: NOW,
        sessionToken: SESSION_TOKEN,
      }),
    /quota_note_count_exceeded/,
  );

  const storageHarness = createHarness({ maxStorageBytes: 1 });
  await assert.rejects(
    () =>
      upsertEncryptedRecord(storageHarness.ctx, {
        adapter: storageHarness.adapter,
        encryptedRecord: encryptedNote({ noteId: "storage-heavy-note" }),
        now: NOW,
        sessionToken: SESSION_TOKEN,
      }),
    /quota_storage_exceeded/,
  );
}

async function staleUsageLedgerIsReconciledBeforeQuotaFailure() {
  const harness = createHarness({
    records: [],
    usage: {
      liveSyncedNoteCount: FREE_SYNC_MAX_NOTES,
      liveStorageBytes: FREE_SYNC_MAX_STORAGE_BYTES,
    },
  });

  await upsertEncryptedRecord(harness.ctx, {
    adapter: harness.adapter,
    encryptedRecord: encryptedNote({ noteId: "note-after-cloud-delete" }),
    now: NOW,
    sessionToken: SESSION_TOKEN,
  });

  assert.equal(harness.records.length, 1);
  assert.equal(harness.db.vaultUsage[0].liveSyncedNoteCount, 1);
  assert.equal(harness.db.vaultUsage[0].liveStorageBytes, harness.records[0].accountedStorageBytes);
}

async function deliberateUsageReconciliationPatchesStaleCounts() {
  const liveNote = rowFromEncrypted(encryptedNote({ noteId: "note-live" }), {
    _id: "note-live",
    accountedStorageBytes: 42,
  });
  const deletedNote = rowFromEncrypted(encryptedNote({ noteId: "note-deleted" }), {
    _id: "note-deleted",
    accountedStorageBytes: 100,
    cloudState: "deleted",
    serverDeletedAtBucketMs: serverBucket(NOW),
  });
  const removedNote = rowFromEncrypted(encryptedNote({ noteId: "note-removed" }), {
    _id: "note-removed",
    accountedStorageBytes: 100,
    ciphertext: "",
    cloudState: "removed_from_sync",
    nonce: "",
  });
  const harness = createHarness({
    records: [liveNote, deletedNote, removedNote],
    usage: {
      liveStorageBytes: 999,
      liveSyncedFolderCount: 999,
      liveSyncedNoteCount: 999,
    },
  });
  harness.db.folders.push(
    rowFromEncrypted(encryptedNote({ noteId: "folder-live" }), {
      _id: "folder-live",
      accountedStorageBytes: 17,
    }),
    rowFromEncrypted(encryptedNote({ noteId: "folder-removed" }), {
      _id: "folder-removed",
      accountedStorageBytes: 100,
      ciphertext: "",
      cloudState: "removed_from_sync",
      nonce: "",
    }),
  );

  const usage = await reconcileUsageForVault(harness.ctx, VAULT_ID);

  assert.equal(usage.liveSyncedNoteCount, 1);
  assert.equal(usage.liveSyncedFolderCount, 1);
  assert.equal(usage.liveStorageBytes, 59);
  assert.equal(harness.db.vaultUsage[0].liveSyncedNoteCount, 1);
  assert.equal(harness.db.vaultUsage[0].liveSyncedFolderCount, 1);
  assert.equal(harness.db.vaultUsage[0].liveStorageBytes, 59);
}

async function deliberateUsageReconciliationCountsLegacyRowsWithoutAccountedBytes() {
  const liveNote = rowFromEncrypted(encryptedNote({ noteId: "legacy-note" }), {
    _id: "legacy-note",
  });
  delete liveNote.accountedStorageBytes;
  const harness = createHarness({
    records: [liveNote],
    usage: {
      liveStorageBytes: 0,
      liveSyncedNoteCount: 0,
    },
  });

  const usage = await reconcileUsageForVault(harness.ctx, VAULT_ID);

  assert.equal(usage.liveSyncedNoteCount, 1);
  assert(usage.liveStorageBytes > 0);
  assert.equal(harness.db.vaultUsage[0].liveSyncedNoteCount, 1);
  assert.equal(harness.db.vaultUsage[0].liveStorageBytes, usage.liveStorageBytes);
}

async function deliberateUsageReconciliationRequiresValidSession() {
  const harness = createHarness();
  const handler = (reconcileUsage as unknown as TestMutationHandler<{ sessionToken: string }>)._handler;

  await assert.rejects(
    () => handler(harness.ctx, { sessionToken: "invalid-session-token" }),
    /session expired or invalid/,
  );
}

async function tombstoneNewerVersion() {
  const harness = createHarness({ records: [rowFromEncrypted(encryptedNote({ contentVersion: 1 }))] });
  const encryptedTombstone = encryptedNote({ contentVersion: 2 });

  const rowId = await tombstoneEncryptedRecord(harness.ctx, {
    adapter: harness.adapter,
    deletedAtMs: NOW,
    encryptedRecord: encryptedTombstone,
    now: NOW,
    sessionToken: SESSION_TOKEN,
  });

  assert.equal(rowId, "note-1");
  assert.equal(harness.records[0].contentVersion, 2);
  assert.equal(harness.records[0].cloudState, "deleted");
  assert.equal(harness.records[0].serverDeletedAtBucketMs, serverBucket(NOW));
  assert.equal(harness.records[0].retentionExpiresAtBucketMs, serverBucket(NOW + 30 * SERVER_TIMESTAMP_BUCKET_MS));
  assert.equal(harness.records[0].nonce, encryptedTombstone.nonce);
  assert.equal(harness.records[0].ciphertext, encryptedTombstone.ciphertext);
  assert.equal(harness.db.vaultUsage[0].liveSyncedNoteCount, 0);
}

async function tombstoneNoopAndConflict() {
  const encryptedTombstone = encryptedNote({ contentVersion: 2 });
  const tombstone = rowFromEncrypted(encryptedTombstone, {
    cloudState: "deleted",
    retentionExpiresAtBucketMs: serverBucket(NOW - 1 + 30 * SERVER_TIMESTAMP_BUCKET_MS),
    serverDeletedAtBucketMs: serverBucket(NOW - 1),
  });
  const noopHarness = createHarness({ records: [tombstone] });

  const rowId = await tombstoneEncryptedRecord(noopHarness.ctx, {
    adapter: noopHarness.adapter,
    deletedAtMs: NOW - 1,
    encryptedRecord: encryptedTombstone,
    now: NOW,
    sessionToken: SESSION_TOKEN,
  });

  assert.equal(rowId, "note-1");
  assert.equal(noopHarness.patchCount, 0);

  const conflictHarness = createHarness({ records: [tombstone] });
  await assert.rejects(
    () =>
      tombstoneEncryptedRecord(conflictHarness.ctx, {
        adapter: conflictHarness.adapter,
        deletedAtMs: NOW,
        encryptedRecord: encryptedNote({
          ciphertext: paddedCiphertext(99),
          contentVersion: 2,
        }),
        now: NOW,
        sessionToken: SESSION_TOKEN,
      }),
    /stale note tombstone/,
  );
}

async function missingTombstoneTargetReturnsNull() {
  const harness = createHarness();

  const rowId = await tombstoneEncryptedRecord(harness.ctx, {
    adapter: harness.adapter,
    deletedAtMs: NOW - MAX_TIMESTAMP_SKEW_MS - 1,
    encryptedRecord: encryptedNote({ contentVersion: 1 }),
    now: NOW,
    sessionToken: SESSION_TOKEN,
  });

  assert.equal(rowId, null);
}

async function oldTombstoneTimestampIsAccepted() {
  const oldDeletedAtMs = NOW - MAX_TIMESTAMP_SKEW_MS - 1;
  const harness = createHarness({ records: [rowFromEncrypted(encryptedNote({ contentVersion: 1 }))] });
  const encryptedTombstone = encryptedNote({ contentVersion: 2 });

  const rowId = await tombstoneEncryptedRecord(harness.ctx, {
    adapter: harness.adapter,
    deletedAtMs: oldDeletedAtMs,
    encryptedRecord: encryptedTombstone,
    now: NOW,
    sessionToken: SESSION_TOKEN,
  });

  assert.equal(rowId, "note-1");
  assert.equal(harness.records[0].serverDeletedAtBucketMs, serverBucket(NOW));
  assert.equal(harness.records[0].retentionExpiresAtBucketMs, serverBucket(NOW + 30 * SERVER_TIMESTAMP_BUCKET_MS));
  assert.equal(harness.records[0].cloudState, "deleted");
  assert.equal(harness.records[0].ciphertext, encryptedTombstone.ciphertext);
}

async function futureTombstoneTimestampStillFails() {
  const harness = createHarness({ records: [rowFromEncrypted(encryptedNote({ contentVersion: 1 }))] });

  await assert.rejects(
    () =>
      tombstoneEncryptedRecord(harness.ctx, {
        adapter: harness.adapter,
        deletedAtMs: NOW + MAX_TIMESTAMP_SKEW_MS + 1,
        encryptedRecord: encryptedNote({ contentVersion: 2 }),
        now: NOW,
        sessionToken: SESSION_TOKEN,
      }),
    /note delete timestamp is outside the allowed clock skew/,
  );
}

async function emptyEncryptedTombstoneStillFails() {
  const harness = createHarness({ records: [rowFromEncrypted(encryptedNote({ contentVersion: 1 }))] });

  await assert.rejects(
    () =>
      tombstoneEncryptedRecord(harness.ctx, {
        adapter: harness.adapter,
        deletedAtMs: NOW,
        encryptedRecord: encryptedNote({ ciphertext: "", contentVersion: 2 }),
        now: NOW,
        sessionToken: SESSION_TOKEN,
      }),
    /note ciphertext is required/,
  );
}

async function removeFromCloudSyncClearsUsageWithoutDeletingLocalMetadata() {
  const harness = createHarness({ records: [rowFromEncrypted(encryptedNote({ contentVersion: 1 }))] });

  const rowId = await removeEncryptedRecordFromCloudSync(harness.ctx, {
    adapter: harness.adapter,
    contentVersion: 1,
    now: NOW,
    recordId: "note-1",
    removedAtMs: NOW,
    sessionToken: SESSION_TOKEN,
  });

  assert.equal(rowId, "note-1");
  assert.equal(harness.records[0].cloudState, "removed_from_sync");
  assert.equal(harness.records[0].serverRemovedFromSyncAtBucketMs, serverBucket(NOW));
  assert.equal(harness.records[0].serverDeletedAtBucketMs, undefined);
  assert.equal(harness.records[0].retentionExpiresAtBucketMs, serverBucket(NOW + 7 * SERVER_TIMESTAMP_BUCKET_MS));
  assert.equal(harness.records[0].nonce, "");
  assert.equal(harness.records[0].ciphertext, "");
  assert.equal(harness.db.vaultUsage[0].liveSyncedNoteCount, 0);

  const retryRowId = await removeEncryptedRecordFromCloudSync(harness.ctx, {
    adapter: harness.adapter,
    contentVersion: 1,
    now: NOW + 1,
    recordId: "note-1",
    removedAtMs: NOW + 1,
    sessionToken: SESSION_TOKEN,
  });

  assert.equal(retryRowId, "note-1");
  assert.equal(harness.patchCount, 1);
  assert.equal(harness.records[0].cloudState, "removed_from_sync");
  assert.equal(harness.records[0].serverRemovedFromSyncAtBucketMs, serverBucket(NOW));

  await upsertEncryptedRecord(harness.ctx, {
    adapter: harness.adapter,
    encryptedRecord: encryptedNote({ contentVersion: 1 }),
    now: NOW + 1,
    sessionToken: SESSION_TOKEN,
  });
  assert.equal(harness.records[0].cloudState, "live");
  assert.equal(harness.records[0].contentVersion, 1);
  assert.equal(harness.db.vaultUsage[0].liveSyncedNoteCount, 1);
}

async function v2CiphertextMustUsePaddingBucket() {
  const harness = createHarness();

  await assert.rejects(
    () =>
      upsertEncryptedRecord(harness.ctx, {
        adapter: harness.adapter,
        encryptedRecord: encryptedNote({
          ciphertext: Buffer.alloc(1_039).toString("base64url"),
        }),
        now: NOW,
        sessionToken: SESSION_TOKEN,
      }),
    /note ciphertext padding bucket is unsupported/,
  );
}

async function cleanupDeletesExpiredMarkersOnly() {
  const expiredDeleted = rowFromEncrypted(encryptedNote({ noteId: "deleted-note" }), {
    _id: "deleted-note",
    cloudState: "deleted",
    retentionExpiresAtBucketMs: serverBucket(NOW - SERVER_TIMESTAMP_BUCKET_MS),
    serverDeletedAtBucketMs: serverBucket(NOW - 31 * SERVER_TIMESTAMP_BUCKET_MS),
  });
  const expiredRemoved = rowFromEncrypted(encryptedNote({ noteId: "removed-note" }), {
    _id: "removed-note",
    ciphertext: "",
    cloudState: "removed_from_sync",
    nonce: "",
    retentionExpiresAtBucketMs: serverBucket(NOW - SERVER_TIMESTAMP_BUCKET_MS),
    serverRemovedFromSyncAtBucketMs: serverBucket(NOW - 8 * SERVER_TIMESTAMP_BUCKET_MS),
  });
  const live = rowFromEncrypted(encryptedNote({ noteId: "live-note" }), {
    _id: "live-note",
  });
  const explicitLive = rowFromEncrypted(encryptedNote({ noteId: "explicit-live-note" }), {
    _id: "explicit-live-note",
    cloudState: "live",
    retentionExpiresAtBucketMs: serverBucket(NOW - SERVER_TIMESTAMP_BUCKET_MS),
  });
  const harness = createHarness({ records: [expiredDeleted, expiredRemoved, live] });
  harness.records.push(explicitLive);
  harness.db.folders.push(rowFromEncrypted(encryptedNote({ noteId: "expired-folder-marker" }), {
    _id: "expired-folder-marker",
    cloudState: "deleted",
    retentionExpiresAtBucketMs: serverBucket(NOW - SERVER_TIMESTAMP_BUCKET_MS),
    serverDeletedAtBucketMs: serverBucket(NOW - 31 * SERVER_TIMESTAMP_BUCKET_MS),
  }));

  const result = await cleanupExpiredEncryptedRecordMarkers(harness.ctx, { batchSize: 10, now: NOW });

  assert.equal(result.notes, 2);
  assert.equal(result.folders, 1);
  assert.deepEqual(harness.records.map((row) => row.noteId), ["live-note", "explicit-live-note"]);
  assert.deepEqual(harness.db.folders.map((row) => row.noteId), []);
}

const { logs } = await captureConsoleLogs(async () => {
  await insertLiveRecord();
  await updateNewerVersion();
  await sameVersionIdenticalLiveWriteIsNoop();
  await conflictingOrStaleLiveWritesFail();
  await validationFailuresAreCentralized();
  await capacityAppliesOnlyToInserts();
  await freeQuotaLimitsAreEnforced();
await staleUsageLedgerIsReconciledBeforeQuotaFailure();
await deliberateUsageReconciliationPatchesStaleCounts();
await deliberateUsageReconciliationCountsLegacyRowsWithoutAccountedBytes();
await deliberateUsageReconciliationRequiresValidSession();
  await tombstoneNewerVersion();
  await tombstoneNoopAndConflict();
  await missingTombstoneTargetReturnsNull();
  await oldTombstoneTimestampIsAccepted();
  await futureTombstoneTimestampStillFails();
  await emptyEncryptedTombstoneStillFails();
  await removeFromCloudSyncClearsUsageWithoutDeletingLocalMetadata();
  await v2CiphertextMustUsePaddingBucket();
  await cleanupDeletesExpiredMarkersOnly();
});

assertLogsDoNotExposeVaultIdentifiers(logs, [VAULT_ID, "other-vault"]);
assertLogCaptured(logs, "test_note_write", "insert");
assertLogCaptured(logs, "test_note_write", "update");
assertLogCaptured(logs, "test_note_delete", "delete");
assertLogCaptured(logs, "test_note_delete", "remove_from_sync");

console.log("encrypted record policy tests passed");

async function captureConsoleLogs<T>(run: () => Promise<T>) {
  const originalLog = console.log;
  const logs: CapturedLog[] = [];
  console.log = (...args: CapturedLog) => {
    logs.push(args);
  };

  try {
    return { logs, result: await run() };
  } finally {
    console.log = originalLog;
  }
}

function assertLogsDoNotExposeVaultIdentifiers(logs: CapturedLog[], forbiddenValues: string[]) {
  const serialized = JSON.stringify(logs);
  assert(!serialized.includes("vaultId"), `logs included vaultId field: ${serialized}`);
  for (const value of forbiddenValues) {
    assert(!serialized.includes(value), `logs included raw vault identifier ${value}: ${serialized}`);
  }
}

function assertLogCaptured(logs: CapturedLog[], eventName: string, kind: string) {
  assert(
    logs.some(([name, payload]) => name === eventName && logPayloadKind(payload) === kind),
    `missing ${eventName} ${kind} log in ${JSON.stringify(logs)}`,
  );
}

function logPayloadKind(payload: unknown) {
  return typeof payload === "object" && payload !== null
    ? (payload as { kind?: unknown }).kind
    : undefined;
}

function cloneRow<T>(value: T): T {
  return value === null ? value : structuredClone(value);
}

function applyPatch(row: TestNoteRow, patch: Partial<TestNoteRow>) {
  for (const [key, value] of Object.entries(patch)) {
    if (value === undefined) {
      delete (row as Record<string, unknown>)[key];
    } else {
      (row as Record<string, unknown>)[key] = value;
    }
  }
}

function isLiveRecord(row: TestNoteRow) {
  return (
    row.cloudState !== "deleted" &&
    row.cloudState !== "removed_from_sync" &&
    row.serverDeletedAtBucketMs === undefined &&
    row.nonce !== "" &&
    row.ciphertext !== ""
  );
}

function serverBucket(value: number) {
  return Math.floor(value / SERVER_TIMESTAMP_BUCKET_MS) * SERVER_TIMESTAMP_BUCKET_MS;
}

function paddedCiphertext(seed: number) {
  return Buffer.alloc(1_040, seed).toString("base64url");
}
