import assert from "node:assert/strict";

import { ed25519 } from "@noble/curves/ed25519.js";
import type { MutationCtx, QueryCtx } from "../convex/_generated/server";
import {
  completeBackendAuthChallenge,
  createBackendKeyChallenge,
  createChallengeFromVerifiedAttestation,
  deleteVaultCloudCopyBatch,
  discoverCloudReplica,
  newChallengeMaterial,
  verifiedAttestedChallengeFromSigner,
  type AttestedChallengeRequest,
  type ChallengeResponse,
  type ChallengeMaterial,
} from "../convex/lib/authLifecycle";
import {
  challengeBackendKeyRateLimitKey,
  challengeVaultRateLimitKey,
  readAuthAttestationMode,
  shouldRequireAttestationForNewChallenge,
  shouldRequireFreshAttestationForCloudDelete,
  vaultCreateRateLimitKey,
} from "../convex/lib/authPolicy";
import {
  backendAuthKeyIdFromPublicKey,
  hashOperationalIdentifier,
  requireSession,
  sessionTokenHash,
  verifyBackendAuthSignature,
} from "../convex/lib/backendAuth";
import { encodeBase64Url, utf8Bytes } from "../convex/lib/encoding";
import { metadataHash } from "../convex/lib/privacyMetadata";

const NOW = 1_779_720_000_000;
const SESSION_TOKEN = "session-token";
const BACKEND_AUTH_ALGORITHM = "ed25519-v1";
const BACKEND_AUTH_KEY_VERSION = 1;
const BACKEND_AUTH_SEED = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const BACKEND_AUTH_PUBLIC_KEY = encodeBase64Url(ed25519.getPublicKey(BACKEND_AUTH_SEED));
const BACKEND_AUTH_KEY_ID = backendAuthKeyIdFromPublicKey({
  backendAuthAlgorithm: BACKEND_AUTH_ALGORITHM,
  backendAuthKeyVersion: BACKEND_AUTH_KEY_VERSION,
  backendAuthPublicKey: BACKEND_AUTH_PUBLIC_KEY,
});
const OTHER_BACKEND_AUTH_SEED = Uint8Array.from({ length: 32 }, (_, index) => 255 - index);
const OTHER_BACKEND_AUTH_PUBLIC_KEY = encodeBase64Url(
  ed25519.getPublicKey(OTHER_BACKEND_AUTH_SEED),
);
const OTHER_BACKEND_AUTH_KEY_ID = backendAuthKeyIdFromPublicKey({
  backendAuthAlgorithm: BACKEND_AUTH_ALGORITHM,
  backendAuthKeyVersion: BACKEND_AUTH_KEY_VERSION,
  backendAuthPublicKey: OTHER_BACKEND_AUTH_PUBLIC_KEY,
});
const METADATA_HASH_SECRET = "test-metadata-hash-secret";
process.env.CONVEX_METADATA_HASH_SECRET = METADATA_HASH_SECRET;

type CapturedLog = Parameters<typeof console.log>;
type FakeFilter =
  | { field: string; op: "eq"; value: unknown }
  | { field: string; op: "lt"; value: unknown };
type FakeTable =
  | "challenges"
  | "folders"
  | "notes"
  | "rateLimits"
  | "sessions"
  | "vaults"
  | "vaultUsage";

const request: AttestedChallengeRequest = {
  appEncryptionRequestId: "request-1",
  appIdentityIAddress: "i-app",
  backendAuthAlgorithm: BACKEND_AUTH_ALGORITHM,
  backendAuthKeyId: BACKEND_AUTH_KEY_ID,
  backendAuthPublicKey: BACKEND_AUTH_PUBLIC_KEY,
  backendAuthKeyVersion: BACKEND_AUTH_KEY_VERSION,
  chain: "VRSCTEST",
  cloudAttestationExpiresAt: NOW + 20 * 60_000,
  cloudAttestationId: "cloud-attestation-1",
  cloudAttestationSecret: "cloud-attestation-secret",
  derivationNumber: 1,
  requestHashHex: "request-hash",
  signerSessionId: "signer-session-1",
  vaultId: "vault-1",
  walletSignerIdentityIAddress: "i-wallet",
};

const material: ChallengeMaterial = {
  challenge: "challenge-1",
  expiresAtMs: NOW + 5 * 60_000,
  sessionId: "convex-challenge-1",
};

function attestedChallengeHandoffDropsVerifierSecrets() {
  const verifiedChallenge = verifiedAttestedChallengeFromSigner({
    material,
    now: NOW,
    request,
    signerAttestation: {
      expiresAtMs: NOW + 20 * 60_000,
      issuedAtMs: NOW - 1_000,
    },
  });

  assert.deepEqual(verifiedChallenge, {
    appEncryptionRequestId: "request-1",
    appIdentityIAddress: "i-app",
    attestationIdHash: hashOperationalIdentifier(
      "cloud-attestation-id",
      "cloud-attestation-1",
    ),
    attestedAtMs: NOW - 1_000,
    backendAuthAlgorithm: BACKEND_AUTH_ALGORITHM,
    backendAuthKeyId: BACKEND_AUTH_KEY_ID,
    backendAuthPublicKey: BACKEND_AUTH_PUBLIC_KEY,
    backendAuthKeyVersion: BACKEND_AUTH_KEY_VERSION,
    chain: "VRSCTEST",
    challenge: "challenge-1",
    derivationNumber: 1,
    expiresAtMs: NOW + 5 * 60_000,
    sessionId: "convex-challenge-1",
    signerSessionIdHash: hashOperationalIdentifier("signer-session-id", "signer-session-1"),
    vaultId: "vault-1",
    walletSignerIdentityIAddress: "i-wallet",
    walletUnlockFreshUntilMs: NOW + 10 * 60_000,
  });

  assert(!("cloudAttestationSecret" in verifiedChallenge));
  assert(!("cloudAttestationId" in verifiedChallenge));
  assert(!("signerSessionId" in verifiedChallenge));
  assert(!("requestHashHex" in verifiedChallenge));
}

function authPolicyNamesRateLimitKeys() {
  assert.equal(challengeVaultRateLimitKey("vault-1"), "challenge:vault:vault-1");
  assert.equal(
    challengeBackendKeyRateLimitKey(BACKEND_AUTH_KEY_ID),
    `challenge:backend-key:${BACKEND_AUTH_KEY_ID}`,
  );
  assert.equal(vaultCreateRateLimitKey(BACKEND_AUTH_KEY_ID), `vault:create:${BACKEND_AUTH_KEY_ID}`);
}

function authPolicyDecidesAttestationModes() {
  assert.equal(
    shouldRequireAttestationForNewChallenge({ mode: "required", existingVault: {} }),
    true,
  );
  assert.equal(
    shouldRequireAttestationForNewChallenge({
      mode: "required_for_new_vaults",
      existingVault: null,
    }),
    true,
  );
  assert.equal(
    shouldRequireAttestationForNewChallenge({
      mode: "required_for_new_vaults",
      existingVault: {},
    }),
    false,
  );
  assert.equal(
    shouldRequireAttestationForNewChallenge({ mode: "observe", existingVault: null }),
    false,
  );
  assert.equal(shouldRequireFreshAttestationForCloudDelete("required"), true);
  assert.equal(shouldRequireFreshAttestationForCloudDelete("required_for_new_vaults"), true);
  assert.equal(shouldRequireFreshAttestationForCloudDelete("observe"), false);
}

function authPolicyDefaultsToRequired() {
  const originalMode = process.env.CONVEX_AUTH_ATTESTATION_MODE;
  delete process.env.CONVEX_AUTH_ATTESTATION_MODE;

  try {
    assert.equal(readAuthAttestationMode(), "required");
  } finally {
    if (originalMode === undefined) {
      delete process.env.CONVEX_AUTH_ATTESTATION_MODE;
    } else {
      process.env.CONVEX_AUTH_ATTESTATION_MODE = originalMode;
    }
  }
}

async function backendKeyChallengeRequiresExistingVault() {
  await withAttestationMode("required_for_new_vaults", async () => {
    const db = new FakeAuthDb();

    await assert.rejects(
      () => createBackendKeyChallenge({ db } as unknown as MutationCtx, request),
      /signer_attestation_required/,
    );
    assert.equal(db.challenges.length, 0);
  });
}

async function backendKeyChallengeAcceptsExistingVaultMetadata() {
  await withAttestationMode("required_for_new_vaults", async () => {
    const db = new FakeAuthDb({ vaults: [activeVaultRow()] });
    const response = await createBackendKeyChallenge({ db } as unknown as MutationCtx, request);

    assert.equal(response.backendAuthAlgorithm, BACKEND_AUTH_ALGORITHM);
    assert.equal(response.backendAuthKeyId, BACKEND_AUTH_KEY_ID);
    assert.equal(response.backendAuthPublicKey, BACKEND_AUTH_PUBLIC_KEY);
    assert.equal(response.backendAuthKeyVersion, BACKEND_AUTH_KEY_VERSION);
    assert.equal(db.challenges.length, 1);
    assert.equal(db.rateLimits.length, 2);
  });
}

async function backendKeyChallengeRejectsStoredMetadataMismatch() {
  await withAttestationMode("required_for_new_vaults", async () => {
    const db = new FakeAuthDb({ vaults: [activeVaultRow()] });

    await assert.rejects(
      () =>
        createBackendKeyChallenge({ db } as unknown as MutationCtx, {
          ...request,
          backendAuthKeyId: OTHER_BACKEND_AUTH_KEY_ID,
          backendAuthPublicKey: OTHER_BACKEND_AUTH_PUBLIC_KEY,
        }),
      /vault backend auth metadata mismatch/,
    );
    assert.equal(db.challenges.length, 0);
  });
}

async function oldV1ShapedChallengeDataIsRejected() {
  await withAttestationMode("required_for_new_vaults", async () => {
    const db = new FakeAuthDb({ vaults: [activeVaultRow()] });

    await assert.rejects(
      () =>
        createBackendKeyChallenge({ db } as unknown as MutationCtx, {
          ...request,
          backendAuthAlgorithm: undefined,
          backendAuthKeyId: undefined,
          backendAuthKeyVersion: undefined,
        } as any),
      /backend auth algorithm is unsupported/,
    );
    assert.equal(db.challenges.length, 0);
  });
}

async function attestedNewVaultCreationWorksWithV2Metadata() {
  const db = new FakeAuthDb();
  const ctx = { db } as unknown as MutationCtx;
  const now = Date.now();
  const verifiedChallenge = verifiedAttestedChallengeFromSigner({
    material: newChallengeMaterial(now),
    now,
    request: {
      ...request,
      cloudAttestationExpiresAt: now + 20 * 60_000,
    },
    signerAttestation: {
      expiresAtMs: now + 20 * 60_000,
      issuedAtMs: now,
    },
  });
  const challenge = await createChallengeFromVerifiedAttestation(ctx, verifiedChallenge);
  const session = await completeBackendAuthChallenge(ctx, {
    sessionId: challenge.sessionId,
    signature: signRustCanonicalChallenge(challenge),
  });

  assert.equal(session.authStrength, "signer_attested");
  assert.equal(session.vaultId, request.vaultId);
  assert.equal(db.vaults.length, 1);
  assert.equal(db.vaults[0].backendAuthKeyId, BACKEND_AUTH_KEY_ID);
  assert.equal(
    db.vaults[0].walletSignerIdentityHash,
    metadataHash("wallet-signer-identity", request.walletSignerIdentityIAddress),
  );
  assert.equal(db.vaults[0].appIdentityHash, metadataHash("app-identity", request.appIdentityIAddress));
  assert.equal("walletSignerIdentityIAddress" in db.vaults[0], false);
  assert.equal("appIdentityIAddress" in db.vaults[0], false);
  assert.equal("firstAttestedAtMs" in db.vaults[0], false);
  assert.equal("lastAttestedAtMs" in db.vaults[0], false);
  assert.equal(db.sessions.length, 1);
  assert.equal(db.sessions[0].backendAuthKeyVersion, BACKEND_AUTH_KEY_VERSION);
}

async function attestedExistingVaultRejectsIdentityHashMismatch() {
  const db = new FakeAuthDb({
    vaults: [
      activeVaultRow({
        appIdentityHash: metadataHash("app-identity", request.appIdentityIAddress),
        chain: request.chain,
        derivationNumber: request.derivationNumber,
        walletSignerIdentityHash: metadataHash(
          "wallet-signer-identity",
          request.walletSignerIdentityIAddress,
        ),
      }),
    ],
  });
  const ctx = { db } as unknown as MutationCtx;
  const now = Date.now();
  const mismatchedRequest = {
    ...request,
    walletSignerIdentityIAddress: "i-other-wallet",
  };
  const verifiedChallenge = verifiedAttestedChallengeFromSigner({
    material: newChallengeMaterial(now),
    now,
    request: mismatchedRequest,
    signerAttestation: {
      expiresAtMs: now + 20 * 60_000,
      issuedAtMs: now,
    },
  });
  const challenge = await createChallengeFromVerifiedAttestation(ctx, verifiedChallenge);

  await assert.rejects(
    () =>
      completeBackendAuthChallenge(ctx, {
        sessionId: challenge.sessionId,
        signature: signRustCanonicalChallenge(challenge),
      }),
    /wallet identity metadata mismatch/,
  );
}

async function missingMetadataHashSecretFailsForAttestedVaultPersistence() {
  const originalSecret = process.env.CONVEX_METADATA_HASH_SECRET;
  delete process.env.CONVEX_METADATA_HASH_SECRET;

  try {
    const db = new FakeAuthDb();
    const ctx = { db } as unknown as MutationCtx;
    const now = Date.now();
    const verifiedChallenge = verifiedAttestedChallengeFromSigner({
      material: newChallengeMaterial(now),
      now,
      request,
      signerAttestation: {
        expiresAtMs: now + 20 * 60_000,
        issuedAtMs: now,
      },
    });
    const challenge = await createChallengeFromVerifiedAttestation(ctx, verifiedChallenge);

    await assert.rejects(
      () =>
        completeBackendAuthChallenge(ctx, {
          sessionId: challenge.sessionId,
          signature: signRustCanonicalChallenge(challenge),
        }),
      /CONVEX_METADATA_HASH_SECRET is required/,
    );
  } finally {
    process.env.CONVEX_METADATA_HASH_SECRET = originalSecret ?? METADATA_HASH_SECRET;
  }
}

function backendAuthSignatureMatchesRustCanonicalChallengeOrder() {
  const challenge: ChallengeResponse = {
    appEncryptionRequestId: request.appEncryptionRequestId,
    appIdentityIAddress: request.appIdentityIAddress,
    backendAuthAlgorithm: BACKEND_AUTH_ALGORITHM,
    backendAuthKeyId: BACKEND_AUTH_KEY_ID,
    backendAuthKeyVersion: BACKEND_AUTH_KEY_VERSION,
    backendAuthPublicKey: BACKEND_AUTH_PUBLIC_KEY,
    challenge: "challenge-1",
    derivationNumber: request.derivationNumber,
    expiresAtMs: NOW + 5 * 60_000,
    sessionId: "convex-challenge-1",
    vaultId: request.vaultId,
    walletSignerIdentityIAddress: request.walletSignerIdentityIAddress,
  };

  assert.equal(
    verifyBackendAuthSignature(
      challenge,
      BACKEND_AUTH_PUBLIC_KEY,
      signRustCanonicalChallenge(challenge),
    ),
    true,
  );
}

async function sessionValidationChecksKeyIdAndVersion() {
  const db = new FakeAuthDb({
    sessions: [activeSessionRow({ backendAuthKeyId: OTHER_BACKEND_AUTH_KEY_ID })],
    vaults: [activeVaultRow()],
  });
  const ctx = { db } as unknown as MutationCtx;

  await assert.rejects(() => requireSession(ctx, SESSION_TOKEN), /session expired or invalid/);

  db.sessions[0].backendAuthKeyId = BACKEND_AUTH_KEY_ID;
  db.sessions[0].backendAuthKeyVersion = 2;

  await assert.rejects(() => requireSession(ctx, SESSION_TOKEN), /session expired or invalid/);
}

async function cloudReplicaDiscoveryReturnsEmptyWithoutWritingRows() {
  const db = new FakeAuthDb();
  const ctx = { db } as unknown as QueryCtx;
  const challenge = discoveryChallenge();

  const result = await discoverCloudReplica(ctx, {
    ...challenge,
    signature: signRustCanonicalChallenge(challenge),
  });

  assert.deepEqual(result, { liveFolderCount: 0, liveNoteCount: 0, status: "empty" });
  assert.equal(db.writeCount, 0);
  assert.equal(db.vaults.length, 0);
  assert.equal(db.sessions.length, 0);
  assert.equal(db.challenges.length, 0);
  assert.equal(db.rateLimits.length, 0);
}

async function cloudReplicaDiscoveryReturnsLiveCountsWithoutWritingRows() {
  const db = new FakeAuthDb({
    folders: [
      liveCloudRow("folder-live"),
      { ...liveCloudRow("folder-removed"), ciphertext: "", cloudState: "removed_from_sync", nonce: "" },
    ],
    notes: [
      liveCloudRow("note-live"),
      { ...liveCloudRow("note-deleted"), cloudState: "deleted", serverDeletedAtBucketMs: NOW },
    ],
    vaults: [activeVaultRow()],
  });
  const ctx = { db } as unknown as QueryCtx;
  const challenge = discoveryChallenge();

  const result = await discoverCloudReplica(ctx, {
    ...challenge,
    signature: signRustCanonicalChallenge(challenge),
  });

  assert.deepEqual(result, { liveFolderCount: 1, liveNoteCount: 1, status: "found" });
  assert.equal(db.writeCount, 0);
  assert.equal(db.vaults.length, 1);
  assert.equal(db.sessions.length, 0);
  assert.equal(db.challenges.length, 0);
  assert.equal(db.rateLimits.length, 0);
}

async function cloudReplicaDiscoveryRejectsInvalidSignature() {
  const db = new FakeAuthDb({ vaults: [activeVaultRow()] });
  const ctx = { db } as unknown as QueryCtx;

  await assert.rejects(
    () =>
      discoverCloudReplica(ctx, {
        ...discoveryChallenge(),
        signature: signRustCanonicalChallenge(discoveryChallenge({ challenge: "verus_notes_discovery_other" })),
      }),
    /backend auth signature verification failed/,
  );
  assert.equal(db.writeCount, 0);
}

async function cloudReplicaDiscoveryRejectsStoredMetadataMismatch() {
  const db = new FakeAuthDb({
    vaults: [activeVaultRow({ backendAuthKeyId: OTHER_BACKEND_AUTH_KEY_ID, backendAuthPublicKey: OTHER_BACKEND_AUTH_PUBLIC_KEY })],
  });
  const ctx = { db } as unknown as QueryCtx;
  const challenge = discoveryChallenge();

  await assert.rejects(
    () =>
      discoverCloudReplica(ctx, {
        ...challenge,
        signature: signRustCanonicalChallenge(challenge),
      }),
    /vault backend auth metadata mismatch/,
  );
  assert.equal(db.writeCount, 0);
}

class FakeQuery {
  private filters: FakeFilter[] = [];

  constructor(private readonly rows: Array<Record<string, unknown>>) {}

  withIndex(
    _name: string,
    build?: (q: { eq: (field: string, value: unknown) => unknown }) => unknown,
  ) {
    const query = {
      eq: (field: string, value: unknown) => {
        this.filters.push({ field, op: "eq", value });
        return query;
      },
    };
    build?.(query);
    return this;
  }

  filter(
    build: (q: {
      field: (field: string) => { field: string };
      lt: (field: { field: string }, value: unknown) => unknown;
    }) => unknown,
  ) {
    const query = {
      field: (field: string) => ({ field }),
      lt: (field: { field: string }, value: unknown) => {
        this.filters.push({ field: field.field, op: "lt", value });
        return query;
      },
    };
    build(query);
    return this;
  }

  async unique() {
    return this.matchingRows()[0] ?? null;
  }

  async take(count: number) {
    return this.matchingRows().slice(0, count);
  }

  async collect() {
    return this.matchingRows();
  }

  private matchingRows() {
    return this.rows.filter((row) =>
      this.filters.every((filter) => {
        if (filter.op === "eq") return row[filter.field] === filter.value;
        return Number(row[filter.field]) < Number(filter.value);
      }),
    );
  }
}

class FakeAuthDb {
  challenges: Array<Record<string, unknown>> = [];
  folders: Array<Record<string, unknown>> = [];
  notes: Array<Record<string, unknown>> = [];
  rateLimits: Array<Record<string, unknown>> = [];
  sessions: Array<Record<string, unknown>> = [];
  vaults: Array<Record<string, unknown>> = [];
  vaultUsage: Array<Record<string, unknown>> = [];
  writeCount = 0;
  private nextId = 1;

  constructor(
    input: {
      folders?: Array<Record<string, unknown>>;
      notes?: Array<Record<string, unknown>>;
      sessions?: Array<Record<string, unknown>>;
      vaults?: Array<Record<string, unknown>>;
    } = {},
  ) {
    this.folders = input.folders ?? [];
    this.notes = input.notes ?? [];
    this.sessions = input.sessions ?? [];
    this.vaults = input.vaults ?? [];
  }

  query(table: FakeTable) {
    return new FakeQuery(this[table]);
  }

  async insert(table: FakeTable, row: Record<string, unknown>) {
    this.writeCount += 1;
    const stored = { _id: `${table}-${this.nextId++}`, ...row };
    this[table].push(stored);
    return stored._id;
  }

  async patch(rowId: string, patch: Record<string, unknown>) {
    this.writeCount += 1;
    const row = this.allRows().find((candidate) => candidate._id === rowId);
    if (!row) throw new Error(`missing fake row ${rowId}`);
    Object.assign(row, patch);
  }

  async delete(rowId: string) {
    this.writeCount += 1;
    for (const rows of this.allTables()) {
      const index = rows.findIndex((row) => row._id === rowId);
      if (index >= 0) {
        rows.splice(index, 1);
        return;
      }
    }
    throw new Error(`missing fake row ${rowId}`);
  }

  private allRows() {
    return this.allTables().flat();
  }

  private allTables() {
    return [
      this.challenges,
      this.folders,
      this.notes,
      this.rateLimits,
      this.sessions,
      this.vaults,
      this.vaultUsage,
    ];
  }
}

class FakeDeleteCloudCopyDb {
  readonly challenges = [{ _id: "challenge-1", vaultId: "vault-1" }];
  readonly folders = [{ _id: "folder-1", vaultId: "vault-1" }];
  readonly notes = [{ _id: "note-1", vaultId: "vault-1" }];
  readonly sessions = [
    {
      _id: "session-1",
      backendAuthAlgorithm: BACKEND_AUTH_ALGORITHM,
      backendAuthKeyId: BACKEND_AUTH_KEY_ID,
      backendAuthPublicKey: BACKEND_AUTH_PUBLIC_KEY,
      backendAuthKeyVersion: BACKEND_AUTH_KEY_VERSION,
      createdAtMs: NOW - 900,
      expiresAtMs: Number.MAX_SAFE_INTEGER,
      lastSeenAtMs: NOW - 500,
      sessionTokenHash: sessionTokenHash(SESSION_TOKEN),
      vaultId: "vault-1",
    },
    { _id: "session-2", vaultId: "vault-1" },
  ];
  readonly vaults = [
    {
      _id: "vault-row-1",
      backendAuthAlgorithm: BACKEND_AUTH_ALGORITHM,
      backendAuthKeyId: BACKEND_AUTH_KEY_ID,
      backendAuthPublicKey: BACKEND_AUTH_PUBLIC_KEY,
      backendAuthKeyVersion: BACKEND_AUTH_KEY_VERSION,
      createdAtMs: NOW - 1_000,
      updatedAtMs: NOW - 1_000,
      vaultId: "vault-1",
    },
  ];
  readonly vaultUsage = [{ _id: "usage-1", vaultId: "vault-1" }];

  query(table: "challenges" | "folders" | "notes" | "sessions" | "vaults" | "vaultUsage") {
    return new FakeQuery(this[table]);
  }

  async patch(rowId: string, patch: Record<string, unknown>) {
    const row = this.allRows().find((candidate) => candidate._id === rowId);
    if (!row) throw new Error(`missing fake row ${rowId}`);
    Object.assign(row, patch);
  }

  async delete(rowId: string) {
    for (const rows of [
      this.challenges,
      this.folders,
      this.notes,
      this.sessions,
      this.vaults,
      this.vaultUsage,
    ]) {
      const index = rows.findIndex((row) => row._id === rowId);
      if (index >= 0) {
        rows.splice(index, 1);
        return;
      }
    }
    throw new Error(`missing fake row ${rowId}`);
  }

  private allRows() {
    return [
      ...this.challenges,
      ...this.folders,
      ...this.notes,
      ...this.sessions,
      ...this.vaults,
      ...this.vaultUsage,
    ];
  }
}

async function deleteCloudCopyDeletesUsageLedger() {
  const originalMode = process.env.CONVEX_AUTH_ATTESTATION_MODE;
  process.env.CONVEX_AUTH_ATTESTATION_MODE = "observe";
  const db = new FakeDeleteCloudCopyDb();
  const ctx = { db } as unknown as MutationCtx;

  try {
    const { logs, result } = await captureConsoleLogs(() =>
      deleteVaultCloudCopyBatch(ctx, { sessionToken: SESSION_TOKEN }),
    );

    assert.deepEqual(result, { done: true });
    assert.equal(db.notes.length, 0);
    assert.equal(db.folders.length, 0);
    assert.equal(db.vaultUsage.length, 0);
    assert.equal(db.vaults.length, 0);
    assert.equal(db.sessions.length, 0);
    assert.deepEqual(logs, [["convex_cloud_copy_deleted", { mode: "observe" }]]);
    assertLogsDoNotExposeVaultIdentifiers(logs, ["vault-1"]);
  } finally {
    if (originalMode === undefined) {
      delete process.env.CONVEX_AUTH_ATTESTATION_MODE;
    } else {
      process.env.CONVEX_AUTH_ATTESTATION_MODE = originalMode;
    }
  }
}

attestedChallengeHandoffDropsVerifierSecrets();
authPolicyNamesRateLimitKeys();
authPolicyDecidesAttestationModes();
authPolicyDefaultsToRequired();
await backendKeyChallengeRequiresExistingVault();
await backendKeyChallengeAcceptsExistingVaultMetadata();
await backendKeyChallengeRejectsStoredMetadataMismatch();
await oldV1ShapedChallengeDataIsRejected();
await attestedNewVaultCreationWorksWithV2Metadata();
await attestedExistingVaultRejectsIdentityHashMismatch();
await missingMetadataHashSecretFailsForAttestedVaultPersistence();
backendAuthSignatureMatchesRustCanonicalChallengeOrder();
await sessionValidationChecksKeyIdAndVersion();
await cloudReplicaDiscoveryReturnsEmptyWithoutWritingRows();
await cloudReplicaDiscoveryReturnsLiveCountsWithoutWritingRows();
await cloudReplicaDiscoveryRejectsInvalidSignature();
await cloudReplicaDiscoveryRejectsStoredMetadataMismatch();
await deleteCloudCopyDeletesUsageLedger();

console.log("convex auth lifecycle tests passed");

function activeVaultRow(overrides: Record<string, unknown> = {}) {
  return {
    _id: "vault-row-1",
    backendAuthAlgorithm: BACKEND_AUTH_ALGORITHM,
    backendAuthKeyId: BACKEND_AUTH_KEY_ID,
    backendAuthPublicKey: BACKEND_AUTH_PUBLIC_KEY,
    backendAuthKeyVersion: BACKEND_AUTH_KEY_VERSION,
    createdAtMs: 0,
    updatedAtMs: 0,
    vaultId: request.vaultId,
    ...overrides,
  };
}

function activeSessionRow(overrides: Record<string, unknown> = {}) {
  return {
    _id: "session-1",
    backendAuthAlgorithm: BACKEND_AUTH_ALGORITHM,
    backendAuthKeyId: BACKEND_AUTH_KEY_ID,
    backendAuthPublicKey: BACKEND_AUTH_PUBLIC_KEY,
    backendAuthKeyVersion: BACKEND_AUTH_KEY_VERSION,
    createdAtMs: 0,
    expiresAtMs: Number.MAX_SAFE_INTEGER,
    lastSeenAtMs: 0,
    sessionTokenHash: sessionTokenHash(SESSION_TOKEN),
    vaultId: request.vaultId,
    ...overrides,
  };
}

function discoveryChallenge(overrides: Partial<ChallengeResponse> = {}): ChallengeResponse {
  return {
    appEncryptionRequestId: request.appEncryptionRequestId,
    appIdentityIAddress: request.appIdentityIAddress,
    backendAuthAlgorithm: BACKEND_AUTH_ALGORITHM,
    backendAuthKeyId: BACKEND_AUTH_KEY_ID,
    backendAuthKeyVersion: BACKEND_AUTH_KEY_VERSION,
    backendAuthPublicKey: BACKEND_AUTH_PUBLIC_KEY,
    challenge: "verus_notes_discovery_challenge",
    derivationNumber: request.derivationNumber,
    expiresAtMs: Date.now() + 60_000,
    sessionId: "verus_notes_discovery_session",
    vaultId: request.vaultId,
    walletSignerIdentityIAddress: request.walletSignerIdentityIAddress,
    ...overrides,
  };
}

function liveCloudRow(_id: string) {
  return {
    _id,
    ciphertext: "ciphertext",
    cloudState: "live",
    nonce: "nonce",
    vaultId: request.vaultId,
  };
}

async function withAttestationMode<T>(mode: string, run: () => Promise<T>) {
  const originalMode = process.env.CONVEX_AUTH_ATTESTATION_MODE;
  process.env.CONVEX_AUTH_ATTESTATION_MODE = mode;

  try {
    return await run();
  } finally {
    if (originalMode === undefined) {
      delete process.env.CONVEX_AUTH_ATTESTATION_MODE;
    } else {
      process.env.CONVEX_AUTH_ATTESTATION_MODE = originalMode;
    }
  }
}

function signRustCanonicalChallenge(challenge: ChallengeResponse) {
  return encodeBase64Url(ed25519.sign(rustCanonicalChallengeBytes(challenge), BACKEND_AUTH_SEED));
}

function rustCanonicalChallengeBytes(challenge: ChallengeResponse) {
  return utf8Bytes(
    JSON.stringify({
      appEncryptionRequestID: challenge.appEncryptionRequestId,
      appIdentityIAddress: challenge.appIdentityIAddress,
      backendAuthAlgorithm: challenge.backendAuthAlgorithm,
      backendAuthKeyId: challenge.backendAuthKeyId,
      backendAuthKeyVersion: challenge.backendAuthKeyVersion,
      backendAuthPublicKey: challenge.backendAuthPublicKey,
      challenge: challenge.challenge,
      derivationNumber: challenge.derivationNumber,
      expiresAtMs: challenge.expiresAtMs,
      protocol: "verus-notes.backend-auth.challenge.v2",
      sessionId: challenge.sessionId,
      vaultId: challenge.vaultId,
      walletSignerIdentityIAddress: challenge.walletSignerIdentityIAddress,
    }),
  );
}

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
