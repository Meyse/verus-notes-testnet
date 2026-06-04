import type { Doc } from "../_generated/dataModel";
import type { MutationCtx, QueryCtx } from "../_generated/server";
import {
  ATTESTATION_PROTOCOL,
  CHALLENGE_CREATE_LIMIT,
  CHALLENGE_CREATE_WINDOW_MS,
  CHALLENGE_TTL_MS,
  CLEANUP_BATCH_SIZE,
  SESSION_TTL_MS,
  VAULT_CREATE_LIMIT,
  VAULT_CREATE_WINDOW_MS,
  WALLET_UNLOCK_FRESHNESS_MS,
  challengeBackendKeyRateLimitKey,
  challengeVaultRateLimitKey,
  readAuthAttestationMode,
  shouldRequireAttestationForNewChallenge,
  shouldRequireFreshAttestationForCloudDelete,
  vaultCreateRateLimitKey,
} from "./authPolicy";
import {
  consumeRateLimit,
  hashOperationalIdentifier,
  newSessionToken,
  requireSession,
  sessionTokenHash,
  validateBackendAuthMetadata,
  verifyBackendAuthSignature,
  type AuthStrength,
  type BackendAuthChallenge,
} from "./backendAuth";
import { randomBase64Url } from "./encoding";
import { cleanupExpiredEncryptedRecordMarkers, isLiveCloudRecord } from "./encryptedRecords";
import { metadataHash } from "./privacyMetadata";
import type { VerifiedSignerAttestation } from "./signerAttestation";

export type ChallengeRequest = {
  appEncryptionRequestId: string;
  appIdentityIAddress: string;
  backendAuthAlgorithm: string;
  backendAuthKeyId: string;
  backendAuthPublicKey: string;
  backendAuthKeyVersion: number;
  chain: string;
  derivationNumber: number;
  vaultId: string;
  walletSignerIdentityIAddress: string;
};

export type AttestedChallengeRequest = ChallengeRequest & {
  cloudAttestationExpiresAt: number;
  cloudAttestationId: string;
  cloudAttestationSecret: string;
  requestHashHex: string;
  signerSessionId: string;
};

export type ChallengeResponse = {
  appEncryptionRequestId: string;
  appIdentityIAddress: string;
  backendAuthAlgorithm: string;
  backendAuthKeyId: string;
  backendAuthPublicKey: string;
  backendAuthKeyVersion: number;
  challenge: string;
  derivationNumber: number;
  expiresAtMs: number;
  sessionId: string;
  vaultId: string;
  walletSignerIdentityIAddress: string;
};

export type ChallengeMaterial = {
  challenge: string;
  expiresAtMs: number;
  sessionId: string;
};

export type CloudReplicaDiscoveryInput = BackendAuthChallenge & {
  signature: string;
};

export type CloudReplicaDiscoveryResult = {
  liveFolderCount: number;
  liveNoteCount: number;
  status: "empty" | "found";
};

export type VerifiedAttestedChallenge = ChallengeRequest &
  ChallengeMaterial & {
    attestationIdHash: string;
    attestedAtMs: number;
    signerSessionIdHash: string;
    walletUnlockFreshUntilMs: number;
  };

type CompleteChallengeInput = {
  sessionId: string;
  signature: string;
};

type DeleteCloudCopyInput = {
  sessionToken: string;
};

type PersistedChallengeInput = ChallengeRequest &
  ChallengeMaterial & {
    attestationIdHash?: string;
    attestationProtocol?: string;
    attestedAtMs?: number;
    authStrength: AuthStrength;
    createdAtMs: number;
    signerSessionIdHash?: string;
    walletUnlockFreshUntilMs?: number;
  };

const DISCOVERY_PROOF_MAX_TTL_MS = 10 * 60_000;

export async function createBackendKeyChallenge(
  ctx: MutationCtx,
  request: ChallengeRequest,
): Promise<ChallengeResponse> {
  const now = Date.now();
  await cleanupExpiredAuthRowsBatch(ctx, now, 32);
  const existingVault = await validateChallengeRequest(ctx, request, now);
  const mode = readAuthAttestationMode();

  if (!existingVault || shouldRequireAttestationForNewChallenge({ mode, existingVault })) {
    throw new Error("signer_attestation_required");
  }

  await consumeChallengeRateLimits(ctx, request.vaultId, request.backendAuthKeyId, now);
  console.log("convex_auth_challenge_created", {
    authStrength: "backend_key",
    mode,
    existingVault: existingVault !== null,
  });

  return await insertChallenge(ctx, {
    ...request,
    ...newChallengeMaterial(now),
    authStrength: "backend_key",
    createdAtMs: now,
  });
}

export function newChallengeMaterial(now: number): ChallengeMaterial {
  return {
    challenge: randomBase64Url(32),
    expiresAtMs: now + CHALLENGE_TTL_MS,
    sessionId: `verus_notes_chal_${randomBase64Url(16)}`,
  };
}

export function verifiedAttestedChallengeFromSigner(input: {
  material: ChallengeMaterial;
  now: number;
  request: AttestedChallengeRequest;
  signerAttestation: VerifiedSignerAttestation;
}): VerifiedAttestedChallenge {
  const { material, now, request, signerAttestation } = input;

  return {
    appEncryptionRequestId: request.appEncryptionRequestId,
    appIdentityIAddress: request.appIdentityIAddress,
    attestedAtMs: signerAttestation.issuedAtMs ?? now,
    backendAuthAlgorithm: request.backendAuthAlgorithm,
    backendAuthKeyId: request.backendAuthKeyId,
    backendAuthPublicKey: request.backendAuthPublicKey,
    backendAuthKeyVersion: request.backendAuthKeyVersion,
    chain: request.chain,
    challenge: material.challenge,
    derivationNumber: request.derivationNumber,
    expiresAtMs: material.expiresAtMs,
    sessionId: material.sessionId,
    signerSessionIdHash: hashOperationalIdentifier("signer-session-id", request.signerSessionId),
    attestationIdHash: hashOperationalIdentifier("cloud-attestation-id", request.cloudAttestationId),
    vaultId: request.vaultId,
    walletSignerIdentityIAddress: request.walletSignerIdentityIAddress,
    walletUnlockFreshUntilMs: Math.min(
      signerAttestation.expiresAtMs ?? request.cloudAttestationExpiresAt,
      now + WALLET_UNLOCK_FRESHNESS_MS,
    ),
  };
}

export async function createChallengeFromVerifiedAttestation(
  ctx: MutationCtx,
  challenge: VerifiedAttestedChallenge,
): Promise<ChallengeResponse> {
  const now = Date.now();
  await cleanupExpiredAuthRowsBatch(ctx, now, 32);
  await validateChallengeRequest(ctx, challenge, now);
  await consumeChallengeRateLimits(ctx, challenge.vaultId, challenge.backendAuthKeyId, now);

  console.log("convex_auth_challenge_created", {
    authStrength: "signer_attested",
    mode: readAuthAttestationMode(),
  });

  return await insertChallenge(ctx, {
    ...challenge,
    authStrength: "signer_attested",
    attestationProtocol: ATTESTATION_PROTOCOL,
    createdAtMs: now,
  });
}

export async function completeBackendAuthChallenge(
  ctx: MutationCtx,
  input: CompleteChallengeInput,
) {
  const challengeDoc = await ctx.db
    .query("challenges")
    .withIndex("by_session_id", (q) => q.eq("sessionId", input.sessionId))
    .unique();
  const now = Date.now();

  if (!challengeDoc || challengeDoc.usedAtMs !== undefined || challengeDoc.expiresAtMs <= now) {
    throw new Error("challenge expired or invalid");
  }

  const challenge = backendAuthChallengeFromDoc(challengeDoc);

  if (!verifyBackendAuthSignature(challenge, challengeDoc.backendAuthPublicKey, input.signature)) {
    console.log("convex_auth_challenge_failed", {
      reason: "bad_signature",
    });
    throw new Error("backend auth signature verification failed");
  }

  const existingVault = await getVaultUnlessDeleting(ctx, challengeDoc.vaultId);

  if (existingVault) {
    validateStoredBackendAuthMetadata(existingVault, challengeDoc);
  }

  const authStrength = (challengeDoc.authStrength ?? "backend_key") as AuthStrength;
  const attestedChallenge =
    authStrength === "signer_attested" ? requireAttestedChallengeMetadata(challengeDoc) : null;
  if (attestedChallenge) validatePinnedWalletMetadata(existingVault, attestedChallenge);

	if (existingVault) {
	  await ctx.db.patch(existingVault._id, {
	    ...(attestedChallenge ? attestedVaultPatch(attestedChallenge) : {}),
	    updatedAtMs: now,
	  });
  } else {
    if (!attestedChallenge) {
      throw new Error("signer_attestation_required");
    }
    await consumeRateLimit(
      ctx,
      vaultCreateRateLimitKey(challengeDoc.backendAuthKeyId),
      VAULT_CREATE_LIMIT,
      VAULT_CREATE_WINDOW_MS,
      now,
    );
    await ctx.db.insert("vaults", {
      vaultId: challengeDoc.vaultId,
      backendAuthAlgorithm: challengeDoc.backendAuthAlgorithm,
      backendAuthKeyId: challengeDoc.backendAuthKeyId,
	      backendAuthPublicKey: challengeDoc.backendAuthPublicKey,
	      backendAuthKeyVersion: challengeDoc.backendAuthKeyVersion,
	      authStrength,
	      ...(attestedChallenge ? attestedVaultPatch(attestedChallenge) : {}),
	      createdAtMs: now,
	      updatedAtMs: now,
	    });
    console.log("convex_vault_created", { authStrength });
  }

  const sessionToken = newSessionToken();
  const expiresAtMs = now + SESSION_TTL_MS;

  await ctx.db.patch(challengeDoc._id, { usedAtMs: now });
  await ctx.db.insert("sessions", {
    sessionTokenHash: sessionTokenHash(sessionToken),
    vaultId: challengeDoc.vaultId,
    backendAuthAlgorithm: challengeDoc.backendAuthAlgorithm,
    backendAuthKeyId: challengeDoc.backendAuthKeyId,
    backendAuthPublicKey: challengeDoc.backendAuthPublicKey,
    backendAuthKeyVersion: challengeDoc.backendAuthKeyVersion,
    authStrength,
    attestationProtocol: challengeDoc.attestationProtocol,
    attestedAtMs: challengeDoc.attestedAtMs,
    walletUnlockFreshUntilMs: challengeDoc.walletUnlockFreshUntilMs,
    requiresFreshAttestationForCloudDelete: authStrength !== "signer_attested",
    signerSessionIdHash: challengeDoc.signerSessionIdHash,
    attestationIdHash: challengeDoc.attestationIdHash,
    createdAtMs: now,
    expiresAtMs,
    lastSeenAtMs: now,
  });

  console.log("convex_session_created", { authStrength });

  return {
    authStrength,
    expiresAtMs,
    sessionToken,
    vaultId: challengeDoc.vaultId,
  };
}

export async function discoverCloudReplica(
  ctx: QueryCtx,
  input: CloudReplicaDiscoveryInput,
): Promise<CloudReplicaDiscoveryResult> {
  const now = Date.now();
  validateDiscoveryChallenge(input, now);
  validateBackendAuthMetadata(input);
  if (!verifyBackendAuthSignature(input, input.backendAuthPublicKey, input.signature)) {
    throw new Error("backend auth signature verification failed");
  }

  const vault = await ctx.db
    .query("vaults")
    .withIndex("by_vault_id", (q) => q.eq("vaultId", input.vaultId))
    .unique();
  if (!vault || vault.deletingAtMs !== undefined) {
    return { liveFolderCount: 0, liveNoteCount: 0, status: "empty" };
  }
  validateStoredBackendAuthMetadata(vault, input);

  const [noteRows, folderRows] = await Promise.all([
    ctx.db
      .query("notes")
      .withIndex("by_vault_updated", (q) => q.eq("vaultId", input.vaultId))
      .collect(),
    ctx.db
      .query("folders")
      .withIndex("by_vault_updated", (q) => q.eq("vaultId", input.vaultId))
      .collect(),
  ]);
  const liveNoteCount = noteRows.filter(isLiveCloudRecord).length;
  const liveFolderCount = folderRows.filter(isLiveCloudRecord).length;

  return {
    liveFolderCount,
    liveNoteCount,
    status: liveNoteCount > 0 || liveFolderCount > 0 ? "found" : "empty",
  };
}

export async function deleteVaultCloudCopyBatch(ctx: MutationCtx, input: DeleteCloudCopyInput) {
  const mode = readAuthAttestationMode();
  const session = await requireSession(ctx, input.sessionToken, {
    allowDeletingVault: true,
    allowMissingVault: true,
    requireFreshAttestation: shouldRequireFreshAttestationForCloudDelete(mode),
  });
  const vaultId = session.vaultId;
  const batchSize = 128;
  const now = Date.now();

  const vault = await ctx.db
    .query("vaults")
    .withIndex("by_vault_id", (q) => q.eq("vaultId", vaultId))
    .unique();
  if (vault && vault.deletingAtMs === undefined) {
    await ctx.db.patch(vault._id, { deletingAtMs: now, updatedAtMs: now });
  }

  const folders = await ctx.db
    .query("folders")
    .withIndex("by_vault_updated", (q) => q.eq("vaultId", vaultId))
    .take(batchSize);
  for (const folder of folders) {
    await ctx.db.delete(folder._id);
  }
  if (folders.length === batchSize) return { done: false };

  const notes = await ctx.db
    .query("notes")
    .withIndex("by_vault_updated", (q) => q.eq("vaultId", vaultId))
    .take(batchSize);
  for (const note of notes) {
    await ctx.db.delete(note._id);
  }
  if (notes.length === batchSize) return { done: false };

  const usageRows = await ctx.db
    .query("vaultUsage")
    .withIndex("by_vault_id", (q) => q.eq("vaultId", vaultId))
    .take(batchSize);
  for (const usage of usageRows) {
    await ctx.db.delete(usage._id);
  }
  if (usageRows.length === batchSize) return { done: false };

  const challenges = await ctx.db
    .query("challenges")
    .withIndex("by_vault_id", (q) => q.eq("vaultId", vaultId))
    .take(batchSize);
  for (const challenge of challenges) {
    await ctx.db.delete(challenge._id);
  }
  if (challenges.length === batchSize) return { done: false };

  const sessions = await ctx.db
    .query("sessions")
    .withIndex("by_vault_id", (q) => q.eq("vaultId", vaultId))
    .take(batchSize);
  for (const sessionRow of sessions) {
    if (sessionRow._id === session._id) continue;
    await ctx.db.delete(sessionRow._id);
  }
  if (sessions.length === batchSize) return { done: false };

  const vaultToDelete = await ctx.db
    .query("vaults")
    .withIndex("by_vault_id", (q) => q.eq("vaultId", vaultId))
    .unique();
  if (vaultToDelete) {
    await ctx.db.delete(vaultToDelete._id);
  }

  await ctx.db.delete(session._id);
  console.log("convex_cloud_copy_deleted", { mode });

  return { done: true };
}

export async function cleanupExpiredAuthRows(
  ctx: MutationCtx,
  batchSize = CLEANUP_BATCH_SIZE,
) {
  return await cleanupExpiredMetadataRowsBatch(ctx, Date.now(), Math.min(batchSize, CLEANUP_BATCH_SIZE));
}

export async function cleanupExpiredMetadataRows(
  ctx: MutationCtx,
  batchSize = CLEANUP_BATCH_SIZE,
) {
  return await cleanupExpiredMetadataRowsBatch(ctx, Date.now(), Math.min(batchSize, CLEANUP_BATCH_SIZE));
}

export async function cleanupExpiredMetadataRowsBatch(
  ctx: MutationCtx,
  now: number,
  batchSize: number,
) {
  const auth = await cleanupExpiredAuthRowsBatch(ctx, now, batchSize);
  const records = await cleanupExpiredEncryptedRecordMarkers(ctx, { batchSize, now });
  return {
    ...auth,
    expiredRecordFolders: records.folders,
    expiredRecordNotes: records.notes,
  };
}

export async function cleanupExpiredAuthRowsBatch(
  ctx: MutationCtx,
  now: number,
  batchSize: number,
) {
  const expiredChallenges = await ctx.db
    .query("challenges")
    .withIndex("by_expires_at")
    .filter((q) => q.lt(q.field("expiresAtMs"), now))
    .take(batchSize);
  for (const challenge of expiredChallenges) {
    await ctx.db.delete(challenge._id);
  }

  const expiredSessions = await ctx.db
    .query("sessions")
    .withIndex("by_expires_at")
    .filter((q) => q.lt(q.field("expiresAtMs"), now))
    .take(batchSize);
  for (const session of expiredSessions) {
    await ctx.db.delete(session._id);
  }

  const staleRateLimits = await ctx.db.query("rateLimits").take(batchSize);
  let deletedRateLimits = 0;
  for (const rateLimit of staleRateLimits) {
    if (now - rateLimit.updatedAtMs > VAULT_CREATE_WINDOW_MS) {
      await ctx.db.delete(rateLimit._id);
      deletedRateLimits += 1;
    }
  }

  const result = {
    challenges: expiredChallenges.length,
    rateLimits: deletedRateLimits,
    sessions: expiredSessions.length,
  };
  if (result.challenges || result.sessions || result.rateLimits) {
    console.log("convex_auth_cleanup", result);
  }
  return result;
}

async function validateChallengeRequest(
  ctx: MutationCtx,
  request: {
    backendAuthAlgorithm: string;
    backendAuthKeyId: string;
    backendAuthPublicKey: string;
    backendAuthKeyVersion: number;
    vaultId: string;
  },
  now: number,
) {
  validateBackendAuthMetadata(request);

  const existingVault = await getVaultUnlessDeleting(ctx, request.vaultId);
  if (!existingVault) return null;

  validateStoredBackendAuthMetadata(existingVault, request);

  if (existingVault.deletingAtMs !== undefined || existingVault.createdAtMs > now) {
    throw new Error("vault cloud copy is unavailable");
  }

  return existingVault;
}

async function consumeChallengeRateLimits(
  ctx: MutationCtx,
  vaultId: string,
  backendAuthKeyId: string,
  now: number,
) {
  await consumeRateLimit(
    ctx,
    challengeVaultRateLimitKey(vaultId),
    CHALLENGE_CREATE_LIMIT,
    CHALLENGE_CREATE_WINDOW_MS,
    now,
  );
  await consumeRateLimit(
    ctx,
    challengeBackendKeyRateLimitKey(backendAuthKeyId),
    CHALLENGE_CREATE_LIMIT,
    CHALLENGE_CREATE_WINDOW_MS,
    now,
  );
}

async function insertChallenge(
  ctx: MutationCtx,
  challenge: PersistedChallengeInput,
): Promise<ChallengeResponse> {
  await ctx.db.insert("challenges", {
    sessionId: challenge.sessionId,
    vaultId: challenge.vaultId,
    backendAuthAlgorithm: challenge.backendAuthAlgorithm,
    backendAuthKeyId: challenge.backendAuthKeyId,
    backendAuthPublicKey: challenge.backendAuthPublicKey,
    backendAuthKeyVersion: challenge.backendAuthKeyVersion,
    appEncryptionRequestId: challenge.appEncryptionRequestId,
    appIdentityIAddress: challenge.appIdentityIAddress,
    chain: challenge.chain,
    challenge: challenge.challenge,
    derivationNumber: challenge.derivationNumber,
    expiresAtMs: challenge.expiresAtMs,
    walletSignerIdentityIAddress: challenge.walletSignerIdentityIAddress,
    authStrength: challenge.authStrength,
    attestationProtocol: challenge.attestationProtocol,
    attestationIdHash: challenge.attestationIdHash,
    signerSessionIdHash: challenge.signerSessionIdHash,
    attestedAtMs: challenge.attestedAtMs,
    walletUnlockFreshUntilMs: challenge.walletUnlockFreshUntilMs,
    createdAtMs: challenge.createdAtMs,
  });

  return challengeResponse(challenge);
}

function challengeResponse(challenge: ChallengeRequest & ChallengeMaterial): ChallengeResponse {
  return {
    appEncryptionRequestId: challenge.appEncryptionRequestId,
    appIdentityIAddress: challenge.appIdentityIAddress,
    backendAuthAlgorithm: challenge.backendAuthAlgorithm,
    backendAuthKeyId: challenge.backendAuthKeyId,
    backendAuthPublicKey: challenge.backendAuthPublicKey,
    backendAuthKeyVersion: challenge.backendAuthKeyVersion,
    challenge: challenge.challenge,
    derivationNumber: challenge.derivationNumber,
    expiresAtMs: challenge.expiresAtMs,
    sessionId: challenge.sessionId,
    vaultId: challenge.vaultId,
    walletSignerIdentityIAddress: challenge.walletSignerIdentityIAddress,
  };
}

async function getVaultUnlessDeleting(ctx: MutationCtx, vaultId: string) {
  const vault = await ctx.db
    .query("vaults")
    .withIndex("by_vault_id", (q) => q.eq("vaultId", vaultId))
    .unique();

  if (vault?.deletingAtMs !== undefined) {
    throw new Error("vault cloud copy is being deleted");
  }

  return vault;
}

function backendAuthChallengeFromDoc(challengeDoc: Doc<"challenges">): BackendAuthChallenge {
  return {
    appEncryptionRequestId: challengeDoc.appEncryptionRequestId,
    appIdentityIAddress: challengeDoc.appIdentityIAddress,
    backendAuthAlgorithm: challengeDoc.backendAuthAlgorithm,
    backendAuthKeyId: challengeDoc.backendAuthKeyId,
    backendAuthPublicKey: challengeDoc.backendAuthPublicKey,
    backendAuthKeyVersion: challengeDoc.backendAuthKeyVersion,
    challenge: challengeDoc.challenge,
    derivationNumber: challengeDoc.derivationNumber,
    expiresAtMs: challengeDoc.expiresAtMs,
    sessionId: challengeDoc.sessionId,
    vaultId: challengeDoc.vaultId,
    walletSignerIdentityIAddress: challengeDoc.walletSignerIdentityIAddress,
  };
}

function validateStoredBackendAuthMetadata(
  stored: {
    backendAuthAlgorithm: string;
    backendAuthKeyId: string;
    backendAuthPublicKey: string;
    backendAuthKeyVersion: number;
  },
  request: {
    backendAuthAlgorithm: string;
    backendAuthKeyId: string;
    backendAuthPublicKey: string;
    backendAuthKeyVersion: number;
  },
) {
  if (
    stored.backendAuthAlgorithm !== request.backendAuthAlgorithm ||
    stored.backendAuthKeyId !== request.backendAuthKeyId ||
    stored.backendAuthPublicKey !== request.backendAuthPublicKey ||
    stored.backendAuthKeyVersion !== request.backendAuthKeyVersion
  ) {
    throw new Error("vault backend auth metadata mismatch");
  }
}

function validateDiscoveryChallenge(
  challenge: BackendAuthChallenge,
  now: number,
) {
  if (
    challenge.expiresAtMs <= now ||
    challenge.expiresAtMs > now + DISCOVERY_PROOF_MAX_TTL_MS ||
    !challenge.challenge.startsWith("verus_notes_discovery_") ||
    !challenge.sessionId.startsWith("verus_notes_discovery_")
  ) {
    throw new Error("discovery proof expired or invalid");
  }
}

function validatePinnedWalletMetadata(
  vault: Doc<"vaults"> | null,
  challenge: AttestedChallengeMetadata,
) {
  if (!vault) return;
  const expectedWalletSignerIdentityHash = metadataHash(
    "wallet-signer-identity",
    challenge.walletSignerIdentityIAddress,
  );
  const expectedAppIdentityHash = metadataHash("app-identity", challenge.appIdentityIAddress);

  const mismatched =
    (vault.walletSignerIdentityHash !== undefined &&
      vault.walletSignerIdentityHash !== expectedWalletSignerIdentityHash) ||
    (vault.appIdentityHash !== undefined && vault.appIdentityHash !== expectedAppIdentityHash) ||
    (vault.chain !== undefined && vault.chain !== challenge.chain) ||
    (vault.derivationNumber !== undefined && vault.derivationNumber !== challenge.derivationNumber);

  if (mismatched) {
    throw new Error("wallet identity metadata mismatch");
  }
}

type AttestedChallengeMetadata = {
  appIdentityIAddress: string;
  attestationProtocol?: string;
  authStrength?: string;
  chain: string;
  derivationNumber: number;
  walletSignerIdentityIAddress: string;
};

function requireAttestedChallengeMetadata(challenge: Doc<"challenges">): AttestedChallengeMetadata {
  if (!challenge.chain) {
    throw new Error("attested challenge is missing chain metadata");
  }

  return {
    appIdentityIAddress: challenge.appIdentityIAddress,
    attestationProtocol: challenge.attestationProtocol,
    authStrength: challenge.authStrength,
    chain: challenge.chain,
    derivationNumber: challenge.derivationNumber,
    walletSignerIdentityIAddress: challenge.walletSignerIdentityIAddress,
  };
}

function attestedVaultPatch(
  challenge: AttestedChallengeMetadata,
) {
  if (challenge.authStrength !== "signer_attested") return {};

  return {
    authStrength: "signer_attested" as const,
    attestationProtocol: challenge.attestationProtocol ?? ATTESTATION_PROTOCOL,
    walletSignerIdentityHash: metadataHash(
      "wallet-signer-identity",
      challenge.walletSignerIdentityIAddress,
    ),
    appIdentityHash: metadataHash("app-identity", challenge.appIdentityIAddress),
    chain: challenge.chain,
    derivationNumber: challenge.derivationNumber,
  };
}
