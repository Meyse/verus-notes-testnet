import { v } from "convex/values";

import { internal } from "./_generated/api";
import { action, internalMutation, mutation, query } from "./_generated/server";
import {
  cleanupExpiredAuthRows as cleanupExpiredAuthRowsLifecycle,
  cleanupExpiredMetadataRows as cleanupExpiredMetadataRowsLifecycle,
  completeBackendAuthChallenge,
  createBackendKeyChallenge,
  createChallengeFromVerifiedAttestation as createChallengeFromVerifiedAttestationLifecycle,
  deleteVaultCloudCopyBatch,
  discoverCloudReplica as discoverCloudReplicaLifecycle,
  newChallengeMaterial,
  verifiedAttestedChallengeFromSigner,
  type ChallengeResponse,
} from "./lib/authLifecycle";
import { verifySignerAttestation } from "./lib/signerAttestation";

const internalApi = internal as any;

const challengeArgs = {
  appEncryptionRequestId: v.string(),
  appIdentityIAddress: v.string(),
  backendAuthAlgorithm: v.string(),
  backendAuthKeyId: v.string(),
  backendAuthPublicKey: v.string(),
  backendAuthKeyVersion: v.number(),
  chain: v.string(),
  derivationNumber: v.number(),
  vaultId: v.string(),
  walletSignerIdentityIAddress: v.string(),
};

const attestationArgs = {
  ...challengeArgs,
  cloudAttestationId: v.string(),
  cloudAttestationSecret: v.string(),
  cloudAttestationExpiresAt: v.number(),
  requestHashHex: v.string(),
  signerSessionId: v.string(),
};

const verifiedAttestedChallengeArgs = {
  ...challengeArgs,
  attestationIdHash: v.string(),
  attestedAtMs: v.number(),
  challenge: v.string(),
  expiresAtMs: v.number(),
  sessionId: v.string(),
  signerSessionIdHash: v.string(),
  walletUnlockFreshUntilMs: v.number(),
};

export const createChallenge = mutation({
  args: challengeArgs,
  handler: async (ctx, args) => {
    return await createBackendKeyChallenge(ctx, args);
  },
});

export const createAttestedChallenge = action({
  args: attestationArgs,
  handler: async (ctx, args): Promise<ChallengeResponse> => {
    const now = Date.now();
    const material = newChallengeMaterial(now);
    const signerAttestation = await verifySignerAttestation({
      appEncryptionRequestId: args.appEncryptionRequestId,
      appIdentityIAddress: args.appIdentityIAddress,
      backendAuthAlgorithm: args.backendAuthAlgorithm,
      backendAuthKeyId: args.backendAuthKeyId,
      backendAuthPublicKey: args.backendAuthPublicKey,
      backendAuthKeyVersion: args.backendAuthKeyVersion,
      chain: args.chain,
      cloudAttestationId: args.cloudAttestationId,
      cloudAttestationSecret: args.cloudAttestationSecret,
      convexChallengeSessionId: material.sessionId,
      derivationNumber: args.derivationNumber,
      requestHashHex: args.requestHashHex,
      signerSessionId: args.signerSessionId,
      vaultId: args.vaultId,
      walletSignerIdentityIAddress: args.walletSignerIdentityIAddress,
    });
    const verifiedChallenge = verifiedAttestedChallengeFromSigner({
      material,
      now,
      request: args,
      signerAttestation,
    });

    return await ctx.runMutation(
      internalApi.auth.createChallengeFromVerifiedAttestation,
      verifiedChallenge,
    );
  },
});

export const createChallengeFromVerifiedAttestation = internalMutation({
  args: verifiedAttestedChallengeArgs,
  handler: async (ctx, args) => {
    return await createChallengeFromVerifiedAttestationLifecycle(ctx, args);
  },
});

export const completeChallenge = mutation({
  args: {
    sessionId: v.string(),
    signature: v.string(),
  },
  handler: async (ctx, args) => {
    return await completeBackendAuthChallenge(ctx, args);
  },
});

export const deleteCloudCopy = mutation({
  args: {
    sessionToken: v.string(),
  },
  handler: async (ctx, args) => {
    return await deleteVaultCloudCopyBatch(ctx, args);
  },
});

export const discoverCloudReplica = query({
  args: {
    challenge: v.object({
      appEncryptionRequestId: v.string(),
      appIdentityIAddress: v.string(),
      backendAuthAlgorithm: v.string(),
      backendAuthKeyId: v.string(),
      backendAuthPublicKey: v.string(),
      backendAuthKeyVersion: v.number(),
      challenge: v.string(),
      derivationNumber: v.number(),
      expiresAtMs: v.number(),
      sessionId: v.string(),
      vaultId: v.string(),
      walletSignerIdentityIAddress: v.string(),
    }),
    signature: v.string(),
  },
  handler: async (ctx, args) => {
    return await discoverCloudReplicaLifecycle(ctx, {
      ...args.challenge,
      signature: args.signature,
    });
  },
});

export const cleanupExpiredAuthRows = mutation({
  args: {
    batchSize: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    return await cleanupExpiredAuthRowsLifecycle(ctx, args.batchSize);
  },
});

export const cleanupExpiredMetadataRows = internalMutation({
  args: {
    batchSize: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const result = await cleanupExpiredMetadataRowsLifecycle(ctx, args.batchSize);
    const batchSize = args.batchSize ?? 128;
    if (
      result.challenges + result.sessions + result.rateLimits +
        result.expiredRecordFolders + result.expiredRecordNotes >=
      batchSize
    ) {
      await ctx.scheduler.runAfter(0, internalApi.auth.cleanupExpiredMetadataRows, {
        batchSize,
      });
    }
    return result;
  },
});
