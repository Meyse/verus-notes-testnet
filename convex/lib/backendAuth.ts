import { ed25519 } from "@noble/curves/ed25519.js";

import type { QueryCtx, MutationCtx } from "../_generated/server";
import { decodeBase64Url, encodeBase64Url, sha256Base64Url, sha256Hex, utf8Bytes } from "./encoding";

export type AuthStrength = "backend_key" | "signer_attested";
export const BACKEND_AUTH_ALGORITHM = "ed25519-v1";
export const BACKEND_AUTH_KEY_VERSION = 1;
export const BACKEND_AUTH_ATTESTATION_BINDING_STRENGTH = "client_asserted_backend_auth_v2";

export type BackendAuthChallenge = {
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

type RequireSessionOptions = {
  allowDeletingVault?: boolean;
  allowMissingVault?: boolean;
  requireFreshAttestation?: boolean;
};

export async function requireSession(
  ctx: QueryCtx | MutationCtx,
  sessionToken: string,
  options: RequireSessionOptions = {},
) {
  const tokenHash = sessionTokenHash(sessionToken);
  const session = await ctx.db
    .query("sessions")
    .withIndex("by_token_hash", (q) => q.eq("sessionTokenHash", tokenHash))
    .unique();

  const now = Date.now();

  if (!session || session.expiresAtMs <= now) {
    throw new Error("session expired or invalid");
  }

  const vault = await ctx.db
    .query("vaults")
    .withIndex("by_vault_id", (q) => q.eq("vaultId", session.vaultId))
    .unique();

  if (
    (!vault && !options.allowMissingVault) ||
    (vault && !options.allowDeletingVault && vault.deletingAtMs !== undefined) ||
    (vault && session.backendAuthAlgorithm !== vault.backendAuthAlgorithm) ||
    (vault && session.backendAuthKeyId !== vault.backendAuthKeyId) ||
    (vault && session.backendAuthPublicKey !== vault.backendAuthPublicKey) ||
    (vault && session.backendAuthKeyVersion !== vault.backendAuthKeyVersion) ||
    (vault && session.createdAtMs < vault.createdAtMs)
  ) {
    throw new Error("session expired or invalid");
  }

  if (options.requireFreshAttestation && !isFreshSignerAttestedSession(session, now)) {
    throw new Error("fresh_attestation_required");
  }

  return session;
}

export function verifyBackendAuthSignature(
  challenge: BackendAuthChallenge,
  backendAuthPublicKey: string,
  signature: string,
): boolean {
  validateBackendAuthMetadata({
    backendAuthAlgorithm: challenge.backendAuthAlgorithm,
    backendAuthKeyId: challenge.backendAuthKeyId,
    backendAuthPublicKey,
    backendAuthKeyVersion: challenge.backendAuthKeyVersion,
  });
  const publicKeyBytes = decodeBase64Url("backend auth public key", backendAuthPublicKey, 32);
  const signatureBytes = decodeBase64Url("backend auth signature", signature, 64);
  return ed25519.verify(signatureBytes, canonicalChallengeBytes(challenge), publicKeyBytes);
}

export function sessionTokenHash(sessionToken: string): string {
  return sha256Hex(utf8Bytes(`verus-notes/session-token/v1\0${sessionToken}`));
}

export function hashOperationalIdentifier(kind: string, value: string): string {
  return sha256Hex(utf8Bytes(`verus-notes/${kind}/v1\0${value}`));
}

export function backendAuthKeyIdFromPublicKey(input: {
  backendAuthAlgorithm: string;
  backendAuthKeyVersion: number;
  backendAuthPublicKey: string;
}): string {
  if (input.backendAuthAlgorithm !== BACKEND_AUTH_ALGORITHM) {
    throw new Error("backend auth algorithm is unsupported");
  }
  if (input.backendAuthKeyVersion !== BACKEND_AUTH_KEY_VERSION) {
    throw new Error("backend auth key version is unsupported");
  }
  const publicKeyBytes = decodeBase64Url("backend auth public key", input.backendAuthPublicKey, 32);
  if (publicKeyBytes.length !== 32) {
    throw new Error("backend auth public key must be 32 bytes");
  }
  return sha256Base64Url(
    utf8Bytes(
      JSON.stringify({
        algorithm: input.backendAuthAlgorithm,
        keyVersion: input.backendAuthKeyVersion,
        protocol: "verus-notes.backend-auth-key-id.v1",
        publicKey: input.backendAuthPublicKey,
      }),
    ),
  );
}

export function validateBackendAuthMetadata(input: {
  backendAuthAlgorithm: string;
  backendAuthKeyId: string;
  backendAuthPublicKey: string;
  backendAuthKeyVersion: number;
}) {
  const expectedKeyId = backendAuthKeyIdFromPublicKey(input);
  if (input.backendAuthKeyId !== expectedKeyId) {
    throw new Error("backend auth key ID mismatch");
  }
}

export function newSessionToken(): string {
  return `verus_notes_sess_${randomToken()}`;
}

export function isFreshSignerAttestedSession(
  session: { authStrength?: string; walletUnlockFreshUntilMs?: number },
  now: number,
) {
  return session.authStrength === "signer_attested" && (session.walletUnlockFreshUntilMs ?? 0) > now;
}

export async function consumeRateLimit(
  ctx: MutationCtx,
  key: string,
  limit: number,
  windowMs: number,
  now: number,
) {
  const existing = await ctx.db
    .query("rateLimits")
    .withIndex("by_key", (q) => q.eq("key", key))
    .unique();

  if (!existing || now - existing.windowStartedAtMs >= windowMs) {
    if (existing) {
      await ctx.db.patch(existing._id, {
        count: 1,
        windowStartedAtMs: now,
        updatedAtMs: now,
      });
    } else {
      await ctx.db.insert("rateLimits", {
        key,
        count: 1,
        windowStartedAtMs: now,
        updatedAtMs: now,
      });
    }
    return;
  }

  if (existing.count >= limit) {
    throw new Error("rate limit exceeded");
  }

  await ctx.db.patch(existing._id, {
    count: existing.count + 1,
    updatedAtMs: now,
  });
}

function randomToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return encodeBase64Url(bytes);
}

function canonicalChallengeBytes(challenge: BackendAuthChallenge): Uint8Array {
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
