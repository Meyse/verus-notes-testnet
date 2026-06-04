import assert from "node:assert/strict";

import {
  createCloudReplicaDiscoveryProof,
  createCloudSession,
  type CloudAuthSessionContext,
  type CloudAuthSessionDependencies,
} from "../src/lib/notes/cloudAuthSession";
import type { CloudAuthAttestation, CloudChallenge, CloudSession } from "../src/lib/notes/types";

type Call = {
  input?: unknown;
  name: string;
};

const context: CloudAuthSessionContext = {
  unlockInput: {
    appEncryptionRequestId: "request-1",
    appIdentityIAddress: "i-app",
    chain: "VRSCTEST",
    derivationNumber: 1,
    keyVersion: 1,
    walletSignerIdentityIAddress: "i-wallet",
    walletSignerIdentityName: "Wallet",
  },
  vault: {
    backendAuthAlgorithm: "ed25519-v1",
    backendAuthKeyId: "backend-key-id",
    backendAuthPublicKey: "backend-key",
    backendAuthKeyVersion: 1,
    exportCheckHash: "export-check",
    vaultId: "vault-1",
    walletSignerIdentityIAddress: "i-wallet",
    walletSignerIdentityName: "Wallet",
  },
};

const challenge: CloudChallenge = {
  appEncryptionRequestId: "request-1",
  appIdentityIAddress: "i-app",
  backendAuthAlgorithm: "ed25519-v1",
  backendAuthKeyId: "backend-key-id",
  backendAuthPublicKey: "backend-key",
  backendAuthKeyVersion: 1,
  challenge: "challenge-1",
  derivationNumber: 1,
  expiresAtMs: 1_779_720_000_000,
  sessionId: "challenge-session-1",
  vaultId: "vault-1",
  walletSignerIdentityIAddress: "i-wallet",
};

const session: CloudSession = {
  authStrength: "signer_attested",
  expiresAtMs: 1_779_720_100_000,
  sessionToken: "session-token",
  vaultId: "vault-1",
};

const readyAttestation: Extract<CloudAuthAttestation, { status: "ready" }> = {
  status: "ready",
  cloudAttestationExpiresAt: 1_779_720_000_000,
  cloudAttestationId: "cloud-attestation-id",
  cloudAttestationSecret: "cloud-attestation-secret",
  requestHashHex: "request-hash",
  signerSessionId: "signer-session-1",
  unlockContext: context.unlockInput,
  vault: context.vault,
};

function makeDependencies(
  calls: Call[],
  overrides: Partial<CloudAuthSessionDependencies> = {},
): CloudAuthSessionDependencies {
  return {
    async completeChallenge(input) {
      calls.push({ input, name: "completeChallenge" });
      return session;
    },
    async createAttestedChallenge(input) {
      calls.push({ input, name: "createAttestedChallenge" });
      return challenge;
    },
    async getCloudAuthAttestation(vaultId) {
      calls.push({ input: vaultId, name: "getCloudAuthAttestation" });
      return readyAttestation;
    },
    async signBackendChallenge(input) {
      calls.push({ input, name: "signBackendChallenge" });
      return "backend-signature";
    },
    ...overrides,
  };
}

async function signerAttestedHappyPath() {
  const calls: Call[] = [];

  const result = await createCloudSession(makeDependencies(calls), context);

  assert.deepEqual(result, session);
  assert.deepEqual(calls.map((call) => call.name), [
    "getCloudAuthAttestation",
    "createAttestedChallenge",
    "signBackendChallenge",
    "completeChallenge",
  ]);

  assert.deepEqual(calls[1].input, {
    appEncryptionRequestId: "request-1",
    appIdentityIAddress: "i-app",
    backendAuthAlgorithm: "ed25519-v1",
    backendAuthKeyId: "backend-key-id",
    backendAuthPublicKey: "backend-key",
    backendAuthKeyVersion: 1,
    chain: "VRSCTEST",
    cloudAttestationExpiresAt: 1_779_720_000_000,
    cloudAttestationId: "cloud-attestation-id",
    cloudAttestationSecret: "cloud-attestation-secret",
    derivationNumber: 1,
    requestHashHex: "request-hash",
    signerSessionId: "signer-session-1",
    vaultId: "vault-1",
    walletSignerIdentityIAddress: "i-wallet",
  });
  assert.deepEqual(calls[2].input, challenge);
  assert.deepEqual(calls[3].input, {
    sessionId: "challenge-session-1",
    signature: "backend-signature",
  });
  assert(!JSON.stringify(calls[3].input).includes("cloud-attestation-secret"));
}

async function walletUnlockRequiredStopsBeforeConvex() {
  const calls: Call[] = [];

  await assert.rejects(
    () =>
      createCloudSession(
        makeDependencies(calls, {
          async getCloudAuthAttestation(vaultId) {
            calls.push({ input: vaultId, name: "getCloudAuthAttestation" });
            return { reason: "wallet_unlock_required", status: "wallet_unlock_required" };
          },
        }),
        context,
      ),
    /Wallet unlock required to enable encrypted sync/,
  );

  assert.deepEqual(calls.map((call) => call.name), ["getCloudAuthAttestation"]);
}

async function verifierUnconfiguredFailsClosed() {
  const calls: Call[] = [];

  await assert.rejects(
    () =>
      createCloudSession(
        makeDependencies(calls, {
          async createAttestedChallenge(input) {
            calls.push({ input, name: "createAttestedChallenge" });
            throw new Error("signer attestation verifier is not configured");
          },
        }),
        context,
      ),
    /signer attestation verifier is not configured/,
  );

  assert.deepEqual(calls.map((call) => call.name), [
    "getCloudAuthAttestation",
    "createAttestedChallenge",
  ]);
}

async function signerAttestationErrorsDoNotDowngrade() {
  const calls: Call[] = [];

  await assert.rejects(
    () =>
      createCloudSession(
        makeDependencies(calls, {
          async createAttestedChallenge(input) {
            calls.push({ input, name: "createAttestedChallenge" });
            throw new Error("signer attestation rejected: 403");
          },
        }),
        context,
      ),
    /signer attestation rejected: 403/,
  );

  assert.deepEqual(calls.map((call) => call.name), [
    "getCloudAuthAttestation",
    "createAttestedChallenge",
  ]);
}

async function discoveryProofDoesNotCreateCloudSession() {
  const calls: Call[] = [];

  const proof = await createCloudReplicaDiscoveryProof(makeDependencies(calls), context, 1_779_720_000_000);

  assert.deepEqual(calls.map((call) => call.name), ["signBackendChallenge"]);
  assert.deepEqual(calls[0].input, proof.challenge);
  assert.equal(proof.signature, "backend-signature");
  assert.equal(proof.challenge.appEncryptionRequestId, "request-1");
  assert.equal(proof.challenge.backendAuthKeyId, "backend-key-id");
  assert.equal(proof.challenge.expiresAtMs, 1_779_720_300_000);
  assert(proof.challenge.challenge.startsWith("verus_notes_discovery_"));
  assert(proof.challenge.sessionId.startsWith("verus_notes_discovery_"));
}

await signerAttestedHappyPath();
await walletUnlockRequiredStopsBeforeConvex();
await verifierUnconfiguredFailsClosed();
await signerAttestationErrorsDoNotDowngrade();
await discoveryProofDoesNotCreateCloudSession();

console.log("cloud auth session tests passed");
