import { invoke } from "@tauri-apps/api/core";
import type { ConvexHttpClient } from "convex/browser";

import { api } from "../../../convex/_generated/api";
import type {
  CloudAuthAttestation,
  CloudChallenge,
  CloudSession,
  UnlockInput,
  UnlockOutput,
} from "./types";

export type CloudAuthSessionContext = {
  unlockInput: UnlockInput;
  vault: UnlockOutput;
};

type AttestedChallengeInput = {
  appEncryptionRequestId: string;
  appIdentityIAddress: string;
  backendAuthAlgorithm: string;
  backendAuthKeyId: string;
  backendAuthPublicKey: string;
  backendAuthKeyVersion: number;
  chain: string;
  cloudAttestationExpiresAt: number;
  cloudAttestationId: string;
  cloudAttestationSecret: string;
  derivationNumber: number;
  requestHashHex: string;
  signerSessionId: string;
  vaultId: string;
  walletSignerIdentityIAddress: string;
};

export type CloudAuthSessionDependencies = {
  completeChallenge(input: { sessionId: string; signature: string }): Promise<CloudSession>;
  createAttestedChallenge(input: AttestedChallengeInput): Promise<CloudChallenge>;
  getCloudAuthAttestation(vaultId: string): Promise<CloudAuthAttestation>;
  signBackendChallenge(challenge: CloudChallenge): Promise<string>;
};

export type CloudReplicaDiscoveryProof = {
  challenge: CloudChallenge;
  signature: string;
};

const DISCOVERY_PROOF_TTL_MS = 5 * 60_000;

export function createTauriConvexCloudAuthDependencies(
  client: ConvexHttpClient,
): CloudAuthSessionDependencies {
  return {
    async completeChallenge(input) {
      return (await client.mutation(api.auth.completeChallenge, input)) as CloudSession;
    },
    async createAttestedChallenge(input) {
      return (await client.action(api.auth.createAttestedChallenge, input)) as CloudChallenge;
    },
    async getCloudAuthAttestation(vaultId) {
      return await invoke<CloudAuthAttestation>("get_cloud_auth_attestation", {
        input: { vaultId },
      });
    },
    async signBackendChallenge(challenge) {
      return await invoke<string>("sign_backend_challenge", { challenge });
    },
  };
}

export async function createCloudSession(
  dependencies: CloudAuthSessionDependencies,
  context: CloudAuthSessionContext,
): Promise<CloudSession> {
  const challenge = await createCloudChallenge(dependencies, context);
  const signature = await dependencies.signBackendChallenge(challenge);

  return await dependencies.completeChallenge({
    sessionId: challenge.sessionId,
    signature,
  });
}

export async function createCloudReplicaDiscoveryProof(
  dependencies: Pick<CloudAuthSessionDependencies, "signBackendChallenge">,
  context: CloudAuthSessionContext,
  nowMs = Date.now(),
): Promise<CloudReplicaDiscoveryProof> {
  const challenge = cloudDiscoveryChallenge(context, nowMs);
  const signature = await dependencies.signBackendChallenge(challenge);
  return { challenge, signature };
}

async function createCloudChallenge(
  dependencies: CloudAuthSessionDependencies,
  context: CloudAuthSessionContext,
): Promise<CloudChallenge> {
  const attestation = await dependencies
    .getCloudAuthAttestation(context.vault.vaultId)
    .catch((error) => {
      throw new Error(toErrorMessage(error));
    });

  if (attestation.status === "wallet_unlock_required") {
    throw new Error("Wallet unlock required to enable encrypted sync");
  }

  return await dependencies.createAttestedChallenge(attestedChallengeInput(attestation));
}

function attestedChallengeInput(attestation: Extract<CloudAuthAttestation, { status: "ready" }>) {
  return {
    appEncryptionRequestId: attestation.unlockContext.appEncryptionRequestId,
    appIdentityIAddress: attestation.unlockContext.appIdentityIAddress,
    backendAuthAlgorithm: attestation.vault.backendAuthAlgorithm,
    backendAuthKeyId: attestation.vault.backendAuthKeyId,
    backendAuthPublicKey: attestation.vault.backendAuthPublicKey,
    backendAuthKeyVersion: attestation.vault.backendAuthKeyVersion,
    chain: attestation.unlockContext.chain,
    cloudAttestationExpiresAt: attestation.cloudAttestationExpiresAt,
    cloudAttestationId: attestation.cloudAttestationId,
    cloudAttestationSecret: attestation.cloudAttestationSecret,
    derivationNumber: attestation.unlockContext.derivationNumber,
    requestHashHex: attestation.requestHashHex,
    signerSessionId: attestation.signerSessionId,
    vaultId: attestation.vault.vaultId,
    walletSignerIdentityIAddress: attestation.unlockContext.walletSignerIdentityIAddress,
  };
}

function cloudDiscoveryChallenge(
  context: CloudAuthSessionContext,
  nowMs: number,
): CloudChallenge {
  const token = randomTokenHex();
  return {
    appEncryptionRequestId: context.unlockInput.appEncryptionRequestId,
    appIdentityIAddress: context.unlockInput.appIdentityIAddress,
    backendAuthAlgorithm: context.vault.backendAuthAlgorithm,
    backendAuthKeyId: context.vault.backendAuthKeyId,
    backendAuthPublicKey: context.vault.backendAuthPublicKey,
    backendAuthKeyVersion: context.vault.backendAuthKeyVersion,
    challenge: `verus_notes_discovery_${token}`,
    derivationNumber: context.unlockInput.derivationNumber,
    expiresAtMs: nowMs + DISCOVERY_PROOF_TTL_MS,
    sessionId: `verus_notes_discovery_${token}`,
    vaultId: context.vault.vaultId,
    walletSignerIdentityIAddress: context.unlockInput.walletSignerIdentityIAddress,
  };
}

function randomTokenHex() {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function toErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}
