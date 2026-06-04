import { ATTESTATION_PROTOCOL } from "./authPolicy";
import { BACKEND_AUTH_ATTESTATION_BINDING_STRENGTH } from "./backendAuth";

export type SignerAttestationVerificationRequest = {
  appEncryptionRequestId: string;
  appIdentityIAddress: string;
  backendAuthAlgorithm: string;
  backendAuthKeyId: string;
  backendAuthPublicKey: string;
  backendAuthKeyVersion: number;
  chain: string;
  cloudAttestationId: string;
  cloudAttestationSecret: string;
  convexChallengeSessionId: string;
  derivationNumber: number;
  requestHashHex: string;
  signerSessionId: string;
  vaultId: string;
  walletSignerIdentityIAddress: string;
};

export type VerifiedSignerAttestation = {
  expiresAtMs?: number;
  issuedAtMs?: number;
};

export async function verifySignerAttestation(
  input: SignerAttestationVerificationRequest,
): Promise<VerifiedSignerAttestation> {
  const signerBaseUrl = process.env.CONVEX_ATTESTATION_SIGNER_URL?.replace(/\/+$/g, "");
  if (!signerBaseUrl) {
    throw new Error("signer attestation verifier is not configured");
  }

  const headers: Record<string, string> = {
    Accept: "application/json",
    "Content-Type": "application/json",
  };
  const edgeSecret = process.env.CONVEX_ATTESTATION_EDGE_SECRET;
  if (edgeSecret) headers["x-verus-notes-edge-secret"] = edgeSecret;

  const response = await fetch(`${signerBaseUrl}/cloud-attestations/verify`, {
    method: "POST",
    headers,
    body: JSON.stringify(input),
  });

  if (!response.ok) {
    throw new Error(`signer attestation rejected: ${response.status}`);
  }

  const body = (await response.json()) as {
    bindingStrength?: string;
    backendAuthAlgorithm?: string;
    backendAuthKeyId?: string;
    backendAuthPublicKey?: string;
    backendAuthKeyVersion?: number;
    expiresAtMs?: number;
    issuedAtMs?: number;
    protocol?: string;
    verified?: boolean;
  };

  if (
    body.verified !== true ||
    body.protocol !== ATTESTATION_PROTOCOL ||
    body.bindingStrength !== BACKEND_AUTH_ATTESTATION_BINDING_STRENGTH ||
    body.backendAuthAlgorithm !== input.backendAuthAlgorithm ||
    body.backendAuthKeyId !== input.backendAuthKeyId ||
    body.backendAuthPublicKey !== input.backendAuthPublicKey ||
    body.backendAuthKeyVersion !== input.backendAuthKeyVersion
  ) {
    throw new Error("signer attestation verifier returned an invalid response");
  }

  return body;
}
