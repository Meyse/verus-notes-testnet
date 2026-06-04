export const SESSION_TTL_MS = 2 * 60 * 60 * 1000;
export const CHALLENGE_TTL_MS = 5 * 60 * 1000;
export const WALLET_UNLOCK_FRESHNESS_MS = 10 * 60 * 1000;

export const CHALLENGE_CREATE_LIMIT = 12;
export const CHALLENGE_CREATE_WINDOW_MS = 5 * 60 * 1000;
export const VAULT_CREATE_LIMIT = 3;
export const VAULT_CREATE_WINDOW_MS = 60 * 60 * 1000;
export const CLEANUP_BATCH_SIZE = 128;
export const ATTESTATION_PROTOCOL = "verus-notes.signer-attestation.v1";

export type AuthAttestationMode = "off" | "observe" | "required_for_new_vaults" | "required";

export function readAuthAttestationMode(): AuthAttestationMode {
  const value = process.env.CONVEX_AUTH_ATTESTATION_MODE ?? "required";

  if (
    value === "off" ||
    value === "observe" ||
    value === "required_for_new_vaults" ||
    value === "required"
  ) {
    return value;
  }

  throw new Error("CONVEX_AUTH_ATTESTATION_MODE must be off, observe, required_for_new_vaults, or required");
}

export function shouldRequireAttestationForNewChallenge(input: {
  mode: AuthAttestationMode;
  existingVault: unknown;
}) {
  if (input.mode === "required") return true;
  if (input.mode === "required_for_new_vaults" && !input.existingVault) return true;
  return false;
}

export function shouldRequireFreshAttestationForCloudDelete(mode: AuthAttestationMode) {
  return mode === "required" || mode === "required_for_new_vaults";
}

export function challengeVaultRateLimitKey(vaultId: string) {
  return `challenge:vault:${vaultId}`;
}

export function challengeBackendKeyRateLimitKey(backendAuthKeyId: string) {
  return `challenge:backend-key:${backendAuthKeyId}`;
}

export function vaultCreateRateLimitKey(backendAuthKeyId: string) {
  return `vault:create:${backendAuthKeyId}`;
}
