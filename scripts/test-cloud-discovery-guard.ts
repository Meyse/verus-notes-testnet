import assert from "node:assert/strict";
import { isCloudDiscoveryRunCurrent } from "../src/lib/notes/cloudDiscoveryRunGuard";

const vaultA = { vaultId: "vault-a" };
const vaultB = { vaultId: "vault-b" };
const unlockA = { appEncryptionRequestId: "unlock-a" };
const unlockB = { appEncryptionRequestId: "unlock-b" };

function currentState(input: {
  runId: number;
  storageOnboardingOpen?: boolean;
  unlockInput?: typeof unlockA | typeof unlockB | null;
  vault?: typeof vaultA | typeof vaultB | null;
}) {
  return {
    runId: input.runId,
    storageOnboardingOpen: input.storageOnboardingOpen ?? true,
    unlockInput: input.unlockInput ?? unlockA,
    vault: input.vault ?? vaultA
  };
}

function currentDiscoveryRunCanApply() {
  assert.equal(
    isCloudDiscoveryRunCurrent(
      {
        runId: 1,
        unlockInput: unlockA,
        vault: vaultA
      },
      currentState({ runId: 1 })
    ),
    true
  );
}

function staleDiscoveryAfterReturnToOnboardingCannotApply() {
  assert.equal(
    isCloudDiscoveryRunCurrent(
      {
        runId: 1,
        unlockInput: unlockA,
        vault: vaultA
      },
      currentState({
        runId: 2,
        storageOnboardingOpen: false,
        unlockInput: null,
        vault: vaultA
      })
    ),
    false
  );
}

function staleDiscoveryFromOlderUnlockCannotApply() {
  assert.equal(
    isCloudDiscoveryRunCurrent(
      {
        runId: 1,
        unlockInput: unlockA,
        vault: vaultA
      },
      currentState({
        runId: 2,
        unlockInput: unlockB,
        vault: vaultB
      })
    ),
    false
  );
}

currentDiscoveryRunCanApply();
staleDiscoveryAfterReturnToOnboardingCannotApply();
staleDiscoveryFromOlderUnlockCannotApply();

console.log("cloud discovery guard tests passed");
