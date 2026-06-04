import assert from "node:assert/strict";
import { WALLET_IDLE_MESSAGE } from "../src/lib/notes/constants";
import { deriveNotesAppScreen } from "../src/lib/notes/notesAppScreen";
import { deriveWalletUnlockState } from "../src/lib/notes/walletUnlockState";

const NOW = 1_700_000_000_000;

function baseInput() {
  return {
    idleMessage: WALLET_IDLE_MESSAGE,
    unlocking: false,
    walletBridgeMessage: WALLET_IDLE_MESSAGE,
    walletNowMs: NOW,
    walletOpeningWorkspace: false,
    walletPostUnlockLoading: false,
    walletQrDataUrl: "",
    walletQrLoading: false,
    walletSession: null,
    walletSessionStarting: false,
    walletUnlockSucceeded: false
  };
}

function idleState() {
  const state = deriveWalletUnlockState(baseInput());
  assert.equal(state.walletFlowStarted, false);
  assert.equal(state.walletHasError, false);
  assert.equal(state.walletQrPending, false);
  assert.equal(state.walletCountdownLabel, "");
}

function pendingQrState() {
  const state = deriveWalletUnlockState({
    ...baseInput(),
    walletBridgeMessage: "Preparing QR code",
    walletQrLoading: true,
    walletSession: {
      deeplink: "verus://request",
      expiresAt: NOW + 90_000,
      sessionId: "session-1"
    }
  });

  assert.equal(state.walletFlowStarted, true);
  assert.equal(state.walletQrPending, true);
  assert.equal(state.walletSessionExpired, false);
  assert.equal(state.walletCountdownLabel, "Scan within 01:30");
}

function expiredSessionState() {
  const state = deriveWalletUnlockState({
    ...baseInput(),
    walletBridgeMessage: "Waiting for Verus Mobile",
    walletQrDataUrl: "data:image/png;base64,abc",
    walletSession: {
      deeplink: "verus://request",
      expiresAt: NOW - 1,
      sessionId: "session-1"
    }
  });

  assert.equal(state.walletSessionExpired, true);
  assert.equal(state.walletHasError, true);
  assert.equal(state.walletStatusMessage, "Wallet session expired");
  assert.equal(state.walletCountdownLabel, "");
}

function staleErrorState() {
  const state = deriveWalletUnlockState({
    ...baseInput(),
    walletBridgeMessage: "Signer session rejected"
  });

  assert.equal(state.walletFlowStarted, true);
  assert.equal(state.walletHasError, true);
  assert.equal(state.walletStatusMessage, "Signer session rejected");
}

function postUnlockCloudDiscoveryLoadingState() {
  const state = deriveWalletUnlockState({
    ...baseInput(),
    walletBridgeMessage: "Checking encrypted cloud sync",
    walletPostUnlockLoading: true
  });

  assert.equal(state.walletFlowStarted, true);
  assert.equal(state.walletHasError, false);
  assert.equal(state.walletStatusMessage, "Checking encrypted cloud sync");
}

function appScreenRouting() {
  assert.equal(
    deriveNotesAppScreen({
      isLockedAccessBlocking: true,
      isStorageOnboardingOpen: true,
      isUnlocked: false
    }),
    "locked"
  );
  assert.equal(
    deriveNotesAppScreen({
      isLockedAccessBlocking: false,
      isStorageOnboardingOpen: true,
      isUnlocked: false
    }),
    "storage"
  );
  assert.equal(
    deriveNotesAppScreen({
      isLockedAccessBlocking: false,
      isStorageOnboardingOpen: false,
      isUnlocked: true
    }),
    "workspace"
  );
}

idleState();
pendingQrState();
expiredSessionState();
staleErrorState();
postUnlockCloudDiscoveryLoadingState();
appScreenRouting();

console.log("wallet unlock state tests passed");
