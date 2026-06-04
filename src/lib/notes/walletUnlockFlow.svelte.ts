import { invoke } from "@tauri-apps/api/core";
import QRCode from "qrcode";
import { tick } from "svelte";
import { WALLET_IDLE_MESSAGE, WALLET_SUCCESS_DELAY_MS } from "./constants";
import { delay } from "./helpers";
import { deriveWalletUnlockState } from "./walletUnlockState";
import type {
  LockedAccessCommands,
  LockedAccessViewModel
} from "./workspaceTypes";
import type {
  UnlockInput,
  UnlockOutput,
  VaultPreference,
  WalletUnlockPollResponse,
  WalletUnlockSession
} from "./types";

type WalletUnlockFlowOptions = {
  acceptWalletUnlock(vault: UnlockOutput, unlockContext: UnlockInput): Promise<VaultPreference | null>;
  discardAcceptedWalletUnlock(): void;
  getDeviceIdHex(): string;
  lockVault(): Promise<void>;
  openUnlockedWorkspace(input: UnlockInput, vault: UnlockOutput, preference: VaultPreference): Promise<void>;
  returnToOnboarding(): void;
  setStatus(message: string): void;
  showStorageOnboarding(): void | Promise<void>;
};

export function createWalletUnlockFlow(options: WalletUnlockFlowOptions) {
  let walletSession = $state<WalletUnlockSession | null>(null);
  let walletQrDataUrl = $state("");
  let walletBridgeMessage = $state(WALLET_IDLE_MESSAGE);
  let walletSessionStarting = $state(false);
  let walletQrLoading = $state(false);
  let walletPolling = $state(false);
  let walletNowMs = $state(Date.now());
  let walletUnlockSucceeded = $state(false);
  let walletOpeningWorkspace = $state(false);
  let walletPostUnlockLoading = $state(false);
  let cleanedExpiredWalletSessionId = $state<string | null>(null);
  let unlocking = $state(false);
  let walletPollTimer: number | null = null;
  let walletCountdownTimer: number | null = null;
  let walletFlowId = 0;

  const derivedWalletState = $derived(
    deriveWalletUnlockState({
      idleMessage: WALLET_IDLE_MESSAGE,
      unlocking,
      walletBridgeMessage,
      walletNowMs,
      walletOpeningWorkspace,
      walletPostUnlockLoading,
      walletQrDataUrl,
      walletQrLoading,
      walletSession,
      walletSessionStarting,
      walletUnlockSucceeded
    })
  );
  const walletFlowStarted = $derived(derivedWalletState.walletFlowStarted);
  const walletQrPending = $derived(derivedWalletState.walletQrPending);
  const walletSessionExpired = $derived(derivedWalletState.walletSessionExpired);
  const walletHasError = $derived(derivedWalletState.walletHasError);
  const walletStatusMessage = $derived(derivedWalletState.walletStatusMessage);
  const walletCountdownLabel = $derived(derivedWalletState.walletCountdownLabel);

  async function startWalletSession() {
    const flowId = beginWalletFlow();
    await paintPendingWalletState();

    if (flowId !== walletFlowId) return;

    try {
      const session = await invoke<WalletUnlockSession>("start_wallet_unlock_session", {
        input: {}
      });

      if (flowId !== walletFlowId) {
        await cancelPendingWalletUnlock(session.sessionId);
        return;
      }

      walletSession = session;
      walletNowMs = Date.now();
      walletQrLoading = true;
      walletBridgeMessage = "Preparing QR code";
      walletQrDataUrl = await QRCode.toDataURL(session.deeplink, {
        errorCorrectionLevel: "M",
        margin: 1,
        width: 244,
        color: {
          dark: "#17201a",
          light: "#ffffff"
        }
      });

      if (flowId !== walletFlowId) {
        await cancelPendingWalletUnlock(session.sessionId);
        return;
      }

      walletQrLoading = false;
      walletBridgeMessage = "Waiting for Verus Mobile";
      options.setStatus("Waiting for wallet response");
      startWalletCountdown();
      scheduleWalletPoll(1200);
    } catch (error) {
      if (flowId !== walletFlowId) return;

      const message = error instanceof Error ? error.message : String(error);
      walletSession = null;
      walletQrDataUrl = "";
      walletQrLoading = false;
      walletBridgeMessage = message;
      options.setStatus(message);
    } finally {
      if (flowId === walletFlowId) {
        walletSessionStarting = false;
        walletQrLoading = false;
      }
    }
  }

  function beginWalletFlow() {
    void cancelPendingWalletUnlock(walletSession?.sessionId);
    walletFlowId += 1;
    stopWalletPolling();
    stopWalletCountdown();
    walletSession = null;
    walletQrDataUrl = "";
    walletQrLoading = false;
    walletUnlockSucceeded = false;
    walletNowMs = Date.now();
    cleanedExpiredWalletSessionId = null;
    walletPolling = false;
    unlocking = false;
    walletSessionStarting = true;
    walletOpeningWorkspace = false;
    walletPostUnlockLoading = false;
    walletBridgeMessage = "Creating secure request";
    options.setStatus("Creating app-encryption request");
    return walletFlowId;
  }

  async function paintPendingWalletState() {
    await tick();
    await new Promise<void>((resolve) => {
      window.requestAnimationFrame(() => {
        window.requestAnimationFrame(() => resolve());
      });
    });
  }

  async function pollWalletSession() {
    const session = walletSession;
    const flowId = walletFlowId;

    if (!session || walletPolling || walletUnlockSucceeded || walletSessionExpired) {
      return;
    }

    walletPolling = true;

    try {
      const poll = await invoke<WalletUnlockPollResponse>("poll_wallet_unlock_session", {
        input: {
          deviceIdHex: options.getDeviceIdHex(),
          sessionId: session.sessionId
        }
      });

      if (flowId !== walletFlowId) return;

      if (poll.status === "pending") {
        walletBridgeMessage = "Waiting for Verus Mobile";
        scheduleWalletPoll();
        return;
      }

      if (poll.status === "unlocked") {
        walletBridgeMessage = "Unlocking vault";
        options.setStatus("Vault unlocked");
        stopWalletPolling();
        stopWalletCountdown();
        await finishWalletUnlock(poll.vault, poll.unlockContext, flowId);
        return;
      }
    } catch (error) {
      if (flowId !== walletFlowId) return;

      const message = error instanceof Error ? error.message : String(error);
      stopWalletPolling();
      stopWalletCountdown();
      await cancelPendingWalletUnlock(session.sessionId);
      walletSession = null;
      walletQrDataUrl = "";
      walletBridgeMessage = message;
      options.setStatus(message);
    } finally {
      if (flowId === walletFlowId) {
        walletPolling = false;
      }
    }
  }

  async function finishWalletUnlock(unlockedVault: UnlockOutput, unlockContext: UnlockInput, flowId = walletFlowId): Promise<boolean> {
    unlocking = true;
    walletBridgeMessage = "Unlocking vault";
    let acceptedUnlock = false;

    try {
      if (flowId !== walletFlowId) {
        await options.lockVault().catch(() => undefined);
        return false;
      }

      acceptedUnlock = true;
      const storagePreference = await options.acceptWalletUnlock(unlockedVault, unlockContext);
      unlocking = false;

      if (flowId !== walletFlowId) {
        await options.lockVault().catch(() => undefined);
        options.discardAcceptedWalletUnlock();
        walletUnlockSucceeded = false;
        return false;
      }

      if (!storagePreference) {
        walletPostUnlockLoading = true;
        walletSession = null;
        walletQrDataUrl = "";
        walletQrLoading = false;
        walletSessionStarting = false;
        walletBridgeMessage = "Checking encrypted cloud sync";
        options.setStatus("Checking encrypted cloud sync");
        await options.showStorageOnboarding();
        if (flowId !== walletFlowId) return false;
        clearWalletSession({ cancelPending: false });
        return true;
      }

      walletUnlockSucceeded = true;
      walletBridgeMessage = "Request approved";
      await delay(WALLET_SUCCESS_DELAY_MS);

      if (flowId !== walletFlowId) {
        await options.lockVault().catch(() => undefined);
        options.discardAcceptedWalletUnlock();
        walletUnlockSucceeded = false;
        return false;
      }

      walletUnlockSucceeded = false;
      walletOpeningWorkspace = true;
      walletBridgeMessage = "Decrypting private notes";
      await options.openUnlockedWorkspace(unlockContext, unlockedVault, storagePreference);
      walletOpeningWorkspace = false;
      clearWalletSession({ cancelPending: false });
      return true;
    } catch (error) {
      if (flowId === walletFlowId) {
        const message = error instanceof Error ? error.message : String(error);
        if (acceptedUnlock) {
          await options.lockVault().catch(() => undefined);
          options.discardAcceptedWalletUnlock();
          walletUnlockSucceeded = false;
        }
        await cancelPendingWalletUnlock(walletSession?.sessionId);
        walletSession = null;
        walletQrDataUrl = "";
        walletOpeningWorkspace = false;
        walletPostUnlockLoading = false;
        options.setStatus(message);
        walletBridgeMessage = message;
      }
      return false;
    } finally {
      if (flowId === walletFlowId && !walletUnlockSucceeded) {
        unlocking = false;
      }
    }
  }

  function scheduleWalletPoll(delayMs = 2000) {
    if (!walletSession) return;

    if (walletPollTimer !== null) {
      window.clearTimeout(walletPollTimer);
    }

    walletPollTimer = window.setTimeout(() => {
      walletPollTimer = null;
      void pollWalletSession();
    }, delayMs);
  }

  function stopWalletPolling() {
    if (walletPollTimer !== null) {
      window.clearTimeout(walletPollTimer);
      walletPollTimer = null;
    }
  }

  function startWalletCountdown() {
    stopWalletCountdown();
    walletNowMs = Date.now();
    walletCountdownTimer = window.setInterval(() => {
      walletNowMs = Date.now();
      if (!walletSessionExpired || !walletSession || cleanedExpiredWalletSessionId === walletSession.sessionId) return;

      cleanedExpiredWalletSessionId = walletSession.sessionId;
      stopWalletPolling();
      void cancelPendingWalletUnlock(walletSession.sessionId);
    }, 1000);
  }

  function stopWalletCountdown() {
    if (walletCountdownTimer !== null) {
      window.clearInterval(walletCountdownTimer);
      walletCountdownTimer = null;
    }
  }

  function returnToIdle() {
    const sessionId = walletSession?.sessionId;
    walletFlowId += 1;
    stopWalletPolling();
    stopWalletCountdown();
    walletSession = null;
    walletQrDataUrl = "";
    walletQrLoading = false;
    walletSessionStarting = false;
    walletPolling = false;
    unlocking = false;
    walletUnlockSucceeded = false;
    walletOpeningWorkspace = false;
    walletPostUnlockLoading = false;
    walletNowMs = Date.now();
    cleanedExpiredWalletSessionId = null;
    walletBridgeMessage = WALLET_IDLE_MESSAGE;
    void cancelPendingWalletUnlock(sessionId);
  }

  function clearWalletSession(options: { cancelPending?: boolean } = {}) {
    const sessionId = walletSession?.sessionId;
    stopWalletPolling();
    stopWalletCountdown();
    walletSession = null;
    walletQrDataUrl = "";
    walletQrLoading = false;
    walletSessionStarting = false;
    walletPolling = false;
    walletUnlockSucceeded = false;
    walletOpeningWorkspace = false;
    walletPostUnlockLoading = false;
    walletNowMs = Date.now();
    cleanedExpiredWalletSessionId = null;
    walletBridgeMessage = WALLET_IDLE_MESSAGE;

    if (options.cancelPending !== false) {
      void cancelPendingWalletUnlock(sessionId);
    }
  }

  async function cancelPendingWalletUnlock(sessionId: string | null | undefined) {
    if (!sessionId) return;

    await invoke("cancel_wallet_unlock_session", {
      input: { sessionId }
    }).catch(() => undefined);
  }

  function destroy() {
    stopWalletPolling();
    stopWalletCountdown();
    void cancelPendingWalletUnlock(walletSession?.sessionId);
  }

  const view: LockedAccessViewModel = {
    get walletFlowStarted() {
      return walletFlowStarted;
    },
    get walletUnlockSucceeded() {
      return walletUnlockSucceeded;
    },
    get walletHasError() {
      return walletHasError;
    },
    get walletQrDataUrl() {
      return walletQrDataUrl;
    },
    get walletSessionExpired() {
      return walletSessionExpired;
    },
    get walletQrPending() {
      return walletQrPending;
    },
    get unlocking() {
      return unlocking;
    },
    get walletOpeningWorkspace() {
      return walletOpeningWorkspace;
    },
    get walletStatusMessage() {
      return walletStatusMessage;
    },
    get walletSuccessMessage() {
      return "Opening notes";
    },
    get walletCountdownLabel() {
      return walletCountdownLabel;
    },
    get walletSessionStarting() {
      return walletSessionStarting;
    }
  };

  const commands: LockedAccessCommands = {
    returnToOnboarding: options.returnToOnboarding,
    startWalletSession
  };

  return {
    clearWalletSession,
    commands,
    destroy,
    get isUnlocking() {
      return unlocking;
    },
    get unlockSucceeded() {
      return walletUnlockSucceeded;
    },
    returnToIdle,
    startWalletSession,
    view
  };
}
