import { formatCountdown } from "./helpers";
import type { WalletUnlockSession } from "./types";

export type WalletUnlockStateInput = {
  idleMessage: string;
  unlocking: boolean;
  walletBridgeMessage: string;
  walletNowMs: number;
  walletOpeningWorkspace: boolean;
  walletPostUnlockLoading: boolean;
  walletQrDataUrl: string;
  walletQrLoading: boolean;
  walletSession: WalletUnlockSession | null;
  walletSessionStarting: boolean;
  walletUnlockSucceeded: boolean;
};

export function deriveWalletUnlockState(input: WalletUnlockStateInput) {
  const walletFlowStarted = Boolean(
    input.walletSession ||
      input.walletSessionStarting ||
      input.walletQrLoading ||
      input.unlocking ||
      input.walletUnlockSucceeded ||
      input.walletOpeningWorkspace ||
      input.walletPostUnlockLoading ||
      input.walletBridgeMessage !== input.idleMessage
  );
  const walletQrPending = Boolean(input.walletQrLoading || (input.walletSession && !input.walletQrDataUrl));
  const walletSecondsRemaining = input.walletSession
    ? Math.max(0, Math.ceil((input.walletSession.expiresAt - input.walletNowMs) / 1000))
    : 0;
  const walletSessionExpired = Boolean(
    input.walletSession && walletSecondsRemaining <= 0 && !input.walletUnlockSucceeded && !input.walletOpeningWorkspace
  );
  const walletHasError = Boolean(
    walletSessionExpired ||
      (!input.walletSession &&
        !input.walletSessionStarting &&
        !input.walletQrLoading &&
        !input.unlocking &&
        !input.walletUnlockSucceeded &&
        !input.walletOpeningWorkspace &&
        !input.walletPostUnlockLoading &&
        input.walletBridgeMessage !== input.idleMessage)
  );

  return {
    walletCountdownLabel:
      input.walletSession && !walletSessionExpired ? `Scan within ${formatCountdown(walletSecondsRemaining)}` : "",
    walletFlowStarted,
    walletHasError,
    walletQrPending,
    walletSecondsRemaining,
    walletSessionExpired,
    walletStatusMessage: walletSessionExpired ? "Wallet session expired" : input.walletBridgeMessage
  };
}
