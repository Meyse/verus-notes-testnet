import { invoke } from "@tauri-apps/api/core";
import { deriveNotesAppScreen } from "./notesAppScreen";
import { createWalletUnlockFlow } from "./walletUnlockFlow.svelte";
import { createWorkspaceController } from "./workspaceController.svelte";
import { createVaultWorkspaceRuntime } from "./vaultWorkspaceRuntime";

type NotesAppControllerOptions = {
  convexUrl?: string;
};

export function createNotesAppController(options: NotesAppControllerOptions) {
  const runtime = createVaultWorkspaceRuntime({ convexUrl: options.convexUrl });
  let wallet: ReturnType<typeof createWalletUnlockFlow>;

  const workspace = createWorkspaceController({
    clearWalletSession: () => wallet?.clearWalletSession(),
    convexUrl: options.convexUrl,
    requestWalletUnlock: () => wallet.startWalletSession(),
    runtime
  });

  wallet = createWalletUnlockFlow({
    acceptWalletUnlock: workspace.acceptWalletUnlock,
    discardAcceptedWalletUnlock: workspace.discardAcceptedWalletUnlock,
    getDeviceIdHex,
    lockVault: () => invoke("lock_vault"),
    openUnlockedWorkspace: workspace.openUnlockedWorkspace,
    returnToOnboarding,
    setStatus: workspace.setStatus,
    showStorageOnboarding: workspace.showStorageOnboarding
  });

  function getDeviceIdHex() {
    const stored = localStorage.getItem("verus-notes.deviceIdHex");

    if (stored && /^[0-9a-f]{32}$/i.test(stored)) {
      return stored.toLowerCase();
    }

    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    const generated = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    localStorage.setItem("verus-notes.deviceIdHex", generated);
    return generated;
  }

  function returnToOnboarding() {
    const shouldLockVault = workspace.hasVault || wallet.isUnlocking || wallet.unlockSucceeded;
    wallet.returnToIdle();
    workspace.returnToOnboarding(shouldLockVault);
  }

  function mount() {
    workspace.mount();
  }

  function destroy() {
    wallet.destroy();
    workspace.destroy();
  }

  return {
    destroy,
    get lockedCommands() {
      return wallet.commands;
    },
    get lockedView() {
      return workspace.lockedAccessView ?? wallet.view;
    },
    mount,
    get screen() {
      return deriveNotesAppScreen({
        isLockedAccessBlocking: Boolean(workspace.lockedAccessView),
        isStorageOnboardingOpen: workspace.isStorageOnboardingOpen,
        isUnlocked: workspace.isUnlocked
      });
    },
    get storageCommands() {
      return {
        ...workspace.storageCommands,
        cancelStorageOnboarding: returnToOnboarding
      };
    },
    get storageView() {
      return workspace.storageView;
    },
    get workspaceCommands() {
      return workspace.workspaceCommands;
    },
    get workspaceView() {
      return workspace.workspaceView;
    }
  };
}
