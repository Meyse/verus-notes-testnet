<script lang="ts">
  import { ArrowLeft, Check, CircleQuestionMark, LoaderCircle, QrCode, X } from "@lucide/svelte";
  import type { LockedAccessCommands, LockedAccessViewModel } from "$lib/notes/workspaceTypes";

  type Props = {
    commands: LockedAccessCommands;
    view: LockedAccessViewModel;
  };

  let { commands, view }: Props = $props();
  const walletFlowStarted = $derived(view.walletFlowStarted);
  const walletUnlockSucceeded = $derived(view.walletUnlockSucceeded);
  const walletHasError = $derived(view.walletHasError);
  const walletQrDataUrl = $derived(view.walletQrDataUrl);
  const walletSessionExpired = $derived(view.walletSessionExpired);
  const walletQrPending = $derived(view.walletQrPending);
  const unlocking = $derived(view.unlocking);
  const walletOpeningWorkspace = $derived(view.walletOpeningWorkspace);
  const walletStatusMessage = $derived(view.walletStatusMessage);
  const walletSuccessMessage = $derived(view.walletSuccessMessage);
  const walletCountdownLabel = $derived(view.walletCountdownLabel);
  const walletSessionStarting = $derived(view.walletSessionStarting);

  let infoPanelOpen = $state(false);

  function returnToOnboarding() {
    commands.returnToOnboarding();
  }

  async function startWalletSession() {
    await commands.startWalletSession();
  }

  function closeLockedPanel() {
    if (infoPanelOpen) {
      infoPanelOpen = false;
      return;
    }

    returnToOnboarding();
  }

  async function handleStartWalletSession() {
    infoPanelOpen = false;
    await startWalletSession();
  }
</script>

<main class="locked-access">
  <div class="locked-drag-strip" data-tauri-drag-region="deep" aria-hidden="true"></div>
  {#if infoPanelOpen || (walletFlowStarted && !walletUnlockSucceeded && !walletOpeningWorkspace)}
    <button
      class="wallet-close-button"
      type="button"
      title="Back to onboarding"
      aria-label="Back to onboarding"
      onclick={closeLockedPanel}
    >
      <X size={20} aria-hidden="true" />
    </button>
    <button
      class="wallet-back-button"
      type="button"
      title="Back"
      aria-label="Back"
      data-tauri-drag-region="false"
      onclick={closeLockedPanel}
    >
      <ArrowLeft size={17} aria-hidden="true" />
      <span>Back</span>
    </button>
  {/if}

  <section class:panel-active={walletFlowStarted || infoPanelOpen} class="locked-hero" aria-label="Unlock Verus Notes">
    {#if !walletFlowStarted && !infoPanelOpen}
      <div class="locked-copy">
        <img class="locked-app-icon" src="/macos-icon.png" alt="Verus Notes" width="76" height="76" />
        <h1>Your notes encrypted and accessible anywhere</h1>

        <div class="onboarding-actions">
          <button
            class="primary-button unlock-wallet-button"
            type="button"
            onclick={handleStartWalletSession}
            disabled={walletSessionStarting || unlocking}
          >
            Access my notes
          </button>
          <button
            class="icon-button onboarding-help-button"
            type="button"
            title="How it works"
            aria-label="How it works"
            onclick={() => (infoPanelOpen = true)}
          >
            <CircleQuestionMark size={20} aria-hidden="true" />
          </button>
        </div>
      </div>
    {:else if infoPanelOpen}
      <aside class="onboarding-info-panel" aria-label="How Verus Notes works">
        <div class="info-step-list">
          <section class="info-step info-paragraph">
            <strong>Your VerusID reopens the same vault</strong>
            <p>
              Approve Verus Notes with the same VerusID and wallet, and the app derives the same vault keys again.
            </p>
          </section>
          <section class="info-step info-paragraph">
            <strong>Readable notes stay local</strong>
            <p>
              Notes, folders, and bookmarks are encrypted on this device before they are saved or synced.
            </p>
          </section>
          <section class="info-step info-paragraph">
            <strong>Cloud sync stores ciphertext</strong>
            <p>
              Encrypted sync lets other approved devices fetch encrypted records. The cloud cannot read note text or
              folder names.
            </p>
          </section>
          <section class="info-step info-paragraph">
            <strong>No wallet secrets requested</strong>
            <p>Verus Notes never asks for your seed phrase, WIF, or spending key.</p>
          </section>
        </div>
      </aside>
    {:else}
      <aside class="wallet-unlock-panel" aria-label="Verus wallet unlock request">
        {#if !walletHasError && walletQrDataUrl && !walletSessionExpired && !unlocking && !walletUnlockSucceeded && !walletOpeningWorkspace}
          <div class="wallet-panel-header qr-panel-header">
            <QrCode size={20} aria-hidden="true" />
            <div>
              <h2>Scan with Verus Mobile</h2>
            </div>
          </div>
        {/if}

        {#if walletUnlockSucceeded}
          <div class="wallet-success-state" role="status" aria-live="polite">
            <span class="success-check-ring">
              <Check class="success-check-icon" size={42} aria-hidden="true" />
            </span>
            <span>{walletSuccessMessage}</span>
          </div>
        {:else if walletHasError}
          <div class="wallet-error-state" role="status" aria-live="polite">
            <p class="locked-access-status">{walletStatusMessage}</p>
          </div>
        {:else if walletQrDataUrl && !walletSessionExpired && !unlocking && !walletOpeningWorkspace}
          <div class="qr-frame locked-qr" aria-label="Verus wallet request QR" aria-busy={walletQrPending}>
            <img src={walletQrDataUrl} alt="Verus wallet request QR" />
          </div>

          <div class="wallet-qr-meta">
            {#if walletCountdownLabel}
              <p class="wallet-expiry" role="status" aria-live="polite">{walletCountdownLabel}</p>
            {/if}
          </div>
        {:else}
          <div class="wallet-loading-state" role="status" aria-live="polite">
            <LoaderCircle class="loading-spinner" size={34} aria-hidden="true" />
            <span>{walletStatusMessage}</span>
          </div>
        {/if}

        {#if walletHasError}
          <button class="secondary-button wallet-retry-button" type="button" onclick={startWalletSession}>
            Try again
          </button>
        {/if}
      </aside>
    {/if}
  </section>
</main>
