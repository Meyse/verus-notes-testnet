<script lang="ts">
  import { ArrowLeft, CircleAlert, Cloud, HardDrive, LoaderCircle, RefreshCw, X } from "@lucide/svelte";
  import type { StorageMode } from "$lib/notes/types";
  import type { StorageOnboardingCommands, StorageOnboardingViewModel } from "$lib/notes/workspaceTypes";
  import CloudSyncSelectionModal from "./CloudSyncSelectionModal.svelte";

  type Props = {
    commands: StorageOnboardingCommands;
    view: StorageOnboardingViewModel;
  };

  let { commands, view }: Props = $props();
  const busy = $derived(view.busy);
  const cloudDiscovery = $derived(view.cloudDiscovery);
  const cloudSyncSelection = $derived(view.cloudSyncSelection);
  const status = $derived(view.status);
  const canUseCloud = $derived(view.canUseCloud);
  const connectedVerusIdAddress = $derived(view.connectedVerusIdAddress);
  const connectedVerusIdName = $derived(view.connectedVerusIdName);
  const connectedVerusIdLabel = $derived(
    connectedVerusIdName?.trim() || shortenIdentity(connectedVerusIdAddress) || "Unknown VerusID"
  );
  const connectedVerusIdTitle = $derived(
    connectedVerusIdName && connectedVerusIdAddress ? `${connectedVerusIdName} (${connectedVerusIdAddress})` : connectedVerusIdAddress
  );
  const cloudErrorHeading = $derived(
    status === "Cloud sync could not be downloaded" ? "Cloud sync could not be downloaded" : "Cloud sync could not be checked"
  );
  const cloudErrorBody = $derived(
    status === "Cloud sync could not be downloaded"
      ? "Try again before opening the synced vault, or keep this device local."
      : "Try again before enabling sync, or keep this device local."
  );
  let cloudSyncEnabled = $state(false);
  // svelte-ignore state_referenced_locally
  const {
    cancelCloudSyncSelection,
    cancelStorageOnboarding,
    confirmCloudSyncSelection,
    enableFoundCloudSync,
    keepCloudSyncSelectionLocal,
    retryCloudDiscovery,
    toggleCloudSyncSelectionNote
  } = commands;

  $effect(() => {
    if (!canUseCloud) cloudSyncEnabled = false;
  });

  function chooseStorageMode(mode: StorageMode) {
    return commands.chooseStorageMode(mode);
  }

  function toggleCloudSync() {
    if (busy || !canUseCloud) return;
    cloudSyncEnabled = !cloudSyncEnabled;
  }

  function continueWithStorageChoice() {
    return chooseStorageMode(cloudSyncEnabled ? "sync_enabled" : "local_only");
  }

  function useThisDeviceOnly() {
    return chooseStorageMode("local_only");
  }

  function countLabel(count: number, singular: string, plural: string) {
    return `${count} ${count === 1 ? singular : plural}`;
  }

  function shortenIdentity(identity: string) {
    if (identity.length <= 18) return identity;
    return `${identity.slice(0, 8)}...${identity.slice(-6)}`;
  }
</script>

<main class="storage-onboarding">
  <div class="locked-drag-strip" data-tauri-drag-region="deep" aria-hidden="true"></div>
  <button
    class="wallet-close-button"
    type="button"
    title="Back to unlock"
    aria-label="Back to unlock"
    data-tauri-drag-region="false"
    onclick={cancelStorageOnboarding}
  >
    <X size={20} aria-hidden="true" />
  </button>
  <button
    class="wallet-back-button"
    type="button"
    title="Back"
    aria-label="Back"
    data-tauri-drag-region="false"
    onclick={cancelStorageOnboarding}
  >
    <ArrowLeft size={17} aria-hidden="true" />
    <span>Back</span>
  </button>
  <section class="storage-choice-panel" aria-label="Set up encrypted storage">
    {#if cloudDiscovery.status === "found"}
      <div class="storage-choice-copy">
        <h1>Encrypted cloud sync found</h1>
      </div>

      <div class="storage-choice-actions">
        <div class="storage-choice-card storage-foundation-card" aria-label="Encrypted cloud sync found">
          <Cloud size={22} aria-hidden="true" />
          <span class="storage-choice-text">
            <span class="storage-choice-title">
              <strong>Cloud sync available</strong>
              <span class="storage-verusid-chip" title={connectedVerusIdTitle}>{connectedVerusIdLabel}</span>
            </span>
            <small>
              {countLabel(cloudDiscovery.liveNoteCount, "note", "notes")} and {countLabel(cloudDiscovery.liveFolderCount, "folder", "folders")} are available to download.
            </small>
          </span>
        </div>
      </div>

      <div class="storage-choice-controls">
        <button class="primary-button storage-choice-continue" type="button" disabled={busy} onclick={enableFoundCloudSync}>
          <Cloud size={16} aria-hidden="true" />
          <span>Enable sync and download</span>
        </button>
        <button class="secondary-button storage-choice-continue" type="button" disabled={busy} onclick={useThisDeviceOnly}>
          <HardDrive size={16} aria-hidden="true" />
          <span>Use this device only</span>
        </button>
      </div>
    {:else if cloudDiscovery.status === "error"}
      <div class="storage-choice-copy">
        <h1>{cloudErrorHeading}</h1>
        <p>{cloudErrorBody}</p>
      </div>

      <div class="storage-choice-actions">
        <div class="storage-choice-card storage-foundation-card" aria-label="Cloud sync check failed">
          <CircleAlert size={22} aria-hidden="true" />
          <span class="storage-choice-text">
            <span class="storage-choice-title"><strong>Cloud check failed</strong></span>
            <small>{cloudDiscovery.error}</small>
          </span>
        </div>
      </div>

      <div class="storage-choice-controls">
        <button class="primary-button storage-choice-continue" type="button" disabled={busy} onclick={retryCloudDiscovery}>
          <RefreshCw size={16} aria-hidden="true" />
          <span>Try again</span>
        </button>
        <button class="secondary-button storage-choice-continue" type="button" disabled={busy} onclick={useThisDeviceOnly}>
          <HardDrive size={16} aria-hidden="true" />
          <span>Use this device only</span>
        </button>
      </div>
    {:else}
      <div class="storage-choice-copy">
        <h1>Set up encrypted storage</h1>
        <p>You can enable encrypted cloud sync later in Settings.</p>
      </div>

      <div class="storage-choice-actions">
        <div class="storage-choice-card storage-foundation-card" aria-label="Local encrypted vault">
          <HardDrive size={22} aria-hidden="true" />
          <span class="storage-choice-text">
            <span class="storage-choice-title"><strong>Local encrypted vault</strong></span>
            <small>Notes stay encrypted on this computer and can be backed up locally.</small>
          </span>
        </div>
        <button
          class:enabled={cloudSyncEnabled}
          class="storage-choice-card storage-cloud-toggle"
          type="button"
          role="switch"
          aria-checked={cloudSyncEnabled}
          disabled={busy || !canUseCloud}
          title={canUseCloud ? "Encrypted sync" : "Cloud sync is not configured"}
          onclick={toggleCloudSync}
        >
          <Cloud size={22} aria-hidden="true" />
          <span class="storage-choice-text">
            <span class="storage-choice-title">
              <strong>Encrypted cloud sync</strong>
              <span class="storage-choice-badge">20 NOTES FOR FREE</span>
            </span>
            <small>Your unlocked devices can stay in sync. The cloud can never read your notes.</small>
          </span>
          <span class="storage-sync-switch" aria-hidden="true">
            <span></span>
          </span>
        </button>
      </div>

      <div class="storage-choice-controls">
        <button class="primary-button storage-choice-continue" type="button" disabled={busy} onclick={continueWithStorageChoice}>Continue</button>
      </div>

      {#if busy}
        <div class="storage-choice-footer">
          <span class="storage-choice-status">
            <LoaderCircle class="loading-spinner" size={16} aria-hidden="true" />
            {status}
          </span>
        </div>
      {/if}
    {/if}
  </section>
</main>

{#if cloudSyncSelection}
  <CloudSyncSelectionModal
    busy={busy}
    selection={cloudSyncSelection}
    cancel={cancelCloudSyncSelection}
    confirm={confirmCloudSyncSelection}
    keepLocal={keepCloudSyncSelectionLocal}
    toggleNote={toggleCloudSyncSelectionNote}
  />
{/if}
