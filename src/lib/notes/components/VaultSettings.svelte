<script lang="ts">
  import { ArrowLeft, CircleAlert, Cloud, CloudOff, Download, Lock, RefreshCw, ShieldCheck, Upload, X } from "@lucide/svelte";
  import type { AppearanceMode, CloudUsage, NoteDraft, StorageMode, VaultSettingsSectionId } from "$lib/notes/types";
  import ConfirmPopover from "./ConfirmPopover.svelte";
  import VaultSettingsCard from "./VaultSettingsCard.svelte";
  import VaultSettingsRow from "./VaultSettingsRow.svelte";
  import VaultSettingsSidebar from "./VaultSettingsSidebar.svelte";

	type Props = {
	  appearanceMode: AppearanceMode;
	  canUseCloud: boolean;
    cloudBusy: boolean;
    cloudCopyDeleted: boolean;
    cloudStatus: string;
    cloudUsage: CloudUsage | null;
    cloudSyncNeedsNewWalletUnlock: boolean;
    localCloudSyncNoteCount: number;
    localCloudSyncStorageBytes: number;
    closeSettings: () => void;
    connectedVerusIdAddress: string;
    connectedVerusIdName: string | null;
    deleteCloudCopy: () => void | Promise<void>;
    enableEncryptedSync: () => void | Promise<void>;
    exportEncryptedBackup: () => void | Promise<void>;
	  importBackup: () => void | Promise<void>;
	  includeNoteInCloudSync: (noteId: string) => void | Promise<void>;
	  initialSection?: VaultSettingsSectionId;
	  syncNotesModalOpen: boolean;
	  notes: NoteDraft[];
	  getFolderName: (folderId: string) => string;
	  getNoteTitle: (note: NoteDraft | null | undefined) => string;
	  closeSyncNotesModal: () => void;
	  openSyncNotesModal: () => void;
	  removeNoteFromCloudSync: (noteId: string) => void | Promise<void>;
	  reconnectCloudSync: () => void | Promise<void>;
	  retryCloudSync: () => void | Promise<void>;
	  retryNoteSync: (noteId: string) => void | Promise<void>;
	  setAppearanceMode: (mode: AppearanceMode) => void;
	  stopSyncingThisDevice: () => void | Promise<void>;
    storageMode: StorageMode | null;
    storageStatusLabel: string;
  };

  let {
    appearanceMode,
    canUseCloud,
    cloudBusy,
    cloudCopyDeleted,
    cloudStatus,
    cloudUsage,
    cloudSyncNeedsNewWalletUnlock,
    localCloudSyncNoteCount,
    localCloudSyncStorageBytes,
    closeSettings,
    connectedVerusIdAddress,
    connectedVerusIdName,
    deleteCloudCopy,
	    enableEncryptedSync,
	    exportEncryptedBackup,
	    importBackup,
	    includeNoteInCloudSync,
	    initialSection = "general",
	    syncNotesModalOpen,
	    notes,
	    getFolderName,
	    getNoteTitle,
	    closeSyncNotesModal,
	    openSyncNotesModal,
	    removeNoteFromCloudSync,
	    reconnectCloudSync,
	    retryCloudSync,
	    retryNoteSync,
	    setAppearanceMode,
    stopSyncingThisDevice,
    storageMode,
    storageStatusLabel
  }: Props = $props();

	  let activeSection = $state<VaultSettingsSectionId>("general");
  let confirmingDeleteCloudCopy = $state(false);
  const syncEnabled = $derived(storageMode === "sync_enabled");
  const cloudHasRecoverableSyncError = $derived(syncEnabled && storageStatusLabel === "Sync error" && !cloudSyncNeedsNewWalletUnlock);
  const settingsStorageLabel = $derived(getSettingsStorageLabel(storageStatusLabel));
  const cloudActionLabel = $derived(
    cloudSyncNeedsNewWalletUnlock ? "Lock and unlock" : cloudHasRecoverableSyncError ? "Retry sync" : syncEnabled ? "Cloud sync enabled" : "Enable cloud sync"
  );
  const cloudActionDisabled = $derived(!canUseCloud || cloudBusy || (syncEnabled && !cloudSyncNeedsNewWalletUnlock && !cloudHasRecoverableSyncError));
  const displayedMaxNotes = $derived(cloudUsage?.maxSyncedNotes ?? 20);
  const displayedMaxStorageBytes = $derived(cloudUsage?.maxStorageBytes ?? 2 * 1024 * 1024);
  const displayedSyncedNoteCount = $derived(Math.max(clampUsageValue(cloudUsage?.liveSyncedNoteCount ?? 0), localCloudSyncNoteCount));
  const displayedStorageBytes = $derived(Math.max(clampUsageValue(cloudUsage?.liveStorageBytes ?? 0), clampUsageValue(localCloudSyncStorageBytes)));
  const connectedVerusIdLabel = $derived(
    connectedVerusIdName?.trim() || shortenIdentity(connectedVerusIdAddress) || "Unknown VerusID"
  );
	  const connectedVerusIdTitle = $derived(
	    connectedVerusIdName && connectedVerusIdAddress ? `${connectedVerusIdName} (${connectedVerusIdAddress})` : connectedVerusIdAddress
	  );
	  const managedSyncNotes = $derived.by(() => {
	    const statePriority = (note: NoteDraft) => {
	      if (note.syncBlockedReason) return 0;
	      if (note.cloudSyncScope === "included") return 1;
	      return 2;
	    };
	    return [...notes].sort((left, right) => {
	      const priorityDelta = statePriority(left) - statePriority(right);
	      if (priorityDelta !== 0) return priorityDelta;
	      return right.updatedAtMs - left.updatedAtMs;
	    });
	  });

	  $effect(() => {
	    activeSection = initialSection;
	  });

	  $effect(() => {
	    if (syncNotesModalOpen) activeSection = "cloud";
	  });

  async function runSettingsAction(action: () => void | Promise<void>) {
    await action();
  }

  async function runCloudAction() {
    if (cloudSyncNeedsNewWalletUnlock) {
      await reconnectCloudSync();
      return;
    }
    if (cloudHasRecoverableSyncError) {
      await retryCloudSync();
      return;
    }
    await enableEncryptedSync();
  }

  function handleWindowKeydown(event: KeyboardEvent) {
    if (event.key !== "Escape") return;
    if (confirmingDeleteCloudCopy) {
      confirmingDeleteCloudCopy = false;
      return;
    }
    if (syncNotesModalOpen) {
      closeSyncNotesModal();
      return;
    }
    closeSettings();
  }

	  function showSyncNotesModal() {
	    activeSection = "cloud";
	    openSyncNotesModal();
	  }

  function requestDeleteCloudCopy() {
    confirmingDeleteCloudCopy = true;
  }

  async function confirmDeleteCloudCopy() {
    confirmingDeleteCloudCopy = false;
    await runSettingsAction(deleteCloudCopy);
  }

  function getSettingsStorageLabel(label: string) {
    if (label === "Encrypted sync on") return "Cloud synced";
    if (label === "This device only" || label === "Cloud copy removed") return "Local only";
    return label;
  }

  function shortenIdentity(identity: string) {
    if (identity.length <= 18) return identity;
    return `${identity.slice(0, 8)}...${identity.slice(-6)}`;
  }

  function usagePercent(used: number, total: number) {
    if (total <= 0) return 0;
    return Math.min(100, (clampUsageValue(used) / total) * 100);
  }

  function usageIsFull() {
    return displayedSyncedNoteCount >= displayedMaxNotes || (displayedStorageBytes ?? 0) >= displayedMaxStorageBytes;
  }

  function clampUsageValue(value: number) {
    if (!Number.isFinite(value)) return 0;
    return Math.max(0, value);
  }

  function formatStorageBytes(bytes: number) {
    const clampedBytes = clampUsageValue(bytes);
    if (clampedBytes >= 1024 * 1024) return `${formatCompactNumber(clampedBytes / (1024 * 1024))} MB`;
    if (clampedBytes >= 1024) return `${formatCompactNumber(clampedBytes / 1024)} KB`;
    return `${clampedBytes} B`;
  }

	  function formatCompactNumber(value: number) {
	    return Number.isInteger(value) ? value.toString() : value.toFixed(1);
	  }

	  function noteSyncManagementLabel(note: NoteDraft) {
	    if (note.cloudSyncScope === "local_only") return "This device only";
	    if (note.syncBlockedReason === "record_too_large") return "Too large to sync";
	    if (note.syncBlockedReason && note.lastSyncedRevisionHash && note.revisionHash && note.lastSyncedRevisionHash !== note.revisionHash) {
	      return "Cloud out of date";
	    }
	    if (note.syncBlockedReason) return "Sync limit reached";
	    if (note.syncState === "pending_upsert" || note.syncState === "pending_delete") return "Sync queued";
	    if (note.syncState === "synced" && note.revisionHash && note.lastSyncedRevisionHash === note.revisionHash) return "Cloud synced";
	    return "Included";
	  }

	  function noteIsCloudSynced(note: NoteDraft) {
	    return Boolean(
	      note.cloudSyncScope !== "local_only" &&
	        !note.syncBlockedReason &&
	        note.syncState === "synced" &&
	        note.revisionHash &&
	        note.lastSyncedRevisionHash === note.revisionHash
	    );
	  }

	  function noteSyncManagementTone(note: NoteDraft) {
	    if (note.cloudSyncScope === "local_only") return "local";
	    if (note.syncBlockedReason) return "warning";
	    return "cloud";
	  }

	  function noteCanIncludeInCloudSync(note: NoteDraft) {
	    return syncEnabled && note.cloudSyncScope === "local_only" && !note.syncBlockedReason && !usageIsFull();
	  }

	  function noteNeedsQuotaBeforeInclude(note: NoteDraft) {
	    return syncEnabled && note.cloudSyncScope === "local_only" && !note.syncBlockedReason && usageIsFull();
	  }

	  function noteCanRemoveFromCloudSync(note: NoteDraft) {
	    return syncEnabled && note.cloudSyncScope === "included" && note.lastSyncedRevisionHash && !note.syncBlockedReason;
	  }

	  function noteCanRetrySync(note: NoteDraft) {
	    if (!syncEnabled || note.cloudSyncScope === "local_only") return false;
	    if (note.syncState === "pending_upsert") return true;
	    if (note.syncBlockedReason === "session_expired" || note.syncBlockedReason === "network") return true;
	    if (note.syncBlockedReason === "quota_note_count" || note.syncBlockedReason === "quota_storage") return !usageIsFull();
	    return false;
	  }

	  function noteCanKeepLocalOnly(note: NoteDraft) {
	    return syncEnabled && note.cloudSyncScope !== "local_only" && Boolean(note.syncBlockedReason);
	  }
</script>

<svelte:window onkeydown={handleWindowKeydown} />

<main class="vault-settings-screen" aria-label="Vault settings">
  <div class="settings-drag-strip" data-tauri-drag-region="deep" aria-hidden="true"></div>

  <button
    class="settings-screen-close"
    type="button"
    title="Close settings"
    aria-label="Close settings"
    onclick={closeSettings}
  >
    <X size={20} aria-hidden="true" />
  </button>

  <button
    class="settings-screen-back"
    type="button"
    title="Back to notes"
    aria-label="Back to notes"
    data-tauri-drag-region="false"
    onclick={closeSettings}
  >
    <ArrowLeft size={17} aria-hidden="true" />
    <span>Back to notes</span>
  </button>

  <VaultSettingsSidebar {activeSection} setActiveSection={(section) => (activeSection = section)} />

  <section class="settings-content-panel" aria-live="polite">
    {#if activeSection === "general"}
      <div class="settings-page">
        <VaultSettingsCard>
          <VaultSettingsRow title="Connected VerusID" description="Wallet identity for this vault.">
            {#snippet action()}
              <span class="settings-value-chip" title={connectedVerusIdTitle}>{connectedVerusIdLabel}</span>
            {/snippet}
          </VaultSettingsRow>

          <VaultSettingsRow title="Appearance" description="Follow system appearance, or choose manually.">
            {#snippet action()}
              <div class="settings-segmented-control" role="group" aria-label="Appearance">
                <button
                  class:active={appearanceMode === "system"}
                  type="button"
                  aria-pressed={appearanceMode === "system"}
                  onclick={() => setAppearanceMode("system")}
                >
                  System
                </button>
                <button
                  class:active={appearanceMode === "light"}
                  type="button"
                  aria-pressed={appearanceMode === "light"}
                  onclick={() => setAppearanceMode("light")}
                >
                  Light
                </button>
                <button
                  class:active={appearanceMode === "dark"}
                  type="button"
                  aria-pressed={appearanceMode === "dark"}
                  onclick={() => setAppearanceMode("dark")}
                >
                  Dark
                </button>
              </div>
            {/snippet}
          </VaultSettingsRow>
        </VaultSettingsCard>
      </div>
    {:else if activeSection === "cloud"}
      <div class="settings-page">
        <VaultSettingsCard>
          <VaultSettingsRow
            title="Encrypted cloud sync"
            description="Upload encrypted records for this vault."
          >
            <div class="settings-cloud-summary">
              <div class="settings-state-row">
                <span>Status</span>
                <strong>{settingsStorageLabel}</strong>
              </div>
              <p class="settings-encryption-note">
                <ShieldCheck size={14} aria-hidden="true" />
                <span>End-to-end encrypted. The cloud cannot read note text or folder names.</span>
              </p>
              {#if syncEnabled}
                <div class:full={usageIsFull()} class="settings-quota-panel" role="status">
                  <div class="settings-quota-header">
                    <span>Free cloud sync</span>
                    <strong>{displayedSyncedNoteCount} of {displayedMaxNotes} notes included</strong>
                  </div>
                  <div class="settings-quota-meter" aria-hidden="true">
                    <span
                      class:has-usage={displayedSyncedNoteCount > 0}
                      style={`width: ${usagePercent(displayedSyncedNoteCount, displayedMaxNotes)}%`}
                    ></span>
                  </div>
                  <div class="settings-quota-header">
                    <span>Encrypted storage</span>
                    <strong>{formatStorageBytes(displayedStorageBytes)} of {formatStorageBytes(displayedMaxStorageBytes)} used</strong>
                  </div>
                  <div class="settings-quota-meter" aria-hidden="true">
                    <span
                      class:has-usage={displayedStorageBytes > 0}
                      style={`width: ${usagePercent(displayedStorageBytes, displayedMaxStorageBytes)}%`}
                    ></span>
                  </div>
                  {#if usageIsFull()}
                    <p>New notes stay on this device until you free space.</p>
                  {/if}
                </div>
              {/if}
            </div>
            {#if cloudSyncNeedsNewWalletUnlock}
              <div class="settings-sync-alert" role="status">
                <CircleAlert size={16} aria-hidden="true" />
                <div>
                  <strong>Cloud sync needs new wallet unlock</strong>
                  <p>
                    The vault is still unlocked here and your changes are saved on this device. Lock this vault, then
                    unlock again with Verus Mobile to upload encrypted changes.
                  </p>
                </div>
              </div>
            {:else if storageStatusLabel === "Sync error"}
              <div class="settings-sync-alert" role="status">
                <CircleAlert size={16} aria-hidden="true" />
                <div>
                  <strong>Cloud sync could not finish</strong>
                  <p>{cloudStatus || "Your encrypted changes are saved on this device."}</p>
                </div>
              </div>
            {/if}
            {#if !canUseCloud}
              <p class="settings-note">Cloud sync is not configured in this build.</p>
            {:else if cloudCopyDeleted && !syncEnabled}
              <p class="settings-note">The cloud copy was removed. Enabling sync will create a new encrypted cloud copy.</p>
            {/if}

            {#snippet action()}
              <button
                class="primary-button settings-action-button"
                type="button"
                disabled={cloudActionDisabled}
                onclick={() => runSettingsAction(runCloudAction)}
              >
                {#if cloudSyncNeedsNewWalletUnlock}
                  <Lock size={16} />
                {:else if cloudHasRecoverableSyncError}
                  <RefreshCw size={16} />
                {:else}
                  <Cloud size={16} />
                {/if}
                <span>{cloudActionLabel}</span>
              </button>
            {/snippet}
          </VaultSettingsRow>

          {#if syncEnabled}
            <VaultSettingsRow
              title="Synced notes"
              description="Choose which notes are included in encrypted cloud sync."
            >
              {#snippet action()}
                <button class="secondary-button settings-action-button" type="button" onclick={showSyncNotesModal}>
                  <Cloud size={16} />
                  <span>Manage synced notes</span>
                </button>
              {/snippet}
            </VaultSettingsRow>
          {/if}

          <VaultSettingsRow
            title="Stop syncing this device"
            description="Keep this device local."
          >
            {#snippet action()}
              <button
                class="secondary-button settings-action-button"
                type="button"
                disabled={cloudBusy || !syncEnabled}
                onclick={() => runSettingsAction(stopSyncingThisDevice)}
              >
                Stop syncing
              </button>
            {/snippet}
          </VaultSettingsRow>

          <VaultSettingsRow
            title="Delete cloud copy"
            description="Remove encrypted records from cloud storage."
          >
            {#snippet action()}
              <button
                class="secondary-button danger settings-action-button"
                type="button"
                disabled={!canUseCloud || cloudBusy || cloudCopyDeleted || !syncEnabled}
                onclick={requestDeleteCloudCopy}
              >
                Delete cloud copy
              </button>
            {/snippet}
          </VaultSettingsRow>
        </VaultSettingsCard>
      </div>
    {:else}
      <div class="settings-page">
        <VaultSettingsCard>
          <VaultSettingsRow
            title="Export encrypted notes"
            description="Create an encrypted .verusnotes backup."
          >
            <p class="settings-note">Includes folders, notes, tombstones, and bookmarks.</p>

            {#snippet action()}
              <button class="secondary-button settings-action-button" type="button" onclick={() => runSettingsAction(exportEncryptedBackup)}>
                <Upload size={16} />
                <span>Export</span>
              </button>
            {/snippet}
          </VaultSettingsRow>

          <VaultSettingsRow
            title="Import encrypted notes"
            description="Merge a .verusnotes backup into this vault."
          >
            <p class="settings-note">Existing local notes stay in place.</p>
            <p class="settings-note">Conflicts are preserved instead of overwritten.</p>
            {#if syncEnabled}
              <p class="settings-note">Imported changes will queue for cloud sync after import.</p>
            {/if}

            {#snippet action()}
              <button class="secondary-button settings-action-button" type="button" onclick={() => runSettingsAction(importBackup)}>
                <Download size={16} />
                <span>Import</span>
              </button>
            {/snippet}
          </VaultSettingsRow>
        </VaultSettingsCard>
      </div>
    {/if}
  </section>

  {#if syncEnabled && syncNotesModalOpen}
    <div class="settings-modal-layer" role="presentation" onclick={closeSyncNotesModal}>
      <div
        class="settings-sync-modal sync-management-modal"
        role="dialog"
        tabindex="-1"
        aria-modal="true"
        aria-labelledby="settings-sync-modal-title"
        onclick={(event) => event.stopPropagation()}
        onkeydown={(event) => event.stopPropagation()}
      >
        <header class="settings-sync-modal-header">
          <div>
            <h2 id="settings-sync-modal-title">Manage synced notes</h2>
            <p>{displayedSyncedNoteCount} of {displayedMaxNotes} notes included in encrypted cloud sync</p>
          </div>
          <button
            class="settings-sync-modal-close"
            type="button"
            title="Close"
            aria-label="Close synced notes"
            onclick={closeSyncNotesModal}
          >
            <X size={18} aria-hidden="true" />
          </button>
        </header>

	        <div class="settings-sync-modal-body">
          {#if usageIsFull()}
            <p class="settings-sync-quota-note" role="status">
              Cloud sync is full. Keep a synced note local before including another.
            </p>
          {/if}

	          <div class="settings-sync-note-list sync-management-list" aria-label="Synced notes">
            {#if managedSyncNotes.length > 0}
              {#each managedSyncNotes as note}
                <div class="settings-sync-note-row sync-management-row">
                  <div class="settings-sync-note-copy">
                    <strong title={getNoteTitle(note)}>{getNoteTitle(note)}</strong>
                    <div class="settings-sync-note-meta">
                      <span class="settings-sync-note-folder" title={getFolderName(note.folderId)}>{getFolderName(note.folderId)}</span>
                      {#if noteIsCloudSynced(note)}
                        <span class="settings-sync-note-cloud-icon cloud" title="Cloud synced" aria-label="Cloud synced">
                          <Cloud size={13} aria-hidden="true" />
                        </span>
                      {:else}
                        <span class={noteSyncManagementTone(note)}>{noteSyncManagementLabel(note)}</span>
                      {/if}
                    </div>
                  </div>
                  <div class="settings-sync-note-actions">
                    {#if noteCanRetrySync(note)}
                      <button
                        class="secondary-button compact"
                        type="button"
                        disabled={cloudBusy}
                        title="Retry sync"
                        aria-label={`Retry sync for ${getNoteTitle(note)}`}
                        onclick={() => runSettingsAction(() => retryNoteSync(note.id))}
                      >
                        <RefreshCw size={14} aria-hidden="true" />
                      </button>
                    {/if}
                    {#if noteCanIncludeInCloudSync(note)}
                      <button
                        class="secondary-button compact"
                        type="button"
                        disabled={cloudBusy}
                        onclick={() => runSettingsAction(() => includeNoteInCloudSync(note.id))}
                      >
                        <Cloud size={14} aria-hidden="true" />
                        <span>Include</span>
	                      </button>
	                    {/if}
                    {#if noteNeedsQuotaBeforeInclude(note)}
                      <button
                        class="secondary-button compact"
                        type="button"
                        disabled
                        title="Keep a synced note local before including another note"
                        aria-label={`Include ${getNoteTitle(note)} in cloud sync unavailable because the quota is full`}
                      >
                        <Cloud size={14} aria-hidden="true" />
                        <span>Include</span>
                      </button>
                    {/if}
	                    {#if noteCanRemoveFromCloudSync(note)}
                      <button
                        class="secondary-button compact"
                        type="button"
                        disabled={cloudBusy}
                        onclick={() => runSettingsAction(() => removeNoteFromCloudSync(note.id))}
                      >
                        <CloudOff size={14} aria-hidden="true" />
                        <span>Keep local</span>
                      </button>
                    {/if}
                    {#if noteCanKeepLocalOnly(note)}
                      <button
                        class="secondary-button compact"
                        type="button"
                        disabled={cloudBusy}
                        onclick={() => runSettingsAction(() => removeNoteFromCloudSync(note.id))}
                      >
                        <CloudOff size={14} aria-hidden="true" />
                        <span>Keep local</span>
                      </button>
                    {/if}
                  </div>
                </div>
              {/each}
            {:else}
              <p class="settings-sync-modal-empty">No notes in this vault.</p>
            {/if}
          </div>
        </div>

        <footer class="settings-sync-modal-footer">
          <button class="secondary-button settings-action-button sync-management-done-button" type="button" onclick={closeSyncNotesModal}>
            Done
          </button>
        </footer>
      </div>
    </div>
  {/if}

  {#if confirmingDeleteCloudCopy}
    <ConfirmPopover
      body="This removes encrypted notes and folders from cloud storage. Local notes on this device stay available. This can't be undone."
      cancel={() => (confirmingDeleteCloudCopy = false)}
      confirm={confirmDeleteCloudCopy}
      confirmLabel="Delete cloud copy"
      danger
      heading="Delete cloud copy?"
      headingId="delete-cloud-copy-heading"
    />
  {/if}
</main>
