<script lang="ts">
  import { Copy, Minus, Square, X } from "@lucide/svelte";
  import { isTauri } from "@tauri-apps/api/core";
  import type { UnlistenFn } from "@tauri-apps/api/event";
  import { getCurrentWindow } from "@tauri-apps/api/window";
  import { onMount } from "svelte";

  let controlsVisible = $state(false);
  let focused = $state(true);
  let maximized = $state(false);

  let appWindow: ReturnType<typeof getCurrentWindow> | null = null;
  const unlisteners: UnlistenFn[] = [];

  function isWindowsTauriRuntime() {
    return isTauri() && /\bWindows\b/i.test(window.navigator.userAgent);
  }

  async function refreshMaximizedState() {
    if (!appWindow) return;
    maximized = await appWindow.isMaximized();
  }

  async function minimizeWindow() {
    await appWindow?.minimize();
  }

  async function toggleMaximizedWindow() {
    await appWindow?.toggleMaximize();
    await refreshMaximizedState();
  }

  async function closeWindow() {
    await appWindow?.close();
  }

  onMount(() => {
    if (!isWindowsTauriRuntime()) return;

    let disposed = false;
    controlsVisible = true;
    appWindow = getCurrentWindow();
    document.documentElement.dataset.windowChrome = "windows";

    void refreshMaximizedState();
    void appWindow.onResized(() => void refreshMaximizedState()).then((unlisten) => {
      if (disposed) {
        unlisten();
        return;
      }
      unlisteners.push(unlisten);
    });
    void appWindow.onFocusChanged(({ payload }) => {
      focused = payload;
    }).then((unlisten) => {
      if (disposed) {
        unlisten();
        return;
      }
      unlisteners.push(unlisten);
    });

    return () => {
      disposed = true;
      controlsVisible = false;
      appWindow = null;
      for (const unlisten of unlisteners.splice(0)) unlisten();
      if (document.documentElement.dataset.windowChrome === "windows") {
        delete document.documentElement.dataset.windowChrome;
      }
    };
  });
</script>

{#if controlsVisible}
  <div class:inactive={!focused} class="windows-window-controls" aria-label="Window controls">
    <button
      class="windows-window-control"
      type="button"
      title="Minimize"
      aria-label="Minimize"
      data-tauri-drag-region="false"
      onclick={minimizeWindow}
    >
      <Minus size={14} aria-hidden="true" />
    </button>
    <button
      class="windows-window-control"
      type="button"
      title={maximized ? "Restore" : "Maximize"}
      aria-label={maximized ? "Restore" : "Maximize"}
      data-tauri-drag-region="false"
      onclick={toggleMaximizedWindow}
    >
      {#if maximized}
        <Copy size={13} aria-hidden="true" />
      {:else}
        <Square size={13} aria-hidden="true" />
      {/if}
    </button>
    <button
      class="windows-window-control close"
      type="button"
      title="Close"
      aria-label="Close"
      data-tauri-drag-region="false"
      onclick={closeWindow}
    >
      <X size={16} aria-hidden="true" />
    </button>
  </div>
{/if}
