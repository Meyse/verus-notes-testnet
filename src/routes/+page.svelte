<script lang="ts">
  import { env } from "$env/dynamic/public";
  import { onDestroy, onMount } from "svelte";
  import LockedAccess from "$lib/notes/components/LockedAccess.svelte";
  import StorageOnboarding from "$lib/notes/components/StorageOnboarding.svelte";
  import WindowsWindowControls from "$lib/notes/components/WindowsWindowControls.svelte";
  import Workspace from "$lib/notes/components/Workspace.svelte";
  import { createNotesAppController } from "$lib/notes/notesAppController.svelte";
  import "$lib/notes/styles.css";

  const CONVEX_URL = env.PUBLIC_CONVEX_URL || (import.meta.env.VITE_CONVEX_URL as string | undefined);
  const controller = createNotesAppController({ convexUrl: CONVEX_URL });

  onMount(() => {
    controller.mount();
  });

  onDestroy(() => {
    controller.destroy();
  });
</script>

<svelte:head>
  <title>Verus Notes</title>
</svelte:head>

<WindowsWindowControls />

{#if controller.screen === "workspace"}
  <Workspace view={controller.workspaceView} commands={controller.workspaceCommands} />
{:else if controller.screen === "storage"}
  <StorageOnboarding view={controller.storageView} commands={controller.storageCommands} />
{:else}
  <LockedAccess view={controller.lockedView} commands={controller.lockedCommands} />
{/if}
