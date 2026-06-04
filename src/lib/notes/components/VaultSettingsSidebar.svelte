<script lang="ts">
  import { Archive, CircleUserRound, Cloud } from "@lucide/svelte";
  import type { VaultSettingsSectionId } from "$lib/notes/types";

  type Props = {
    activeSection: VaultSettingsSectionId;
    setActiveSection: (section: VaultSettingsSectionId) => void;
  };

  let { activeSection, setActiveSection }: Props = $props();

  const sections: Array<{
    id: VaultSettingsSectionId;
    label: string;
    icon: typeof CircleUserRound;
  }> = [
    { id: "general", label: "General", icon: CircleUserRound },
    { id: "cloud", label: "Cloud syncing", icon: Cloud },
    { id: "backup", label: "Backup", icon: Archive }
  ];
</script>

<aside class="settings-sidebar" aria-label="Settings sections">
  <nav>
    {#each sections as section}
      {@const SectionIcon = section.icon}
      <button
        class:active={activeSection === section.id}
        class="settings-sidebar-item"
        type="button"
        aria-current={activeSection === section.id ? "page" : undefined}
        onclick={() => setActiveSection(section.id)}
      >
        <SectionIcon size={17} aria-hidden="true" />
        <span>{section.label}</span>
      </button>
    {/each}
  </nav>
</aside>
