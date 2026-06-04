<script lang="ts">
  import type { Snippet } from "svelte";

  type Props = {
    action?: Snippet;
    children?: Snippet;
    description?: string;
    title: string;
  };

  let { action, children, description, title }: Props = $props();
</script>

<section class="settings-row">
  <div class="settings-row-copy">
    <h3>{title}</h3>
    {#if description}
      <p>{description}</p>
    {/if}
    {#if children}
      {@render children()}
    {/if}
  </div>

  {#if action}
    <div class="settings-row-action">
      {@render action()}
    </div>
  {/if}
</section>
