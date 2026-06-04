<script lang="ts">
  type Props = {
    body: string;
    cancel: () => void;
    cancelLabel?: string;
    confirm: () => void | Promise<void>;
    confirmLabel: string;
    danger?: boolean;
    heading: string;
    headingId: string;
  };

  let {
    body,
    cancel,
    cancelLabel = "Cancel",
    confirm,
    confirmLabel,
    danger = false,
    heading,
    headingId
  }: Props = $props();
</script>

<div class="confirm-popover-layer" role="presentation" onclick={cancel}>
  <div
    class="confirm-popover"
    role="dialog"
    tabindex="-1"
    aria-modal="true"
    aria-labelledby={headingId}
    onclick={(event) => event.stopPropagation()}
    oncontextmenu={(event) => {
      event.preventDefault();
      event.stopPropagation();
    }}
    onkeydown={(event) => event.stopPropagation()}
  >
    <h2 id={headingId}>{heading}</h2>
    <p>{body}</p>
    <div class="confirm-popover-actions">
      <button class="secondary-button" type="button" onclick={cancel}>{cancelLabel}</button>
      <button class:danger class="secondary-button" type="button" onclick={() => void confirm()}>{confirmLabel}</button>
    </div>
  </div>
</div>
