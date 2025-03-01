<script lang="ts">
  import { Tooltip } from "bits-ui";
  import type { Snippet } from "svelte";

  // FIXME: fix error with Arrow ResizeObserver
  // TODO: add animation

  type Props = {
    value?: string;
    children: Snippet;
  };
  let { value, children }: Props = $props();
</script>

<Tooltip.Provider delayDuration={50}>
  <Tooltip.Root>
    <Tooltip.Trigger>
      {@render children()}
    </Tooltip.Trigger>
    <Tooltip.Content sideOffset={5}>
      {value}
    </Tooltip.Content>
  </Tooltip.Root>
</Tooltip.Provider>

<style>
  :global {
    [data-tooltip-trigger] {
      background: transparent;
      border: none;
      padding: 0;
      margin: 0;
    }

    [data-tooltip-content] {
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 0.5rem;
      border: 1px solid var(--bg-light-extra);
      background-color: var(--bg-dark);
      padding: 0.1rem 0.5rem 0.1rem 0.5rem;
      font-size: smaller;
      color: var(--text);
    }
  }
</style>
