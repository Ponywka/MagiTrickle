<script lang="ts">
  import { Tabs } from "bits-ui";
  import Groups from "./blocks/Groups.svelte";
  import HeaderSettings from "./blocks/HeaderSettings.svelte";
  // import Logs from "./blocks/Logs.svelte";
  // import SettingsPage from "./blocks/Settings.svelte";

  let active_tab = $state("Groups");
</script>

<!-- TODO: add locales -->
<!-- TODO: add white/dark themes -->
<!-- TODO: make it adaptive -->
<main>
  <Tabs.Root bind:value={active_tab}>
    <nav>
      <Tabs.List>
        <Tabs.Trigger value="Groups">Groups</Tabs.Trigger>
        <!-- <Tabs.Trigger value="Settings">Settings</Tabs.Trigger> -->
        <!-- <Tabs.Trigger value="Logs">Logs</Tabs.Trigger> -->
      </Tabs.List>
      <div class="header-settings">
        <HeaderSettings />
      </div>
    </nav>
    <article>
      <Tabs.Content value="Groups">
        <Groups />
      </Tabs.Content>
      <!-- <Tabs.Content value="Settings">
        <SettingsPage />
      </Tabs.Content> -->
      <!-- <Tabs.Content value="Logs">
        <Logs />
      </Tabs.Content> -->
    </article>
  </Tabs.Root>
</main>

<style>
  main {
    display: flex;
    flex-direction: column;
    align-items: center;
  }

  nav {
    display: flex;
    flex-direction: row;
    align-items: center;
    justify-content: space-between;
  }

  :global {
    [data-tabs-root] {
      max-width: 1000px;
      width: 100%;
    }

    [data-tabs-list] {
      display: flex;
      flex-direction: row;
      gap: 1rem;
    }

    [data-tabs-trigger] {
      & {
        padding: 0.5rem 1rem;
        border: none;
        border-bottom: 2px solid transparent;
        font-size: 1.5rem;
        font-family: var(--font);
        background-color: transparent;
        color: var(--text);
      }

      &[data-state="active"] {
        color: var(--accent);
        border-color: var(--accent);
      }

      &[data-state="inactive"]:hover {
        border-color: var(--text);
      }
    }

    [data-tabs-content] {
      padding-top: 1rem;
    }
  }

  @media (max-width: 600px) {
    :global {
      [data-tabs-root] {
        width: 100%;
      }
    }
  }
</style>
