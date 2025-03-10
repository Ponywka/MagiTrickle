<script lang="ts">
  import { tick } from "svelte";
  import Tooltip from "../common/Tooltip.svelte";
  import Select from "../common/Select.svelte";
  import Button from "../common/Button.svelte";
  import { API_BASE } from "../../utils/fetcher";
  import { Clear, Filter, ScrollToBottom, Save } from "../common/icons";

  const LOGS_BUFFER_LIMIT = 10000 as const;
  const SCROLL_TO_BOTTOM_DELTA = 40 as const;
  const LINE_HEIGHT = 16 as const;
  const OVERSCAN = 20 as const;

  type LogEntry = {
    time: string;
    level: string;
    message: string;
    error?: string;
  };

  const levels: Record<string, number> = {
    trace: -1,
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
    fatal: 4,
    panic: 5,
  };

  let items: LogEntry[] = $state([]);
  let level: string = $state("trace");
  let filter: string = $state("");
  let items_filtered: LogEntry[] = $derived.by(() =>
    items.filter(
      (item) =>
        levels[item.level] >= levels[level] &&
        (!filter ||
          filter.length === 0 ||
          item.message.includes(filter) ||
          item.error?.includes(filter)),
    ),
  );

  let spacer_height = $derived(items_filtered.length * LINE_HEIGHT);
  let container: HTMLDivElement = $state(document.createElement("div"));
  let container_height = $state(0);
  let scroll_top = $state(LINE_HEIGHT / 2);
  let start = $derived(Math.max(0, Math.floor(scroll_top / LINE_HEIGHT) - OVERSCAN));
  let end = $derived(
    Math.min(
      items_filtered.length,
      Math.ceil((scroll_top + container_height) / LINE_HEIGHT) + OVERSCAN,
    ),
  );
  let visible_items = $derived(items_filtered.slice(start, end));

  function scrollTopChanges() {
    scroll_top = container?.scrollTop ?? 0;
  }

  function stickToBottom() {
    if (
      container.scrollHeight - container.offsetHeight - container.scrollTop <
      SCROLL_TO_BOTTOM_DELTA
    ) {
      scrollToBottom();
    }
  }

  function scrollToBottom() {
    container.scrollTop = container.scrollHeight;
  }

  function clearLinesBuf() {
    items = [];
  }

  function saveLogs() {
    const blob = new Blob(
      [items_filtered.map(({ time, level, message }) => `${time} ${level} ${message}`).join("\n")],
      { type: "text/plain" },
    );
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `${new Date().getTime()}-mtrickle.log`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  let connect = false;
  $effect(() => {
    if (!connect && container_height > 0) {
      connect = true;
      connectToEndpoint();
    }
  });

  function connectToEndpoint() {
    console.debug("connect to logs endpoint");
    const es = new EventSource(`${API_BASE}/logs`);

    es.onmessage = async (event) => {
      const data = JSON.parse(event.data);
      items.push(data);
      if (items.length > LOGS_BUFFER_LIMIT) {
        items.shift();
      }
      await tick();
      stickToBottom();
    };
    es.onerror = (event) => {
      console.error("Failed to fetch logs:", event);
    };
    return () => {
      es.close();
    };
  }
</script>

<div class="logs-controls">
  <div class="filter">
    <Filter size={22} opacity={0.5} />
    <input type="text" class="filter-input" placeholder="filter logs..." bind:value={filter} />
    <Select
      options={Object.keys(levels).map((item) => ({
        label: item,
        value: item,
      }))}
      bind:selected={level}
      style="width: 100px"
    />
  </div>

  <div class="logs-controls-actions">
    <Tooltip value="Save Logs">
      <Button onclick={saveLogs}>
        <Save size={22} />
      </Button>
    </Tooltip>
    <Tooltip value="Clear">
      <Button onclick={clearLinesBuf}><Clear size={22} /></Button>
    </Tooltip>
    <Tooltip value="Scroll to bottom">
      <Button onclick={scrollToBottom}><ScrollToBottom size={22} /></Button>
    </Tooltip>
  </div>
</div>

<div
  bind:this={container}
  bind:clientHeight={container_height}
  onscroll={scrollTopChanges}
  class="container"
>
  <div class="spacer" style="height: {spacer_height}px;"></div>

  {#each visible_items as { time, level, message, error }, index (index)}
    <div class="line" style="top: {(start + index) * LINE_HEIGHT + 5}px; height: {LINE_HEIGHT}px;">
      <span class="time">{time}</span>
      <span class={level}>{level.toLocaleUpperCase()}</span>
      {message}{error ? ", " + error : ""}
    </div>
  {/each}
</div>

<style>
  .container {
    position: relative;
    height: 600px;
    overflow: auto;
    padding: 0.3rem 0.5rem;
    border-radius: 0.5rem;
    background-color: var(--bg-dark-extra);
    border: 1px solid var(--bg-light-extra);
  }

  .spacer {
    position: relative;
  }

  .logs-controls {
    display: flex;
    align-items: end;
    justify-items: end;
    gap: 0.5rem;
    padding: 0.5rem 0 0.5rem 0;
    margin-bottom: 0.5rem;
  }

  .logs-controls-actions {
    display: flex;
    align-items: end;
    justify-content: end;
    gap: 0.5rem;
    width: 100%;
  }

  .filter {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    background-color: var(--bg-dark-extra);
    padding: 0.5rem;
    border-radius: 0.5rem;
    border: 1px solid var(--bg-light-extra);
    width: 100%;
  }

  .filter-input {
    & {
      border: none;
      background-color: transparent;
      font-size: 1rem;
      font-weight: 400;
      font-family: var(--font);
      color: var(--text);
      top: 0.1rem;
      border-bottom: 1px solid transparent;
      width: 100%;
      position: relative;
    }

    &:focus-visible {
      outline: none;
      border-bottom: 1px solid var(--accent);
    }
  }

  .line {
    position: absolute;
    font-family: var(--font-mono);
    font-size: 0.8rem;
    white-space: nowrap;
  }

  .time {
    color: var(--text-2);
  }

  .trace {
    color: #e0e0e0;
  }
  .debug {
    color: #00aaff;
  }
  .info {
    color: #66bb6a;
  }
  .warn {
    color: #ffd600;
  }
  .error {
    color: #ff3d3d;
  }
  .fatal {
    color: #ff1493;
  }
  .panic {
    color: #ff4500;
  }
</style>
