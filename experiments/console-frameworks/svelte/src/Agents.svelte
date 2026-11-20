<!-- Agents: who is working, waiting, finished or failed; each opens its own page. -->
<script>
  import RunRow from "./RunRow.svelte";
  let { s } = $props();
</script>

<section class="view" id="view-agents" aria-labelledby="agents-h">
  <div class="view-head"><h2 id="agents-h">Agents</h2><button type="button" class="approve" onclick={() => console.info("start")}>Start an agent…</button></div>
  <div class="card flush" id="runs">
    {#each s.runs as x (x.id)}<RunRow {s} {x} />{:else}<div class="empty">No runs yet.</div>{/each}
  </div>
</section>
