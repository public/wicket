<!-- An agent run, as the reference's renderRun builds it: the agent, its zone and state; the run id
     quieter under it; its links. On its own page (`page`), its name is the heading and it can be stopped. -->
<script>
  import { strip, rel } from "./helpers.js";
  import Time from "./Time.svelte";
  import IdShort from "./IdShort.svelte";
  let { s, x, page = false } = $props();

  const name = $derived(x.agent ? strip(x.agent) : "program run");
  const href = $derived("#agent/" + encodeURIComponent(x.id));
  const status = $derived(x.revoked ? "revoked" : String(x.status || ""));
  const waiting = $derived((s.pending || []).some(p => p.run === x.id));
  const tone = $derived(waiting ? "warn" : ({ running: "good", revoked: "bad", failed: "bad", hibernated: "info" })[status] || "");
  const said = $derived(waiting ? "waiting for you" : ({ running: "working", exited: "finished", revoked: "stopped by you", hibernated: "asleep" })[status] || strip(status));
</script>

<div class="row run">
  <div>
    <div class="run-head">{#if page}<h2 class="run-name">{name}</h2>{:else}<a class="run-name" {href}>{name}</a>{/if}<span class="meta">{" · zone " + strip(x.zone)}</span><span class="pill {tone}">{said}</span></div>
    <div class="meta"><Time t={x.started_at} text={"started " + rel(x.started_at, s.now)} />{#if x.ended_at}{" · "}<Time t={x.ended_at} text={"ended " + rel(x.ended_at, s.now)} />{/if}{" · "}<IdShort id={x.id} /></div>
    <div class="links">
      {#if x.acp && x.status === "running" && !x.revoked}<a class="session" href={"/session?run=" + encodeURIComponent(x.id)}>Live session</a>{/if}
      {#if x.remote_url && x.remote_url.startsWith("https://")}<a class="session" href={x.remote_url} target="_blank" rel="noopener noreferrer">Remote Control session ↗</a>{/if}
      {#if !page}<a {href}>What it can reach ›</a>{/if}
    </div>
  </div>
  {#if page && x.status === "running" && x.has_identity && !x.revoked}
    <span class="acts"><button class="deny" onclick={() => console.info("stop", x.id)}>Stop agent…</button></span>
  {/if}
</div>
