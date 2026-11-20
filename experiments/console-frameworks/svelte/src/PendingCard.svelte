<!-- A pending request, as the reference's pendingCard builds it: who, wants to, where, why, risk;
     the choices; the rest (on whose behalf, who in the box asked, the exact request, the ids) under Details. -->
<script>
  import { strip, rel, riskClass, riskLabel, riskCode, asks, verb, span } from "./helpers.js";
  import Time from "./Time.svelte";
  import IdShort from "./IdShort.svelte";
  let { p, now } = $props();

  const a = $derived(asks(p));
  const id = $derived(p.identity || {});
  const program = $derived(!id.verified && (id.error || "").startsWith("no identity was issued"));
  const idOk = $derived(id.verified || program);
  let showId = $state(false);
  // The first button's words are the server's terms for it (`once_terms`): a push is one window.
  const ot = $derived(p.once_terms || { uses: 1, ttl_secs: 600 });
  const window_ = $derived(ot.uses !== 1);
  const onceLabel = $derived(window_ ? "Allow for " + span(ot.ttl_secs) : a.internal ? "Allow" : "Allow once");
  // Only the steps the server grants: a push is one window, R3 and R4 one use, wicket's own kinds one decision.
  const oneStep = $derived(window_ || p.risk === "R4ExecOrPrivilege" || p.risk === "R3ExternalOrIrreversible");
  const parts = $derived(p.path && p.path !== "/" ? String(strip(p.path) + (p.scope_prefix ? "…" : "")).split(/(?<=[/.?&])/) : []);
  const who = $derived(p.attribution || []);
  const line = r => strip(r.agent) + " — " + strip(r.tool) + ": " + strip(r.call).slice(0, 120);
  const decide = choice => console.info("decide", { id: p.id, choice });
</script>

<div class="card req" data-id={p.id}>
  <div class="req-head"><span class="risk {riskClass(p.risk)}">{riskLabel(p.risk)}</span><Time class="age" t={p.created_at} text={rel(p.created_at, now)} /></div>
  <dl class="fields">
    <dt>Who</dt>
    <dd>
      <span class="who-ask">{#if id.verified}<span class="ok">{"✓ "}</span><button type="button" class="idname" title="Show its identity" aria-expanded={showId} onclick={() => (showId = !showId)}>{strip(id.agent)}</button>{" · zone " + strip(id.zone)}<div class="idline" hidden={!showId}>{strip(id.id)}</div>{:else if program}a program (it has no agent identity){:else}<span class="bad">{"We can't confirm which agent this is (" + strip(id.error || "unknown") + "). Only Don't allow is offered."}</span>{/if}</span>
    </dd>
    {#if a.internal}
      <dt>Wants to</dt><dd class="said">{a.what.charAt(0).toLowerCase() + a.what.slice(1)}</dd>
    {:else}
      <dt>Wants to</dt><dd class="said">{verb(p)}</dd>
      <dt>Where</dt>
      <dd><div class="where"><span class="host">{strip(p.host)}</span>{#if parts.length}<div class="path">{#each parts as part}{part}<wbr>{/each}</div>{/if}{#if p.scope_prefix}<div class="meta">and every page under it</div>{/if}</div></dd>
    {/if}
    <dt>Why</dt><dd class="why">{"“" + a.why + "”"}</dd>
  </dl>
  <div class="buttons ladder">
    {#if idOk}<button class="approve" onclick={() => decide("once")}>{onceLabel}</button>{/if}
    {#if idOk && !a.internal && !oneStep}<button onclick={() => decide("hour")}>Allow for 1 hour</button>{/if}
    <button class="deny apart" onclick={() => decide("deny")}>Don't allow</button>
  </div>
  <details class="more req-more">
    <summary>Details</summary>
    {#if id.verified}<div class="chain">{"On behalf of: " + (id.acting_for || []).map(strip).join(" → ")}</div>{/if}
    <div class="mono raw">{strip(p.method + " " + p.host + p.path) + " · risk class " + riskCode(p.risk)}</div>
    <div class="who">
      {#if !who.length}<div>Asked by (in the box): unknown (no agent event stream)</div>{/if}
      {#each who as w, i (i)}
        {@const rs = w.requesters || []}
        {#if w.basis === "none" || !rs.length}
          {#if who.length > 1}<div>Asked by (in the box): unknown — no tool call was in flight</div>{/if}
        {:else if w.basis === "ambiguous"}
          <div>{"Asked by (in the box): one of " + rs.length + " concurrent calls:"}</div>
          {#each rs as r, j (j)}<div class="cand">{"• " + line(r)}</div>{/each}
        {:else}
          <div>{"Asked by (in the box): " + line(rs[0])}</div>
        {/if}
      {/each}
      {#if who.length > 1}<div class="warn">Asked by more than one agent: one grant would serve all of them.</div>{/if}
      <div class="note">{(who.length ? "As the agent reports it, not proven: anything" : "Anything") + " in this box could use the grant."}</div>
    </div>
    <div class="meta">{strip(p.id) + " · zone " + strip(p.zone) + " · run "}<IdShort id={p.run} /></div>
    {#if idOk && !a.internal && oneStep}
      <div class="note">{window_ ? "A push is allowed as one window: any number of requests for " + span(ot.ttl_secs) + ", for its ref discovery and upload." : "This kind is allowed one request at a time."}</div>
    {/if}
  </details>
</div>
