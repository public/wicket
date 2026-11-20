<!-- An agent's page: its head, what it can reach (the reference's showAuthority), and what it did. -->
<script>
  import { strip, at, whenMs, num, plural, verb, verbsOf, pathsText, nowSecs } from "./helpers.js";
  import RunRow from "./RunRow.svelte";
  import LogLine from "./LogLine.svelte";
  import Time from "./Time.svelte";
  let { s, run } = $props();

  const x = $derived(s.runs.find(r => r.id === run));
  const mine = $derived(s.audit.filter(op => op.run === run).slice().reverse());

  // Its authority, fetched once per page (as the reference does), not on every poll.
  let a = $state.raw(null), error = $state("");
  $effect(() => {
    const want = run;
    a = null; error = "";
    fetch("/api/runs/" + encodeURIComponent(want) + "/authority")
      .then(async r => { const j = await r.json().catch(() => ({ error: "unreadable answer" })); if (!r.ok) throw new Error(j.error || r.statusText); return j; })
      .then(j => { if (want === run) a = j; }, e => { if (want === run) error = strip(e.message); });
  });
  const t = $derived((a && a.token) || {});
  // What it can reach: its zone's rules, its live grants, the standing rules that apply to it.
  const reach = $derived.by(() => {
    if (!a) return [];
    const now = nowSecs(), out = [];
    for (const r of t.reach || []) out.push({ text: verbsOf(r.methods) + " " + strip(r.host) + "  " + pathsText(r.paths),
      note: "from its zone's rules" + (r.allow_dangerous ? "; including requests that can't be undone" : "") });
    for (const g of (t.grants || []).filter(g => !g.revoked && (!g.expires_at || g.expires_at > now))) out.push({ text: verb(g) + " " + strip(g.host + g.path),
      end: "you allowed it; ends ", endT: g.expires_at, endText: at(g.expires_at),
      note: (g.uses == null ? "any number of times" : plural(g.uses, "more time", "more times")) + " · allowed by " + strip(g.approved_by || "?") + (g.reached_node === false ? " · not yet on its server" : "") });
    const row = x || {};
    for (const r of ((s.standing || {}).rules || []).filter(r => r.live && (r.for === "zone" ? r.zone === t.zone : row.agent && String(r.principal || "").endsWith("/z/" + row.zone + "/a/" + row.agent))))
      out.push({ text: verbsOf(r.rule.methods) + " " + strip(r.rule.host) + "  " + pathsText(r.rule.paths), end: "always allowed, ",
        endT: r.expires_at, endText: r.expires_at ? "ends " + at(r.expires_at) : "until removed", note: r.for === "zone" ? "for every agent in its zone" : "for this agent" });
    return out;
  });
  const where = $derived.by(() => {
    if (!a) return [];
    const kv = [["server", strip(a.node)]];
    if (a.deadline) kv.push(["its permissions end", whenMs(a.deadline.until_ms) + (a.deadline.stopped ? " (stopped)" : "")]);
    if (a.holdings) {
      kv.push(["keys it can use", a.holdings.secrets.length ? a.holdings.secrets.map(strip).join(", ") : "none"]);
      const sl = a.holdings.slice;
      kv.push(["model budget left on its server", sl ? num(sl.requests) + " requests, " + num(sl.output_tokens) + " output tokens" + (sl.input_tokens != null ? ", " + num(sl.input_tokens) + " input tokens" : "") : "none"]);
    }
    kv.push(["organisation rules", a.policy.version ? strip(a.policy.version) + (a.policy.current ? " (current)" : " (not the installed " + strip(a.policy.installed || "none") + ")") : "none"]);
    return kv;
  });
  const grantText = g => g.method + " " + g.host + g.path + " · " + (g.uses == null ? "unlimited uses" : g.uses + " uses (counted on the node)") +
    " · ends " + at(g.expires_at) + " · approved by " + (g.approved_by || "?") + " at " + at(g.approved_at) +
    (g.revoked ? " · revoked" : "") + (g.reached_node === false ? " · not yet on its node" : "");
</script>

{#snippet kv(k, v)}<div class="row"><span class="meta">{k}</span><span class="mono">{strip(v)}</span></div>{/snippet}

<section class="view" id="view-agent" aria-labelledby="detail-title">
  <a class="back" href="#agents">‹ Agents</a>
  <div id="agent-head">
    {#if x}<RunRow {s} {x} page />{:else}<h2>Agent</h2><p class="note">This agent run isn't in the latest list (only the 15 most recent are).</p>{/if}
  </div>
  <div class="card" id="detail">
    <div class="card-head"><h3 id="detail-title">Permissions</h3></div>
    <div id="detail-body">
      {#if error}<div class="blocked">{error}</div>
      {:else if !a}<div class="meta">loading…</div>
      {:else}
        <h4>Can reach</h4>
        {#each reach as r (r.text)}
          <div class="reach"><div class="mono">{r.text}</div><div class="meta">{#if r.end}<span>{r.end}{#if r.endT}<Time t={r.endT} text={r.endText} />{:else}{r.endText}{/if}</span>{" · "}{/if}{r.note}</div></div>
        {/each}
        {#if !t.held}<div class="note">{"No token now: " + strip(t.why)}</div>
        {:else if !reach.length}<div class="empty">Nothing: everything it asks for waits for you.</div>{/if}
        <h4>Where it runs</h4>
        {#if a.revoked}<div class="callout warn">{"Stopped by " + strip(a.revoked.by) + ": " + strip(a.revoked.reason)}</div>{/if}
        {#each where as [k, v] (k)}{@render kv(k, v)}{/each}
        {#if t.held}
          <details class="more">
            <summary>Technical details: its token, grants and zone policy</summary>
            {@render kv("status", strip(a.status) + (a.feed ? " · node feed epoch " + strip(a.feed.epoch) : ""))}
            {@render kv("token", "box " + strip(t.box_path) + " · epoch " + strip(t.epoch) + " · zone " + strip(t.zone) + " · minted by " + strip(t.issued_by) +
              (t.loads === true ? " · loads" : " · does NOT load: " + strip((t.loads || {}).error || "")))}
            {#each t.blocks || [] as b (b.index)}
              <div class="row"><span class={b.revoked ? "blocked" : "ok"}>{"block " + b.index + " · " + strip(b.kind) + (b.revoked ? " · REVOKED" : "")}</span><span class="meta">{"revocation " + strip(b.revocation_fingerprint) + (b.signed_by ? " · signed by " + strip(b.signed_by) : "")}</span></div>
              <pre class="src">{b.source}</pre>
            {/each}
            {#each t.grants || [] as g (g.id)}{@render kv(g.id, grantText(g))}{/each}
            {#if t.zone_cedar}<div class="meta">zone policy (Cedar, generated from the manifest)</div><pre class="src">{t.zone_cedar}</pre>{/if}
          </details>
        {/if}
      {/if}
    </div>
  </div>
  <div class="card"><h3>Recent activity</h3><div class="log" id="agent-log">
    {#each mine as op (op.seq)}<LogLine {op} runs={s.runs} />{:else}<div class="empty">Nothing recorded for it in the latest activity.</div>{/each}
  </div></div>
</section>
