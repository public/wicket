<!-- The console's frame: the tabs, routed by location.hash; the 2 s poll of /api/state. -->
<script>
  import { onMount } from "svelte";
  import { strip, setSkew, problemList } from "./helpers.js";
  import Inbox from "./Inbox.svelte";
  import Agents from "./Agents.svelte";
  import AgentPage from "./AgentPage.svelte";

  let s = $state.raw(null);
  let signedIn = $state(null);
  let stale = $state("");
  let hash = $state(location.hash);
  let lastHeard = 0;

  const route = $derived.by(() => {
    const ag = /^#agent\/([A-Za-z0-9_-]{1,80})$/.exec(hash);
    if (ag) return { view: "agent", run: ag[1] };
    return { view: ["#agents", "#activity", "#settings"].includes(hash) ? hash.slice(1) : "inbox" };
  });
  const tab = $derived(route.view === "agent" ? "agents" : route.view);
  const waiting = $derived(s ? s.pending.length + ((s.standing || {}).asks || []).length : 0);
  const alerts = $derived(s ? problemList(s).length : 0);
  $effect(() => { document.title = waiting ? "(" + waiting + ") wicket" : "wicket"; });

  // One poll at a time, each bounded: a hung fetch is a stale page, said so, not a frozen one.
  let polling = false;
  async function poll() {
    if (polling) return;
    polling = true;
    try {
      const r = await fetch("/api/state", { signal: AbortSignal.timeout(10000) });
      if (r.status === 401 || r.status === 403) { signedIn = false; return; }
      if (!r.ok) { stale = "HTTP " + r.status; return; }
      const j = await r.json();
      if (typeof j.now === "number") setSkew(j.now - Date.now() / 1000);
      lastHeard = Date.now(); stale = ""; s = j;
    } catch (e) {
      stale = e && e.name === "TimeoutError" ? "no answer in 10 s" : "no answer";
    } finally { polling = false; }
  }
  const staleText = $derived(stale && "Can't reach wicket (" + stale + ")" +
    (lastHeard ? " since " + new Date(lastHeard).toISOString().slice(11, 19) + "Z; what is shown is as of then" : "") + ". Retrying.");

  onMount(() => {
    const onHash = () => { hash = location.hash; window.scrollTo(0, 0); };
    window.addEventListener("hashchange", onHash);
    let timer;
    (async () => {
      // Like the other prototypes, no sign-in check first: it costs every candidate the same round trip.
      signedIn = true;
      await poll();
      timer = setInterval(poll, 2000);
    })();
    return () => { window.removeEventListener("hashchange", onHash); clearInterval(timer); };
  });
</script>

<a class="skip" href="#main">Skip to the page</a>
<header class="top">
  <div class="bar"><h1>wicket</h1><span id="tenant">{s ? "tenant " + strip(s.tenant) : ""}</span></div>
  <nav id="nav" aria-label="Views" hidden={!signedIn}>
    {#each [["inbox", "Inbox"], ["agents", "Agents"], ["activity", "Activity"], ["settings", "Settings"]] as [v, label] (v)}
      <a href={"#" + v} data-view={v} aria-current={tab === v ? "page" : undefined}>{label}{#if v === "inbox"}<span class="count" id="nav-waiting" hidden={!waiting}>{waiting || ""}</span>{:else if v === "settings"}<span class="count bad" id="nav-health" hidden={!alerts}>{alerts || ""}</span>{/if}</a>
    {/each}
  </nav>
</header>
<div class="banner" id="stale" role="status" hidden={!stale}>{staleText}</div>
<main id="main">
  {#if signedIn === false}
    <div id="auth" class="card narrow"><div>Sign in to approve or deny what your agents are waiting on, start runs and steer them.</div></div>
  {:else if s}
    <div id="console">
      {#if route.view === "inbox"}<Inbox {s} {waiting} />
      {:else if route.view === "agents"}<Agents {s} />
      {:else if route.view === "agent"}<AgentPage {s} run={route.run} />
      {:else}<section class="view"><h2>{route.view === "activity" ? "Activity" : "Settings"}</h2><p class="note">Not in this prototype.</p></section>{/if}
    </div>
  {/if}
</main>
