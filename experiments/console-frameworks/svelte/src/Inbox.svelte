<!-- The Inbox: one line of how things are, what needs a decision, and what is wrong. -->
<script>
  import { plural, problemList } from "./helpers.js";
  import PendingCard from "./PendingCard.svelte";
  let { s, waiting } = $props();

  const working = $derived(s.runs.filter(r => r.status === "running" && !r.revoked).length);
  const problems = $derived(problemList(s));
</script>

<section class="view" id="view-inbox" aria-labelledby="inbox-h">
  <h2 id="inbox-h" class="sr-only">Inbox</h2>
  <p class="status" id="status" aria-live="polite"><a href="#agents">{plural(working, "agent working", "agents working")}</a>{#if waiting}{" · "}<a class="warn" href="#inbox">{plural(waiting, "request waiting for you", "requests waiting for you")}</a>{/if}{" · "}{#if problems.length}<a class="bad" href="#health">{plural(problems.length, "problem")}</a>{:else}<span class="ok">no problems</span>{/if}</p>
  <div class="grid inbox">
    <div>
      <h3 class="sub" id="waiting-h">{waiting ? "Needs you (" + waiting + ")" : "Needs you"}</h3>
      <div id="pending" class="deck">
        {#each s.pending as p (p.id)}<PendingCard {p} now={s.now} />{:else}<div class="empty">Nothing is waiting for you.</div>{/each}
      </div>
    </div>
    <div>
      <h3 class="sub">Problems</h3>
      <div id="problems" class="card flush">
        {#each problems as [tone, text, href], i (i + " " + text)}<a class="problem {tone}" {href}>{text}</a>{:else}<div class="empty">Nothing is wrong.</div>{/each}
      </div>
    </div>
  </div>
</section>
