<!-- One record of activity as a sentence: the reference's logLine, from what `line` says. -->
<script>
  import { clock, line, strip } from "./helpers.js";
  import Time from "./Time.svelte";
  let { op, runs } = $props();
  const runName = id => { const x = runs.find(r => r.id === id); return x ? (x.agent ? strip(x.agent) : "a program") : strip(id); };
  const l = $derived(line(op, runName));
</script>

<div class="logline">{#if op.ts}<Time t={op.ts} text={clock(op.ts)} />{:else}<span></span>{/if}<span class="tag {l.tone}">{l.tag}</span><span class="text">{l.text}{#if l.why}{" "}<button type="button" class="link" onclick={() => console.info("explain", op.seq)}>why?</button>{/if}</span></div>
