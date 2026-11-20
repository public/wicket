<!-- The reference's idEl: a long id cut in the middle, its head and tail kept, the whole id its title. -->
<script>
  import { strip } from "./helpers.js";
  let { id } = $props();
  const s = $derived(strip(id));
</script>

<span class="id-short" title={s}>{#if s.length <= 18}{s}{:else}<span class="id-head">{s.slice(0, -6)}</span><span class="id-tail">{s.slice(-6)}</span>{/if}</span>
