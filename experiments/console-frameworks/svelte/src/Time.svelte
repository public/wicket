<!-- The reference's timeEl: a time as text, its exact UTC value in `title` and `datetime`. -->
<script>
  import { at, iso } from "./helpers.js";
  let { t, text, class: cls } = $props();
</script>

<time class={cls} title={t ? iso(t) : undefined} datetime={t ? iso(t) : undefined}>{text ?? at(t)}</time>
