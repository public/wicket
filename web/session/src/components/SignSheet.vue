<!-- What the passkey is about to sign (#124), as on the console's page: the server's reading of the
     action, fixed at the top of the screen above a phone's passkey sheet, blocking the page below.
     With it, as the console's sheet shows them (#652): what else an approval that widens would allow
     (`blast`, #369) and what approving an update request installs (`update`, #465). Both are read
     from the begun action, the object the passkey's challenge is the hash of, never from the page. -->
<script setup lang="ts">
import { ref, watch } from 'vue';
import { blastSections, describe, updateSections } from '../lib/wicket';
import { SETTLE_MS, sheet } from '../lib/sign';

const ready = ref(false);
let timer: ReturnType<typeof setTimeout> | undefined;
watch(
  () => sheet.value?.begun,
  (b) => {
    clearTimeout(timer);
    ready.value = false;
    // Not tappable at once: a second tap aimed at the button below mustn't land on it.
    if (b) timer = setTimeout(() => (ready.value = true), SETTLE_MS);
  },
);
const deny = (a: Record<string, any>) => a.decision === 'deny';
</script>

<template>
  <div v-if="sheet" class="sheet" role="dialog" aria-modal="true" aria-labelledby="sheet-title">
    <div class="card">
      <div id="sheet-title" class="title">Your passkey will sign exactly this:</div>
      <div class="what">{{ describe(sheet.begun.action) }}</div>
      <div v-for="(part, k) in [blastSections(sheet.begun.action.blast), updateSections(sheet.begun.action.update)].filter((p) => p.length)" :key="k" class="blast">
        <template v-for="(sec, i) in part" :key="i">
          <div class="head">{{ sec.title }}</div>
          <ul v-if="sec.items.length"><li v-for="(x, j) in sec.items" :key="j">{{ x }}</li></ul>
        </template>
      </div>
      <div v-if="sheet.waiting" class="state">Waiting for your passkey…</div>
      <div class="buttons">
        <button type="button" :class="deny(sheet.begun.action) ? 'deny' : 'approve'" :disabled="!ready || sheet.waiting" @click="sheet.go()">
          {{ deny(sheet.begun.action) ? 'Sign: deny' : 'Sign with passkey' }}
        </button>
        <button type="button" :disabled="sheet.waiting" @click="sheet.cancel()">Cancel</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.sheet { position: fixed; inset: 0; z-index: 10; background: rgba(10, 12, 16, .5); display: flex; align-items: flex-start; justify-content: center; padding: max(12px, env(safe-area-inset-top)) 12px 12px; }
.card { width: 100%; max-width: 720px; background: var(--card); border-radius: var(--radius); padding: 18px 20px; box-shadow: 0 12px 40px rgba(0, 0, 0, .28); }
.title { font-size: 13px; font-weight: 600; color: var(--quiet); }
.what { font: 600 16px/1.45 var(--sans); margin-top: 8px; word-break: break-word; }
.state { color: var(--quiet); font-size: 12.5px; margin-top: 8px; }
.blast { margin-top: 12px; padding: 10px 12px; border-radius: 8px; border: 1px solid var(--warn); font-size: 13.5px; word-break: break-word; }
.blast .head { color: var(--ink); }
.blast ul { margin: 4px 0 8px; padding-left: 20px; }
.buttons { display: flex; gap: 8px; margin-top: 16px; flex-wrap: wrap; }
.buttons button:first-child { flex: 1 1 auto; }
</style>
