<script setup>
// A long id shortened in the middle by the CSS, its head and tail kept; the whole id is its title.
import { computed } from "vue";
import { strip } from "../shared.js";
const props = defineProps({ id: String });
const id = computed(() => strip(props.id));
</script>

<template>
  <span class="id-short" :title="id"><template v-if="id.length <= 18">{{ id }}</template><template v-else><span
    class="id-head">{{ id.slice(0, -6) }}</span><span class="id-tail">{{ id.slice(-6) }}</span></template></span>
</template>
