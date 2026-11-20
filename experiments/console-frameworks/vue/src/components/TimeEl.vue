<script setup>
// A time as text ("19:20 (in 8 h)" unless told otherwise), its exact UTC value in title and datetime.
import { at, iso } from "../shared.js";
defineProps({ t: Number, text: String });
</script>

<template>
  <time :title="t ? iso(t) : undefined" :datetime="t ? iso(t) : undefined">{{ text === undefined ? at(t) : text }}</time>
</template>
