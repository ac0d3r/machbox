<script setup>
import { computed } from 'vue'

const props = defineProps({
  name: { type: String, required: true },
  lines: { type: Number, default: 2 },
})

const rawName = computed(() => String(props.name ?? ''))
</script>

<template>
  <span
    class="symbol-name"
    :title="rawName"
    :style="{ '--lines': lines }"
  >
    {{ rawName }}
  </span>
</template>

<style scoped>
.symbol-name {
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: var(--lines, 2);
  line-clamp: var(--lines, 2);
  overflow: hidden;
  text-overflow: ellipsis;
  word-break: break-all;
  font-family: "SFMono-Regular", Consolas, monospace;
}
</style>
