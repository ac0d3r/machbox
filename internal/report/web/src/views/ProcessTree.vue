<script setup>
import { ref } from 'vue'

const props = defineProps({
  node: Object,
  depth: { type: Number, default: 0 }
})

const expanded = ref(true)

const hasChildren = props.node?.children && props.node.children.length > 0
const eventCount = props.node?.events ? props.node.events.length : 0
const isSynthetic = props.node?.pid === 0 && props.node?.path === '<root>'
</script>

<template>
  <div class="tree-node" :class="{ 'synthetic-node': isSynthetic }">
    <div
      class="tree-row"
      :style="{ paddingLeft: (depth * 20 + 12) + 'px' }"
      @click="hasChildren && (expanded = !expanded)"
    >
      <span v-if="hasChildren" class="tree-toggle" :class="{ collapsed: !expanded }">▾</span>
      <span v-else class="tree-toggle-placeholder"></span>
      <span class="tree-pid">{{ node.pid }}</span>
      <span class="tree-path">{{ node.path || '-' }}</span>
      <span v-if="eventCount" class="tree-badge">{{ eventCount }} events</span>
    </div>
    <div v-if="expanded && hasChildren" class="tree-children">
      <ProcessTree
        v-for="child in node.children"
        :key="child.pid"
        :node="child"
        :depth="depth + 1"
      />
    </div>
  </div>
</template>

<style scoped>
.tree-node {
  font-size: 13px;
}
.tree-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 0;
  border-bottom: 1px solid #f5f5f5;
  cursor: default;
  transition: background 0.15s;
}
.tree-row:hover {
  background: #fafafa;
}
.tree-toggle {
  display: inline-block;
  width: 14px;
  text-align: center;
  color: #888;
  font-size: 12px;
  cursor: pointer;
  transition: transform 0.15s;
}
.tree-toggle.collapsed {
  transform: rotate(-90deg);
}
.tree-toggle-placeholder {
  display: inline-block;
  width: 14px;
}
.tree-pid {
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 12px;
  color: #e64a19;
  min-width: 50px;
}
.tree-path {
  color: #333;
  flex: 1;
  word-break: break-all;
}
.tree-badge {
  font-size: 11px;
  color: #888;
  background: #f5f5f5;
  padding: 1px 6px;
  border-radius: 10px;
  white-space: nowrap;
}
.synthetic-node .tree-row {
  font-weight: 600;
  color: #666;
}
</style>
