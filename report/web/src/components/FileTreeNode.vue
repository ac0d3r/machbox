<script setup>
import { ref, computed } from 'vue'
import { formatSize } from '../utils.js'
import MachoAnalysis from './MachoAnalysis.vue'
import AppBundle from './AppBundle.vue'

defineOptions({ name: 'FileTreeNode' })

const props = defineProps({
  node: { type: Object, required: true },
  depth: { type: Number, default: 0 }
})

const expanded = ref(props.depth < 2)

const hasChildren = computed(() => props.node?.children && props.node.children.length > 0)
const nodeData = computed(() => props.node?.data)
const isDir = computed(() => props.node?.base?.is_dir)

const isMachoData = (data) => {
  if (!data || typeof data !== 'object') return false
  const keys = Object.keys(data)
  if (keys.length === 0) return false
  const first = data[keys[0]]
  return first && typeof first === 'object' && first.header !== undefined
}

const isMacho = computed(() => isMachoData(nodeData.value))
const isAppBundle = computed(() => props.node?.base?.type === 'appbundle')
const displayType = computed(() => {
  if (props.node?.base?.type === 'unknown' && props.node?.base?.is_dir) {
    return 'dir'
  }
  return props.node?.base?.type || 'unknown'
})
</script>

<template>
  <div class="tree-node">
    <div
      class="node-header"
      :style="{ paddingLeft: depth * 16 + 12 + 'px' }"
      :class="{ clickable: hasChildren || isMacho || isAppBundle || nodeData }"
      @click="(hasChildren || isMacho || isAppBundle || nodeData) && (expanded = !expanded)"
    >
      <span v-if="hasChildren || isMacho || isAppBundle || nodeData" class="arrow" :class="{ open: expanded }">▸</span>
      <span v-else class="arrow-placeholder"></span>
      <span class="node-name">{{ node.base?.name }}</span>
      <span class="badge" :class="'badge-' + displayType">{{ displayType }}</span>
      <span class="node-path">{{ node.base?.path }}</span>
      <span v-if="node.base?.size && !isDir" class="node-size">{{ formatSize(node.base.size) }}</span>
    </div>

    <div v-if="expanded" class="node-body">
      <div v-if="nodeData" class="node-data">
        <div v-if="isMacho" class="data-panel">
          <MachoAnalysis :data="nodeData" />
        </div>
        <div v-else-if="isAppBundle" class="data-panel">
          <AppBundle :data="nodeData" />
        </div>
        <div v-else class="data-panel json-viewer">
          <pre>{{ JSON.stringify(nodeData, null, 2) }}</pre>
        </div>
      </div>

      <div v-if="hasChildren" class="node-children">
        <FileTreeNode
          v-for="(child, idx) in node.children"
          :key="idx"
          :node="child"
          :depth="depth + 1"
        />
      </div>
    </div>
  </div>
</template>

<style scoped>
.tree-node {
  font-size: 13px;
}
.node-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 0;
  border-bottom: 1px solid #f5f5f5;
  transition: background 0.15s;
  border-radius: 4px;
}
.node-header.clickable {
  cursor: pointer;
}
.node-header.clickable:hover {
  background: #f9f9f9;
}
.node-name {
  font-weight: 500;
  color: #333;
  word-break: break-all;
}
.node-path {
  font-size: 12px;
  color: #888;
  flex: 1;
  word-break: break-all;
}
.node-size {
  font-size: 12px;
  color: #999;
  white-space: nowrap;
}
.arrow {
  display: inline-block;
  transition: transform 0.2s;
  font-size: 12px;
  width: 12px;
  text-align: center;
  color: #666;
}
.arrow.open {
  transform: rotate(90deg);
}
.arrow-placeholder {
  display: inline-block;
  width: 12px;
}
.badge {
  display: inline-block;
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 500;
  text-transform: uppercase;
  white-space: nowrap;
}
.badge-unknown { background: #f0f0f0; color: #666; }
.badge-zip { background: #fff3e0; color: #e65100; }
.badge-mach-o { background: #e3f2fd; color: #1565c0; }
.badge-directory,
.badge-dir { background: #f3e5f5; color: #6a1b9a; }
.badge-appbundle { background: #e8f5e9; color: #2e7d32; }

.node-data {
  padding: 8px 0 8px 12px;
}
.data-panel {
  margin-bottom: 8px;
}

.kv-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.kv-table th {
  width: 160px;
  text-align: left;
  padding: 8px 12px;
  color: #666;
  font-weight: 500;
  background: #fafafa;
  border-bottom: 1px solid #f0f0f0;
}
.kv-table td {
  padding: 8px 12px;
  border-bottom: 1px solid #f0f0f0;
  color: #333;
  word-break: break-all;
}

.json-viewer {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 12px;
  border-radius: 6px;
  overflow-x: auto;
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 400px;
  overflow-y: auto;
}
.json-viewer pre {
  margin: 0;
}
</style>
