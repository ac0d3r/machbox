<script setup>
import { ref, watch, computed } from 'vue'
import MachoAnalysis from '../components/MachoAnalysis.vue'
import AppBundle from '../components/AppBundle.vue'
import PackageInfo from '../components/PackageInfo.vue'
import FileTreeNode from '../components/FileTreeNode.vue'

const props = defineProps({
  report: { type: Object, required: true },
})

const parsedStatic = ref(null)

watch(() => props.report?.static_result, (val) => {
  parsedStatic.value = val || null
}, { immediate: true })

const isMachoData = (data) => {
  if (!data || typeof data !== 'object') return false
  const keys = Object.keys(data)
  if (keys.length === 0) return false
  const first = data[keys[0]]
  return first && typeof first === 'object' && first.header !== undefined
}

const rawDataJson = computed(() => {
  if (!parsedStatic.value?.data) return ''
  return JSON.stringify(parsedStatic.value.data, null, 2)
})

const hasDeep = computed(() => !!parsedStatic.value?.data)
const children = computed(() => parsedStatic.value?.children || [])
const hasChildren = computed(() => children.value.length > 0)
const hasContent = computed(() => hasDeep.value || hasChildren.value)

const deepTitle = computed(() => {
  const typ = parsedStatic.value?.base?.type
  if (typ === 'appbundle') return 'App bundle'
  if (typ === 'pkg') return 'Package'
  if (isMachoData(parsedStatic.value?.data)) return 'Mach-O'
  return 'Details'
})
</script>

<template>
  <div class="tab-panel">
    <div v-if="!hasContent" class="panel empty-state">
      <p class="empty-title">No static analysis</p>
      <p class="empty-hint">This report has no static result payload.</p>
    </div>

    <template v-else>
      <section v-if="hasDeep" class="panel">
        <div class="panel-head">{{ deepTitle }}</div>
        <div class="panel-body">
          <div v-if="isMachoData(parsedStatic.data)">
            <MachoAnalysis :data="parsedStatic.data" />
          </div>
          <div v-else-if="parsedStatic.base?.type === 'appbundle'">
            <AppBundle :data="parsedStatic.data" />
          </div>
          <div v-else-if="parsedStatic.base?.type === 'pkg'">
            <PackageInfo :data="parsedStatic.data" />
          </div>
          <pre v-else class="json-viewer">{{ rawDataJson }}</pre>
        </div>
      </section>

      <section v-if="hasChildren" class="panel">
        <div class="panel-head">
          <span>Contained artifacts</span>
          <span class="head-meta">{{ children.length }} top-level</span>
        </div>
        <div class="panel-body flush tree-wrap">
          <FileTreeNode
            v-for="(child, idx) in children"
            :key="idx"
            :node="child"
          />
        </div>
      </section>
    </template>
  </div>
</template>

<style scoped>
.tab-panel {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.panel {
  background: #fff;
  border: 1px solid #ebebeb;
  border-radius: 10px;
  overflow: hidden;
}

.panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 16px;
  font-size: 13px;
  font-weight: 600;
  color: #333;
  background: #fafafa;
  border-bottom: 1px solid #f0f0f0;
}

.head-meta {
  font-size: 11px;
  font-weight: 500;
  color: #999;
}

.panel-body {
  padding: 14px 16px;
}

.panel-body.flush {
  padding: 0;
}

.tree-wrap {
  max-height: 640px;
  overflow: auto;
}

.empty-state {
  padding: 48px 24px;
  text-align: center;
}

.empty-title {
  margin: 0 0 6px;
  font-size: 15px;
  font-weight: 600;
  color: #555;
}

.empty-hint {
  margin: 0 auto;
  max-width: 420px;
  font-size: 13px;
  line-height: 1.5;
  color: #999;
}

.json-viewer {
  margin: 0;
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 14px;
  border-radius: 6px;
  overflow: auto;
  font-family: "SF Mono", "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 480px;
}
</style>
