<script setup>
import { ref, watch, computed } from 'vue'
import { formatSize } from '../utils.js'
import MachoAnalysis from '../components/MachoAnalysis.vue'
import AppBundle from '../components/AppBundle.vue'
import FileTreeNode from '../components/FileTreeNode.vue'

const props = defineProps({
  report: Object,
})

const expanded = ref({ base: true, deep: true })

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
</script>

<template>
  <div class="tab-panel">
    <h3 class="section-title">Static Analysis</h3>

    <!-- Base Info -->
    <div class="panel-card">
      <div class="panel-header" @click="expanded.base = !expanded.base">
        <span class="panel-icon">📋</span>
        <span>Base Info</span>
        <span class="arrow" :class="{ open: expanded.base }">▸</span>
      </div>
      <div v-show="expanded.base" class="panel-body">
        <table class="kv-table">
          <tr><th>File Name</th><td>{{ parsedStatic?.base?.name || report.sample_name }}</td></tr>
          <tr><th>File Format</th><td>{{ report.file_type || '-' }}</td></tr>
          <tr>
            <th>File Type</th>
            <td>
              {{ parsedStatic?.base?.evidence?.filetype || '-' }}
              <span v-if="parsedStatic?.base?.evidence?.mime" class="mime-hint">({{ parsedStatic.base.evidence.mime }})</span>
            </td>
          </tr>
          <tr><th>File Size</th><td>{{ formatSize(report.file_size) }}</td></tr>
          <tr><th v-if="parsedStatic?.base?.hash?.md5">MD5</th><td v-if="parsedStatic?.base?.hash?.md5">{{ parsedStatic.base.hash.md5 }}</td></tr>
          <tr><th v-if="parsedStatic?.base?.hash?.sha1">SHA1</th><td v-if="parsedStatic?.base?.hash?.sha1">{{ parsedStatic.base.hash.sha1 }}</td></tr>
          <tr><th v-if="parsedStatic?.base?.hash?.sha256">SHA256</th><td v-if="parsedStatic?.base?.hash?.sha256">{{ parsedStatic.base.hash.sha256 }}</td></tr>
          <tr><th>Extension</th><td>{{ parsedStatic?.base?.ext || '-' }}</td></tr>
        </table>
      </div>
    </div>

    <!-- Deep analysis -->
    <div class="panel-card" v-if="parsedStatic?.data">
      <div class="panel-header" @click="expanded.deep = !expanded.deep">
        <span class="panel-icon">🔍</span>
        <span>Deep Analysis</span>
        <span class="arrow" :class="{ open: expanded.deep }">▸</span>
      </div>
      <div v-show="expanded.deep" class="panel-body">
        <div v-if="isMachoData(parsedStatic.data)" class="macho-content">
          <MachoAnalysis :data="parsedStatic.data" />
        </div>
        <div v-else-if="parsedStatic.base?.type === 'appbundle'" class="appbundle-content">
          <AppBundle :data="parsedStatic.data" />
        </div>
        <div v-else class="json-viewer">{{ rawDataJson }}</div>
      </div>
    </div>

    <!-- Children -->
    <div class="panel-card" v-if="parsedStatic?.children && parsedStatic.children.length">
      <div class="panel-header">
        <span class="panel-icon">📁</span>
        <span>Children</span>
      </div>
      <div class="panel-body">
        <FileTreeNode
          v-for="(child, idx) in parsedStatic.children"
          :key="idx"
          :node="child"
        />
      </div>
    </div>
  </div>
</template>

<style scoped>
.section-title { font-size: 16px; font-weight: 600; margin-bottom: 16px; color: #333; display: flex; align-items: center; gap: 8px; }
.section-title::before { content: ''; display: inline-block; width: 4px; height: 16px; background: #e64a19; border-radius: 2px; }

/* Panel card */
.panel-card { background: #fff; border-radius: 8px; margin-bottom: 16px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,0.04); }
.panel-header {
  display: flex; align-items: center; gap: 8px;
  padding: 14px 20px; font-size: 14px; font-weight: 600; color: #333;
  background: #fafafa; border-bottom: 1px solid #f0f0f0; cursor: pointer;
}
.panel-header:hover { background: #f5f5f5; }
.panel-icon { font-size: 16px; }
.panel-body { padding: 16px 20px; }

/* Architecture block */
.arch-block { margin-bottom: 16px; border: 1px solid #eee; border-radius: 8px; overflow: hidden; }
.arch-title-row {
  display: flex; align-items: center; justify-content: space-between;
  padding: 12px 16px; background: #fafafa; cursor: pointer;
}
.arch-title-row:hover { background: #f5f5f5; }
.arch-title { font-size: 15px; font-weight: 600; color: #333; margin: 0; }
.arch-body { padding: 12px 16px; font-size: 12px; }

/* Sub-panel (collapsible inside deep analysis) */
.sub-panel { margin-bottom: 10px; border: 1px solid #f0f0f0; border-radius: 6px; overflow: hidden; }
.sub-panel-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 14px; font-size: 13px; font-weight: 600; color: #444;
  background: #f9f9f9; cursor: pointer;
}
.sub-panel-header:hover { background: #f3f3f3; }
.sub-panel-title { display: flex; align-items: center; gap: 6px; }
.sub-panel-body { padding: 12px 14px; }
.sub-panel-body.scrollable {
  max-height: 320px;
  overflow-y: auto;
  padding: 0;
}
.sub-panel-body.scrollable .data-table {
  margin-top: 0;
}
.sub-panel-body.scrollable .data-table thead th {
  position: sticky;
  top: 0;
  z-index: 2;
  background: #f5f5f5;
  border-bottom: 2px solid #e0e0e0;
}

/* Tables */
.kv-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.arch-body .kv-table,
.arch-body .data-table { font-size: 12px; }
.kv-table th { width: 160px; text-align: left; padding: 8px 12px; color: #666; font-weight: 500; background: #fafafa; border-bottom: 1px solid #f0f0f0; }
.kv-table td { padding: 8px 12px; border-bottom: 1px solid #f0f0f0; color: #333; word-break: break-all; }
.mime-hint { color: #888; font-size: 12px; margin-left: 6px; }
.data-table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }
.data-table th { text-align: left; padding: 8px 12px; background: #f5f5f5; color: #555; font-weight: 600; border-bottom: 1px solid #e0e0e0; }
.data-table td { padding: 8px 12px; border-bottom: 1px solid #f0f0f0; color: #333; }

/* Mach-O */
.cd-block { margin-bottom: 12px; padding: 10px; background: #fafafa; border-radius: 6px; }
.cd-title { font-size: 13px; font-weight: 600; color: #555; margin-bottom: 8px; padding-bottom: 6px; border-bottom: 1px solid #eee; }
.ent-row { display: flex; gap: 8px; align-items: flex-start; line-height: 1.6; font-size: 12px; }
.ent-row + .ent-row { margin-top: 4px; }
.ent-key { color: #555; font-weight: 500; min-width: 120px; word-break: break-all; }
.ent-val { color: #333; word-break: break-all; }
.sub-section { margin-bottom: 8px; border: 1px solid #f0f0f0; border-radius: 4px; overflow: hidden; }
.sub-section-header { display: flex; align-items: center; gap: 6px; padding: 8px 10px; font-size: 12px; font-weight: 600; color: #444; background: #f9f9f9; cursor: pointer; }
.sub-section-header:hover { background: #f3f3f3; }
.sub-section-body { padding: 0 10px 8px; max-height: 240px; overflow-y: auto; }
.sub-section-body .data-table thead th {
  position: sticky;
  top: 0;
  z-index: 2;
  background: #f5f5f5;
  border-bottom: 2px solid #e0e0e0;
}
.import-block { margin-bottom: 8px; padding-left: 8px; border-left: 2px solid #e0e0e0; }
.import-lib { font-size: 12px; color: #666; cursor: pointer; display: flex; align-items: center; gap: 6px; padding: 4px 0; }
.import-lib:hover { color: #333; }
.import-count { font-size: 11px; color: #999; }
.arrow { display: inline-block; transition: transform 0.2s; font-size: 12px; }
.arrow.open { transform: rotate(90deg); }
.import-syms { font-size: 12px; color: #333; }
.import-sym { padding: 2px 0; font-family: "SFMono-Regular", Consolas, monospace; font-size: 10px; }
.string-block {
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 12px;
  line-height: 1.6;
  background: #fafafa;
  border: 1px solid #f0f0f0;
  border-radius: 4px;
  padding: 12px;
  margin: 0;
  max-height: 400px;
  overflow-y: auto;
  white-space: pre-wrap;
  word-break: break-all;
}
.more { font-size: 12px; color: #1976d2; margin-top: 4px; cursor: pointer; }
.more:hover { text-decoration: underline; }

/* Children */
.child-item { display: flex; align-items: center; gap: 10px; padding: 8px 0; border-bottom: 1px solid #f5f5f5; }
.child-name { font-weight: 500; color: #333; }
.child-path { font-size: 12px; color: #888; flex: 1; word-break: break-all; }

/* JSON viewer */
.json-viewer {
  background: #1e1e1e; color: #d4d4d4; padding: 16px; border-radius: 6px;
  overflow-x: auto; font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 12px; white-space: pre-wrap; word-break: break-all;
  max-height: 600px; overflow-y: auto;
}

</style>
