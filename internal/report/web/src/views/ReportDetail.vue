<script setup>
import { ref, onMounted, watch, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import StaticAnalysis from './StaticAnalysis.vue'
import DynamicAnalysis from './DynamicAnalysis.vue'
import { formatDate, formatSize, badgeClass } from '../utils.js'

const route = useRoute()
const router = useRouter()
const report = ref(null)
const loading = ref(true)
const error = ref(null)
const activeTab = ref('static')

onMounted(async () => {
  try {
    const res = await fetch(`./api/reports/${route.params.id}`)
    if (!res.ok) throw new Error(await res.text())
    report.value = await res.json()
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
})

const parsedStatic = ref(null)
const parsedEnv = ref({})

watch(() => report.value?.static_result, (val) => {
  parsedStatic.value = val || null
}, { immediate: true })

watch(() => report.value?.analysis_env, (val) => {
  parsedEnv.value = val || {}
}, { immediate: true })

const hashes = computed(() => {
  const h = parsedStatic.value?.base?.hash || {}
  return [
    h.md5 && { label: 'MD5', value: h.md5 },
    h.sha1 && { label: 'SHA1', value: h.sha1 },
    h.sha256 && { label: 'SHA256', value: h.sha256 },
  ].filter(Boolean)
})

const typeLabel = computed(() => {
  const typ = report.value?.file_type || parsedStatic.value?.base?.type || '-'
  const mime = parsedStatic.value?.base?.mime
  return mime ? `${typ} · ${mime}` : typ
})

const hasDynamic = computed(() => !!report.value?.dynamic_result?.process_tree)

const navItems = computed(() => [
  { key: 'static', label: 'Static' },
  { key: 'dynamic', label: 'Dynamic', muted: !hasDynamic.value },
])
</script>

<template>
  <div v-if="loading" class="detail-page">
    <div class="loading">Loading...</div>
  </div>
  <div v-else-if="error" class="detail-page">
    <div class="error">{{ error }}</div>
  </div>
  <div v-else-if="report" class="detail-page">
    <aside class="sidebar">
      <button type="button" class="back-row" @click="router.push('/')">← Reports</button>
      <nav>
        <button
          v-for="item in navItems"
          :key="item.key"
          type="button"
          class="nav-item"
          :class="{ active: activeTab === item.key, muted: item.muted }"
          @click="activeTab = item.key"
        >
          {{ item.label }}
        </button>
      </nav>
    </aside>

    <main class="detail-main">
      <section class="overview-card">
        <div class="overview-top">
          <div class="title-block">
            <h1 class="sample-name">{{ report.sample_name }}</h1>
            <div class="meta-row">
              <span>{{ formatDate(report.created_at) }}</span>
              <span v-if="parsedEnv.os_version">
                {{ parsedEnv.os_version }}
                <template v-if="parsedEnv.build_version">({{ parsedEnv.build_version }})</template>
              </span>
            </div>
          </div>
          <div class="verdict-text" :class="badgeClass(report.verdict)">
            {{ report.verdict || 'Unknown' }}
          </div>
        </div>

        <div class="info-grid">
          <div class="info-item">
            <span class="info-label">Size</span>
            <span class="info-value">{{ formatSize(report.file_size) }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Type</span>
            <span class="info-value">{{ typeLabel }}</span>
          </div>
        </div>

        <div v-if="hashes.length" class="hash-section">
          <div
            v-for="h in hashes"
            :key="h.label"
            class="hash-row"
          >
            <span class="hash-label">{{ h.label }}</span>
            <span class="hash-value">{{ h.value }}</span>
          </div>
        </div>
      </section>

      <StaticAnalysis v-if="activeTab === 'static'" :report="report" />
      <DynamicAnalysis v-else :report="report" />
    </main>
  </div>
</template>

<style scoped>
.detail-page {
  display: flex;
  height: 100%;
}

.sidebar {
  width: 168px;
  background: #fff;
  border-right: 1px solid #e8e8e8;
  flex-shrink: 0;
  overflow-y: auto;
}

.back-row {
  display: block;
  width: 100%;
  padding: 14px 16px;
  font-size: 13px;
  color: #1976d2;
  cursor: pointer;
  border: 0;
  border-bottom: 1px solid #f0f0f0;
  background: transparent;
  text-align: left;
  font: inherit;
}

.back-row:hover {
  background: #f5f7fa;
}

.nav-item {
  display: block;
  width: 100%;
  padding: 12px 16px;
  font-size: 14px;
  color: #555;
  cursor: pointer;
  border: 0;
  background: transparent;
  text-align: left;
  font: inherit;
}

.nav-item:hover {
  background: #f5f7fa;
}

.nav-item.active {
  color: #e64a19;
  background: #fff3e0;
  font-weight: 600;
}

.nav-item.muted:not(.active) {
  color: #aaa;
}

.detail-main {
  flex: 1;
  overflow-y: auto;
  padding: 20px 24px;
  background: #f5f7fa;
}

.overview-card {
  background: #fff;
  border: 1px solid #ebebeb;
  border-radius: 10px;
  padding: 18px 20px;
  margin-bottom: 14px;
}

.overview-top {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 14px;
}

.title-block {
  min-width: 0;
  flex: 1;
}

.sample-name {
  margin: 0 0 6px;
  font-size: 20px;
  font-weight: 700;
  color: #222;
  word-break: break-all;
  line-height: 1.25;
}

.meta-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 16px;
  font-size: 12px;
  color: #888;
}

.verdict-text {
  flex-shrink: 0;
  font-size: 13px;
  font-weight: 700;
  padding: 6px 12px;
  border-radius: 6px;
  text-transform: capitalize;
  background: #f5f5f5;
  color: #616161;
}

.verdict-text.badge-clean {
  background: #e8f5e9;
  color: #2e7d32;
}

.verdict-text.badge-suspicious {
  background: #fff3e0;
  color: #ef6c00;
}

.verdict-text.badge-malicious {
  background: #ffebee;
  color: #c62828;
}

.verdict-text.badge-unknown {
  background: #f5f5f5;
  color: #616161;
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px 20px;
}

.info-item {
  display: flex;
  gap: 10px;
  align-items: baseline;
  min-width: 0;
}

.info-label {
  font-size: 12px;
  color: #999;
  min-width: 36px;
  flex-shrink: 0;
}

.info-value {
  font-size: 13px;
  color: #333;
  font-weight: 500;
  word-break: break-all;
}

.hash-section {
  margin-top: 14px;
  padding-top: 12px;
  border-top: 1px solid #f0f0f0;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.hash-row {
  display: flex;
  gap: 12px;
  align-items: baseline;
  font-size: 12px;
}

.hash-label {
  color: #999;
  min-width: 52px;
  flex-shrink: 0;
  font-weight: 600;
}

.hash-value {
  font-family: "SF Mono", "SFMono-Regular", Menlo, Consolas, monospace;
  color: #444;
  word-break: break-all;
}

.loading,
.error {
  text-align: center;
  padding: 60px;
  color: #888;
}

.error {
  color: #c62828;
}
</style>
