<script setup>
import { ref, onMounted, watch } from 'vue'
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

const navItems = [
  { key: 'static', label: 'Static Analysis', icon: '☰' },
  { key: 'dynamic', label: 'Dynamic Analysis', icon: '◎' },
]
</script>

<template>
  <div class="detail-page" v-if="loading">
    <div class="loading">Loading...</div>
  </div>
  <div class="detail-page" v-else-if="error">
    <div class="error">{{ error }}</div>
  </div>
  <div class="detail-page" v-else-if="report">
    <!-- Sidebar -->
    <aside class="sidebar">
      <div class="back-row" @click="router.push('/')">← Back to list</div>
      <nav>
        <div
          v-for="item in navItems"
          :key="item.key"
          class="nav-item"
          :class="{ active: activeTab === item.key }"
          @click="activeTab = item.key"
        >
          <span class="nav-icon">{{ item.icon }}</span>
          <span>{{ item.label }}</span>
        </div>
      </nav>
    </aside>

    <!-- Main -->
    <main class="detail-main">
      <!-- Overview card -->
      <div class="overview-card" v-once>
        <div class="overview-left">
          <div class="hex-icon">
            <svg viewBox="0 0 100 100" width="80" height="80">
              <polygon points="50,5 95,27.5 95,72.5 50,95 5,72.5 5,27.5" fill="none" stroke="#e67e22" stroke-width="3"/>
              <polygon points="50,15 85,33 85,67 50,85 15,67 15,33" fill="#fdf2e9" stroke="#e67e22" stroke-width="2"/>
              <text x="50" y="58" text-anchor="middle" fill="#e67e22" font-size="28" font-weight="700">?</text>
            </svg>
          </div>
          <div class="verdict-text" :class="badgeClass(report.verdict)">{{ report.verdict || 'Unknown' }}</div>
        </div>
        <div class="overview-right">
          <h1 class="sample-name">{{ report.sample_name }}</h1>
          <div class="meta-row">
            <span>Analysis Time: {{ formatDate(report.created_at) }}</span>
          </div>
          <div class="info-grid">
            <div class="info-item">
              <span class="info-label">File Size</span>
              <span class="info-value">{{ formatSize(report.file_size) }}</span>
            </div>
            <div class="info-item">
              <span class="info-label">File Type</span>
              <span class="info-value">{{ report.file_type || '-' }}</span>
            </div>
            <div class="info-item">
              <span class="info-label">OS Version</span>
              <span class="info-value env-box">{{ parsedEnv.os_version || '-' }} ({{ parsedEnv.build_version || '-' }})</span>
            </div>
          </div>
          <div class="hash-section" v-if="parsedStatic?.base?.hash?.md5 || parsedStatic?.base?.hash?.sha1 || parsedStatic?.base?.hash?.sha256">
            <div class="hash-title">HASH</div>
            <div class="hash-row" v-if="parsedStatic?.base?.hash?.md5">
              <span class="hash-label">MD5</span>
              <span class="hash-value">{{ parsedStatic.base.hash.md5 }}</span>
            </div>
            <div class="hash-row" v-if="parsedStatic?.base?.hash?.sha1">
              <span class="hash-label">SHA1</span>
              <span class="hash-value">{{ parsedStatic.base.hash.sha1 }}</span>
            </div>
            <div class="hash-row" v-if="parsedStatic?.base?.hash?.sha256">
              <span class="hash-label">SHA256</span>
              <span class="hash-value">{{ parsedStatic.base.hash.sha256 }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Tab content -->
      <StaticAnalysis v-if="activeTab === 'static'" :report="report" />
      <DynamicAnalysis v-else :report="report" />
    </main>
  </div>
</template>

<style scoped>
.detail-page { display: flex; height: 100%; }

/* Sidebar */
.sidebar {
  width: 220px; background: #fff; border-right: 1px solid #e8e8e8;
  flex-shrink: 0; overflow-y: auto;
}
.back-row {
  padding: 14px 16px; font-size: 13px; color: #1976d2; cursor: pointer;
  border-bottom: 1px solid #f0f0f0;
}
.back-row:hover { background: #f5f7fa; }
.nav-item {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 16px; font-size: 14px; color: #555; cursor: pointer;
}
.nav-item:hover { background: #f5f7fa; }
.nav-item.active { color: #e64a19; background: #fff3e0; font-weight: 600; }
.nav-icon { font-size: 16px; width: 20px; text-align: center; }

/* Main */
.detail-main { flex: 1; overflow-y: auto; padding: 20px 24px; background: #f5f7fa; }

/* Overview */
.overview-card {
  background: #fff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.06);
  padding: 24px; margin-bottom: 20px;
  display: flex; gap: 28px;
}
.overview-left {
  display: flex; flex-direction: column; align-items: center; gap: 12px;
  min-width: 100px;
}
.hex-icon { display: flex; align-items: center; justify-content: center; }
.verdict-text {
  font-size: 20px; font-weight: 700; padding: 4px 16px; border-radius: 4px;
}
.overview-right { flex: 1; }
.sample-name { font-size: 22px; font-weight: 700; margin-bottom: 12px; color: #222; }
.meta-row { display: flex; gap: 24px; font-size: 13px; color: #666; margin-bottom: 16px; }
.info-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin-bottom: 16px; }
.info-item { display: flex; gap: 8px; align-items: center; }
.info-label { font-size: 13px; color: #888; min-width: 70px; }
.info-value { font-size: 14px; color: #333; font-weight: 500; }
.env-box { border: 1px solid #e0e0e0; padding: 2px 8px; border-radius: 4px; background: #fafafa; }
.hash-section { margin-top: 12px; }
.hash-title { font-size: 13px; color: #888; margin-bottom: 8px; font-weight: 600; }
.hash-row { display: flex; gap: 12px; align-items: center; font-size: 13px; margin-bottom: 4px; }
.hash-label { color: #888; min-width: 60px; }
.hash-value { font-family: monospace; color: #333; word-break: break-all; }

.loading, .error { text-align: center; padding: 60px; color: #888; }
.error { color: #c62828; }
</style>
