<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { formatDate, badgeClass } from '../utils.js'

const parseEnv = (env) => {
  if (!env) return '-'
  if (env.os_version && env.build_version) {
    return `${env.os_version} (${env.build_version})`
  }
  return env.os_version || '-'
}

const reports = ref([])
const loading = ref(true)
const error = ref(null)
const router = useRouter()

onMounted(async () => {
  try {
    const res = await fetch('./api/reports')
    if (!res.ok) throw new Error(await res.text())
    reports.value = await res.json()
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
})

const goDetail = (id) => router.push(`/report/${id}`)
</script>

<template>
  <div class="list-page">
    <div class="list-card">
      <div class="list-header">
        <h2>Analysis Reports</h2>
        <span class="count">{{ reports.length }} reports</span>
      </div>
      <div v-if="loading" class="loading">Loading...</div>
      <div v-else-if="error" class="error">{{ error }}</div>
      <table v-else class="data-table">
        <thead>
          <tr>
            <th>File Name</th>
            <th>File Type</th>
            <th>OS Version</th>
            <th>Analysis Time</th>
            <th>Verdict</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in reports" :key="r.id" @click="goDetail(r.id)">
            <td>
              <div class="file-name">{{ r.sample_name }}</div>
              <div class="file-hash">{{ r.sha256?.slice(0, 32) }}...</div>
            </td>
            <td>
              <span class="badge" :class="'badge-' + (r.file_type || 'unknown')">{{ r.file_type }}</span>
            </td>
            <td>{{ parseEnv(r.analysis_env) }}</td>
            <td>{{ formatDate(r.created_at) }}</td>
            <td>
              <span class="badge" :class="badgeClass(r.verdict)">{{ r.verdict }}</span>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-if="!loading && !error && reports.length === 0" class="empty">No reports yet.</div>
    </div>
  </div>
</template>

<style scoped>
.list-page { padding: 24px; max-width: 1200px; margin: 0 auto; }
.list-card { background: #fff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); padding: 20px; }
.list-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.list-header h2 { font-size: 18px; font-weight: 600; }
.count { font-size: 13px; color: #888; }
.data-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.data-table th { text-align: left; padding: 10px 12px; border-bottom: 1px solid #eee; color: #666; font-weight: 600; background: #fafafa; }
.data-table td { padding: 14px 12px; border-bottom: 1px solid #f0f0f0; vertical-align: middle; }
.data-table tbody tr:hover { background: #fafafa; cursor: pointer; }
.file-name { font-weight: 500; color: #333; }
.file-hash { font-size: 12px; color: #888; margin-top: 2px; font-family: monospace; }
.loading, .error, .empty { text-align: center; padding: 40px; color: #888; }
.error { color: #c62828; }


</style>
