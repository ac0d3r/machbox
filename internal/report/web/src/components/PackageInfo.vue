<script setup>
import { ref } from 'vue'

defineProps({
  data: Object,
})

const expanded = ref({ meta: true, scripts: true, components: true, signature: true })
</script>

<template>
  <div class="pkg-content">
    <div class="sub-panel">
      <div class="sub-panel-header" @click="expanded.meta = !expanded.meta">
        <span class="sub-panel-title">Package</span>
        <span class="arrow" :class="{ open: expanded.meta }">▸</span>
      </div>
      <div v-show="expanded.meta" class="sub-panel-body">
        <table class="kv-table">
          <tr><th>ID</th><td>{{ data.id || '-' }}</td></tr>
          <tr><th>Version</th><td>{{ data.version || '-' }}</td></tr>
          <tr><th>Location</th><td>{{ data.location || '-' }}</td></tr>
          <tr><th>Auth</th><td>{{ data.auth || '-' }}</td></tr>
          <tr v-if="data.payload">
            <th>Payload</th>
            <td>{{ data.payload.items || 0 }} items, {{ data.payload.size || 0 }} KB</td>
          </tr>
        </table>
      </div>
    </div>

    <div class="sub-panel" v-if="data.scripts?.preinstall || data.scripts?.postinstall">
      <div class="sub-panel-header" @click="expanded.scripts = !expanded.scripts">
        <span class="sub-panel-title">Scripts</span>
        <span class="arrow" :class="{ open: expanded.scripts }">▸</span>
      </div>
      <div v-show="expanded.scripts" class="sub-panel-body">
        <div v-if="data.scripts.preinstall" class="script-block">
          <div class="script-title">preinstall</div>
          <pre class="script-body">{{ data.scripts.preinstall }}</pre>
        </div>
        <div v-if="data.scripts.postinstall" class="script-block">
          <div class="script-title">postinstall</div>
          <pre class="script-body">{{ data.scripts.postinstall }}</pre>
        </div>
      </div>
    </div>

    <div class="sub-panel" v-if="data.components?.length">
      <div class="sub-panel-header" @click="expanded.components = !expanded.components">
        <span class="sub-panel-title">Components ({{ data.components.length }})</span>
        <span class="arrow" :class="{ open: expanded.components }">▸</span>
      </div>
      <div v-show="expanded.components" class="sub-panel-body">
        <table class="data-table">
          <thead>
            <tr><th>ID</th><th>Version</th><th>Location</th><th>Path</th></tr>
          </thead>
          <tbody>
            <tr v-for="(c, i) in data.components" :key="i">
              <td>{{ c.id || '-' }}</td>
              <td>{{ c.version || '-' }}</td>
              <td>{{ c.location || '-' }}</td>
              <td>{{ c.path || '-' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="sub-panel" v-if="data.signature">
      <div class="sub-panel-header" @click="expanded.signature = !expanded.signature">
        <span class="sub-panel-title">Signature</span>
        <span class="arrow" :class="{ open: expanded.signature }">▸</span>
      </div>
      <div v-show="expanded.signature" class="sub-panel-body">
        <table class="kv-table">
          <tr><th>Status</th><td>{{ data.signature.status || '-' }}</td></tr>
          <tr><th>Notarized</th><td>{{ data.signature.notarized ? 'Yes' : 'No' }}</td></tr>
          <tr v-if="data.signature.timestamp"><th>Timestamp</th><td>{{ data.signature.timestamp }}</td></tr>
        </table>
      </div>
    </div>
  </div>
</template>

<style scoped>
.pkg-content { font-size: 12px; }
.sub-panel { margin-bottom: 10px; border: 1px solid #f0f0f0; border-radius: 6px; overflow: hidden; }
.sub-panel-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 14px; font-size: 13px; font-weight: 600; color: #444;
  background: #f9f9f9; cursor: pointer;
}
.sub-panel-header:hover { background: #f3f3f3; }
.sub-panel-title { display: flex; align-items: center; gap: 6px; }
.sub-panel-body { padding: 12px 14px; }
.kv-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.kv-table th { width: 160px; text-align: left; padding: 8px 12px; color: #666; font-weight: 500; background: #fafafa; border-bottom: 1px solid #f0f0f0; }
.kv-table td { padding: 8px 12px; border-bottom: 1px solid #f0f0f0; color: #333; word-break: break-all; }
.data-table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }
.data-table th { text-align: left; padding: 8px 12px; background: #f5f5f5; color: #555; font-weight: 600; border-bottom: 1px solid #e0e0e0; }
.data-table td { padding: 8px 12px; border-bottom: 1px solid #f0f0f0; color: #333; word-break: break-all; }
.arrow { display: inline-block; transition: transform 0.2s; font-size: 12px; }
.arrow.open { transform: rotate(90deg); }
.script-block + .script-block { margin-top: 12px; }
.script-title { font-size: 12px; font-weight: 600; color: #555; margin-bottom: 6px; }
.script-body {
  margin: 0; padding: 10px; max-height: 240px; overflow: auto;
  font-family: "SFMono-Regular", Consolas, monospace; font-size: 11px;
  background: #fafafa; border: 1px solid #f0f0f0; border-radius: 4px;
  white-space: pre-wrap; word-break: break-all;
}
</style>
