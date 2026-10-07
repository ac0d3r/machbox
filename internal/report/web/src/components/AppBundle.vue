<script setup>
import { ref } from 'vue'
import MachoAnalysis from './MachoAnalysis.vue'

const props = defineProps({
  data: Object,
})

const expanded = ref({ appInfo: true, mainExec: true })
</script>

<template>
  <div class="appbundle-content">
    <div class="sub-panel">
      <div class="sub-panel-header" @click="expanded.appInfo = !expanded.appInfo">
        <span class="sub-panel-title">App Info</span>
        <span class="arrow" :class="{ open: expanded.appInfo }">▸</span>
      </div>
      <div v-show="expanded.appInfo" class="sub-panel-body">
        <table class="kv-table">
          <tr><th>Name</th><td>{{ data.info.name }}</td></tr>
          <tr><th>Identifier</th><td>{{ data.info.identifier }}</td></tr>
          <tr><th>Version</th><td>{{ data.info.version }}</td></tr>
          <tr><th>Build</th><td>{{ data.info.build }}</td></tr>
          <tr><th>Executable</th><td>{{ data.info.executable }}</td></tr>
          <tr v-if="data.hashes">
            <th>Executable Hash</th>
            <td>
              <div v-if="data.hashes.md5" class="hash-sub">MD5: {{ data.hashes.md5 }}</div>
              <div v-if="data.hashes.sha1" class="hash-sub">SHA1: {{ data.hashes.sha1 }}</div>
              <div v-if="data.hashes.sha256" class="hash-sub">SHA256: {{ data.hashes.sha256 }}</div>
            </td>
          </tr>
          <tr><th>Package Type</th><td>{{ data.info.package_type }}</td></tr>
          <tr><th>Min System Version</th><td>{{ data.info.minimum_system_version }}</td></tr>
          <tr v-if="data.info.supported_platforms?.length"><th>Supported Platforms</th><td>{{ data.info.supported_platforms.join(', ') }}</td></tr>
        </table>
      </div>
    </div>
    <div class="sub-panel">
      <div class="sub-panel-header" @click="expanded.mainExec = !expanded.mainExec">
        <span class="sub-panel-title">Main Executable</span>
        <span class="arrow" :class="{ open: expanded.mainExec }">▸</span>
      </div>
      <div v-show="expanded.mainExec" class="sub-panel-body">
        <div v-if="data.main_executable.macho" class="macho-content">
          <MachoAnalysis :data="data.main_executable.macho" />
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.appbundle-content { font-size: 12px; }
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
.arrow { display: inline-block; transition: transform 0.2s; font-size: 12px; }
.arrow.open { transform: rotate(90deg); }
.macho-content { margin-top: 8px; }
.hash-sha256 { font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; word-break: break-all; }
.hash-sub { font-family: "SFMono-Regular", Consolas, monospace; font-size: 11px; color: #888; margin-top: 2px; word-break: break-all; }
</style>
