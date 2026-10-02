<script setup>
import { ref, watch, computed } from 'vue'
import ProcessTree from './ProcessTree.vue'

const props = defineProps({
  report: Object,
})

const parsedDynamic = ref(null)

watch(() => props.report?.dynamic_result, (val) => {
  parsedDynamic.value = val || null
}, { immediate: true })

const hasData = computed(() => {
  return parsedDynamic.value && parsedDynamic.value.process_tree
})

const summary = computed(() => parsedDynamic.value?.summary || {})
const behavior = computed(() => summary.value?.behavior_summary || {})

const verdictClass = (verdict) => {
  if (verdict === 'malicious') return 'verdict-malicious'
  if (verdict === 'suspicious') return 'verdict-suspicious'
  if (verdict === 'clean') return 'verdict-clean'
  return 'verdict-unknown'
}

// Events grouped by process — walk the process_tree recursively.
const eventsByProcess = computed(() => {
  if (!parsedDynamic.value?.process_tree) return []
  const groups = {}

  const walk = (node) => {
    if (!node) return
    const pid = node.pid
    if (!groups[pid]) {
      groups[pid] = { pid, path: node.path || 'unknown', events: [] }
    }
    if (node.events) {
      for (const ev of node.events) {
        groups[pid].events.push(ev)
      }
    }
    if (node.children) {
      for (const child of node.children) {
        walk(child)
      }
    }
  }

  walk(parsedDynamic.value.process_tree)

  // Filter out synthetic root node.
  const result = Object.values(groups).filter(g => !(g.pid === 0 && g.path === '<root>'))
  return result.sort((a, b) => a.pid - b.pid)
})

// Network events grouped by process — walk the process_tree recursively.
const networksByProcess = computed(() => {
  if (!parsedDynamic.value?.process_tree) return []
  const groups = {}

  const walk = (node) => {
    if (!node) return
    const pid = node.pid
    if (!groups[pid]) {
      groups[pid] = { pid, path: node.path || 'unknown', networks: [] }
    }
    if (node.networks) {
      for (const ev of node.networks) {
        groups[pid].networks.push(ev)
      }
    }
    if (node.children) {
      for (const child of node.children) {
        walk(child)
      }
    }
  }

  walk(parsedDynamic.value.process_tree)

  const result = Object.values(groups).filter(g => g.networks.length > 0)
  return result.sort((a, b) => a.pid - b.pid)
})

const networkEventBadgeClass = (type) => {
  const high = ['tcp_connect', 'bind', 'tcp_accept']
  const medium = ['udp_send', 'udp_recv', 'msg_send', 'msg_recv']
  if (high.includes(type)) return 'badge-network-high'
  if (medium.includes(type)) return 'badge-network-medium'
  return 'badge-network'
}

const networkEventTarget = (ev) => {
  if (ev.metadata) {
    if (ev.metadata.local) return ev.metadata.local
    if (ev.metadata.remote) return ev.metadata.remote
    if (ev.metadata.path) return ev.metadata.path
  }
  if (ev.target) return ev.target
  return '-'
}

const networkEventDetails = (ev) => {
  const parts = []
  if (ev.metadata) {
    for (const [k, v] of Object.entries(ev.metadata)) {
      if (k === 'local' || k === 'remote' || k === 'path') continue
      parts.push(`${k}=${v}`)
    }
  }
  return parts.length ? parts.join(' | ') : '-'
}

const formatEventTime = (ts) => {
  const d = new Date(ts)
  const ms = String(d.getMilliseconds()).padStart(3, '0')
  return d.toLocaleTimeString() + '.' + ms
}

const eventBadgeClass = (type) => {
  const malicious = ['kextload', 'kextunload', 'get_task', 'get_task_name', 'get_task_read', 'get_task_inspect']
  const suspicious = ['btm_launch_item_add', 'btm_launch_item_remove', 'seteuid', 'setegid', 'setreuid', 'setregid', 'link', 'mount', 'remount', 'mprotect']
  if (malicious.includes(type)) return 'badge-malicious'
  if (suspicious.includes(type)) return 'badge-suspicious'
  return 'badge-clean'
}

const eventTarget = (ev) => {
  if (ev.target) return ev.target
  if (ev.object?.path) return ev.object.path
  if (ev.object?.name) return ev.object.name
  return '-'
}

const eventDetails = (ev) => {
  const parts = []
  let envBlock = null

  if (ev.metadata && Object.keys(ev.metadata).length > 0) {
    for (const [k, v] of Object.entries(ev.metadata)) {
      if (k === 'env' && typeof v === 'string' && v.includes('\u0000')) {
        const envVars = v.split('\u0000').filter(Boolean)
        envBlock = `env:\n${envVars.join('\n')}`
      } else {
        parts.push(`${k}=${v}`)
      }
    }
  }

  if (ev.subject?.path) parts.push(`subject=${ev.subject.path}`)
  if (ev.object?.kind) parts.push(`kind=${ev.object.kind}`)

  let result = parts.length ? parts.join(' | ') : '-'
  if (envBlock) {
    result = result + '\n\n' + envBlock
  }
  return result
}

const collapsed = ref({})
const isCollapsed = (pid) => collapsed.value[pid]
const toggle = (pid) => { collapsed.value[pid] = !collapsed.value[pid] }
</script>

<template>
  <div class="tab-panel">
    <h3 class="section-title">Dynamic Analysis</h3>

    <div v-if="!hasData" class="panel-card empty-state">
      <div class="empty-content">
        <p>No dynamic analysis data available</p>
      </div>
    </div>

    <template v-else>
      <!-- Summary -->
      <div class="panel-card">
        <div class="panel-header">
          <span class="panel-icon">📊</span>
          <span>Summary</span>
        </div>
        <div class="panel-body">
          <div class="summary-grid">
            <div class="summary-item">
              <span class="summary-value" :class="verdictClass(summary.verdict)">{{ summary.verdict || 'unknown' }}</span>
              <span class="summary-label">Verdict</span>
            </div>
            <div class="summary-item">
              <span class="summary-value">{{ summary.risk_score }}</span>
              <span class="summary-label">Risk Score</span>
            </div>
            <div class="summary-item" v-if="summary.injection_count">
              <span class="summary-value warn">{{ summary.injection_count }}</span>
              <span class="summary-label">Injections</span>
            </div>
            <div class="summary-item" v-if="summary.persistence_count">
              <span class="summary-value warn">{{ summary.persistence_count }}</span>
              <span class="summary-label">Persistence</span>
            </div>
            <div class="summary-item" v-if="behavior.has_launchctl_persistence">
              <span class="summary-value warn">launchctl</span>
              <span class="summary-label">Persistence</span>
            </div>
            <div class="summary-item" v-if="summary.privilege_changes">
              <span class="summary-value warn">{{ summary.privilege_changes }}</span>
              <span class="summary-label">Privilege Changes</span>
            </div>
            <div class="summary-item" v-if="summary.code_sig_invalidations">
              <span class="summary-value warn">{{ summary.code_sig_invalidations }}</span>
              <span class="summary-label">Code Sig Invalidated</span>
            </div>
            <div class="summary-item" v-if="summary.parse_errors">
              <span class="summary-value warn">{{ summary.parse_errors }}</span>
              <span class="summary-label">Parse Errors</span>
            </div>
            <div class="summary-item" v-if="behavior.child_processes">
              <span class="summary-value">{{ behavior.child_processes }}</span>
              <span class="summary-label">Child Processes</span>
            </div>
          </div>

          <div class="risk-factors" v-if="summary.risk_factors?.length">
            <div class="behavior-title">⚠️ Risk Factors</div>
            <div class="risk-factor-item" v-for="(factor, idx) in summary.risk_factors" :key="'rf-' + idx">{{ factor }}</div>
          </div>

          <!-- Behavior Summary -->
          <div class="behavior-summary" v-if="Object.keys(behavior).length">
            <div class="behavior-section" v-if="behavior.has_external_network || behavior.has_bind_all_interfaces || behavior.has_listen_socket || behavior.network_connections?.length">
              <div class="behavior-title">🌐 Network</div>
              <div class="behavior-tags">
                <span class="behavior-tag warn" v-if="behavior.has_external_network">External Connection</span>
                <span class="behavior-tag warn" v-if="behavior.has_bind_all_interfaces">Bind 0.0.0.0/::</span>
                <span class="behavior-tag suspicious" v-if="behavior.has_listen_socket">Listen Socket</span>
              </div>
              <div class="detail-list-item" v-for="(conn, idx) in behavior.network_connections" :key="'net-' + idx">{{ conn }}</div>
            </div>

            <div class="behavior-section" v-if="behavior.files_written?.length || behavior.files_deleted?.length || behavior.files_modified_perms?.length || behavior.has_sensitive_write || behavior.has_sensitive_delete || behavior.has_sensitive_chmod">
              <div class="behavior-title">📁 File System</div>
              <div class="behavior-tags">
                <span class="behavior-tag warn" v-if="behavior.has_sensitive_write">Sensitive Write</span>
                <span class="behavior-tag warn" v-if="behavior.has_sensitive_delete">Sensitive Delete</span>
                <span class="behavior-tag warn" v-if="behavior.has_sensitive_chmod">Sensitive Chmod</span>
              </div>
              <div class="detail-list" v-if="behavior.files_written?.length">
                <div class="detail-list-title">Written</div>
                <div class="detail-list-item" v-for="(path, idx) in behavior.files_written" :key="'w-' + idx">{{ path }}</div>
              </div>
              <div class="detail-list" v-if="behavior.files_deleted?.length">
                <div class="detail-list-title">Deleted</div>
                <div class="detail-list-item" v-for="(path, idx) in behavior.files_deleted" :key="'d-' + idx">{{ path }}</div>
              </div>
              <div class="detail-list" v-if="behavior.files_modified_perms?.length">
                <div class="detail-list-title">Permission Changes</div>
                <div class="detail-list-item" v-for="(path, idx) in behavior.files_modified_perms" :key="'p-' + idx">{{ path }}</div>
              </div>
            </div>

            <div class="behavior-section" v-if="behavior.command_lines?.length || behavior.commands_executed?.length || behavior.has_shell_execution || behavior.has_script_execution">
              <div class="behavior-title">🖥 Command Execution</div>
              <div class="behavior-tags">
                <span class="behavior-tag warn" v-if="behavior.has_shell_execution">Shell</span>
                <span class="behavior-tag suspicious" v-if="behavior.has_script_execution">Script</span>
              </div>
              <div class="detail-list-item" v-for="(cmd, idx) in behavior.commands_executed" :key="'cmdpath-' + idx">{{ cmd }}</div>
              <textarea
                v-if="behavior.command_lines?.length"
                class="command-lines-textarea"
                readonly
                :value="behavior.command_lines.join('\n')"
              ></textarea>
            </div>

            <div class="behavior-section" v-if="behavior.privilege_escalation">
              <div class="behavior-title">🔒 Privilege</div>
              <div class="behavior-tags">
                <span class="behavior-tag warn">Privilege Escalation</span>
              </div>
            </div>
          </div>

          <div class="detail-lists" v-if="summary.persistence_paths?.length || summary.injected_targets?.length">
            <div class="detail-list" v-if="parsedDynamic.summary.persistence_paths?.length">
              <div class="detail-list-title">📝 Persistence Items</div>
              <div class="detail-list-item" v-for="(path, idx) in parsedDynamic.summary.persistence_paths" :key="idx">{{ path }}</div>
            </div>
            <div class="detail-list" v-if="parsedDynamic.summary.injected_targets?.length">
              <div class="detail-list-title">💉 Injected Targets</div>
              <div class="detail-list-item" v-for="(target, idx) in parsedDynamic.summary.injected_targets" :key="idx">{{ target }}</div>
            </div>
          </div>
        </div>
      </div>
      <!-- Process Tree -->
      <div class="panel-card" v-if="parsedDynamic.process_tree">
        <div class="panel-header">
          <span class="panel-icon">🌳</span>
          <span>Process Tree</span>
        </div>
        <div class="panel-body no-padding">
          <ProcessTree :node="parsedDynamic.process_tree" />
        </div>
      </div>

      <!-- Network by Process -->
      <div class="panel-card" v-if="networksByProcess.length">
        <div class="panel-header">
          <span class="panel-icon">🌐</span>
          <span>Network by Process</span>
        </div>
        <div class="panel-body no-padding">
          <div
            class="process-group"
            v-for="proc in networksByProcess"
            :key="proc.pid"
          >
            <div class="process-header" @click="toggle('net-' + proc.pid)">
              <span class="process-toggle">{{ isCollapsed('net-' + proc.pid) ? '▸' : '▾' }}</span>
              <span class="process-pid">PID {{ proc.pid }}</span>
              <span class="process-path">{{ proc.path }}</span>
              <span class="process-count">{{ proc.networks.length }} events</span>
            </div>
            <div v-if="!isCollapsed('net-' + proc.pid)" class="process-events">
              <table class="event-table">
                <thead>
                  <tr>
                    <th class="col-time">Time</th>
                    <th class="col-type">Type</th>
                    <th class="col-target">Target</th>
                    <th class="col-details">Details</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(ev, idx) in proc.networks" :key="idx">
                    <td class="col-time">{{ formatEventTime(ev.ts) }}</td>
                    <td class="col-type">
                      <span class="badge" :class="networkEventBadgeClass(ev.type)">{{ ev.type }}</span>
                    </td>
                    <td class="col-target">{{ networkEventTarget(ev) }}</td>
                    <td class="col-details">{{ networkEventDetails(ev) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      <!-- Events by Process -->
      <div class="panel-card" v-if="eventsByProcess.length">
        <div class="panel-header">
          <span class="panel-icon">📋</span>
          <span>Events by Process</span>
        </div>
        <div class="panel-body no-padding">
          <div
            class="process-group"
            v-for="proc in eventsByProcess"
            :key="proc.pid"
          >
            <div class="process-header" @click="toggle(proc.pid)">
              <span class="process-toggle">{{ isCollapsed(proc.pid) ? '▸' : '▾' }}</span>
              <span class="process-pid">PID {{ proc.pid }}</span>
              <span class="process-path">{{ proc.path }}</span>
              <span class="process-count">{{ proc.events.length }} events</span>
            </div>
            <div v-if="!isCollapsed(proc.pid)" class="process-events">
              <table class="event-table">
                <thead>
                  <tr>
                    <th class="col-time">Time</th>
                    <th class="col-type">Type</th>
                    <th class="col-target">Target</th>
                    <th class="col-details">Details</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(ev, idx) in proc.events" :key="idx">
                    <td class="col-time">{{ formatEventTime(ev.ts) }}</td>
                    <td class="col-type">
                      <span class="badge" :class="eventBadgeClass(ev.type)">{{ ev.type }}</span>
                    </td>
                    <td class="col-target">{{ eventTarget(ev) }}</td>
                    <td class="col-details">{{ eventDetails(ev) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<style scoped>
.section-title {
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 16px;
  color: #333;
  display: flex;
  align-items: center;
  gap: 8px;
}
.section-title::before {
  content: '';
  display: inline-block;
  width: 4px;
  height: 16px;
  background: #e64a19;
  border-radius: 2px;
}

.panel-card {
  background: #fff;
  border-radius: 8px;
  margin-bottom: 16px;
  overflow: hidden;
  box-shadow: 0 1px 4px rgba(0,0,0,0.04);
}
.panel-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 14px 20px;
  font-size: 14px;
  font-weight: 600;
  color: #333;
  background: #fafafa;
  border-bottom: 1px solid #f0f0f0;
}
.panel-icon {
  font-size: 16px;
}
.panel-body {
  padding: 16px 20px;
}
.panel-body.no-padding {
  padding: 0;
}

.empty-state {
  text-align: center;
  color: #888;
  padding: 60px;
}
.empty-content p {
  margin: 0;
}

/* Summary grid */
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
  gap: 16px;
  margin-bottom: 20px;
}
.summary-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
  padding: 12px;
  background: #fafafa;
  border-radius: 6px;
}
.summary-value {
  font-size: 24px;
  font-weight: 700;
  color: #e64a19;
}
.summary-value.warn {
  color: #c62828;
}
.summary-label {
  font-size: 12px;
  color: #888;
}

/* Event type distribution */
.event-types {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.event-type-row {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 13px;
}
.event-type-name {
  width: 140px;
  color: #555;
  text-transform: capitalize;
  flex-shrink: 0;
}
.event-type-bar {
  flex: 1;
  height: 8px;
  background: #f0f0f0;
  border-radius: 4px;
  overflow: hidden;
}
.event-type-fill {
  display: block;
  height: 100%;
  background: #ff7043;
  border-radius: 4px;
  transition: width 0.4s ease;
}
.event-type-count {
  width: 40px;
  text-align: right;
  color: #666;
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 12px;
}

/* Detail lists */
.detail-lists {
  display: flex;
  flex-direction: column;
  gap: 16px;
  margin-top: 16px;
}
.detail-list {
  background: #fafafa;
  border-radius: 6px;
  padding: 12px 16px;
}
.detail-list-title {
  font-size: 12px;
  font-weight: 600;
  color: #555;
  margin-bottom: 8px;
}
.detail-list-item {
  font-size: 12px;
  color: #666;
  font-family: "SFMono-Regular", Consolas, monospace;
  word-break: break-all;
  padding: 3px 0;
  border-bottom: 1px solid #f0f0f0;
}
.detail-list-item:last-child {
  border-bottom: none;
}

/* Events by Process */
.process-group {
  border-bottom: 1px solid #f0f0f0;
}
.process-group:last-child {
  border-bottom: none;
}
.process-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 20px;
  font-size: 13px;
  cursor: pointer;
  background: #fff;
}
.process-header:hover {
  background: #fafafa;
}
.process-toggle {
  width: 14px;
  color: #888;
  font-size: 12px;
}
.process-pid {
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 12px;
  color: #666;
  min-width: 60px;
}
.process-path {
  flex: 1;
  color: #333;
  font-weight: 500;
  word-break: break-all;
}
.process-count {
  font-size: 12px;
  color: #888;
  background: #f5f5f5;
  padding: 2px 8px;
  border-radius: 10px;
}

.process-events {
  padding: 0 20px 16px 20px;
}
.event-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}
.event-table th {
  text-align: left;
  padding: 8px 10px;
  border-bottom: 1px solid #eee;
  color: #888;
  font-weight: 600;
  background: #fafafa;
}
.event-table td {
  padding: 8px 10px;
  border-bottom: 1px solid #f5f5f5;
  vertical-align: top;
}
.event-table tr:last-child td {
  border-bottom: none;
}
.col-time { width: 90px; white-space: nowrap; color: #666; font-family: "SFMono-Regular", Consolas, monospace; }
.col-type { width: 100px; }
.col-target { width: 320px; word-break: break-all; color: #555; }
.col-details { color: #888; word-break: break-all; white-space: pre-wrap; }

.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  text-transform: capitalize;
}
.badge-clean { background: #e8f5e9; color: #2e7d32; }
.badge-suspicious { background: #fff3e0; color: #ef6c00; }
.badge-malicious { background: #ffebee; color: #c62828; }
.badge-network { background: #e3f2fd; color: #1565c0; }
.badge-network-medium { background: #fff8e1; color: #f57f17; }
.badge-network-high { background: #ffebee; color: #c62828; }

/* Verdict colors */
.verdict-malicious { color: #c62828; }
.verdict-suspicious { color: #ef6c00; }
.verdict-clean { color: #2e7d32; }
.verdict-unknown { color: #757575; }

/* Behavior summary */
.behavior-summary {
  display: flex;
  flex-direction: column;
  gap: 16px;
  margin-top: 16px;
}
.behavior-section {
  background: #fafafa;
  border-radius: 6px;
  padding: 12px 16px;
}
.behavior-title {
  font-size: 13px;
  font-weight: 600;
  color: #555;
  margin-bottom: 8px;
}
.behavior-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-bottom: 8px;
}
.behavior-tag {
  display: inline-block;
  padding: 3px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  background: #e3f2fd;
  color: #1565c0;
}
.behavior-tag.warn {
  background: #ffebee;
  color: #c62828;
}
.behavior-tag.suspicious {
  background: #fff3e0;
  color: #ef6c00;
}

/* Risk factors */
.risk-factors {
  background: #fff3e0;
  border-radius: 6px;
  padding: 12px 16px;
  margin-top: 16px;
}
.risk-factor-item {
  font-size: 12px;
  color: #555;
  padding: 3px 0;
  border-bottom: 1px solid #ffe0b2;
}
.risk-factor-item:last-child {
  border-bottom: none;
}

.command-lines-textarea {
  width: 100%;
  min-height: 120px;
  margin-top: 10px;
  font-size: 12px;
  color: #555;
  font-family: "SFMono-Regular", Consolas, monospace;
  background: #fff;
  border: 1px solid #eee;
  border-radius: 4px;
  padding: 8px;
  resize: vertical;
  white-space: pre;
  overflow-wrap: normal;
  overflow-x: auto;
}
</style>
