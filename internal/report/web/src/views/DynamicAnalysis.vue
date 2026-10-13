<script setup>
import { ref, watch, computed } from 'vue'
import ProcessTree from './ProcessTree.vue'

const props = defineProps({
  report: { type: Object, required: true },
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

// Merge executable path + argv into one line, e.g. "/usr/bin/sw_vers -productVersion".
const executedCommands = computed(() => {
  const paths = behavior.value.commands_executed || []
  const lines = behavior.value.command_lines || []
  if (!paths.length && !lines.length) return []

  const n = Math.max(paths.length, lines.length)
  const out = []
  for (let i = 0; i < n; i++) {
    const path = paths[i] || ''
    const line = (lines[i] || '').trim()
    if (!path && line) {
      out.push(line)
      continue
    }
    if (!line) {
      out.push(path)
      continue
    }
    const parts = line.split(/\s+/)
    const base = path.split('/').pop()
    const args =
      parts[0] === base || parts[0] === path ? parts.slice(1) : parts
    out.push(args.length ? `${path} ${args.join(' ')}` : path)
  }
  return out
})

const scoreItems = computed(() => {
  const s = summary.value
  const b = behavior.value
  const items = [
    { key: 'verdict', label: 'Verdict', value: s.verdict || 'unknown', kind: 'verdict' },
    { key: 'risk', label: 'Risk Score', value: s.risk_score ?? '—' },
  ]
  if (s.injection_count) items.push({ key: 'inj', label: 'Injections', value: s.injection_count, warn: true })
  if (s.persistence_count) items.push({ key: 'pers', label: 'Persistence', value: s.persistence_count, warn: true })
  if (b.has_launchctl_persistence) items.push({ key: 'lctl', label: 'Persistence', value: 'launchctl', warn: true })
  if (s.privilege_changes) items.push({ key: 'priv', label: 'Privilege', value: s.privilege_changes, warn: true })
  if (s.code_sig_invalidations) items.push({ key: 'csig', label: 'Code Sig', value: s.code_sig_invalidations, warn: true })
  if (s.parse_errors) items.push({ key: 'parse', label: 'Parse Errors', value: s.parse_errors, warn: true })
  if (b.child_processes) items.push({ key: 'child', label: 'Child Processes', value: b.child_processes })
  return items
})

const hasNetworkBehavior = computed(() =>
  behavior.value.has_external_network ||
  behavior.value.has_bind_all_interfaces ||
  behavior.value.has_listen_socket ||
  (behavior.value.network_connections?.length > 0)
)

const hasFileBehavior = computed(() =>
  behavior.value.files_written?.length ||
  behavior.value.files_deleted?.length ||
  behavior.value.files_modified_perms?.length ||
  behavior.value.has_sensitive_write ||
  behavior.value.has_sensitive_delete ||
  behavior.value.has_sensitive_chmod
)

const hasCommandBehavior = computed(() =>
  executedCommands.value.length ||
  behavior.value.has_shell_execution ||
  behavior.value.has_script_execution
)

const hasBehaviorGrid = computed(() =>
  hasNetworkBehavior.value ||
  hasFileBehavior.value ||
  hasCommandBehavior.value ||
  behavior.value.privilege_escalation ||
  summary.value.persistence_paths?.length ||
  summary.value.injected_targets?.length
)

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
  const medium = ['udp_send', 'udp_recv', 'msg_send', 'msg_recv', 'unix_connect', 'unix_bind', 'socket']
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
  return parts.length ? parts.join(' · ') : '—'
}

const formatEventTime = (ts) => {
  const d = new Date(ts)
  const ms = String(d.getMilliseconds()).padStart(3, '0')
  return d.toLocaleTimeString() + '.' + ms
}

const eventBadgeClass = (type) => {
  const malicious = ['kextload', 'kextunload', 'get_task', 'get_task_name', 'get_task_read', 'get_task_inspect']
  const suspicious = [
    'btm_launch_item_add', 'btm_launch_item_remove',
    'seteuid', 'setegid', 'setreuid', 'setregid',
    'link', 'clone', 'copyfile', 'mount', 'remount', 'mprotect',
  ]
  if (malicious.includes(type)) return 'badge-malicious'
  if (suspicious.includes(type)) return 'badge-suspicious'
  return 'badge-clean'
}

const eventTarget = (ev) => {
  if (ev.object?.path) return ev.object.path
  if (ev.metadata?.destination) return ev.metadata.destination
  if (ev.target) return ev.target
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

  let result = parts.length ? parts.join(' · ') : '—'
  if (envBlock) {
    result = result + '\n\n' + envBlock
  }
  return result
}

const shortPath = (path) => {
  if (!path || path === 'unknown' || path === '<root>') return path
  const parts = path.split('/')
  if (parts.length <= 3) return path
  return '…/' + parts.slice(-2).join('/')
}

// Default collapsed for event tables; expanded for network (usually smaller).
const collapsed = ref({})
const isCollapsed = (key, defaultCollapsed = true) => {
  if (collapsed.value[key] === undefined) return defaultCollapsed
  return collapsed.value[key]
}
const toggle = (key, defaultCollapsed = true) => {
  collapsed.value[key] = !isCollapsed(key, defaultCollapsed)
}
</script>

<template>
  <div class="tab-panel">
    <div v-if="!hasData" class="panel empty-state">
      <p class="empty-title">No dynamic analysis</p>
      <p class="empty-hint">This report has no process tree or behavioral events. It may be a static-only run, or no executable was launched.</p>
    </div>

    <template v-else>
      <!-- Score strip -->
      <section class="panel score-panel">
        <div class="score-strip">
          <div
            v-for="item in scoreItems"
            :key="item.key"
            class="score-cell"
          >
            <div
              class="score-value"
              :class="[
                item.kind === 'verdict' ? verdictClass(item.value) : '',
                item.warn ? 'warn' : '',
              ]"
            >
              {{ item.value }}
            </div>
            <div class="score-label">{{ item.label }}</div>
          </div>
        </div>

        <div v-if="summary.risk_factors?.length" class="risk-block">
          <div class="block-label">Risk factors</div>
          <ul class="risk-list">
            <li v-for="(factor, idx) in summary.risk_factors" :key="'rf-' + idx">{{ factor }}</li>
          </ul>
        </div>
      </section>

      <!-- Behavior grid -->
      <section v-if="hasBehaviorGrid" class="behavior-grid">
        <div v-if="hasNetworkBehavior" class="panel behavior-card">
          <div class="panel-head">Network</div>
          <div class="panel-body">
            <div class="tag-row">
              <span v-if="behavior.has_external_network" class="tag warn">External</span>
              <span v-if="behavior.has_bind_all_interfaces" class="tag warn">Bind all</span>
              <span v-if="behavior.has_listen_socket" class="tag soft">Listen</span>
            </div>
            <ul v-if="behavior.network_connections?.length" class="mono-list">
              <li v-for="(conn, idx) in behavior.network_connections" :key="'net-' + idx">{{ conn }}</li>
            </ul>
          </div>
        </div>

        <div v-if="hasFileBehavior" class="panel behavior-card">
          <div class="panel-head">File system</div>
          <div class="panel-body">
            <div class="tag-row">
              <span v-if="behavior.has_sensitive_write" class="tag warn">Sensitive write</span>
              <span v-if="behavior.has_sensitive_delete" class="tag warn">Sensitive delete</span>
              <span v-if="behavior.has_sensitive_chmod" class="tag warn">Sensitive chmod</span>
            </div>
            <div v-if="behavior.files_written?.length" class="path-group">
              <div class="path-group-label">Written</div>
              <ul class="mono-list">
                <li v-for="(path, idx) in behavior.files_written" :key="'w-' + idx">{{ path }}</li>
              </ul>
            </div>
            <div v-if="behavior.files_deleted?.length" class="path-group">
              <div class="path-group-label">Deleted</div>
              <ul class="mono-list">
                <li v-for="(path, idx) in behavior.files_deleted" :key="'d-' + idx">{{ path }}</li>
              </ul>
            </div>
            <div v-if="behavior.files_modified_perms?.length" class="path-group">
              <div class="path-group-label">Permission changes</div>
              <ul class="mono-list">
                <li v-for="(path, idx) in behavior.files_modified_perms" :key="'p-' + idx">{{ path }}</li>
              </ul>
            </div>
          </div>
        </div>

        <div v-if="hasCommandBehavior" class="panel behavior-card">
          <div class="panel-head">Commands</div>
          <div class="panel-body">
            <div class="tag-row">
              <span v-if="behavior.has_shell_execution" class="tag warn">Shell</span>
              <span v-if="behavior.has_script_execution" class="tag soft">Script</span>
            </div>
            <pre v-if="executedCommands.length" class="cmd-block">{{ executedCommands.join('\n') }}</pre>
          </div>
        </div>

        <div v-if="behavior.privilege_escalation || summary.persistence_paths?.length || summary.injected_targets?.length" class="panel behavior-card">
          <div class="panel-head">Persistence &amp; injection</div>
          <div class="panel-body">
            <div class="tag-row">
              <span v-if="behavior.privilege_escalation" class="tag warn">Privilege escalation</span>
            </div>
            <div v-if="summary.persistence_paths?.length" class="path-group">
              <div class="path-group-label">Persistence items</div>
              <ul class="mono-list">
                <li v-for="(path, idx) in summary.persistence_paths" :key="'pp-' + idx">{{ path }}</li>
              </ul>
            </div>
            <div v-if="summary.injected_targets?.length" class="path-group">
              <div class="path-group-label">Injected targets</div>
              <ul class="mono-list">
                <li v-for="(target, idx) in summary.injected_targets" :key="'it-' + idx">{{ target }}</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      <!-- Process tree -->
      <section v-if="parsedDynamic.process_tree" class="panel">
        <div class="panel-head">Process tree</div>
        <div class="panel-body flush tree-wrap">
          <ProcessTree :node="parsedDynamic.process_tree" />
        </div>
      </section>

      <!-- Network by process -->
      <section v-if="networksByProcess.length" class="panel">
        <div class="panel-head">
          <span>Network by process</span>
          <span class="head-meta">{{ networksByProcess.length }} processes</span>
        </div>
        <div class="panel-body flush">
          <div
            v-for="proc in networksByProcess"
            :key="'netg-' + proc.pid"
            class="proc-group"
          >
            <button type="button" class="proc-header" @click="toggle('net-' + proc.pid, false)">
              <span class="proc-toggle">{{ isCollapsed('net-' + proc.pid, false) ? '▸' : '▾' }}</span>
              <span class="proc-pid">{{ proc.pid }}</span>
              <span class="proc-path" :title="proc.path">{{ shortPath(proc.path) }}</span>
              <span class="proc-count">{{ proc.networks.length }}</span>
            </button>
            <div v-if="!isCollapsed('net-' + proc.pid, false)" class="table-scroll">
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
                    <td class="col-target" :title="networkEventTarget(ev)">{{ networkEventTarget(ev) }}</td>
                    <td class="col-details">{{ networkEventDetails(ev) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </section>

      <!-- Events by process -->
      <section v-if="eventsByProcess.length" class="panel">
        <div class="panel-head">
          <span>Events by process</span>
          <span class="head-meta">{{ eventsByProcess.length }} processes · collapsed by default</span>
        </div>
        <div class="panel-body flush">
          <div
            v-for="proc in eventsByProcess"
            :key="'evg-' + proc.pid"
            class="proc-group"
          >
            <button type="button" class="proc-header" @click="toggle(proc.pid, true)">
              <span class="proc-toggle">{{ isCollapsed(proc.pid, true) ? '▸' : '▾' }}</span>
              <span class="proc-pid">{{ proc.pid }}</span>
              <span class="proc-path" :title="proc.path">{{ shortPath(proc.path) }}</span>
              <span class="proc-count">{{ proc.events.length }}</span>
            </button>
            <div v-if="!isCollapsed(proc.pid, true)" class="table-scroll">
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
                    <td class="col-target" :title="eventTarget(ev)">{{ eventTarget(ev) }}</td>
                    <td class="col-details">{{ eventDetails(ev) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
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

/* Score strip */
.score-panel {
  padding: 0;
}

.score-strip {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
  gap: 0;
  border-bottom: 1px solid #f0f0f0;
}

.score-cell {
  padding: 16px 12px;
  text-align: center;
  border-right: 1px solid #f0f0f0;
}

.score-cell:last-child {
  border-right: none;
}

.score-value {
  font-size: 22px;
  font-weight: 700;
  color: #333;
  line-height: 1.2;
  text-transform: capitalize;
}

.score-value.warn {
  color: #c62828;
}

.score-label {
  margin-top: 4px;
  font-size: 11px;
  color: #999;
  letter-spacing: 0.02em;
}

.risk-block {
  padding: 12px 16px 14px;
  background: #fff8f0;
}

.block-label {
  font-size: 11px;
  font-weight: 600;
  color: #b35c00;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  margin-bottom: 8px;
}

.risk-list {
  margin: 0;
  padding-left: 18px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.risk-list li {
  font-size: 12px;
  color: #5c4a3a;
  line-height: 1.4;
}

/* Behavior grid */
.behavior-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

@media (max-width: 900px) {
  .behavior-grid {
    grid-template-columns: 1fr;
  }
}

.behavior-card .panel-body {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.tag-row {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.tag {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  background: #eef2f7;
  color: #456;
}

.tag.warn {
  background: #fdecea;
  color: #c62828;
}

.tag.soft {
  background: #fff3e0;
  color: #ef6c00;
}

.path-group-label {
  font-size: 11px;
  font-weight: 600;
  color: #888;
  margin-bottom: 4px;
}

.mono-list {
  margin: 0;
  padding: 0;
  list-style: none;
}

.mono-list li {
  font-family: "SF Mono", "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 11.5px;
  color: #555;
  word-break: break-all;
  padding: 3px 0;
  border-bottom: 1px solid #f4f4f4;
}

.mono-list li:last-child {
  border-bottom: none;
}

.cmd-block {
  margin: 0;
  padding: 10px 12px;
  background: #f7f7f8;
  border-radius: 6px;
  border: 1px solid #eee;
  font-family: "SF Mono", "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 11.5px;
  color: #444;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 200px;
  overflow: auto;
  line-height: 1.45;
}

.tree-wrap {
  padding: 4px 0;
  max-height: 360px;
  overflow: auto;
}

/* Process groups */
.proc-group {
  border-bottom: 1px solid #f0f0f0;
}

.proc-group:last-child {
  border-bottom: none;
}

.proc-header {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  padding: 10px 16px;
  border: 0;
  background: #fff;
  cursor: pointer;
  text-align: left;
  font: inherit;
}

.proc-header:hover {
  background: #fafafa;
}

.proc-toggle {
  width: 12px;
  color: #aaa;
  font-size: 11px;
  flex-shrink: 0;
}

.proc-pid {
  font-family: "SF Mono", "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 12px;
  color: #e64a19;
  min-width: 42px;
  flex-shrink: 0;
}

.proc-path {
  flex: 1;
  min-width: 0;
  font-size: 12.5px;
  font-weight: 500;
  color: #333;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.proc-count {
  font-size: 11px;
  color: #888;
  background: #f3f3f3;
  padding: 1px 8px;
  border-radius: 999px;
  flex-shrink: 0;
}

.table-scroll {
  max-height: 280px;
  overflow: auto;
  border-top: 1px solid #f0f0f0;
  background: #fcfcfc;
}

.event-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
  table-layout: fixed;
}

.event-table th {
  position: sticky;
  top: 0;
  z-index: 1;
  text-align: left;
  padding: 8px 12px;
  border-bottom: 1px solid #eee;
  color: #888;
  font-weight: 600;
  background: #f7f7f8;
}

.event-table td {
  padding: 7px 12px;
  border-bottom: 1px solid #f2f2f2;
  vertical-align: top;
}

.event-table tr:last-child td {
  border-bottom: none;
}

.col-time {
  width: 96px;
  white-space: nowrap;
  color: #666;
  font-family: "SF Mono", "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 11px;
}

.col-type {
  width: 120px;
}

.col-target {
  width: 34%;
  word-break: break-all;
  color: #555;
  font-family: "SF Mono", "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 11px;
}

.col-details {
  color: #888;
  word-break: break-all;
  white-space: pre-wrap;
  font-size: 11px;
}

.badge {
  display: inline-block;
  max-width: 100%;
  padding: 2px 7px;
  border-radius: 4px;
  font-size: 10.5px;
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.badge-clean { background: #e8f5e9; color: #2e7d32; }
.badge-suspicious { background: #fff3e0; color: #ef6c00; }
.badge-malicious { background: #ffebee; color: #c62828; }
.badge-network { background: #e3f2fd; color: #1565c0; }
.badge-network-medium { background: #fff8e1; color: #f57f17; }
.badge-network-high { background: #ffebee; color: #c62828; }

.verdict-malicious { color: #c62828; }
.verdict-suspicious { color: #ef6c00; }
.verdict-clean { color: #2e7d32; }
.verdict-unknown { color: #757575; }
</style>
