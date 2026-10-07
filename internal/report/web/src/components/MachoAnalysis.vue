<script setup>
import { ref, watch } from 'vue'
import SymbolName from './SymbolName.vue'

const props = defineProps({
  data: Object,
})

const archExpanded = ref({})
const expandedLibs = ref({})
const showAllStrings = ref({})

watch(() => props.data, (data) => {
  if (data && typeof data === 'object') {
    const archs = Object.keys(data)
    archs.forEach((arch, idx) => {
      if (!archExpanded.value[arch]) {
        archExpanded.value[arch] = {
          collapsed: idx !== 0,
          header: true,
          load_commands: true,
          sections: true,
          code_signature: true,
          symbols: true,
          imports: true,
          exports: true,
          locals: true,
          strings: true,
        }
      }
    })
  }
}, { immediate: true })
</script>

<template>
  <div class="macho-content">
    <div v-for="(info, arch) in data" :key="arch" class="arch-block">
      <div class="arch-title-row" @click="archExpanded[arch].collapsed = !archExpanded[arch].collapsed">
        <h4 class="arch-title">{{ arch }}</h4>
        <span class="arrow" :class="{ open: !archExpanded[arch]?.collapsed }">▸</span>
      </div>
      <div v-if="archExpanded[arch] && !archExpanded[arch].collapsed" class="arch-body">

        <!-- Header -->
        <div class="sub-panel">
          <div class="sub-panel-header" @click="archExpanded[arch].header = !archExpanded[arch].header">
            <span class="sub-panel-title">Mach-O Header</span>
            <span class="arrow" :class="{ open: archExpanded[arch]?.header }">▸</span>
          </div>
          <div v-show="archExpanded[arch]?.header" class="sub-panel-body">
            <table class="kv-table">
              <tr><th>CPU</th><td>{{ info.header.cpu }}</td></tr>
              <tr><th>Sub CPU</th><td>{{ info.header.sub_cpu }}</td></tr>
              <tr><th>Type</th><td>{{ info.header.type }}</td></tr>
              <tr><th>Flags</th><td>{{ info.header.flags }}</td></tr>
              <tr><th>Number of Commands</th><td>{{ info.header.ncmds }}</td></tr>
            </table>
          </div>
        </div>

        <!-- Load Commands -->
        <div class="sub-panel" v-if="info.load_commands && info.load_commands.length">
          <div class="sub-panel-header" @click="archExpanded[arch].load_commands = !archExpanded[arch].load_commands">
            <span class="sub-panel-title">Load Commands ({{ info.load_commands.length }})</span>
            <span class="arrow" :class="{ open: archExpanded[arch]?.load_commands }">▸</span>
          </div>
          <div v-if="archExpanded[arch]?.load_commands" class="sub-panel-body scrollable">
            <table class="data-table">
              <thead>
                <tr><th>Command</th><th>Size</th><th>Content</th></tr>
              </thead>
              <tbody>
                <tr v-for="(lc, i) in info.load_commands" :key="i">
                  <td>{{ lc.command }}</td>
                  <td>{{ lc.size }}</td>
                  <td>{{ lc.content }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Sections -->
        <div class="sub-panel" v-if="info.sections && info.sections.length">
          <div class="sub-panel-header" @click="archExpanded[arch].sections = !archExpanded[arch].sections">
            <span class="sub-panel-title">Sections ({{ info.sections.length }})</span>
            <span class="arrow" :class="{ open: archExpanded[arch]?.sections }">▸</span>
          </div>
          <div v-if="archExpanded[arch]?.sections" class="sub-panel-body scrollable">
            <table class="data-table">
              <thead>
                <tr><th>Name</th><th>Size</th><th>Offset</th><th>Addr</th><th>Flags</th></tr>
              </thead>
              <tbody>
                <tr v-for="(sec, i) in info.sections" :key="i">
                  <td>{{ sec.name }}</td>
                  <td>{{ sec.filesz }}</td>
                  <td>0x{{ sec.offset?.toString(16) }}</td>
                  <td>0x{{ sec.addr?.toString(16) }}</td>
                  <td>{{ sec.flags }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Code Signature -->
        <div class="sub-panel" v-if="info.code_signature">
          <div class="sub-panel-header" @click="archExpanded[arch].code_signature = !archExpanded[arch].code_signature">
            <span class="sub-panel-title">Code Signature</span>
            <span class="arrow" :class="{ open: archExpanded[arch]?.code_signature }">▸</span>
          </div>
          <div v-show="archExpanded[arch]?.code_signature" class="sub-panel-body">
            <table class="kv-table">
              <tr><th>Signed</th><td>{{ info.code_signature.signed ? 'Yes' : 'No' }}</td></tr>
              <tr><th>Identifier</th><td>{{ info.code_signature.identifier || '-' }}</td></tr>
              <tr><th>Team ID</th><td>{{ info.code_signature.team_id || '-' }}</td></tr>
              <tr><th>CDHash</th><td>{{ info.code_signature.cdhash || '-' }}</td></tr>
              <tr><th>Flags</th><td>{{ info.code_signature.code_directories?.[0]?.flags_str || '-' }}</td></tr>
              <tr>
                <th>Entitlements</th>
                <td>
                  <template v-if="info.code_signature.entitlements && Object.keys(info.code_signature.entitlements).length">
                    <div v-for="(val, key) in info.code_signature.entitlements" :key="key" class="ent-row">
                      <span class="ent-key">{{ key }}</span>
                      <span class="ent-val">
                        <span v-if="Array.isArray(val)">{{ JSON.stringify(val) }}</span>
                        <span v-else>{{ val }}</span>
                      </span>
                    </div>
                  </template>
                  <span v-else>-</span>
                </td>
              </tr>
            </table>
          </div>
        </div>

        <!-- Symbols -->
        <div class="sub-panel" v-if="info.symbol && (info.symbol.imports && Object.keys(info.symbol.imports).length || info.symbol.exports?.length || info.symbol.locals?.length)">
          <div class="sub-panel-header" @click="archExpanded[arch].symbols = !archExpanded[arch].symbols">
            <span class="sub-panel-title">Symbols</span>
            <span class="arrow" :class="{ open: archExpanded[arch]?.symbols }">▸</span>
          </div>
          <div v-if="archExpanded[arch]?.symbols" class="sub-panel-body">
            <!-- Imports -->
            <div v-if="info.symbol.imports && Object.keys(info.symbol.imports).length" class="sub-section">
              <div class="sub-section-header" @click="archExpanded[arch].imports = !archExpanded[arch].imports">
                <span class="arrow" :class="{ open: archExpanded[arch]?.imports }">▸</span>
                <span>Imports</span>
              </div>
              <div v-show="archExpanded[arch]?.imports" class="sub-section-body">
                <div v-for="(syms, lib) in info.symbol.imports" :key="lib" class="import-block">
                  <div class="import-lib" @click="expandedLibs[`${arch}::${lib}`] = !expandedLibs[`${arch}::${lib}`]">
                    <span class="arrow" :class="{ open: expandedLibs[`${arch}::${lib}`] }">▸</span>
                    {{ lib }}
                    <span class="import-count">({{ syms.length }})</span>
                  </div>
                  <div v-show="expandedLibs[`${arch}::${lib}`]" class="import-syms">
                    <div v-for="(s, i) in syms" :key="i" class="import-sym"><SymbolName :name="s" /></div>
                  </div>
                </div>
              </div>
            </div>
            <!-- Exports -->
            <div v-if="info.symbol.exports && info.symbol.exports.length" class="sub-section">
              <div class="sub-section-header" @click="archExpanded[arch].exports = !archExpanded[arch].exports">
                <span class="arrow" :class="{ open: archExpanded[arch]?.exports }">▸</span>
                <span>Exports ({{ info.symbol.exports.length }})</span>
              </div>
              <div v-show="archExpanded[arch]?.exports" class="sub-section-body">
                <table class="data-table">
                  <thead><tr><th>Name</th><th>Type</th><th>Address</th></tr></thead>
                  <tbody>
                    <tr v-for="(sym, i) in info.symbol.exports" :key="i">
                      <td class="sym-name"><SymbolName :name="sym.name" /></td>
                      <td>{{ sym.type }}</td>
                      <td>{{ sym.address }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
            <!-- Locals -->
            <div v-if="info.symbol.locals && info.symbol.locals.length" class="sub-section">
              <div class="sub-section-header" @click="archExpanded[arch].locals = !archExpanded[arch].locals">
                <span class="arrow" :class="{ open: archExpanded[arch]?.locals }">▸</span>
                <span>Locals ({{ info.symbol.locals.length }})</span>
              </div>
              <div v-show="archExpanded[arch]?.locals" class="sub-section-body">
                <table class="data-table">
                  <thead><tr><th>Name</th><th>Type</th><th>Address</th></tr></thead>
                  <tbody>
                    <tr v-for="(sym, i) in info.symbol.locals" :key="i">
                      <td class="sym-name"><SymbolName :name="sym.name" /></td>
                      <td>{{ sym.type }}</td>
                      <td>{{ sym.address }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>

        <!-- Strings -->
        <div class="sub-panel" v-if="info.strings?.cstrings?.length || info.strings?.iocs?.length">
          <div class="sub-panel-header" @click="archExpanded[arch].strings = !archExpanded[arch].strings">
            <span class="sub-panel-title">Strings ({{ (info.strings.iocs?.length || 0) + (info.strings.cstrings?.length || 0) }})</span>
            <span class="arrow" :class="{ open: archExpanded[arch]?.strings }">▸</span>
          </div>
          <div v-if="archExpanded[arch]?.strings" class="sub-panel-body strings-body">
            <div v-if="info.strings.iocs?.length" class="string-column iocs-column">
              <div class="string-column-title">IOCs ({{ info.strings.iocs.length }})</div>
              <pre class="string-block">{{ info.strings.iocs.join('\n') }}</pre>
            </div>
            <div v-if="info.strings.cstrings?.length" class="string-column cstrings-column">
              <div class="string-column-title">CStrings ({{ info.strings.cstrings.length }})</div>
              <pre class="string-block">{{ (showAllStrings[arch] ? info.strings.cstrings : info.strings.cstrings.slice(0,30)).map(s => s.str || s).join('\n') }}</pre>
              <div v-if="!showAllStrings[arch] && info.strings.cstrings.length > 30" class="more" @click="showAllStrings[arch] = true">
                ... and {{ info.strings.cstrings.length - 30 }} more
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.macho-content { font-size: 12px; }
.arch-block { margin-bottom: 16px; border: 1px solid #eee; border-radius: 8px; overflow: hidden; }
.arch-title-row {
  display: flex; align-items: center; justify-content: space-between;
  padding: 12px 16px; background: #fafafa; cursor: pointer;
}
.arch-title-row:hover { background: #f5f5f5; }
.arch-title { font-size: 15px; font-weight: 600; color: #333; margin: 0; }
.arch-body { padding: 12px 16px; font-size: 12px; }

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

.kv-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.kv-table th { width: 160px; text-align: left; padding: 8px 12px; color: #666; font-weight: 500; background: #fafafa; border-bottom: 1px solid #f0f0f0; }
.kv-table td { padding: 8px 12px; border-bottom: 1px solid #f0f0f0; color: #333; word-break: break-all; }
.data-table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }
.data-table th { text-align: left; padding: 8px 12px; background: #f5f5f5; color: #555; font-weight: 600; border-bottom: 1px solid #e0e0e0; }
.data-table td { padding: 8px 12px; border-bottom: 1px solid #f0f0f0; color: #333; }
.data-table td.sym-name { max-width: 600px; }

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

.strings-body { display: flex; gap: 16px; align-items: flex-start; }
.string-column { flex: 1; min-width: 0; }
.string-column-title { font-size: 12px; font-weight: 600; color: #555; margin-bottom: 8px; }
.iocs-column .string-block { background: #fff8f0; border-color: #ffe0c0; }
</style>
