<template>
  <div>
    <div class="head">
      <h2>控制平面</h2>
      <div class="filters">
        <el-select v-model="kind" style="width: 160px" @change="load">
          <el-option label="全部类型" value="" />
          <el-option v-for="k in KIND_LABELS" :key="k.value" :label="k.label" :value="k.value" />
        </el-select>
        <el-select v-model="minutes" style="width: 140px" @change="load">
          <el-option label="全部时间" :value="0" />
          <el-option label="最近 1 小时" :value="60" />
          <el-option label="最近 24 小时" :value="1440" />
          <el-option label="最近 7 天" :value="10080" />
        </el-select>
        <el-button :loading="loading" @click="load">刷新</el-button>
      </div>
    </div>

    <el-alert type="info" :closable="false" show-icon class="hint"
      title="控制平面事件：钩子、配置冻结项、记忆文件、MCP 包来源、Agent 身份、委托链、JIT 令牌、熔断。来自本机 pod posture / quarantine / delegate 等命令，经 pod sync 上云。" />

    <div class="cards">
      <el-card shadow="never" class="card">
        <div class="card-num high">{{ summary.by_severity.high || 0 }}</div>
        <div class="card-label">高危</div>
      </el-card>
      <el-card shadow="never" class="card">
        <div class="card-num medium">{{ summary.by_severity.medium || 0 }}</div>
        <div class="card-label">中危</div>
      </el-card>
      <el-card shadow="never" class="card">
        <div class="card-num low">{{ summary.by_severity.low || 0 }}</div>
        <div class="card-label">提示</div>
      </el-card>
      <el-card shadow="never" class="card">
        <div class="card-num">{{ summary.total }}</div>
        <div class="card-label">事件总数</div>
      </el-card>
    </div>

    <div v-if="kindCounts.length" class="kind-tags">
      <el-tag v-for="k in kindCounts" :key="k.kind" size="small" effect="plain" class="kind-tag">
        {{ labelOf(k.kind) }} · {{ k.count }}
      </el-tag>
    </div>

    <el-table :data="events" v-loading="loading" stripe style="width: 100%">
      <el-table-column label="时间" width="180">
        <template #default="{ row }">{{ fmtTime(row.ts) }}</template>
      </el-table-column>
      <el-table-column prop="agent" label="Agent" width="140" />
      <el-table-column label="类型" width="140">
        <template #default="{ row }">
          <el-tag size="small" effect="plain">{{ labelOf(row.kind) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="级别" width="90">
        <template #default="{ row }">
          <el-tag size="small" :type="severityType(row.severity)">{{ severityLabel(row.severity) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="决策" width="100">
        <template #default="{ row }">
          <span :class="`dec-${row.decision}`">{{ row.decision }}</span>
        </template>
      </el-table-column>
      <el-table-column label="详情" min-width="320">
        <template #default="{ row }">
          <div class="reason">{{ row.reason }}</div>
          <div class="meta">
            <span>序号 #{{ row.seq }}</span>
            <code>{{ shortHash(row.hash) }}</code>
          </div>
        </template>
      </el-table-column>
    </el-table>
    <el-empty v-if="!loading && events.length === 0" description="暂无控制平面事件（本机跑 pod posture 并 pod sync 后可见）" :image-size="70" />

    <p class="footnote">
      级别为服务端按事件类型与决策推导（severity_source={{ severitySource }}），用于快速分拣；
      原始事实是每行的事件类型、决策与哈希链。
    </p>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api } from '../api'

type ControlEvent = Awaited<ReturnType<typeof api.controlEvents>>['events'][number]

const KIND_LABELS = [
  { value: 'hook', label: '生命周期钩子' },
  { value: 'config-change', label: '配置冻结/漂移' },
  { value: 'memory', label: '记忆完整性' },
  { value: 'package', label: 'MCP 包来源' },
  { value: 'identity', label: 'Agent 身份' },
  { value: 'delegation', label: '委托链' },
  { value: 'grant', label: 'JIT 令牌' },
  { value: 'quarantine', label: '熔断' },
  { value: 'anomaly', label: '异常信号' },
  { value: 'metadata', label: '工具元数据' },
]

const events = ref<ControlEvent[]>([])
const summary = ref<{ total: number; by_kind: Record<string, number>; by_severity: Record<string, number> }>({
  total: 0,
  by_kind: {},
  by_severity: {},
})
const severitySource = ref('derived')
const kind = ref('')
const minutes = ref(0)
const loading = ref(false)

const kindCounts = computed(() =>
  Object.entries(summary.value.by_kind)
    .map(([k, count]) => ({ kind: k, count }))
    .sort((a, b) => b.count - a.count),
)

function labelOf(k: string): string {
  return KIND_LABELS.find((i) => i.value === k)?.label ?? k
}

function severityType(s: string): 'danger' | 'warning' | 'info' {
  if (s === 'high') return 'danger'
  if (s === 'medium') return 'warning'
  return 'info'
}

function severityLabel(s: string): string {
  if (s === 'high') return '高'
  if (s === 'medium') return '中'
  return '低'
}

function fmtTime(ts: string): string {
  const d = new Date(ts)
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString()
}

function shortHash(h: string): string {
  return h ? `${h.slice(0, 10)}…` : '—'
}

async function load() {
  loading.value = true
  try {
    const [list, sum] = await Promise.all([
      api.controlEvents({ limit: 300, minutes: minutes.value, kind: kind.value || undefined }),
      api.controlEventSummary(minutes.value),
    ])
    events.value = list.events
    severitySource.value = list.severity_source
    summary.value = sum
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.head h2 { margin: 0; }
.filters { display: flex; gap: 8px; }
.hint { margin-bottom: 14px; }
.cards { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 14px; }
.card :deep(.el-card__body) { padding: 14px 16px; }
.card-num { font-size: 24px; font-weight: 600; }
.card-num.high { color: var(--el-color-danger); }
.card-num.medium { color: var(--el-color-warning); }
.card-num.low { color: var(--el-color-info); }
.card-label { color: var(--el-text-color-secondary); font-size: 13px; margin-top: 2px; }
.kind-tags { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
.reason { word-break: break-all; }
.meta { color: var(--el-text-color-secondary); font-size: 12px; display: flex; gap: 12px; margin-top: 4px; }
.dec-deny { color: var(--el-color-danger); font-weight: 600; }
.dec-approve { color: var(--el-color-warning); font-weight: 600; }
.footnote { color: var(--el-text-color-secondary); font-size: 12px; margin-top: 12px; }
@media (max-width: 900px) {
  .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
</style>
