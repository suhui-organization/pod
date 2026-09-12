<template>
  <div class="traces">
    <div class="head">
      <div>
        <h2>调用链追踪</h2>
        <div class="sub">
          任务 = 单个 Agent 连续活动段(间隔 &gt;{{ gap }} 分钟切开);任务为源头,调用为节点,图谱按 server 分泳道
        </div>
      </div>
      <div class="filters">
        <el-select v-model="userFilter" clearable placeholder="全部用户" style="width: 140px" @change="pickFirst">
          <el-option v-for="u in users" :key="u.id" :label="u.full_name || u.email" :value="u.id" />
        </el-select>
        <el-select v-model="agentFilter" clearable placeholder="全部 Agent" style="width: 140px" @change="pickFirst">
          <el-option v-for="a in agentOptions" :key="a" :label="a" :value="a" />
        </el-select>
        <el-select v-model="minutes" style="width: 120px" @change="load">
          <el-option label="最近 1 小时" :value="60" />
          <el-option label="最近 24 小时" :value="1440" />
          <el-option label="最近 7 天" :value="10080" />
        </el-select>
        <el-button :loading="loading" @click="load">刷新</el-button>
      </div>
    </div>

    <!-- 耗时统计条 -->
    <div v-if="stats" class="stats">
      <div class="stat"><b>{{ stats.tasks }}</b><span>任务</span></div>
      <div class="stat"><b>{{ stats.agents }}</b><span>Agent</span></div>
      <div class="stat"><b>{{ stats.calls }}</b><span>调用次数</span></div>
      <div class="stat"><b>{{ fmtDur(stats.durationTotal) }}</b><span>累计耗时</span></div>
      <div class="stat"><b>{{ fmtDur(stats.avgTask) }}</b><span>平均/任务</span></div>
      <div class="stat"><b>{{ fmtDur(stats.maxTask.sec) }}</b><span>最长任务 · {{ stats.maxTask.agent }}</span></div>
      <el-tooltip :content="`相邻调用平均间隔最长: ${fmtDur(stats.maxGap)}`">
        <div class="stat"><b>{{ fmtDur(stats.maxGap) }}</b><span>最长空闲间隔</span></div>
      </el-tooltip>
    </div>

    <div v-if="compareIds.length" class="cmp-bar">
      同屏对比:
      <el-tag v-for="cid in compareIds" :key="cid" size="small" closable @close="toggleCompare(cid)" type="primary" effect="plain">
        {{ taskById(cid)?.agent }} · {{ fmtDT(taskById(cid)?.started_at ?? '').slice(5, 16) }}
      </el-tag>
      <el-button link size="small" @click="compareIds = []">清空(回到单任务)</el-button>
    </div>

    <div v-if="laneTasks.length" class="body">
      <!-- 左: 用户 → Agent → 任务 -->
      <aside class="side">
        <div v-for="u in userGroups" :key="u.id" class="ugroup">
          <div class="uname">{{ u.name }}<span class="u-role">{{ u.role }}</span></div>
          <div v-for="t in u.tasks" :key="t.id" class="task"
            :class="{ active: t.id === activeId, incompare: compareIds.includes(t.id) }"
            @click="selectTask(t)">
            <div class="t-line1">
              <span class="t-agent">{{ t.agent }}</span>
              <span class="t-dur">{{ fmtDur(t.duration_seconds) }}</span>
            </div>
            <div class="t-time">{{ fmtDT(t.started_at).slice(5) }} → {{ fmtTime(t.ended_at) }}</div>
            <div class="t-line2">
              <span class="t-calls">{{ t.call_count }} 次 · 均隔 {{ fmtDur(t.avg_gap_seconds) }}</span>
              <el-tag v-if="t.decisions.deny" size="small" type="danger" effect="dark">{{ t.decisions.deny }} 拒绝</el-tag>
              <el-tag v-else-if="t.decisions.approve" size="small" type="warning" effect="plain">含审批</el-tag>
              <el-tag v-else size="small" type="success" effect="plain">全部放行</el-tag>
              <el-button link size="small" type="primary" class="cmp-btn" @click.stop="toggleCompare(t.id)">
                {{ compareIds.includes(t.id) ? '✓ 对比中' : '⧉ 对比' }}
              </el-button>
            </div>
          </div>
        </div>
      </aside>

      <!-- 中: 泳道关系图谱 -->
      <section class="main">
        <div class="ghead">
          <div v-if="laneTasks.length" class="gtitle">
            <b>{{ laneTasks.length > 1 ? `对比 ${laneTasks.length} 条任务链` : `${laneTasks[0].agent} 任务链` }}</b>
            <span v-for="(t, i) in laneTasks" :key="t.id">
              {{ i + 1 }}. {{ t.agent }} {{ fmtDT(t.started_at).slice(5, 16) }} · {{ t.call_count }} 调用 · {{ fmtDur(t.duration_seconds) }}
            </span>
          </div>
          <div class="legend">
            <span class="lg lg-task">任务源头</span>
            <span class="lg lg-allow">放行</span>
            <span class="lg lg-approve">审批</span>
            <span class="lg lg-deny">拒绝</span>
            <span class="lg lg-other">其他</span>
          </div>
        </div>
        <div ref="chartEl" class="chart" :style="{ height: chartHeight + 'px' }"></div>
      </section>

      <!-- 节点详情 -->
      <aside class="detail" v-if="detail">
        <div class="d-head">
          <b>{{ detail.kind === 'root' ? '任务源头' : '调用节点' }}</b>
          <el-button link size="small" @click="detail = null">关闭</el-button>
        </div>
        <template v-if="rootDetail">
          <div class="d-row"><span>Agent</span><b>{{ rootDetail.agent }} · {{ rootDetail.platform }}</b></div>
          <div class="d-row"><span>归属用户</span><b>{{ rootDetail.owner_name || rootDetail.owner_email || '—' }}</b></div>
          <div class="d-row"><span>开始 → 结束</span><b>{{ fmtDT(rootDetail.started_at).slice(5) }} → {{ fmtDT(rootDetail.ended_at).slice(11) }}</b></div>
          <div class="d-row"><span>任务耗时</span><b>{{ fmtDur(rootDetail.duration_seconds) }}</b></div>
          <div class="d-row"><span>调用节奏</span><b>平均 {{ fmtDur(rootDetail.avg_gap_seconds) }} · 最长间隔 {{ fmtDur(rootDetail.max_gap_seconds) }}</b></div>
          <div class="d-row"><span>调用总数</span><b>{{ rootDetail.call_count }}</b></div>
          <div class="d-row"><span>决策分布</span><b>{{ decisionSummary(rootDetail.decisions) }}</b></div>
        </template>
        <template v-else-if="callDetail">
          <div class="d-row"><span>工具</span><b>{{ callDetail.tool }}</b></div>
          <div class="d-row"><span>服务器(泳道)</span><b>{{ callDetail.server }}</b></div>
          <div class="d-row"><span>决策</span>
            <el-tag size="small" :type="decisionType(callDetail.decision)">{{ decisionLabel(callDetail.decision) }}</el-tag>
          </div>
          <div class="d-row"><span>结果</span><b>{{ outcomeLabel(callDetail.outcome) }}</b></div>
          <div class="d-row"><span>时间</span><b>{{ fmtDT(callDetail.ts) }}</b></div>
          <div class="d-row"><span>距上一调用</span><b>{{ callDetail.inter_gap_seconds == null ? '—' : fmtDur(callDetail.inter_gap_seconds) }}</b></div>
          <div class="d-row"><span>审批人</span><b>{{ callDetail.approver || '—' }}</b></div>
          <div class="d-row"><span>策略版本</span><b>v{{ callDetail.policy_version || '—' }}</b></div>
          <div class="d-block">
            <span class="d-label">处理说明(理由)</span>
            <div class="d-reason">{{ callDetail.reason || '—' }}</div>
          </div>
          <div class="d-block">
            <span class="d-label">参数哈希(隐私最小化)</span>
            <code class="d-hash">{{ callDetail.args_hash }}</code>
          </div>
        </template>
      </aside>
    </div>

    <el-empty v-else-if="!loading" description="窗口内暂无任务数据(Agent 先跑出审计并 pod sync)" :image-size="80" />
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts'
import { api } from '../api'

type TraceResp = Awaited<ReturnType<typeof api.traces>>
type Task = TraceResp['tasks'][number]
type Call = Task['calls'][number]

const users = ref<TraceResp['users']>([])
const tasks = ref<Task[]>([])
const gap = ref(15)
const userFilter = ref<number>()
const agentFilter = ref<string>()
const minutes = ref(1440)
const loading = ref(false)
const activeId = ref('')
const compareIds = ref<string[]>([])
const chartEl = ref<HTMLDivElement>()
const detail = ref<{ kind: 'root' | 'call'; task?: Task; call?: Call } | null>(null)
const rootDetail = computed(() => (detail.value?.kind === 'root' ? (detail.value.task ?? null) : null))
const callDetail = computed(() => (detail.value?.kind === 'call' ? (detail.value.call ?? null) : null))
let chart: echarts.ECharts | null = null

const agentOptions = computed(() => [...new Set(tasks.value.map((t) => t.agent))])
const visibleTasks = computed(() =>
  tasks.value.filter(
    (t) => (!userFilter.value || t.owner_id === userFilter.value) && (!agentFilter.value || t.agent === agentFilter.value),
  ),
)
const userGroups = computed(() => {
  const map = new Map<number, { id: number; name: string; role: string; tasks: Task[] }>()
  for (const t of visibleTasks.value) {
    const key = t.owner_id ?? 0
    const u = users.value.find((x) => x.id === key)
    if (!map.has(key)) map.set(key, { id: key, name: u?.full_name || u?.email || '未归属', role: u?.role || '', tasks: [] })
    map.get(key)!.tasks.push(t)
  }
  return [...map.values()].map((g) => ({ ...g, tasks: [...g.tasks].sort((a, b) => b.started_at.localeCompare(a.started_at)) }))
})
const taskById = (id: string) => tasks.value.find((t) => t.id === id) ?? null
const laneTasks = computed<Task[]>(() => {
  const ids = compareIds.value.length ? compareIds.value : activeId.value ? [activeId.value] : []
  const picked = ids.map((id) => visibleTasks.value.find((t) => t.id === id)).filter((t): t is Task => !!t)
  return picked.length ? picked : visibleTasks.value.slice(0, 1)
})

// ── 耗时统计 ─────────────────────────────────────────────────────────────
function fmtDur(sec: number | null | undefined): string {
  const s = Math.max(0, Math.round(sec ?? 0))
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const r = s % 60
  if (h) return `${h}h${String(m).padStart(2, '0')}m`
  if (m) return `${m}m${String(r).padStart(2, '0')}s`
  return `${r}s`
}
const stats = computed(() => {
  const ts = visibleTasks.value
  if (!ts.length) return null
  const calls = ts.reduce((a, t) => a + t.call_count, 0)
  const durTotal = ts.reduce((a, t) => a + t.duration_seconds, 0)
  const maxT = ts.reduce((a, t) => (t.duration_seconds > a.duration_seconds ? t : a), ts[0])
  const maxGap = ts.reduce((a, t) => Math.max(a, t.max_gap_seconds), 0)
  return {
    tasks: ts.length,
    agents: new Set(ts.map((t) => t.agent)).size,
    calls,
    durationTotal: durTotal,
    avgTask: ts.length ? durTotal / ts.length : 0,
    maxTask: { agent: maxT.agent, sec: maxT.duration_seconds },
    maxGap,
  }
})

const pad = (n: number) => String(n).padStart(2, '0')
function fmtTime(iso: string) {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}
function fmtDT(iso: string) {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${fmtTime(iso)}`
}
const decisionLabel = (d: string) => ({ allow: '放行', approve: '审批', deny: '拒绝' })[d] ?? d
const outcomeLabel = (o: string) => ({ ok: '成功', blocked: '被拦', error: '异常' })[o] ?? o
function decisionSummary(decisions: Record<string, number>) {
  return Object.entries(decisions).map(([k, v]) => `${decisionLabel(k)} ${v}`).join(' · ')
}
function decisionType(d: string): 'success' | 'warning' | 'danger' | 'info' {
  const map: Record<string, 'success' | 'warning' | 'danger' | 'info'> = { allow: 'success', approve: 'warning', deny: 'danger' }
  return map[d] ?? 'info'
}
const CAT = { task: 0, allow: 1, approve: 2, deny: 3, other: 4 }

// ── 泳道布局: 任务为块, 每 server 一行(跨 Agent 同屏时按块纵向堆叠) ──────
const CANVAS_W = 1040
const START_X = 190
const ROW_H = 92
const BLOCK_HEAD = 66
const STEP_MIN = 74

interface Lane {
  task: Task
  servers: string[]
  rows: Map<string, { x: number; y: number; i: number }>
  root: { x: number; y: number }
  height: number
  step: number
}
function computeLanes(tasks: Task[]): { lanes: Lane[]; height: number; labels: Array<{ text: string; x: number; y: number; bold?: boolean }> } {
  const lanes: Lane[] = []
  const labels: Array<{ text: string; x: number; y: number; bold?: boolean }> = []
  let y = 30
  for (const task of tasks) {
    const servers: string[] = []
    for (const c of task.calls) if (!servers.includes(c.server)) servers.push(c.server)
    const rows = servers.length || 1
    const step = Math.max(STEP_MIN, Math.min(120, Math.floor((CANVAS_W - START_X - 60) / Math.max(task.calls.length, 1))))
    const blockH = BLOCK_HEAD + rows * ROW_H + 46
    const rowMap = new Map<string, { x: number; y: number; i: number }>()
    servers.forEach((srv, i) => rowMap.set(srv, { x: START_X, y: y + BLOCK_HEAD + 6 + i * ROW_H, i }))
    const rootY = y + BLOCK_HEAD - 34
    labels.push({ text: `${task.agent} · ${fmtDT(task.started_at).slice(5, 16)} → ${fmtTime(task.ended_at)} · ${task.call_count} 调用 · ${fmtDur(task.duration_seconds)}`, x: 8, y: y + 8, bold: true })
    servers.forEach((srv, i) => labels.push({ text: srv, x: 10, y: y + BLOCK_HEAD + 14 + i * ROW_H }))
    lanes.push({ task, servers, rows: rowMap, root: { x: START_X, y: rootY }, height: blockH, step })
    y += blockH
  }
  return { lanes, height: Math.max(560, y + 40), labels }
}

function graphOption(lanes: { lanes: Lane[]; height: number; labels: Array<{ text: string; x: number; y: number; bold?: boolean }> }): any {
  const nodes: any[] = []
  const links: any[] = []
  const catOf = (d: string) => ({ allow: CAT.allow, approve: CAT.approve, deny: CAT.deny })[d] ?? CAT.other
  for (const lane of lanes.lanes) {
    const { task } = lane
    nodes.push({
      id: `${task.id}#root`,
      name: task.agent,
      category: CAT.task,
      symbol: 'diamond',
      symbolSize: 40,
      x: lane.root.x,
      y: lane.root.y,
      label: { show: true, fontSize: 11, fontWeight: 'bold', color: '#fff' },
      itemStyle: { color: '#f0a020', borderWidth: 2, borderColor: '#fff' },
    })
    task.calls.forEach((c, i) => {
      const row = lane.rows.get(c.server) ?? lane.rows.get(lane.servers[0])!
      const x = START_X + i * lane.step
      const id = `${task.id}#c-${c.id}`
      nodes.push({
        id,
        name: c.tool,
        category: catOf(c.decision),
        symbolSize: 32,
        x,
        y: row.y,
        label: { show: c.decision === 'deny', fontSize: 10, position: 'bottom', color: '#f0887f' },
        call: c,
        taskId: task.id,
        itemStyle: c.decision === 'deny' ? {} : undefined,
      })
      row.x = x
      links.push({ source: i === 0 ? `${task.id}#root` : `${task.id}#c-${task.calls[i - 1].id}`, target: id })
    })
    if (!task.calls.length) links.push({ source: `${task.id}#root`, target: `${task.id}#root` })
  }
  return {
    tooltip: {
      trigger: 'item',
      confine: true,
      formatter: (p: any) => {
        if (!p.data) return ''
        if (p.data.id.endsWith('#root')) return `<b>${p.data.name}</b><br/>任务源头`
        const c = p.data.call as Call
        const t = tasks.value.find((x) => x.id === p.data.taskId)
        const rows: Array<[string, string]> = [
          ['任务', `${t?.agent ?? ''} @ ${fmtDT(c.ts).slice(5, 16)}`],
          ['工具', c.tool],
          ['服务器', c.server],
          ['决策', decisionLabel(c.decision)],
          ['结果', outcomeLabel(c.outcome)],
          ['距上一调用', c.inter_gap_seconds == null ? '—' : fmtDur(c.inter_gap_seconds)],
          ['审批人', c.approver || '—'],
          ['策略', `v${c.policy_version || '—'}`],
          ['说明', (c.reason || '—').slice(0, 140)],
          ['参数哈希', c.args_hash.slice(0, 24) + '…'],
        ]
        return `<b>${c.tool}</b><br/>` + rows.map(([k, v]) => `<div style="max-width:280px"><span style="color:#8b949e">${k}:</span> ${v}</div>`).join('')
      },
    },
    legend: {
      data: ['任务源头', '放行', '审批', '拒绝', '其他'],
      top: 0,
      left: 'center',
      textStyle: { color: '#9aa3af' },
      itemWidth: 12,
      itemHeight: 12,
    },
    graphic: lanes.labels.map((l) => ({
      type: 'text',
      left: l.x,
      top: l.y,
      style: { text: l.text, fill: l.bold ? '#e6edf3' : '#8b949e', font: l.bold ? 'bold 13px sans-serif' : '12px ui-monospace, monospace' },
    })),
    series: [
      {
        type: 'graph',
        layout: 'none',
        roam: true,
        draggable: true,
        categories: [
          { name: '任务源头', itemStyle: { color: '#f0a020' } },
          { name: '放行', itemStyle: { color: '#3fb950' } },
          { name: '审批', itemStyle: { color: '#d29922' } },
          { name: '拒绝', itemStyle: { color: '#f85149' } },
          { name: '其他', itemStyle: { color: '#8b949e' } },
        ],
        edgeSymbol: ['none', 'arrow'],
        edgeSymbolSize: 8,
        lineStyle: { color: 'rgba(160,170,180,0.6)', width: 1.6, curveness: 0.08 },
        emphasis: { focus: 'adjacency', lineStyle: { width: 2.6 } },
        data: nodes,
        links,
      },
    ],
  }
}

const chartHeight = ref(600)
function renderChart() {
  const el = chartEl.value
  if (!el) return
  const lanesData = computeLanes(laneTasks.value)
  chartHeight.value = lanesData.height
  if (!chart) chart = echarts.init(el)
  chart.setOption(graphOption(lanesData), true)
  chart.resize()
  // 节点点击 → 右侧详情(每个点处理了什么)
  chart.off('click')
  chart.on('click', (p: any) => {
    if (!p?.data) return
    const id: string = p.data.id ?? ''
    if (id.endsWith('#root')) {
      const task = laneTasks.value.find((t) => id.startsWith(`${t.id}#`))
      if (task) detail.value = { kind: 'root', task }
      return
    }
    const call: Call | undefined = p.data.call
    const task = laneTasks.value.find((t) => id.startsWith(`${t.id}#`))
    if (call && task) detail.value = { kind: 'call', task, call }
  })
}

async function load() {
  loading.value = true
  try {
    const r = await api.traces({ minutes: minutes.value })
    users.value = r.users
    tasks.value = r.tasks
    gap.value = r.gap_minutes
    pickFirst()
  } finally {
    loading.value = false
  }
}
function pickFirst() {
  if (!visibleTasks.value.some((t) => t.id === activeId.value)) {
    activeId.value = visibleTasks.value[0]?.id ?? ''
  }
  compareIds.value = compareIds.value.filter((id) => visibleTasks.value.some((t) => t.id === id))
}
function selectTask(t: Task) {
  activeId.value = t.id
  detail.value = null
}
function toggleCompare(id: string) {
  const i = compareIds.value.indexOf(id)
  if (i >= 0) compareIds.value.splice(i, 1)
  else {
    compareIds.value.push(id)
    if (compareIds.value.length > 6) compareIds.value = compareIds.value.slice(-6)
  }
  detail.value = null
}
function onResize() {
  chart?.resize()
}

watch([laneTasks, detail], async () => {
  await nextTick()
  renderChart()
})

onMounted(async () => {
  await load()
  window.addEventListener('resize', onResize)
})
onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  chart?.dispose()
  chart = null
})
</script>

<style scoped>
.head { display: flex; justify-content: space-between; align-items: flex-end; gap: 12px; margin-bottom: 10px; flex-wrap: wrap; }
.head h2 { margin: 0; }
.sub { font-size: 12px; color: var(--pod-text-dim, #9aa3af); margin-top: 4px; }
.filters { display: flex; gap: 8px; flex-wrap: wrap; }

.stats { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 10px; }
.stat { display: flex; align-items: baseline; gap: 6px; background: var(--pod-panel-bg, #161a1f); border: 1px solid var(--pod-border, #2a2f37); border-radius: 10px; padding: 6px 12px; font-size: 12px; color: var(--pod-text-dim, #9aa3af); cursor: default; }
.stat b { font-size: 16px; color: var(--pod-text, #e6edf3); }

.cmp-bar { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; font-size: 12px; color: var(--pod-text-dim, #9aa3af); flex-wrap: wrap; }

.body { display: grid; grid-template-columns: 300px 1fr 300px; gap: 14px; align-items: start; }
@media (max-width: 1200px) { .body { grid-template-columns: 1fr; } }

.side { border-radius: 12px; background: var(--pod-panel-bg, #161a1f); border: 1px solid var(--pod-border, #2a2f37); padding: 10px; max-height: 700px; overflow: auto; }
.ugroup { margin-bottom: 12px; }
.uname { font-size: 12px; font-weight: 700; color: var(--pod-text, #e6edf3); padding: 2px 6px; display: flex; gap: 8px; align-items: center; }
.u-role { color: var(--pod-text-dim, #9aa3af); font-weight: 400; }
.task { border: 1px solid var(--pod-border, #2a2f37); border-radius: 8px; padding: 7px 9px; margin: 6px 0 0 6px; cursor: pointer; transition: border-color .15s; }
.task:hover { border-color: #4d8df6; }
.task.active { border-color: #4d8df6; background: rgba(77, 141, 246, 0.08); }
.task.incompare { border-color: #3fb950; }
.t-line1 { display: flex; justify-content: space-between; gap: 6px; align-items: baseline; }
.t-agent { font-weight: 600; font-size: 13px; }
.t-dur { font-size: 11px; color: var(--pod-text-dim, #9aa3af); font-family: ui-monospace, monospace; }
.t-time { font-size: 11px; color: var(--pod-text-dim, #9aa3af); font-family: ui-monospace, monospace; margin-top: 2px; }
.t-line2 { display: flex; align-items: center; gap: 6px; margin-top: 5px; flex-wrap: wrap; }
.t-calls { font-size: 12px; color: var(--pod-text-dim, #9aa3af); }
.cmp-btn { padding: 0; font-size: 11px; }

.main { border-radius: 12px; background: var(--pod-panel-bg, #161a1f); border: 1px solid var(--pod-border, #2a2f37); padding: 12px; }
.ghead { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 6px; }
.gtitle { display: flex; gap: 10px; align-items: baseline; font-size: 13px; flex-wrap: wrap; }
.gtitle b { color: var(--pod-text, #e6edf3); }
.gtitle span { color: var(--pod-text-dim, #9aa3af); font-size: 12px; }
.legend { display: flex; gap: 10px; font-size: 11px; color: var(--pod-text-dim, #9aa3af); }
.lg::before { content: ''; display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 4px; }
.lg-task::before { background: #f0a020; }
.lg-allow::before { background: #3fb950; }
.lg-approve::before { background: #d29922; }
.lg-deny::before { background: #f85149; }
.lg-other::before { background: #8b949e; }
.chart { min-height: 300px; }

.detail { border-radius: 12px; background: var(--pod-panel-bg, #161a1f); border: 1px solid var(--pod-border, #2a2f37); padding: 12px; font-size: 12px; max-height: 700px; overflow: auto; }
.d-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
.d-row { display: flex; justify-content: space-between; gap: 10px; padding: 5px 0; border-bottom: 1px dashed var(--pod-border, #2a2f37); }
.d-row > span { color: var(--pod-text-dim, #9aa3af); flex-shrink: 0; }
.d-row b { font-weight: 600; text-align: right; }
.d-block { margin-top: 10px; }
.d-label { display: block; color: var(--pod-text-dim, #9aa3af); margin-bottom: 4px; }
.d-reason { background: var(--pod-panel-elev, #1c2128); border-radius: 6px; padding: 8px; line-height: 1.6; white-space: pre-wrap; word-break: break-all; }
.d-hash { font-family: ui-monospace, monospace; font-size: 11px; word-break: break-all; background: var(--pod-panel-elev, #1c2128); padding: 6px 8px; border-radius: 6px; display: block; }
</style>
