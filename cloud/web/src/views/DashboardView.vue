<template>
  <div class="dash">
    <div class="dash-meta">
      <span v-if="updatedAt">{{ t('更新于') }} {{ updatedAt }}　·　{{ t('每 30 秒自动刷新') }}</span>
    </div>
    <!-- KPI 行 -->
    <div class="stat-row">
      <div class="stat-card">
        <div class="stat-num">{{ s?.events.total ?? '—' }}</div>
        <div class="stat-label">{{ t('审计事件（累计）') }}</div>
        <div class="stat-sub">{{ t('决策: allow') }} {{ s?.events.by_decision.allow ?? 0 }} · deny {{ s?.events.by_decision.deny ?? 0 }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">{{ s?.agents.online ?? 0 }}<span class="stat-slash">/ {{ s?.agents.total ?? 0 }}</span></div>
        <div class="stat-label">{{ t('Agent 在线 / 总数') }}</div>
        <div class="stat-sub">{{ t('跨 Agent 统一视图') }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">{{ weekEvents }}</div>
        <div class="stat-label">{{ t('近 7 天事件') }}</div>
        <div class="stat-sub">{{ t('趋势见下方图表') }}</div>
      </div>
      <router-link to="/alerts" class="stat-card link-card" :class="{ danger: (s?.alerts.open ?? 0) > 0 }">
        <div class="stat-num">{{ s?.alerts.open ?? 0 }}</div>
        <div class="stat-label">{{ t('未解决告警') }}</div>
        <div class="stat-sub">
          <span v-if="(s?.alerts.open_high ?? 0) > 0" class="high-tag">{{ t('高危') }} {{ s?.alerts.open_high ?? 0 }}</span>
          <span v-else>{{ t('已确认') }} {{ s?.alerts.acknowledged ?? 0 }} · {{ t('已解决') }} {{ s?.alerts.resolved ?? 0 }}</span>
        </div>
      </router-link>
    </div>

    <!-- 图表区 -->
    <!-- 机器上报的资产与发现：先说"还缺什么防护"，再说"干了多少活" -->
    <div class="grid">
      <router-link to="/agents" class="panel link-panel" :class="{ warn: (s?.assets.unmanaged ?? 0) > 0 }">
        <h3>{{ t('网关覆盖率（机器上报）') }}</h3>
        <div class="stat-num">{{ (s?.assets.servers ?? 0) - (s?.assets.unmanaged ?? 0) }}<span class="stat-slash">/ {{ s?.assets.servers ?? 0 }}</span></div>
        <p class="panel-note">
          {{ t('{unmanaged} 个 MCP server 绕过网关（涉及 {agents} 台机器）——这些 server 的策略、审批与审计都不生效。', {
            unmanaged: s?.assets.unmanaged ?? 0,
            agents: s?.assets.machines_with_unmanaged ?? 0,
          }) }}
        </p>
        <p class="panel-note">
          {{ t('纳管 harness {managed}/{total}', { managed: s?.assets.harnesses_managed ?? 0, total: s?.assets.harnesses ?? 0 }) }}
        </p>
      </router-link>
      <div class="panel" :class="{ warn: (s?.findings.totals.high ?? 0) > 0 }">
        <h3>{{ t('扫描发现（机器上报）') }}</h3>
        <div class="stat-num">{{ s?.findings.totals.high ?? 0 }}<span class="stat-slash">/ {{ (s?.findings.totals.high ?? 0) + (s?.findings.totals.medium ?? 0) + (s?.findings.totals.low ?? 0) }}</span></div>
        <p class="panel-note">
          {{ t('high / 全部 · 来自 {agents} 台机器的最近一次扫描', { agents: s?.findings.reported_agents ?? 0 }) }}
        </p>
        <ul v-if="s?.findings.top.length" class="finding-list">
          <li v-for="f in s.findings.top.slice(0, 5)" :key="f.source + f.key + f.severity">
            <span class="sev" :class="'sev--' + f.severity">{{ f.severity }}</span>
            <code>{{ f.key }}</code>
            <span class="cnt">×{{ f.count }}</span>
          </li>
        </ul>
        <p v-else class="panel-note">{{ t('还没有机器上报扫描结果（本机 pod 0.4.1 起随 sync 上报）') }}</p>
      </div>
    </div>

    <div class="grid">
      <div class="panel span2">
        <h3>{{ t('近 7 天事件趋势') }}</h3>
        <ChartBox :option="trendOption" height="240px" />
      </div>
      <div class="panel">
        <h3>{{ t('决策分布') }}</h3>
        <ChartBox :option="decisionOption" height="240px" />
      </div>
      <div class="panel">
        <h3>{{ t('服务器分布') }}</h3>
        <ChartBox :option="serverOption" height="240px" />
      </div>
      <div class="panel">
        <h3>{{ t('Agent 活跃度') }}</h3>
        <ChartBox :option="agentOption" height="240px" />
      </div>
      <div class="panel">
        <h3>{{ t('近 24h 活动分布（按小时）') }}</h3>
        <ChartBox :option="hourlyOption" height="240px" />
      </div>
    </div>

    <!-- 告警图表: 趋势(渐变面积线)与类型分布并排一行 -->
    <div class="grid">
      <div class="panel">
        <h3>{{ t('近 7 天告警趋势') }}</h3>
        <ChartBox :option="alertTrendOption" height="240px" />
      </div>
      <div class="panel">
        <h3>{{ t('告警类型分布') }}</h3>
        <ChartBox :option="alertKindOption" height="240px" />
      </div>
    </div>

    <!-- 工具 Top + 告警 -->
    <div class="grid">
      <div class="panel">
        <h3>{{ t('调用最多的工具 Top 10') }}</h3>
        <ChartBox :option="toolOption" height="260px" />
      </div>
      <div class="panel">
        <h3>{{ t('最近告警') }}</h3>
        <div v-if="s?.alerts_recent.length" class="alert-list">
          <div v-for="a in s!.alerts_recent" :key="a.id" class="alert-item">
            <el-tag :type="a.severity === 'high' ? 'danger' : a.severity === 'medium' ? 'warning' : 'info'" size="small">{{ a.severity }}</el-tag>
            <span class="alert-kind">{{ kindLabel(a.kind) }}</span>
            <span class="alert-msg">{{ a.message }}</span>
            <span class="alert-time">{{ formatDateTime(a.created_at) }}</span>
          </div>
        </div>
        <el-empty v-else :description="t('暂无告警')" :image-size="60" />
      </div>
    </div>

    <el-empty v-if="!s?.events.total" :description="t('还没有审计数据——先注册 Agent 并跑 pod sync')" :image-size="70" class="empty" />
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { formatDateTime, formatTime } from '../i18n'
import { api } from '../api'
import type { DashboardSummary } from '../api/types'
import ChartBox from '../components/ChartBox.vue'

const s = ref<DashboardSummary | null>(null)
const { t } = useI18n()
const updatedAt = ref('')
let refreshTimer: number | undefined

let loading = false
async function load() {
  if (loading) return
  loading = true
  try {
    s.value = await api.dashboardSummary()
    updatedAt.value = formatTime(new Date())
  } finally {
    loading = false
  }
}

/** 页面切回前台时立刻刷新一次（定时器在后台是停的，回来不该看旧数） */
function onVisibilityChange() {
  if (document.visibilityState === 'visible') void load()
}

const kindLabel = (k: string) =>
  t(
    ({
      secret_leak: '密钥拦截', sensitive_path: '敏感路径', policy_mismatch: '策略不匹配',
      deny_burst: 'Deny 突增', tool_spike: '调用风暴', injection_suspect: '注入信号',
      approval_timeout: '审批超时', unregistered_server: '未注册服务器', agent_silence: 'Agent 失联',
      manual_approval: '人工批准', tool_first_use: '新工具使用',
    })[k] ?? k,
  )

const weekEvents = computed(() => (s.value?.trend_7d ?? []).reduce((a, t) => a + t.events, 0))

const alertTrendOption = computed(() => {
  const days = s.value?.alerts.trend_7d ?? []
  const last = days[days.length - 1]
  return {
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'line' },
      formatter: (ps: Array<{ axisValue: string; data: number }>) => {
        const p = ps[0]
        return `${p.axisValue}<br/>${t('告警')} <b>${p.data}</b> ${t('条')}`
      },
    },
    grid: { left: 40, right: 20, top: 30, bottom: 28 },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: days.map((d) => d.date.slice(5)),
      axisLine: { lineStyle: { color: 'rgba(128,128,128,0.35)' } },
      axisLabel: { color: '#9aa3af' },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      splitLine: { lineStyle: { type: 'dashed', color: 'rgba(128,128,128,0.18)' } },
      axisLabel: { color: '#9aa3af' },
    },
    series: [{
      name: t('告警'),
      type: 'line',
      smooth: 0.35,
      symbol: 'circle',
      symbolSize: 7,
      showSymbol: true,
      data: days.map((d) => d.count),
      lineStyle: { width: 2.5, color: '#f56c6c' },
      itemStyle: { color: '#f56c6c', borderColor: '#fff', borderWidth: 1 },
      areaStyle: {
        color: {
          type: 'linear',
          x: 0, y: 0, x2: 0, y2: 1,
          colorStops: [
            { offset: 0, color: 'rgba(245,108,108,0.38)' },
            { offset: 1, color: 'rgba(245,108,108,0.02)' },
          ],
        },
      },
      markPoint: last
        ? {
            symbol: 'pin', symbolSize: 34,
            label: { formatter: (p: { value: number }) => String(p.value), fontSize: 10, color: '#fff' },
            data: [{ type: 'max', name: t('峰值'), itemStyle: { color: '#f56c6c' } }],
          }
        : undefined,
      emphasis: { focus: 'series' },
    }],
  }
})

const alertKindOption = computed(() => {
  const rows = s.value?.alerts.by_kind ?? []
  return {
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { bottom: 0, type: 'scroll' },
    series: [{
      name: t('告警类型'), type: 'pie', radius: ['35%', '62%'],
      data: rows.map((r) => ({ name: kindLabel(r.kind), value: r.count })),
      label: { formatter: '{b} {c}' },
    }],
  }
})

const trendOption = computed(() => ({
  tooltip: { trigger: 'axis' },
  grid: { left: 40, right: 16, top: 20, bottom: 28 },
  xAxis: { type: 'category', data: (s.value?.trend_7d ?? []).map((t) => t.date.slice(5)) },
  yAxis: { type: 'value', minInterval: 1 },
  series: [
    {
      name: t('事件'), type: 'line', smooth: true, areaStyle: { opacity: 0.15 },
      data: (s.value?.trend_7d ?? []).map((t) => t.events),
      itemStyle: { color: '#4f7cff' }, lineStyle: { color: '#4f7cff', width: 2 },
    },
  ],
}))

const decisionOption = computed(() => {
  const d = s.value?.events.by_decision ?? {}
  return {
    tooltip: { trigger: 'item' },
    legend: { bottom: 0 },
    series: [
      {
        type: 'pie', radius: ['45%', '70%'], center: ['50%', '45%'],
        label: { formatter: '{b}: {c}' },
        data: Object.entries(d).map(([name, value]) => ({ name, value })),
        color: ['#4f7cff', '#f56c6c', '#e6a23c'],
      },
    ],
  }
})

const serverOption = computed(() => {
  const m = s.value?.events.by_server ?? {}
  return {
    tooltip: { trigger: 'axis' },
    grid: { left: 40, right: 16, top: 20, bottom: 28 },
    xAxis: { type: 'category', data: Object.keys(m) },
    yAxis: { type: 'value', minInterval: 1 },
    series: [{ type: 'bar', data: Object.values(m), itemStyle: { color: '#4f7cff', borderRadius: [4, 4, 0, 0] }, barWidth: '45%' }],
  }
})

const agentOption = computed(() => {
  const rows = s.value?.events.per_agent ?? []
  return {
    // 柱子是近 7 天（活跃度），累计值放在 tooltip —— 两个口径都给，避免
    // "只增不减的累计量"被当成活跃度，看半天不动。
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      formatter: (params: Array<{ dataIndex: number }>) => {
        const i = params?.[0]?.dataIndex ?? 0
        const r = rows[i]
        if (!r) return ''
        return [
          `<b>${r.agent}</b>`,
          t('近 7 天：调用 {recent} · 控制平面 {control}', {
            recent: r.events_recent,
            control: r.control_recent,
          }),
          t('累计：调用 {total} · 控制平面 {control}', { total: r.events, control: r.control }),
        ].join('<br/>')
      },
    },
    legend: { top: 0, right: 0, itemWidth: 10, itemHeight: 10, textStyle: { fontSize: 11 } },
    grid: { left: 40, right: 16, top: 32, bottom: 28 },
    xAxis: { type: 'category', data: rows.map((r) => r.agent) },
    yAxis: { type: 'value', minInterval: 1 },
    series: [
      {
        name: t('调用（近 7 天）'),
        type: 'bar',
        stack: 'activity',
        data: rows.map((r) => r.events_recent),
        itemStyle: { color: '#34c77b' },
        barWidth: '45%',
      },
      {
        name: t('控制平面（近 7 天）'),
        type: 'bar',
        stack: 'activity',
        data: rows.map((r) => r.control_recent),
        itemStyle: { color: '#7aa2f7', borderRadius: [4, 4, 0, 0] },
      },
    ],
  }
})

const hourlyOption = computed(() => {
  const rows = s.value?.events.hourly_24h ?? []
  const hourMap: Record<string, number> = {}
  for (const r of rows) hourMap[r.hour] = r.events
  const hours = Array.from({ length: 24 }, (_, i) => String(i).padStart(2, '0'))
  return {
    tooltip: { trigger: 'axis' },
    grid: { left: 40, right: 16, top: 20, bottom: 28 },
    xAxis: { type: 'category', data: hours, axisLabel: { interval: 3 } },
    yAxis: { type: 'value', minInterval: 1 },
    series: [{ type: 'bar', data: hours.map((h) => hourMap[h] ?? 0), itemStyle: { color: '#9b7bff' }, barWidth: '55%' }],
  }
})

const toolOption = computed(() => {
  const rows = s.value?.events.by_tool ?? []
  return {
    tooltip: { trigger: 'axis' },
    grid: { left: 40, right: 16, top: 20, bottom: 28 },
    xAxis: { type: 'category', data: rows.map((r) => r.tool) },
    yAxis: { type: 'value', minInterval: 1 },
    series: [{ type: 'bar', data: rows.map((r) => r.events), itemStyle: { color: '#f0a020', borderRadius: [4, 4, 0, 0] }, barWidth: '45%' }],
  }
})

onMounted(async () => {
  await load()
  // D：每 30 秒自动刷新，但仅当页面可见——后台标签页不做无谓请求
  refreshTimer = window.setInterval(() => {
    if (document.visibilityState === 'visible') void load()
  }, 30_000)
  document.addEventListener('visibilitychange', onVisibilityChange)
})

onBeforeUnmount(() => {
  if (refreshTimer) window.clearInterval(refreshTimer)
  document.removeEventListener('visibilitychange', onVisibilityChange)
})
</script>

<style scoped>
.stat-row { display: flex; gap: 16px; margin-bottom: 20px; }
.dash-meta { text-align: right; font-size: 12px; color: var(--el-text-color-secondary); margin-bottom: 8px; min-height: 16px; }
.stat-card {
  flex: 1; padding: 18px 20px; border-radius: 12px;
  background: var(--pod-panel-bg, #161a1f); border: 1px solid var(--pod-border, #2a2f37);
}
.stat-num { font-size: 28px; font-weight: 700; color: #4f7cff; }
.stat-slash { font-size: 16px; color: var(--pod-text-dim, #9aa3af); }
.link-card { text-decoration: none; transition: transform 0.15s; }
.link-card:hover { transform: translateY(-2px); }
.link-card.danger .stat-num { color: #f56c6c; }
.high-tag { display: inline-block; padding: 1px 8px; border-radius: 10px; background: rgba(245, 108, 108, 0.15); color: #f56c6c; font-weight: 600; }
.stat-label { margin-top: 4px; font-size: 13px; color: var(--pod-text-dim, #9aa3af); }
.stat-sub { margin-top: 2px; font-size: 12px; color: var(--pod-text-dim, #9aa3af); opacity: 0.8; }
.link { color: #4f7cff; text-decoration: none; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
.panel { padding: 16px 18px; border-radius: 12px; background: var(--pod-panel-bg, #161a1f); border: 1px solid var(--pod-border, #2a2f37); }
.panel.span2 { grid-column: span 2; }
.panel h3 { margin: 0 0 12px; font-size: 14px; }
/* 机器上报的资产/发现：安静的事实 + 一条可点的说明；只有需要处理时才用告警色 */
.link-panel { text-decoration: none; transition: transform 0.15s; }
.link-panel:hover { transform: translateY(-2px); }
.panel.warn .stat-num { color: #e0a23c; }
.panel-note { margin: 6px 0 0; font-size: 12px; line-height: 1.7; color: var(--pod-text-dim, #9aa3af); }
.finding-list { margin: 8px 0 0; padding: 0; list-style: none; font-size: 12px; }
.finding-list li { display: flex; align-items: center; gap: 6px; padding: 2px 0; }
.finding-list .cnt { color: var(--pod-text-dim, #9aa3af); }
.sev { padding: 0 6px; border-radius: 999px; font-size: 11px; }
.sev--high { background: rgba(245, 108, 108, 0.16); color: #f56c6c; }
.sev--medium { background: rgba(224, 162, 60, 0.16); color: #e0a23c; }
.sev--low { background: rgba(144, 147, 153, 0.16); color: #909399; }
.alert-list { display: flex; flex-direction: column; gap: 8px; }
.alert-item { display: flex; align-items: center; gap: 8px; font-size: 12px; }
.alert-kind { font-weight: 600; white-space: nowrap; }
.alert-msg { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--pod-text-dim, #9aa3af); }
.alert-time { color: var(--pod-text-dim, #9aa3af); font-size: 11px; white-space: nowrap; }
.empty { margin-top: 10px; }
</style>
