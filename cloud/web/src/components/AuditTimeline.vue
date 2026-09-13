<template>
  <div v-if="groups.length" class="audit-timeline">
    <section v-for="g in groups" :key="g.date" class="tl-group">
      <div class="tl-date">
        {{ g.date }}
        <span class="tl-count">{{ g.items.length }} {{ t('条') }}</span>
      </div>
      <ol class="tl-list">
        <li v-for="e in g.items" :key="e.id" class="tl-item">
          <time class="tl-time">{{ fmtTime(e.ts) }}</time>
          <span class="tl-mid">
            <i class="tl-dot" :class="`dot-${e.decision}`" />
          </span>
          <div class="tl-card">
            <div class="tl-line1">
              <el-tag size="small" effect="plain" class="tl-agent">{{ e.agent }}</el-tag>
              <span class="tl-server">{{ e.server }}</span>
              <code class="tl-tool">{{ e.tool }}</code>
              <el-tag size="small" :type="decisionType(e.decision)" class="tl-tag">
                {{ decisionLabel(e.decision) }}
              </el-tag>
              <el-tag size="small" effect="plain" :type="outcomeType(e.outcome)" class="tl-tag">
                {{ e.outcome }}
              </el-tag>
            </div>
            <div v-if="e.reason" class="tl-reason">{{ e.reason }}</div>
            <div class="tl-meta">
              <span v-if="e.approver">{{ t('审批人') }} {{ e.approver }}</span>
              <span>{{ t('策略 v') }}{{ e.policy_version || '—' }}</span>
              <span>{{ t('序号 #') }}{{ e.seq }}</span>
              <code class="tl-hash">{{ shortHash(e.args_hash) }}</code>
            </div>
          </div>
        </li>
      </ol>
    </section>
  </div>
  <el-empty v-else :description="emptyText || t('暂无事件（本地 pod sync 后可见）')" :image-size="70" />
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { formatDate } from '../i18n'

const { t } = useI18n()

export interface TimelineEvent {
  id: number
  agent: string
  agent_id: number
  ts: string
  server: string
  tool: string
  args_hash: string
  decision: string
  outcome: string
  approver: string
  reason: string
  policy_version: string
  enforced: boolean
  seq: number
}

// 空态文案不用 withDefaults：默认值会被提升到 setup 之外，引用不了 t()
const props = defineProps<{
  events: TimelineEvent[]
  emptyText?: string
}>()

interface Group {
  date: string
  items: TimelineEvent[]
}

const pad = (n: number) => String(n).padStart(2, '0')

function fmtTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso.slice(11, 19)
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

const groups = computed<Group[]>(() => {
  const out: Group[] = []
  for (const e of props.events) {
    const d = new Date(e.ts)
    const key = Number.isNaN(d.getTime())
      ? e.ts.slice(0, 10)
      : `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
    const weekday = Number.isNaN(d.getTime())
      ? ''
      : formatDate(d, { weekday: 'short' })
    const label = weekday ? `${key} · ${weekday}` : key
    const last = out[out.length - 1]
    if (last && last.date === label) last.items.push(e)
    else out.push({ date: label, items: [e] })
  }
  return out
})

function decisionLabel(decision: string): string {
  return { allow: t('放行'), approve: t('审批'), deny: t('拒绝') }[decision] ?? decision
}
function decisionType(decision: string): 'success' | 'warning' | 'danger' | 'info' {
  return ({ allow: 'success', approve: 'warning', deny: 'danger' } as Record<string, 'success' | 'warning' | 'danger'>)[decision] ?? 'info'
}
function outcomeType(outcome: string): 'success' | 'danger' | 'info' {
  if (outcome === 'ok') return 'success'
  if (outcome === 'blocked' || outcome === 'error' || outcome === 'denied') return 'danger'
  return 'info'
}
function shortHash(hash: string): string {
  return hash.length > 14 ? `${hash.slice(0, 10)}…` : hash
}
</script>

<style scoped>
.audit-timeline {
  --tl-line: 2px;
  --tl-left: 88px;
  --tl-dot: 12px;
}

.tl-date {
  display: flex;
  align-items: baseline;
  gap: 10px;
  margin: 18px 0 10px;
  font-weight: 600;
  font-size: 13px;
  color: var(--el-text-color-primary);
}
.tl-date:first-of-type { margin-top: 0; }
.tl-count {
  font-weight: 400;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.tl-list {
  list-style: none;
  margin: 0;
  padding: 0;
  position: relative;
}
/* 时间轴主线：贯穿整列，画在 dot 列的中央 */
.tl-list::before {
  content: '';
  position: absolute;
  left: calc(var(--tl-left) + var(--tl-dot) + 4px);
  top: 6px;
  bottom: 6px;
  width: var(--tl-line);
  background: var(--el-border-color);
}

.tl-item {
  display: grid;
  grid-template-columns: var(--tl-left) var(--tl-dot) 1fr;
  gap: 10px;
  padding-bottom: 14px;
}
.tl-item:last-child { padding-bottom: 4px; }

.tl-time {
  text-align: right;
  padding-top: 3px;
  font-family: ui-monospace, Menlo, Consolas, monospace;
  font-size: 12px;
  color: var(--el-text-color-secondary);
  user-select: none;
}

.tl-mid { position: relative; }
.tl-dot {
  position: absolute;
  top: 4px;
  left: 50%;
  transform: translateX(-50%);
  width: var(--tl-dot);
  height: var(--tl-dot);
  border-radius: 50%;
  border: 2px solid var(--el-bg-color);
  box-sizing: border-box;
}
.dot-allow   { background: var(--el-color-success); }
.dot-approve { background: var(--el-color-warning); }
.dot-deny    { background: var(--el-color-danger); }
.dot-default { background: var(--el-text-color-placeholder); }

.tl-card {
  background: var(--el-bg-color);
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 8px;
  padding: 8px 12px;
  min-width: 0;
}
.tl-line1 {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}
.tl-agent { font-weight: 600; }
.tl-server {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
.tl-tool {
  font-family: ui-monospace, Menlo, Consolas, monospace;
  font-size: 13px;
  color: var(--el-text-color-primary);
  background: var(--el-fill-color-light);
  padding: 1px 6px;
  border-radius: 4px;
}
.tl-reason {
  margin-top: 6px;
  font-size: 13px;
  color: var(--el-text-color-primary);
  overflow-wrap: anywhere;
}
.tl-meta {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 6px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
.tl-hash {
  font-family: ui-monospace, Menlo, Consolas, monospace;
  font-size: 11px;
  background: var(--el-fill-color-light);
  padding: 1px 6px;
  border-radius: 4px;
}
</style>
