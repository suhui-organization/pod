<template>
  <div v-if="groups.length" class="alert-timeline">
    <section v-for="g in groups" :key="g.date" class="tl-group">
      <div class="tl-date">
        {{ g.date }}
        <span class="tl-count">{{ g.items.length }} {{ t('条') }}</span>
      </div>
      <ol class="tl-list">
        <li v-for="a in g.items" :key="a.id" class="tl-item">
          <time class="tl-time">{{ fmtTime(a.created_at) }}</time>
          <span class="tl-mid">
            <i class="tl-dot" :class="`dot-${stateTone(a.state)}`" />
          </span>
          <div class="tl-card">
            <div class="tl-line1">
              <el-tag size="small" :type="severityType(a.severity)">
                {{ severityText(a.severity) }}
              </el-tag>
              <el-tag size="small" effect="plain" :type="stateType(a.state)">
                {{ stateText(a.state) }}
              </el-tag>
              <el-tag size="small" effect="plain" class="tl-agent">{{ a.agent }}</el-tag>
              <span class="tl-kind">{{ kindText(a.kind) }}</span>
            </div>
            <div class="tl-message">{{ a.message }}</div>
            <div class="tl-meta">
              <span>{{ t('事件序号 #') }}{{ a.event_seq }}</span>
              <slot name="actions" :item="a" />
            </div>
          </div>
        </li>
      </ol>
    </section>
  </div>
  <el-empty v-else :description="emptyText || t('暂无告警')" :image-size="70" />
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

export interface AlertItem {
  id: number
  agent: string
  agent_id: number
  kind: string
  severity: string
  message: string
  event_seq: number
  state: string
  created_at: string
}

const props = withDefaults(
  defineProps<{
    items: AlertItem[]
    emptyText?: string
    severityText?: (s: string) => string
    kindText?: (k: string) => string
    stateText?: (s: string) => string
  }>(),
  {
    // 默认值会被提升到 setup 之外，不能引用 t()——空态文案在模板里回退
    severityText: (s: string) => s,
    kindText: (k: string) => k,
    stateText: (s: string) => s,
  },
)

defineSlots<{
  actions?: (p: { item: AlertItem }) => unknown
}>()

interface Group {
  date: string
  items: AlertItem[]
}

const pad = (n: number) => String(n).padStart(2, '0')

function fmtTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso.slice(11, 19)
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

const groups = computed<Group[]>(() => {
  const out: Group[] = []
  for (const a of props.items) {
    const d = new Date(a.created_at)
    const key = Number.isNaN(d.getTime())
      ? a.created_at.slice(0, 10)
      : `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
    const weekday = Number.isNaN(d.getTime())
      ? ''
      : d.toLocaleDateString('zh-CN', { weekday: 'short' })
    const label = weekday ? `${key} · ${weekday}` : key
    const last = out[out.length - 1]
    if (last && last.date === label) last.items.push(a)
    else out.push({ date: label, items: [a] })
  }
  return out
})

function severityType(severity: string): 'danger' | 'warning' | 'info' {
  const map: Record<string, 'danger' | 'warning' | 'info'> = {
    high: 'danger',
    medium: 'warning',
    low: 'info',
  }
  return map[severity] ?? 'info'
}
function stateType(state: string): 'danger' | 'warning' | 'success' | 'info' {
  const map: Record<string, 'danger' | 'warning' | 'success' | 'info'> = {
    open: 'danger',
    acknowledged: 'warning',
    resolved: 'success',
  }
  return map[state] ?? 'info'
}
function stateTone(state: string): 'danger' | 'warning' | 'success' | 'info' {
  return stateType(state)
}
</script>

<style scoped>
.alert-timeline {
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
.dot-danger  { background: var(--el-color-danger); }
.dot-warning { background: var(--el-color-warning); }
.dot-success { background: var(--el-color-success); }
.dot-info    { background: var(--el-text-color-placeholder); }

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
.tl-kind {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
.tl-message {
  margin-top: 6px;
  font-size: 13px;
  line-height: 1.6;
  color: var(--el-text-color-primary);
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.tl-meta {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px 14px;
  margin-top: 6px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
</style>
