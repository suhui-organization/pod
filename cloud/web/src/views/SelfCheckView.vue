<template>
  <div class="sc">
    <div class="head">
      <div class="head__title">
        <h2>{{ t('系统自检') }}</h2>
        <p class="head__meta">
          {{ t('一键检查数据库、签名密钥、Agent 网关心跳、审计链、策略与模型的可用性；能安全自动修的会顺手修掉。') }}
        </p>
      </div>
      <div class="head__actions">
        <el-button :loading="running" :disabled="repairing" @click="run(false)">{{ t('开始自检') }}</el-button>
        <el-button type="primary" :loading="repairing" :disabled="running" @click="run(true)">
          {{ t('自检并修复') }}
        </el-button>
      </div>
    </div>

    <el-alert v-if="error" type="error" :closable="false" show-icon :title="error" class="alert" />

    <template v-if="result">
      <div class="summary">
        <el-tag type="success" effect="dark">{{ t('通过') }} {{ result.summary.pass }}</el-tag>
        <el-tag type="warning" effect="plain">{{ t('警告') }} {{ result.summary.warn }}</el-tag>
        <el-tag v-if="result.summary.info" type="info" effect="plain">{{ t('未配置') }} {{ result.summary.info }}</el-tag>
        <el-tag :type="result.summary.fail ? 'danger' : 'info'" :effect="result.summary.fail ? 'dark' : 'plain'">
          {{ t('失败') }} {{ result.summary.fail }}
        </el-tag>
        <el-tag v-if="result.summary.repaired" type="primary" effect="plain">
          {{ t('已修复 {n} 项', { n: result.summary.repaired }) }}
        </el-tag>
        <span class="summary__ts">
          {{ t('检查时间') }} {{ fmt(result.finished_at) }} · {{ result.locale }}
        </span>
      </div>

      <el-card v-if="result.repairs.length" shadow="never" class="repairs">
        <div class="repairs__title">{{ t('这次修了什么') }}</div>
        <ul class="repairs__list">
          <li v-for="(r, i) in result.repairs" :key="i">{{ r }}</li>
        </ul>
      </el-card>

      <el-alert
        v-if="alertNote"
        type="warning"
        :closable="false"
        show-icon
        class="alert-note"
        :title="alertNote"
      />

      <div class="checks">
        <div v-for="c in result.checks" :key="c.id" class="check" :class="`check--${c.status}`">
          <div class="check__line">
            <span class="check__dot" />
            <b class="check__title">{{ c.title }}</b>
            <el-tag size="small" :type="tagType(c.status)" effect="plain">{{ statusLabel(c.status) }}</el-tag>
            <el-tag v-if="c.repaired" size="small" type="primary" effect="dark">{{ t('已修复') }}</el-tag>
            <span v-if="c.repairable && !c.repaired" class="check__rp">{{ t('可自动修复') }}</span>
          </div>
          <div class="check__detail">{{ c.detail }}</div>
          <div v-if="c.hint" class="check__hint">{{ t('建议') }}：{{ c.hint }}</div>
        </div>
      </div>
    </template>

    <el-card v-else shadow="never" class="preview">
      <div class="preview__title">{{ t('这次会检查这些') }}</div>
      <ul class="preview__list">
        <li v-for="item in PREVIEW" :key="item">{{ t(item) }}</li>
      </ul>
      <p class="preview__note">
        {{ t('「自检并修复」会先修掉能安全自动修的问题（补齐缺失的租户设置/订阅行、纠正 Agent 在线状态、清理悬空成员），再跑一遍检查把结果给你。') }}
      </p>
    </el-card>

    <!-- 巡检历史：每日自动巡检的结果也在这里，不用等人点按钮 -->
    <el-card shadow="never" class="history">
      <div class="history__head">
        <span class="history__title">{{ t('巡检记录') }}</span>
        <span class="history__schedule">
          <template v-if="schedule?.enabled">
            {{ t('自动巡检：每天 {hour}:00（北京时间）', { hour: schedule.hour }) }} ·
            {{
              schedule.notify === 'off'
                ? t('不推通知')
                : schedule.notify === 'all'
                  ? t('失败与警告都通知')
                  : t('失败时通知')
            }}
            {{ schedule.repair ? ` · ${t('巡检时自动修复')}` : '' }}
          </template>
          <template v-else>{{ t('自动巡检已关闭（PODCLOUD_SELFCHECK_ENABLED=off）') }}</template>
        </span>
      </div>
      <div v-if="history.length" class="history__list">
        <div v-for="(r, i) in history" :key="r.id" class="history__row">
          <span class="history__when">{{ fmt(r.finished_at) }}</span>
          <el-tag size="small" effect="plain" :type="r.trigger === 'daily' ? 'info' : 'primary'">
            {{ r.trigger === 'daily' ? t('每日巡检') : t('手动') }}
          </el-tag>
          <el-tag size="small" :type="r.summary.fail ? 'danger' : r.summary.warn ? 'warning' : 'success'" effect="plain">
            {{ t('{p} 通过 · {w} 警告 · {f} 失败', { p: r.summary.pass, w: r.summary.warn, f: r.summary.fail }) }}
            <template v-if="r.summary.info">· {{ t('{n} 未配置', { n: r.summary.info }) }}</template>
          </el-tag>
          <el-tag v-if="i === 0" size="small" type="info" effect="plain">{{ t('最近一次') }}</el-tag>
          <span v-if="r.summary.repaired" class="history__rp">{{ t('已修复 {n} 项', { n: r.summary.repaired }) }}</span>
          <span v-if="r.summary.alerts_created" class="history__rp">{{ t('告警 +{n}', { n: r.summary.alerts_created }) }}</span>
          <span v-if="r.summary.alerts_resolved" class="history__rp">✅ {{ t('自动关闭 {n} 条告警', { n: r.summary.alerts_resolved }) }}</span>
        </div>
      </div>
      <p v-else class="history__empty">{{ t('还没有巡检记录：点上面的「开始自检」，或等每日巡检到点自动跑。') }}</p>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { api } from '../api'

const { t } = useI18n()

type Result = Awaited<ReturnType<typeof api.selfcheck>>
const result = ref<Result | null>(null)
const running = ref(false)
const repairing = ref(false)
const error = ref('')
type History = Awaited<ReturnType<typeof api.selfcheckHistory>>
const history = ref<History['runs']>([])
const schedule = ref<History['schedule'] | null>(null)

/** 与后端检查项一一对应：没跑之前先把"会查什么"摆出来，别让人对着空页面点按钮 */
const PREVIEW = [
  '数据库连接与表结构',
  '数据库写入能力',
  '签名密钥强度',
  '租户与管理员',
  'Agent 网关与心跳',
  '审计链完整性',
  '策略就绪',
  '大模型可用性',
  '找回密码投递',
  '计费开关',
]

async function run(repair: boolean) {
  error.value = ''
  if (repair) repairing.value = true
  else running.value = true
  try {
    result.value = await api.selfcheck(repair)
    await loadHistory()  // 手动那次也要进历史
  } catch (e: any) {
    error.value = t('自检失败：{msg}', { msg: e?.response?.data?.error?.message ?? e?.message ?? String(e) })
  } finally {
    running.value = false
    repairing.value = false
  }
}

async function loadHistory() {
  try {
    const r = await api.selfcheckHistory()
    history.value = r.runs
    schedule.value = r.schedule
  } catch {
    // 历史读不到不影响主流程（比如后端还没升级到带 /history 的版本）
    history.value = []
  }
}

onMounted(loadHistory)

/** info = 这项不适用（例如自托管没配模型）—— 不是故障，用灰标如实说明 */
const statusLabel = (s: string) =>
  s === 'pass' ? t('通过') : s === 'warn' ? t('警告') : s === 'info' ? t('未配置') : t('失败')
const tagType = (s: string): 'success' | 'warning' | 'danger' | 'info' =>
  s === 'pass' ? 'success' : s === 'warn' ? 'warning' : s === 'info' ? 'info' : 'danger'

/** 这次自检对告警列表做了什么（开了几条 / 自动关了几条）——没有就不提示 */
const alertNote = computed(() => {
  const a = result.value?.alerts
  if (!a) return ''
  const parts: string[] = []
  if (a.created.length) parts.push(t('已在「告警」列表留 {n} 条平台级记录（agent 显示为 Pod Cloud）', { n: a.created.length }))
  if (a.resolved.length) parts.push(t('这次检查通过的项已自动关闭 {n} 条告警', { n: a.resolved.length }))
  return parts.join('；')
})

function fmt(iso: string) {
  const d = new Date(iso.endsWith('Z') || iso.includes('+') ? iso : `${iso}Z`)
  if (Number.isNaN(d.getTime())) return iso
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}
</script>

<style scoped>
.head { display: flex; justify-content: space-between; align-items: flex-end; gap: 12px; flex-wrap: wrap; }
.head h2 { margin: 0; }
.head__meta { margin: 4px 0 0; font-size: 12px; color: var(--pod-text-dim, #9aa3af); max-width: 720px; }
.head__actions { display: flex; gap: 8px; }
.alert { margin-top: 12px; }

.summary { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin: 12px 0; }
.summary__ts { font-size: 12px; color: var(--pod-text-dim, #9aa3af); font-family: ui-monospace, monospace; }

.repairs { margin-bottom: 12px; }
.repairs__title { font-weight: 600; margin-bottom: 6px; }
.repairs__list { margin: 0; padding-left: 18px; font-size: 13px; }

.checks { display: flex; flex-direction: column; gap: 8px; }
.check { border: 1px solid var(--pod-border, #2a2f37); border-left-width: 3px; border-radius: 10px; padding: 10px 12px; background: var(--pod-panel-bg, #161a1f); }
.check--pass { border-left-color: #3fb950; }
.check--warn { border-left-color: #d29922; }
.check--fail { border-left-color: #f85149; }
.check__line { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.check__dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; opacity: .7; }
.check__title { font-size: 13px; }
.check__rp { font-size: 11px; color: var(--pod-text-dim, #9aa3af); }
.check__detail { margin-top: 5px; font-size: 12px; color: var(--pod-text, #e6edf3); word-break: break-word; }
.check__hint { margin-top: 4px; font-size: 12px; color: var(--pod-text-dim, #9aa3af); }

.preview { margin-top: 12px; }
.preview__title { font-weight: 600; margin-bottom: 6px; }
.preview__list { margin: 0; padding-left: 18px; font-size: 13px; color: var(--pod-text, #e6edf3); }
.preview__note { margin: 10px 0 0; font-size: 12px; color: var(--pod-text-dim, #9aa3af); }

.history { margin-top: 12px; }
.history__head { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; margin-bottom: 8px; }
.history__title { font-weight: 600; }
.history__schedule { font-size: 12px; color: var(--pod-text-dim, #9aa3af); }
.history__list { display: flex; flex-direction: column; gap: 6px; }
.history__row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-size: 12px; }
.history__when { font-family: ui-monospace, monospace; color: var(--pod-text-dim, #9aa3af); }
.history__rp { color: var(--pod-text-dim, #9aa3af); }
.history__empty { margin: 0; font-size: 12px; color: var(--pod-text-dim, #9aa3af); }
</style>
