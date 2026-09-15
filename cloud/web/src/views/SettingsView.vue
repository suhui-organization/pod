<template>
  <div class="settings">
    <h2>{{ t('设置') }}</h2>
    <el-card v-if="tenant" class="card">
      <template #header>{{ t('租户信息') }}</template>
      <el-descriptions :column="2" border>
        <el-descriptions-item :label="t('租户名称')">{{ tenant.name }}</el-descriptions-item>
        <el-descriptions-item :label="t('标识')">{{ tenant.slug }}</el-descriptions-item>
        <el-descriptions-item :label="t('计划')">{{ tenant.plan }}</el-descriptions-item>
        <el-descriptions-item :label="t('成员数')">{{ tenant.members ?? '—' }}</el-descriptions-item>
      </el-descriptions>
    </el-card>

    <!-- AI 模型：三个 AI 功能的共同依赖。状态在前，表单在后——先回答"现在能不能用" -->
    <el-card id="ai-model" class="card" :class="{ 'card--focus': llmFocus }">
      <template #header>
        <span class="llm-head">
          {{ t('AI 模型') }}
          <span class="llm-badge" :class="llm.configured ? 'llm-badge--ok' : 'llm-badge--off'">
            {{ llm.configured ? t('已配置') : t('未配置') }}
          </span>
        </span>
      </template>

      <p v-if="llm.configured" class="llm-state">
        {{ t('当前生效：') }}<b>{{ providerLabel(llm.effective.provider) }}</b>
        <span class="llm-sep">·</span>
        <code class="mono">{{ llm.effective.model }}</code>
        <span v-if="llm.effective.key_source === 'env'" class="llm-tag">{{ t('Key 来自环境变量') }}</span>
        <span v-else-if="llm.api_key_hint" class="llm-tag">Key {{ llm.api_key_hint }}</span>
      </p>
      <p v-else class="llm-state llm-state--off">
        {{ t('还不能调用模型：') }}{{ llm.reason }}
      </p>
      <p v-if="llm.configured" class="llm-sub">
        {{ t('请求发往') }} <code class="mono">{{ llm.effective.endpoint }}</code>
      </p>

      <el-form v-if="auth.isAdmin" label-width="130px" class="llm-form">
        <el-form-item label="Provider">
          <el-select v-model="llmForm.provider" style="width: 260px">
            <el-option v-for="p in llm.providers" :key="p.id" :label="p.label" :value="p.id" />
          </el-select>
          <span class="hint">{{ currentProvider?.note }}</span>
        </el-form-item>
        <el-form-item :label="t('模型')">
          <el-input
            v-model="llmForm.model"
            :placeholder="currentProvider?.default_model || t('例如 qwen-max')"
            style="width: 260px"
          />
          <span class="hint">{{ t('留空用 Provider 默认') }}{{ currentProvider?.default_model ? `（${currentProvider.default_model}）` : '' }}</span>
        </el-form-item>
        <el-form-item v-if="currentProvider?.needs_base_url" label="Base URL">
          <el-input v-model="llmForm.base_url" placeholder="https://your-gateway/v1" style="width: 420px" />
          <span class="hint">{{ t('OpenAI 兼容端点，会自动补') }} <code class="mono">/chat/completions</code></span>
        </el-form-item>
        <el-form-item label="API Key">
          <el-input
            v-model="llmForm.api_key"
            type="password"
            show-password
            :placeholder="llm.api_key_set ? t('已配置 {hint}，留空保持不变', { hint: llm.api_key_hint }) : 'sk-…'"
            style="width: 420px"
          />
          <span class="hint">{{ t('只写不回显；留空 = 保留已存的那把') }}</span>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="llmSaving" @click="saveLlm">{{ t('保存') }}</el-button>
          <el-button :loading="llmTesting" @click="testLlm">{{ t('测试连接') }}</el-button>
          <el-button link type="primary" @click="router.push('/selfcheck')">
            {{ t('模型连通后，去跑一次系统自检 →') }}
          </el-button>
          <span class="hint">{{ t('测试用上面的表单（未保存也能测），会真实发一次请求并进审计') }}</span>
        </el-form-item>
      </el-form>
      <p v-else class="hint">
        {{ t('只有管理员能修改模型配置；上面是当前正在生效的配置，AI 功能不可用时你也可以在这里看到原因。') }}
      </p>

      <p v-if="llmTest" class="llm-test" :class="llmTest.ok ? 'llm-test--ok' : 'llm-test--bad'">
        <template v-if="llmTest.ok">
          {{ t('连通 ·') }} {{ llmTest.model }} · {{ llmTest.latency_ms }}{{ t('ms · 返回「') }}{{ llmTest.sample }}」
        </template>
        <template v-else>{{ t('不通：') }}{{ llmTest.error }}</template>
      </p>

      <div class="llm-deps">
        <div class="llm-deps__title">{{ t('依赖这套配置的功能') }}</div>
        <ul class="llm-deps__list">
          <li v-for="f in llm.features" :key="f.id" class="llm-deps__item">
            <span class="llm-deps__name">{{ f.name }}</span>
            <span class="llm-deps__where">{{ f.where }}</span>
            <span v-if="!llm.configured" class="llm-deps__deg">{{ f.degraded }}</span>
          </li>
        </ul>
      </div>
    </el-card>

    <el-card class="card">
      <template #header>{{ t('合规报告（GDPR）') }}</template>
      <div class="report-row">
        <el-button type="primary" :loading="reportLoading" @click="downloadReport">{{ t('生成 GDPR 报告（Markdown 下载）') }}</el-button>
        <el-button :loading="reportLoading" @click="previewReport">{{ t('查看摘要') }}</el-button>
        <span v-if="reportSummary" class="report-summary">
          {{ t('近 30 天') }} {{ reportSummary.activities.total_events }} {{ t('次调用 · allow') }} {{ reportSummary.activities.by_decision.allow ?? 0 }} / approve
          {{ reportSummary.activities.by_decision.approve ?? 0 }} / deny
          {{ reportSummary.activities.by_decision.deny ?? 0 }} {{ t('· 审批') }} {{ reportSummary.activities.approvals.length }} {{ t('条') }}
        </span>
      </div>
    </el-card>

    <el-card class="card">
      <template #header>{{ t('告警通知') }}</template>
      <el-form label-width="120px">
        <el-form-item :label="t('启用推送')">
          <el-switch v-model="wh.enabled" />
          <span class="hint" style="margin-left: 8px">{{ t('高危/中危告警实时推送到群或自建接收端') }}</span>
        </el-form-item>
        <el-form-item :label="t('渠道')">
          <el-select v-model="wh.channel" style="width: 220px">
            <el-option v-for="c in channels" :key="c.value" :label="c.label" :value="c.value" />
          </el-select>
        </el-form-item>
        <el-form-item label="Webhook URL">
          <el-input v-model="wh.url" placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=…" />
          <span v-if="wh.url_set && !wh.url" class="hint">{{ t('已配置（URL 不回显，重新填写可覆盖）') }}</span>
        </el-form-item>
        <el-form-item :label="t('签名密钥')">
          <el-input v-model="wh.secret" :placeholder="t('可选，发送时放入 X-PodCloud-Signature 头')" />
        </el-form-item>
        <el-form-item :label="t('最低级别')">
          <el-select v-model="wh.min_severity" style="width: 120px">
            <el-option :label="t('高危及以上')" value="high" />
            <el-option :label="t('中危及以上')" value="medium" />
            <el-option :label="t('全部')" value="low" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="whSaving" @click="saveWebhook">{{ t('保存') }}</el-button>
          <el-button v-if="wh.url_set" @click="testWebhook">{{ t('发送测试告警') }}</el-button>
        </el-form-item>
      </el-form>
      <p class="hint">{{ t('支持渠道：企业微信 / 钉钉 / 飞书 / Slack / 自定义 JSON（generic）。规则 11 种：密钥拦截、敏感路径访问、策略不匹配、Deny 突增、调用风暴、注入信号、审批超时、未注册服务器、Agent 失联、人工批准、新工具首次使用。') }}</p>
    </el-card>

    <el-card class="card">
      <template #header>{{ t('邮件通知（SMTP，自行配置）') }}</template>
      <el-form label-width="130px">
        <el-form-item :label="t('启用邮件')">
          <el-switch v-model="smtp.enabled" />
        </el-form-item>
        <el-form-item :label="t('SMTP 服务器')">
          <el-input v-model="smtp.host" placeholder="smtp.example.com" style="width: 320px" />
          <el-input-number v-model="smtp.port" :min="1" :max="65535" style="margin-left: 8px; width: 110px" />
        </el-form-item>
        <el-form-item :label="t('账号')">
          <el-input v-model="smtp.user" :placeholder="t('alert@example.com（QQ/163 等用授权码）')" style="width: 320px" />
        </el-form-item>
        <el-form-item :label="t('密码/授权码')">
          <el-input v-model="smtp.password" type="password" show-password :placeholder="t('留空则保留已保存的密码')" style="width: 320px" />
          <span v-if="smtp.user_set && !smtp.password" class="hint">{{ t('已配置（不显示，重新填写可覆盖）') }}</span>
        </el-form-item>
        <el-form-item :label="t('发件人')">
          <el-input v-model="smtp.from_addr" placeholder="alert@example.com" style="width: 320px" />
        </el-form-item>
        <el-form-item :label="t('收件人')">
          <el-input v-model="smtp.to_addrs" :placeholder="t('ops@example.com, boss@example.com（逗号分隔）')" style="width: 420px" />
        </el-form-item>
        <el-form-item label="TLS">
          <el-switch v-model="smtp.tls" />
          <span class="hint" style="margin-left: 8px">{{ t('465 端口自动 SSL；其他端口走 STARTTLS') }}</span>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="smtpSaving" @click="saveSmtp">{{ t('保存') }}</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="card">
      <template #header>{{ t('告警规则阈值') }}</template>
      <el-form label-width="130px">
        <el-form-item :label="t('Deny 突增阈值')">
          <el-input-number v-model="rules.deny_burst_threshold" :min="1" :max="1000" style="width: 140px" />
          <span class="hint" style="margin-left: 8px">{{ t('窗口内 deny 次数达到即告警') }}</span>
        </el-form-item>
        <el-form-item :label="t('统计窗口')">
          <el-input-number v-model="rules.burst_window_seconds" :min="10" :max="86400" :step="10" style="width: 140px" />
          <span class="hint" style="margin-left: 8px">{{ t('秒（deny 突增 / 调用风暴共用）') }}</span>
        </el-form-item>
        <el-form-item :label="t('调用风暴阈值')">
          <el-input-number v-model="rules.spike_threshold" :min="2" :max="100000" style="width: 140px" />
          <span class="hint" style="margin-left: 8px">{{ t('窗口内总调用数达到即告警（疑似失控循环）') }}</span>
        </el-form-item>
        <el-form-item :label="t('失联阈值')">
          <el-input-number v-model="rules.silence_hours" :min="1" :max="720" style="width: 140px" />
          <span class="hint" style="margin-left: 8px">{{ t('小时（agent 未同步即告警，巡检每 30 分钟一轮）') }}</span>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="rulesSaving" @click="saveRules">{{ t('保存') }}</el-button>
          <el-button @click="resetRules">{{ t('恢复默认') }}</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="card">
      <template #header>{{ t('AI 日报') }}</template>
      <!-- 日报也是 AI 功能：模型没配好时先在这里说清楚，别让"立即推送"点了没反应 -->
      <AiNotice v-if="digestNotice" :message="digestNotice" />
      <el-form label-width="130px">
        <el-form-item :label="t('每日推送')">
          <el-switch v-model="digest.enabled" />
          <span class="hint" style="margin-left: 8px">{{ t('每天 09:00 推送昨日安全摘要到已配置的 webhook / 邮件（无告警也会推送一句确认）') }}</span>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="digestSaving" @click="saveDigest">{{ t('保存') }}</el-button>
          <el-button :loading="digestPushing" @click="pushDigestNow">{{ t('立即推送一份') }}</el-button>
          <span v-if="digestResult" class="hint" style="margin-left: 8px">{{ digestResult }}</span>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="card">
      <template #header>{{ t('界面偏好') }}</template>
      <el-form label-width="120px">
        <el-form-item :label="t('主题')">
          <el-switch v-model="dark" :active-text="t('暗色')" :inactive-text="t('亮色')" @change="applyTheme" />
        </el-form-item>
        <el-form-item :label="t('字号缩放')">
          <el-slider v-model="fontScale" :min="0.8" :max="1.3" :step="0.05" show-input @change="applyFont" />
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { useRouter } from 'vue-router'
import { api } from '../api'
import type { LlmSettings, LlmTestResult } from '../api/types'
import AiNotice from '../components/AiNotice.vue'
import { useAiStore } from '../stores/ai'
import { useAuthStore } from '../stores/auth'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
const router = useRouter()

const auth = useAuthStore()
const ai = useAiStore()
const tenant = ref<Awaited<ReturnType<typeof api.tenantMe>> | null>(null)
const dark = ref(true)
const fontScale = ref(1)
const reportLoading = ref(false)
const reportSummary = ref<Awaited<ReturnType<typeof api.gdprReport>> | null>(null)
const channels = [
  { value: 'wecom', label: t('企业微信') },
  { value: 'dingtalk', label: t('钉钉') },
  { value: 'feishu', label: t('飞书') },
  { value: 'slack', label: 'Slack' },
  { value: 'generic', label: t('自定义 JSON') },
]
const wh = ref({ enabled: false, channel: 'wecom', url: '', secret: '', min_severity: 'medium', url_set: false })
const whSaving = ref(false)
const smtp = ref({ enabled: false, host: '', port: 465, user: '', password: '', from_addr: '', to_addrs: '', tls: true, user_set: false })
const smtpSaving = ref(false)
const digest = ref({ enabled: false })
const digestSaving = ref(false)
/** AI 日报相关的"未配置模型"提示（保存开关、立即推送共用一处） */
const digestNotice = ref('')

/* ---------- AI 模型 ---------- */
const llm = ref<LlmSettings>({
  provider: 'auto',
  model: '',
  base_url: '',
  api_key_set: false,
  api_key_hint: '',
  configured: false,
  reason: '',
  effective: {},
  providers: [],
  features: [],
})
const llmForm = ref({ provider: 'auto', model: '', base_url: '', api_key: '' })
const llmSaving = ref(false)
const llmTesting = ref(false)
const llmTest = ref<LlmTestResult | null>(null)
const llmFocus = ref(false)

// 打开"每日推送"就等于开始使用 AI 日报：模型没配好时当场说清楚。
// 注意必须放在 llm 声明之后 —— watch 的 getter 会在 setup 阶段立即求值。
watch(
  [() => digest.value.enabled, () => llm.value.configured],
  ([enabled, configured]) => {
    if (configured) {
      digestNotice.value = ''
      return
    }
    if (enabled) digestNotice.value = llm.value.reason
  },
)

const currentProvider = computed(() =>
  llm.value.providers.find((p) => p.id === llmForm.value.provider),
)

function providerLabel(id?: string): string {
  return llm.value.providers.find((p) => p.id === id)?.label ?? id ?? '—'
}

function applyLlmSettings(s: LlmSettings) {
  llm.value = s
  llmForm.value = {
    // 存量数据里可能是 auto（历史默认值）：它等价于 deepseek 直连，
    // 直接把"实际会用的 provider"预选出来，避免出现空下拉框。
    provider: s.provider && s.provider !== 'auto' ? s.provider : s.effective.provider || 'deepseek',
    model: s.model || '',
    base_url: s.base_url || '',
    api_key: '',
  }
}

async function saveLlm() {
  llmSaving.value = true
  try {
    const body: Record<string, string> = {
      provider: llmForm.value.provider,
      model: llmForm.value.model.trim(),
      base_url: llmForm.value.base_url.trim(),
    }
    // key 留空 = 不修改：不要把"已存的 key"覆盖成空字符串
    if (llmForm.value.api_key.trim()) body.api_key = llmForm.value.api_key.trim()
    applyLlmSettings(await api.saveLlmSettings(body))
    // 其他页面的 AI 入口共用这份状态：保存成功后必须同步，否则用户配好了
    // 模型、切到策略中心仍被旧缓存挡住
    void ai.refresh()
    ElMessage.success(t('模型配置已保存'))
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.error?.message ?? t('保存失败'))
  } finally {
    llmSaving.value = false
  }
}

async function testLlm() {
  llmTesting.value = true
  llmTest.value = null
  try {
    llmTest.value = await api.testLlm({
      provider: llmForm.value.provider,
      model: llmForm.value.model.trim(),
      base_url: llmForm.value.base_url.trim(),
      api_key: llmForm.value.api_key.trim(),
    })
  } catch (e: any) {
    llmTest.value = {
      ok: false,
      provider: llmForm.value.provider,
      model: '',
      endpoint: '',
      latency_ms: 0,
      error: e?.response?.data?.error?.message ?? t('测试请求失败'),
      sample: '',
    }
  } finally {
    llmTesting.value = false
  }
}

const digestPushing = ref(false)
const digestResult = ref('')

async function pushDigestNow() {
  if (!llm.value.configured) {
    // 拦截在发请求之前：省掉一次注定 400 的往返，直接给出口
    digestNotice.value = llm.value.reason
    return
  }
  digestPushing.value = true
  digestResult.value = ''
  digestNotice.value = ''
  try {
    const r = await api.digestNow()
    digestResult.value = t('已推送（{date}，告警 {n} 条）', { date: r.date, n: r.alerts_count })
  } catch (e: any) {
    const msg = e?.response?.data?.error?.message ?? t('推送失败')
    if (e?.response?.status === 400) digestNotice.value = msg
    else ElMessage.error(msg)
  } finally {
    digestPushing.value = false
  }
}

async function saveDigest() {
  digestSaving.value = true
  try {
    await api.updateSettings({ ai_digest: { enabled: digest.value.enabled } })
    ElMessage.success(t('AI 日报设置已保存'))
  } finally {
    digestSaving.value = false
  }
}

const DEFAULT_RULES = { deny_burst_threshold: 5, burst_window_seconds: 60, spike_threshold: 30, silence_hours: 24 }
const rules = ref({ ...DEFAULT_RULES })
const rulesSaving = ref(false)

async function saveRules() {
  rulesSaving.value = true
  try {
    await api.updateSettings({ alert_rules: { ...rules.value } })
    ElMessage.success(t('规则阈值已保存'))
  } finally {
    rulesSaving.value = false
  }
}

function resetRules() {
  rules.value = { ...DEFAULT_RULES }
}

async function saveSmtp() {
  smtpSaving.value = true
  try {
    await api.updateSettings({
      alert_smtp: {
        enabled: smtp.value.enabled,
        host: smtp.value.host.trim(),
        port: smtp.value.port,
        user: smtp.value.user.trim(),
        password: smtp.value.password.trim(),
        from_addr: smtp.value.from_addr.trim(),
        to_addrs: smtp.value.to_addrs.trim(),
        tls: smtp.value.tls,
      },
    })
    smtp.value.user_set = !!smtp.value.user.trim()
    smtp.value.password = ''
    ElMessage.success(t('邮件通知已保存'))
  } finally {
    smtpSaving.value = false
  }
}

async function saveWebhook() {
  whSaving.value = true
  try {
    await api.updateSettings({
      alert_webhook: {
        enabled: wh.value.enabled,
        channel: wh.value.channel,
        url: wh.value.url.trim(),
        secret: wh.value.secret.trim(),
        min_severity: wh.value.min_severity,
      },
    })
    wh.value.url_set = !!wh.value.url.trim()
    wh.value.url = ''
    wh.value.secret = ''
    ElMessage.success(t('告警通知已保存'))
  } finally {
    whSaving.value = false
  }
}

async function testWebhook() {
  await api.updateSettings({
    alert_webhook: { enabled: true, channel: wh.value.channel, url: wh.value.url.trim() || undefined, secret: wh.value.secret.trim() || undefined, min_severity: wh.value.min_severity },
  })
  ElMessage.success(t('测试告警已发送（如未收到请检查 webhook 地址与渠道格式）'))
}

async function downloadReport() {
  reportLoading.value = true
  try {
    const md = await api.gdprReportMarkdown(30)
    const blob = new Blob([md], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `gdpr-report-${Date.now()}.md`
    a.click()
    URL.revokeObjectURL(url)
  } finally {
    reportLoading.value = false
  }
}

async function previewReport() {
  reportLoading.value = true
  try {
    reportSummary.value = await api.gdprReport(30)
  } finally {
    reportLoading.value = false
  }
}

function applyTheme() {
  document.documentElement.dataset.theme = dark.value ? 'dark' : 'light'
  localStorage.setItem('podcloud_theme', dark.value ? 'dark' : 'light')
}

function applyFont() {
  document.documentElement.style.setProperty('--pod-font-scale', String(fontScale.value))
  localStorage.setItem('podcloud_font_scale', String(fontScale.value))
}

onMounted(async () => {
  tenant.value = await api.tenantMe()
  dark.value = (document.documentElement.dataset.theme || 'dark') === 'dark'
  fontScale.value = Number(localStorage.getItem('podcloud_font_scale') || 1)
  // 模型配置单独拉：失败不该拖垮其余设置面板
  try {
    applyLlmSettings(await api.llmSettings())
  } catch {
    /* 保持默认的"未配置"状态 */
  }
  // 从"AI 功能需要先配模型"的引导跳进来时，把面板滚到眼前并短暂高亮
  if (window.location.hash === '#ai-model') {
    llmFocus.value = true
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    window.setTimeout(() => {
      document.getElementById('ai-model')?.scrollIntoView({
        block: 'start',
        behavior: reduce ? 'auto' : 'smooth',
      })
    }, 60)
    window.setTimeout(() => {
      llmFocus.value = false
    }, 2600)
  }
  try {
    const s = await api.settings()
    wh.value.enabled = s.alert_webhook.enabled
    wh.value.channel = s.alert_webhook.channel
    wh.value.min_severity = s.alert_webhook.min_severity
    wh.value.url_set = s.alert_webhook.url_set
    smtp.value.enabled = s.alert_smtp.enabled
    smtp.value.host = s.alert_smtp.host
    smtp.value.port = s.alert_smtp.port
    smtp.value.user_set = s.alert_smtp.user_set
    smtp.value.from_addr = s.alert_smtp.from_addr
    smtp.value.to_addrs = s.alert_smtp.to_addrs
    smtp.value.tls = s.alert_smtp.tls
    digest.value.enabled = s.ai_digest.enabled
    rules.value = {
      deny_burst_threshold: s.alert_rules.deny_burst_threshold ?? DEFAULT_RULES.deny_burst_threshold,
      burst_window_seconds: s.alert_rules.burst_window_seconds ?? DEFAULT_RULES.burst_window_seconds,
      spike_threshold: s.alert_rules.spike_threshold ?? DEFAULT_RULES.spike_threshold,
      silence_hours: s.alert_rules.silence_hours ?? DEFAULT_RULES.silence_hours,
    }
  } catch {
    /* 设置读取失败不阻塞页面 */
  }
})
</script>

<style scoped>
.card { margin-bottom: 16px; max-width: 720px; }
.report-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.report-summary { font-size: 13px; color: var(--pod-text-dim, #9aa3af); }
.hint { font-size: 12px; color: var(--pod-text-dim, #9aa3af); }
.mono { font-family: var(--pod-font-mono); font-size: 12px; }

/* ── AI 模型面板 ─────────────────────────────────────────── */
.llm-head { display: inline-flex; align-items: center; gap: 8px; }
.llm-badge {
  padding: 1px 8px; border-radius: 999px;
  font-size: 12px; font-weight: 500;
}
/* 状态色 + 文字双通道：不靠颜色单独表意 */
/* 徽章文字向正文色混一档：纯 token 色压在 tint 上只有 ~2.5:1，两种主题都过不了 4.5 */
.llm-badge--ok {
  color: color-mix(in srgb, var(--pod-success, #8dc149) 58%, var(--pod-text, #e6e8ec));
  background: rgba(141, 193, 73, 0.14);
}
.llm-badge--off {
  color: color-mix(in srgb, var(--pod-warning, #e37933) 55%, var(--pod-text, #e6e8ec));
  background: rgba(227, 121, 51, 0.14);
}

.llm-state {
  margin: 0; font-size: 13px; line-height: 1.7;
  color: var(--pod-text, #e6e8ec);
}
.llm-state--off { color: var(--pod-text-dim, #9aa3b1); }
.llm-sep { margin: 0 6px; color: var(--pod-text-faint, #6b7280); }
.llm-tag {
  margin-left: 8px; padding: 1px 8px; border-radius: 999px;
  font-size: 12px; color: var(--pod-text-dim, #9aa3b1);
  background: var(--pod-panel-elev, #1c2128);
}
.llm-sub {
  margin: 4px 0 0; font-size: 12px; line-height: 1.6;
  color: var(--pod-text-dim, #9aa2b1);
}
.llm-form { margin-top: 16px; }

.llm-test {
  margin: 12px 0 0; padding: 10px 12px; border-radius: 10px;
  font-size: 13px; line-height: 1.7;
  background: var(--pod-panel-elev, #1c2128);
  border: 1px solid var(--pod-border, rgba(255, 255, 255, 0.07));
}
.llm-test--ok { color: var(--pod-success, #8dc149); }
.llm-test--bad { color: var(--pod-danger, #cc3e44); }

.llm-deps { margin-top: 16px; padding-top: 14px; border-top: 1px solid var(--pod-divider, rgba(255, 255, 255, 0.05)); }
.llm-deps__title { font-size: 12px; color: var(--pod-text-dim, #9aa2b1); }
.llm-deps__list { margin: 8px 0 0; padding: 0; list-style: none; display: flex; flex-direction: column; gap: 6px; }
.llm-deps__item { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 10px; font-size: 13px; }
.llm-deps__name { color: var(--pod-text, #e6e8ec); font-weight: 500; }
.llm-deps__where { font-size: 12px; color: var(--pod-text-dim, #9aa2b1); }
.llm-deps__deg { flex-basis: 100%; font-size: 12px; line-height: 1.6; color: var(--pod-text-dim, #9aa3b1); }

/* 从别处跳进来时的高亮：只描边，不加阴影 */
.card--focus { border-color: var(--pod-accent, #6ea4f9); }
</style>
