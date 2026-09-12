<template>
  <div>
    <div class="head">
      <h2>告警</h2>
      <div class="filters">
        <el-button type="primary" plain size="small" :loading="aiLoading" @click="genSummary">🤖 AI 摘要</el-button>
        <el-select v-model="stateFilter" clearable placeholder="全部状态" style="width: 120px" @change="load">
          <el-option v-for="s in ['open', 'acknowledged', 'resolved']" :key="s" :label="stateLabel(s)" :value="s" />
        </el-select>
        <el-select v-model="severityFilter" clearable placeholder="全部级别" style="width: 120px" @change="load">
          <el-option v-for="s in ['high', 'medium', 'low']" :key="s" :label="severityLabel(s)" :value="s" />
        </el-select>
        <el-select v-model="kindFilter" clearable placeholder="全部类型" style="width: 200px" @change="load">
          <el-option v-for="k in kinds" :key="k" :label="kindLabel(k)" :value="k" />
        </el-select>
        <el-button size="small" :disabled="!openCount" @click="resolveAll">全部已解决 ({{ openCount }})</el-button>
      </div>
    </div>

    <el-card v-if="aiSummary" class="ai-card">
      <template #header>
        <div class="ai-head">
          <span>🤖 AI 分析摘要 <el-tag size="small" type="info" effect="plain">AI 生成，仅供参考</el-tag></span>
          <el-button link size="small" @click="aiSummary = null">关闭</el-button>
        </div>
      </template>
      <div class="ai-meta">基于近 {{ aiHours }}h {{ aiCount }} 条告警 · 模型 {{ aiModel }}</div>
      <div class="ai-body markdown-body">{{ aiSummary }}</div>
    </el-card>

    <!-- 模型没配时不藏按钮：点了在这里说清缺什么、去哪配 -->
    <AiNotice v-if="aiBlocked" :message="aiBlocked" />

    <AlertTimeline
      :items="alerts"
      empty-text="暂无告警（告警由服务端规则引擎产生，本地 sync 后自动入列）"
      :severity-text="severityLabel"
      :kind-text="kindLabel"
      :state-text="stateLabel"
    >
      <template #actions="{ item }">
        <el-button v-if="item.state !== 'acknowledged'" link size="small" type="primary" @click="setState(item, 'acknowledged')">
          确认
        </el-button>
        <el-button v-if="item.state !== 'resolved'" link size="small" type="success" @click="setState(item, 'resolved')">
          解决
        </el-button>
        <el-button v-if="item.state === 'resolved'" link size="small" @click="setState(item, 'open')">
          重开
        </el-button>
      </template>
    </AlertTimeline>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import AlertTimeline from '../components/AlertTimeline.vue'
import AiNotice from '../components/AiNotice.vue'
import { useAiStore } from '../stores/ai'

const ai = useAiStore()

const kinds = [
  'secret_leak',
  'sensitive_path',
  'policy_mismatch',
  'deny_burst',
  'tool_spike',
  'injection_suspect',
  'approval_timeout',
  'unregistered_server',
  'agent_silence',
  'manual_approval',
  'tool_first_use',
]
const severityLabel = (s: string) => ({ high: '高危', medium: '中危', low: '低危' })[s] ?? s
const kindLabel = (k: string) =>
  ({
    secret_leak: '密钥拦截',
    sensitive_path: '敏感路径访问',
    policy_mismatch: '策略不匹配',
    deny_burst: 'Deny 突增',
    tool_spike: '调用风暴',
    injection_suspect: '注入信号',
    approval_timeout: '审批超时',
    unregistered_server: '未注册服务器',
    agent_silence: 'Agent 失联',
    manual_approval: '人工批准',
    tool_first_use: '新工具首次使用',
  })[k] ?? k
const alerts = ref<Awaited<ReturnType<typeof api.alerts>>['alerts']>([])
const aiSummary = ref<string | null>(null)
const aiLoading = ref(false)
const aiModel = ref('')
const aiCount = ref(0)
/** 模型未配置时的 400 文案：留在页面上（带跳转），不要一闪而过的 toast */
const aiBlocked = ref('')
const aiHours = 24

async function genSummary() {
  // 模型是"前置条件"：没配好时先说这个，否则用户看到"暂无告警可分析"
  // 会以为功能正常，永远不知道 AI 其实没通
  if (!ai.configured) {
    aiBlocked.value = ai.reason
    return
  }
  if (!alerts.value.length) return ElMessage.warning('暂无告警可分析')
  aiLoading.value = true
  aiBlocked.value = ''
  try {
    const r = await api.alertSummary(aiHours)
    aiSummary.value = r.summary
    aiModel.value = r.model
    aiCount.value = r.alerts_count
  } catch (e: any) {
    const msg = e?.response?.data?.error?.message ?? 'AI 摘要生成失败'
    // 400 = 还没配模型：留在页面上说清楚，别让用户以为是网络问题
    if (e?.response?.status === 400) aiBlocked.value = msg
    else ElMessage.error(msg)
    if (e?.response?.status === 400) void ai.refresh()
  } finally {
    aiLoading.value = false
  }
}
const kindFilter = ref<string | undefined>(undefined)
const severityFilter = ref<string | undefined>(undefined)
const stateFilter = ref<string | undefined>(undefined)
const stateLabel = (s: string) => ({ open: '待处理', acknowledged: '已确认', resolved: '已解决' })[s] ?? s
const openCount = computed(() => alerts.value.filter((a) => a.state === 'open').length)

async function load() {
  alerts.value = (await api.alerts(50, kindFilter.value, severityFilter.value, stateFilter.value)).alerts
}

async function setState(row: { id: number }, state: string) {
  await api.updateAlertState(row.id, state)
  ElMessage.success(stateLabel(state))
  await load()
}

async function resolveAll() {
  await api.batchAlertState(alerts.value.filter((a) => a.state !== 'resolved').map((a) => a.id), 'resolved')
  ElMessage.success('已全部解决')
  await load()
}

onMounted(async () => {
  await Promise.all([load(), ai.ensureLoaded()])
})
</script>

<style scoped>
.head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.head h2 { margin: 0; }
.filters { display: flex; gap: 8px; }
.ai-card { margin-bottom: 14px; }
.ai-head { display: flex; justify-content: space-between; align-items: center; }
.ai-meta { font-size: 12px; color: var(--fh-text-dim, #9aa3af); margin-bottom: 8px; }
.ai-body { font-size: 13px; line-height: 1.7; white-space: pre-wrap; }
</style>
