<template>
  <div class="hd">
    <div class="head">
      <div class="head__title">
        <h2>{{ t('加固报告') }}</h2>
        <p class="head__meta">
          {{ t('机器上执行 pod harden 得到的审计交付物：暴露面 + 控制平面姿态 + 最小权限草稿 + 证据自检。') }}
        </p>
      </div>
      <el-button :loading="loading" @click="load()">{{ t('刷新') }}</el-button>
    </div>

    <el-alert type="info" :closable="false" show-icon class="hint"
      :title="t('上传是显式动作：机器上跑 pod harden --upload。只传 report.md 与 findings.json（已脱敏），原始审计链 evidence.json 不会上传。')" />

    <el-card shadow="never" class="cmd">
      <div class="cmd__label">{{ t('机器侧上传') }}</div>
      <code class="cmd__code">pod harden --upload</code>
    </el-card>

    <div v-if="error" class="state state--error">
      <p>{{ error }}</p>
      <el-button size="small" @click="load()">{{ t('重试') }}</el-button>
    </div>
    <div v-else-if="loading" class="state" aria-busy="true">
      <el-skeleton :rows="3" animated />
    </div>
    <template v-else>
      <el-table :data="rows" stripe style="width: 100%">
        <el-table-column prop="agent_name" :label="t('机器 / Agent')" width="170" />
        <el-table-column :label="t('生成时间')" width="180">
          <template #default="{ row }">{{ fmtTime(row.generated_at) }}</template>
        </el-table-column>
        <el-table-column :label="t('风险')" width="190">
          <template #default="{ row }">
            <el-tag v-if="row.high" type="danger" size="small" effect="dark">{{ t('高') }} {{ row.high }}</el-tag>
            <el-tag v-if="row.medium" type="warning" size="small" effect="plain" class="tag">{{ t('中') }} {{ row.medium }}</el-tag>
            <el-tag v-if="row.low" type="info" size="small" effect="plain" class="tag">{{ t('低') }} {{ row.low }}</el-tag>
            <span v-if="!row.high && !row.medium && !row.low" class="ok">✅</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('暴露面')" width="200">
          <template #default="{ row }">
            {{ t('{n} 个 MCP server · {s} 处密钥', { n: row.mcp_servers, s: row.exposed_secrets }) }}
          </template>
        </el-table-column>
        <el-table-column :label="t('审计链')" width="130">
          <template #default="{ row }">
            <span v-if="row.broken_chains" class="bad">{{ t('{n} 条断裂', { n: row.broken_chains }) }}</span>
            <span v-else class="ok">{{ t('完整') }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('操作')" width="120">
          <template #default="{ row }">
            <el-button size="small" @click="open(row)">{{ t('查看') }}</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-empty v-if="!rows.length" :description="t('还没有报告：在机器上跑 pod harden --upload。')" />
    </template>

    <el-dialog v-model="detailOpen" :title="t('加固报告')" width="860px">
      <template v-if="detail">
        <div class="detail-head">
          <span class="detail-agent">{{ detail.agent_name || `#${detail.agent_id}` }}</span>
          <span class="detail-time">{{ fmtTime(detail.generated_at) }}</span>
          <span class="detail-rules">{{ t('规则版本') }} {{ detail.rules_version || '—' }}</span>
          <el-button size="small" @click="download()">{{ t('下载 .md') }}</el-button>
          <el-button size="small" @click="copy()">{{ t('复制') }}</el-button>
        </div>
        <!-- 报告是 markdown 原文：这里按纯文本展示（不引 markdown 依赖，也不 v-html 渲染不可信内容） -->
        <pre class="report">{{ detail.report_md }}</pre>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { parseApiError } from '../api/client'
import type { HardenReportDetail, HardenReportItem } from '../api/types'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const rows = ref<HardenReportItem[]>([])
const loading = ref(false)
const error = ref('')
const detail = ref<HardenReportDetail | null>(null)
const detailOpen = ref(false)

function fmtTime(ts: string): string {
  if (!ts) return '—'
  const d = new Date(ts)
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString()
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    rows.value = (await api.hardenReports()).reports
  } catch (e) {
    error.value = parseApiError(e)
  } finally {
    loading.value = false
  }
}

async function open(row: HardenReportItem) {
  try {
    detail.value = (await api.hardenReport(row.id)).report
    detailOpen.value = true
  } catch (e) {
    ElMessage.error(parseApiError(e))
  }
}

function download() {
  if (!detail.value) return
  const blob = new Blob([detail.value.report_md], { type: 'text/markdown' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `pod-harden-${detail.value.generated_at.slice(0, 10)}.md`
  a.click()
  URL.revokeObjectURL(url)
}

async function copy() {
  if (!detail.value) return
  try {
    await navigator.clipboard.writeText(detail.value.report_md)
    ElMessage.success(t('已复制'))
  } catch {
    ElMessage.warning(t('浏览器不允许自动复制，请手动选中'))
  }
}

onMounted(load)
</script>

<style scoped>
.head { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 16px; }
.head__title h2 { margin: 0 0 4px; }
.head__meta { margin: 0; font-size: 12px; color: var(--el-text-color-secondary); }
.hint { margin-bottom: 12px; }
.cmd { margin-bottom: 16px; }
.cmd__label { font-size: 13px; color: var(--el-text-color-secondary); margin-bottom: 6px; }
.cmd__code {
  display: inline-block;
  padding: 6px 10px;
  background: var(--el-fill-color-light);
  border-radius: 4px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 13px;
}
.tag { margin-left: 6px; }
.ok { color: var(--el-color-success); }
.bad { color: var(--el-color-danger); }
.state { padding: 24px 0; }
.state--error { color: var(--el-color-danger); }
.detail-head { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; font-size: 13px; }
.detail-agent { font-weight: 600; }
.detail-time, .detail-rules { color: var(--el-text-color-secondary); }
.report {
  max-height: 60vh;
  overflow: auto;
  background: var(--el-fill-color-light);
  padding: 14px;
  border-radius: 6px;
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-word;
}
</style>
