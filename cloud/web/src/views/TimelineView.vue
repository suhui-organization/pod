<template>
  <div>
    <div class="head">
      <h2>{{ t('取证时间线') }}</h2>
      <div class="filters">
        <el-select v-model="minutes" style="width: 140px" @change="load">
          <el-option :label="t('全部时间')" :value="0" />
          <el-option :label="t('最近 1 小时')" :value="60" />
          <el-option :label="t('最近 24 小时')" :value="1440" />
          <el-option :label="t('最近 7 天')" :value="10080" />
        </el-select>
        <el-button :loading="loading" @click="load">{{ t('刷新') }}</el-button>
      </div>
    </div>

    <el-alert type="info" :closable="false" show-icon class="hint"
      :title="t('跨 Agent 证据链：每条记录含参数 SHA-256 哈希与当时策略版本——不可篡改、可验证。')" />

    <AuditTimeline :events="events" :empty-text="t('暂无事件（本地 pod sync 后可见）')" />
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api } from '../api'
import AuditTimeline from '../components/AuditTimeline.vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

type TimelineEvent = Awaited<ReturnType<typeof api.timeline>>['events'][number]
const events = ref<TimelineEvent[]>([])
const minutes = ref(0)
const loading = ref(false)

async function load() {
  loading.value = true
  try {
    events.value = (await api.timeline({ limit: 300, minutes: minutes.value })).events
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
</style>
