<template>
  <el-dropdown trigger="click" @command="switchTo">
    <button class="lang" type="button" :aria-label="t('语言')">
      <Languages :size="15" />
      <span class="lang__text">{{ current === 'zh-CN' ? '中文' : 'EN' }}</span>
    </button>
    <template #dropdown>
      <el-dropdown-menu>
        <el-dropdown-item command="zh-CN" :disabled="current === 'zh-CN'">中文</el-dropdown-item>
        <el-dropdown-item command="en-US" :disabled="current === 'en-US'">English</el-dropdown-item>
      </el-dropdown-menu>
    </template>
  </el-dropdown>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { Languages } from 'lucide-vue-next'
import { setLocale, type Locale } from '../i18n'

const { t, locale } = useI18n()
const current = computed(() => locale.value as Locale)

function switchTo(value: string) {
  setLocale(value as Locale)
}
</script>

<style scoped>
.lang {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 4px 10px; border-radius: 8px; cursor: pointer;
  background: transparent; color: var(--el-text-color-regular);
  border: 1px solid var(--el-border-color);
}
.lang:hover { color: var(--el-color-primary); border-color: var(--el-color-primary); }
.lang__text { font-size: 12px; }
</style>
