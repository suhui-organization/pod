<script setup lang="ts">
import { useAiStore } from '../stores/ai'

/**
 * 模型未配置时的统一提示。三个 AI 入口共用一份文案与出口，
 * 避免"某个入口弹 toast、另一个入口静悄悄"。
 */
const props = defineProps<{ message?: string }>()
const ai = useAiStore()
</script>

<template>
  <p class="ai-notice">
    {{ props.message || ai.reason }}
    <RouterLink class="ai-notice__link" to="/settings#ai-model">去配置模型</RouterLink>
  </p>
</template>

<style scoped>
.ai-notice {
  display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px;
  margin: 0 0 12px; padding: 10px 14px; border-radius: 10px;
  font-size: var(--fh-size-md, 13px); line-height: 1.7;
  color: var(--fh-text-dim, #9aa2b1);
  background: var(--fh-panel-elev, #1c2128);
  border: 1px solid var(--fh-border, rgba(255, 255, 255, 0.07));
}
/* 提示底色是 panel-elev 而不是纯白，纯 accent 在浅色主题只有 4.27；
   往正文色混一档，两种主题都过 4.5 */
.ai-notice__link {
  color: color-mix(in srgb, var(--fh-accent, #6ea4f9) 82%, var(--fh-text, #e6e8ec));
  text-decoration: none;
}
.ai-notice__link:hover { text-decoration: underline; }
</style>
