<template>
  <div class="hello-panel">
    <div class="hello-title">🖐 Hello 插件</div>
    <div class="hello-body">这是宿主协议插件的示例侧边栏组件（slot: sidebar）。</div>
    <el-tag size="small" type="success">{{ slot.plugin_id }}</el-tag>
  </div>
</template>

<script setup lang="ts">
import type { PluginSlot } from '../../plugins/slotRegistry'

defineProps<{ slot: PluginSlot }>()
</script>

<style scoped>
.hello-panel {
  padding: 10px 12px;
  border-radius: 8px;
  background: var(--el-fill-color-light);
  font-size: 12px;
}
.hello-title {
  font-weight: 600;
  margin-bottom: 4px;
}
.hello-body {
  color: var(--el-text-color-secondary);
  margin-bottom: 6px;
  line-height: 1.5;
}
</style>
