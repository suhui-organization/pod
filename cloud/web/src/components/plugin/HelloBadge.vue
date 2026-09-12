<template>
  <el-tag size="small" type="warning" effect="plain" class="hello-badge" title="Hello 插件已启用">
    🖐 hello
  </el-tag>
</template>

<script setup lang="ts">
import type { PluginSlot } from '../../plugins/slotRegistry'

defineProps<{ slot: PluginSlot }>()
</script>

<style scoped>
.hello-badge {
  margin-left: 8px;
  cursor: default;
}
</style>
