<template>
  <component
    :is="comp"
    v-if="comp"
    :slot="slot"
  />
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { hasSlotComponent, resolveSlotComponent, type PluginSlot } from '../../plugins/slotRegistry'

const props = defineProps<{ slot: PluginSlot }>()

const comp = computed(() => {
  if (!props.slot || !hasSlotComponent(props.slot.component)) return null
  return resolveSlotComponent(props.slot.component)
})
</script>

<style scoped>
.plugin-slot-renderer {
  display: contents;
}
</style>
