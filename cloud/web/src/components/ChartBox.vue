<template>
  <div ref="el" class="chart-box" :style="{ height: height }" />
</template>

<script setup lang="ts">
import { onMounted, onBeforeUnmount, ref, watch, type Ref } from 'vue'
import * as echarts from 'echarts'

const props = defineProps<{ option: Record<string, unknown>; height?: string }>()
const el: Ref<HTMLDivElement | null> = ref(null)
let chart: echarts.ECharts | null = null

function render() {
  if (!el.value) return
  chart ??= echarts.init(el.value)
  chart.setOption(props.option as echarts.EChartsOption, true)
}

function onResize() {
  chart?.resize()
}

onMounted(() => {
  render()
  window.addEventListener('resize', onResize)
})
onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  chart?.dispose()
  chart = null
})
watch(() => props.option, render, { deep: true })
</script>

<style scoped>
.chart-box { width: 100%; }
</style>
