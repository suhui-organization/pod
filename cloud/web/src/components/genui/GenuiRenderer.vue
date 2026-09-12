<template>
  <div class="genui">
    <div v-if="title" class="genui-title">{{ title }}</div>
    <div class="genui-items" :style="{ gap: `${gap ?? 12}px` }">
      <template v-for="(item, i) in items" :key="i">
        <div v-if="item.type === 'text'" class="gi-text" :style="textStyle(item)">{{ item.content ?? item.text ?? '' }}</div>

        <div v-else-if="item.type === 'badge'" class="gi-badge">
          <el-tag :type="tagType(item)" size="small" effect="plain">{{ item.content }}</el-tag>
        </div>

        <div v-else-if="item.type === 'stat'" class="gi-stat">
          <div class="gi-stat-label">{{ item.label || item.title }}</div>
          <div class="gi-stat-value" :style="{ color: item.color || 'var(--el-color-primary)' }">{{ item.value }}</div>
          <div v-if="item.suffix" class="gi-stat-suffix">{{ item.suffix }}</div>
        </div>

        <div v-else-if="item.type === 'progress'" class="gi-progress">
          <el-progress :percentage="clamp(item.value ?? 0)" :status="item.status" />
        </div>

        <el-divider v-else-if="item.type === 'divider'" />

        <div v-else-if="item.type === 'keyvalue'" class="gi-kv">
          <div v-for="(kv, k) in item.data" :key="k" class="gi-kv-line">
            <span class="gi-kv-key">{{ kv.label ?? k }}</span>
            <span class="gi-kv-value">{{ kv.value }}</span>
          </div>
        </div>

        <div v-else-if="item.type === 'list'" class="gi-list">
          <div v-for="(li, j) in item.items" :key="j" class="gi-list-item">
            <span v-if="li.badge" class="gi-list-badge">{{ li.badge }}</span>
            <span>{{ li.content ?? li }}</span>
          </div>
        </div>

        <el-table v-else-if="item.type === 'table'" :data="item.rows || []" size="small" border class="gi-table">
          <el-table-column v-for="(col, c) in (item.columns || [])" :key="c" :prop="typeof col === 'string' ? col : col.key" :label="typeof col === 'string' ? col : col.label" />
        </el-table>

        <pre v-else-if="item.type === 'code'" class="gi-code">{{ item.content }}</pre>
        <pre v-else-if="item.type === 'json'" class="gi-code">{{ prettyJson(item.data ?? item.content) }}</pre>

        <el-button v-else-if="item.type === 'button'" size="small" :type="item.variant || 'primary'" @click="fire(item.action, item)">
          {{ item.content }}
        </el-button>

        <el-input v-else-if="item.type === 'input'" :model-value="item.value ?? ''" :placeholder="item.placeholder" size="small" class="gi-input" @update:model-value="(v: any) => setValue(i, v)" />

        <el-select v-else-if="item.type === 'select'" :model-value="item.value ?? ''" size="small" class="gi-select" @update:model-value="(v: any) => setValue(i, v)">
          <el-option v-for="(opt, o) in (item.options || [])" :key="o" :label="opt.label ?? opt" :value="opt.value ?? opt" />
        </el-select>

        <el-switch v-else-if="item.type === 'switch'" :model-value="item.value ?? false" @update:model-value="(v: any) => setValue(i, v)" />

        <el-tabs v-else-if="item.type === 'tabs'" class="gi-tabs">
          <el-tab-pane v-for="(tab, t) in item.items" :key="t" :label="tab.label">
            <div v-html="tab.content || ''" class="gi-tab-content" />
          </el-tab-pane>
        </el-tabs>

        <div v-else-if="['row', 'col', 'card'].includes(item.type)" class="gi-container" :class="`gi-container--${item.type}`"
             :style="containerStyle(item)">
          <div v-if="item.title" class="gi-container-title">{{ item.title }}</div>
          <GenuiRenderer v-if="(item.children || []).length" :items="item.children" :gap="item.gap" @action="forward" />
        </div>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive } from 'vue'

const props = defineProps<{ items: any[]; title?: string; gap?: number }>()
const emit = defineEmits<{ (e: 'action', payload: { action: string; data: any }): void }>()

const values = reactive<Record<number, any>>({})

function setValue(index: number, v: any) {
  values[index] = v
  const item = props.items[index]
  if (item?.action) fire(item.action, { ...item, value: v })
}

function fire(action: string | undefined, data: any) {
  if (!action) return
  emit('action', { action, data })
}

function forward(payload: { action: string; data: any }) {
  emit('action', payload)
}

function tagType(item: any): any {
  return item.tone || item.variant || 'info'
}
function clamp(v: number): number {
  return Math.max(0, Math.min(100, Number(v) || 0))
}
function textStyle(item: any): Record<string, string> {
  const s: Record<string, string> = {}
  if (item.size) s.fontSize = typeof item.size === 'number' ? `${item.size}px` : item.size
  if (item.weight) s.fontWeight = String(item.weight)
  if (item.color) s.color = item.color
  return s
}
function containerStyle(item: any): Record<string, string> {
  const s: Record<string, string> = {}
  if (item.type === 'col') s.flexDirection = 'column'
  if (item.gap) s.gap = `${item.gap}px`
  return s
}
function prettyJson(data: any): string {
  try {
    return JSON.stringify(data ?? {}, null, 2)
  } catch {
    return String(data ?? '')
  }
}
</script>

<style scoped>
.genui {
  margin: 6px 0;
}
.genui-title {
  font-weight: 600;
  margin-bottom: 8px;
}
.genui-items {
  display: flex;
  flex-direction: column;
}
.gi-container {
  display: flex;
  padding: 10px;
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 8px;
  background: var(--el-fill-color-lighter);
}
.gi-container--row {
  flex-direction: row;
  flex-wrap: wrap;
}
.gi-container--card {
  flex-direction: column;
}
.gi-container-title {
  font-weight: 600;
  margin-bottom: 6px;
  width: 100%;
}
.gi-text {
  line-height: 1.6;
  white-space: pre-wrap;
}
.gi-stat {
  display: flex;
  align-items: baseline;
  gap: 8px;
}
.gi-stat-label {
  color: var(--el-text-color-secondary);
  font-size: 13px;
}
.gi-stat-value {
  font-size: 22px;
  font-weight: 700;
}
.gi-stat-suffix {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
.gi-progress {
  width: 100%;
}
.gi-kv-line {
  display: flex;
  justify-content: space-between;
  padding: 3px 0;
  border-bottom: 1px dashed var(--el-border-color-lighter);
}
.gi-kv-key {
  color: var(--el-text-color-secondary);
}
.gi-list-item {
  display: flex;
  gap: 8px;
  padding: 3px 0;
}
.gi-list-badge {
  color: var(--el-color-primary);
}
.gi-table {
  width: 100%;
}
.gi-code {
  background: var(--el-fill-color-dark);
  border-radius: 6px;
  padding: 10px;
  font-size: 12px;
  overflow: auto;
  max-height: 300px;
  white-space: pre-wrap;
}
.gi-input,
.gi-select {
  max-width: 320px;
}
.gi-tabs {
  width: 100%;
}
.gi-tab-content {
  font-size: 13px;
  line-height: 1.6;
}
</style>
