<template>
  <div ref="root" class="row-actions" :class="`align-${align}`" :style="{ justifyContent: justify }">
    <el-button
      v-for="a in visibleItems"
      :key="a.key"
      size="small"
      :type="a.type || undefined"
      :plain="a.plain || false"
      :link="a.link || false"
      :loading="a.loading || false"
      :disabled="a.disabled || false"
      @click="a.onClick"
    >{{ a.label }}</el-button>

    <!-- 其余操作收纳进「更多」:行内永远单行,窄屏自适应 -->
    <el-dropdown v-if="hiddenItems.length" trigger="click" @command="onCommand">
      <el-button size="small" class="more-btn">
        <span v-if="!narrow">⋯ 更多</span><span v-else>⋯</span>
      </el-button>
      <template #dropdown>
        <el-dropdown-menu>
          <el-dropdown-item
            v-for="a in hiddenItems"
            :key="a.key"
            :command="a"
            :type="a.danger ? 'danger' : 'default'"
            :divided="a.divided || false"
            :disabled="a.disabled || false"
          >{{ a.label }}</el-dropdown-item>
        </el-dropdown-menu>
      </template>
    </el-dropdown>
  </div>
</template>

<script lang="ts" setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'

export interface RowActionItem {
  key: string
  label: string
  onClick?: () => void
  /** 条件显示:为 false 整项隐藏 */
  show?: boolean
  type?: 'primary' | 'success' | 'warning' | 'danger' | 'info'
  plain?: boolean
  link?: boolean
  loading?: boolean
  disabled?: boolean
  /** 危险操作:收纳进「更多」时标红 */
  danger?: boolean
  /** 菜单分隔线 */
  divided?: boolean
  /** 主操作:排在最前 */
  primary?: boolean
}

const props = withDefaults(
  defineProps<{
    /** 全部操作(按展示优先级排列;show=false 自动过滤) */
    items: RowActionItem[]
    /** 最多以按钮形式展示的个数,其余进「更多」下拉(默认 1) */
    maxVisible?: number
    /** 对齐方式,配合表格列 align 使用 */
    align?: 'left' | 'center' | 'right'
  }>(),
  { maxVisible: 1, align: 'left' },
)

const justify = computed(
  () => ({ left: 'flex-start', center: 'center', right: 'flex-end' })[props.align],
)

const shown = computed(() => props.items.filter((a) => a.show !== false))
const visibleItems = computed(() =>
  [...shown.value]
    .sort((a, b) => Number(!!b.primary) - Number(!!a.primary))
    .slice(0, props.maxVisible),
)
const hiddenItems = computed(() => {
  const vis = new Set(visibleItems.value)
  return shown.value.filter((a) => !vis.has(a))
})

function onCommand(item: RowActionItem): void {
  item.onClick?.()
}

// 响应式:容器过窄时「更多」收成纯 ⋯,避免自身挤爆单元格
const root = ref<HTMLElement | null>(null)
const narrow = ref(false)
let ro: ResizeObserver | null = null
onMounted(() => {
  if (root.value && typeof ResizeObserver !== 'undefined') {
    ro = new ResizeObserver(() => {
      // 一行按钮 ≈ 120px+,阈值 100:只在列被压得很窄时才折叠文字
      narrow.value = (root.value?.clientWidth ?? 0) < 100
    })
    ro.observe(root.value)
  }
})
onBeforeUnmount(() => ro?.disconnect())
</script>

<style scoped>
.row-actions {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: nowrap;
  min-width: 0;
}
/* Element Plus 相邻按钮默认 margin-left:12px,flex 布局里用 gap 取代 */
.row-actions :deep(.el-button + .el-button) {
  margin-left: 0;
}
.row-actions :deep(.el-dropdown) {
  flex-shrink: 0;
}
</style>
