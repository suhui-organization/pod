import { onBeforeUnmount, onMounted, ref } from 'vue'

export type ResponsiveMode = 'desktop' | 'tablet' | 'mobile'

export const BREAKPOINTS = {
  desktop: 1280, // ≥ 此宽度为桌面
  tablet: 768,    // ≥ 此宽度且 < desktop 为平板
  // < tablet 为移动
} as const

/**
 * 响应式状态:提供当前窗口宽度与分级(桌面/平板/移动)。
 * 不在此直接改写布局 store —— 模式由组件按需消费。
 */
export function useResponsive() {
  const width = ref(typeof window === 'undefined' ? 1280 : window.innerWidth)
  const mode = ref<ResponsiveMode>(classify(width.value))

  function classify(w: number): ResponsiveMode {
    if (w >= BREAKPOINTS.desktop) return 'desktop'
    if (w >= BREAKPOINTS.tablet) return 'tablet'
    return 'mobile'
  }

  function onResize() {
    width.value = window.innerWidth
    mode.value = classify(width.value)
  }

  onMounted(() => {
    window.addEventListener('resize', onResize)
    onResize()
  })
  onBeforeUnmount(() => {
    window.removeEventListener('resize', onResize)
  })

  return { width, mode }
}
