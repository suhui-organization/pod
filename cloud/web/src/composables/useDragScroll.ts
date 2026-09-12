/**
 * 全局横向拖拽滚动(所有页面通用):
 * 区域中的内容超出可显示范围时,按住鼠标左键即可左右拖动查看。
 *
 * 规则:
 * - mousedown 时向上查找最近的可横向滚动容器(overflow-x 为 auto/scroll/overlay/hidden
 *   且 scrollWidth > clientWidth);找不到则不介入;
 * - 拖拽超过阈值(5px)且横向位移占优才接管 —— 纵向拖动让位原生滚动,避免误伤;
 * - 交互元素(a/button/input/textarea/select/th 表头/可编辑区等)不触发,
 *   保证点击、表格列宽拖拽、文本选择等原生行为不受影响;
 * - 拖动期间容器加 .pod-dragging(cursor:grabbing + user-select:none),结束自动还原。
 */
export function useDragScroll(): void {
  if (typeof window === 'undefined') return

  const DRAG_THRESHOLD = 5
  const INTERACTIVE_TAGS = new Set(['A', 'BUTTON', 'INPUT', 'TEXTAREA', 'SELECT', 'LABEL', 'TH'])
  // 命中这些选择器的最小化交互目标也不触发(Element Plus 控件 + 表格列宽调整 + 自绘滚动条)
  const INTERACTIVE_CLOSEST = [
    '.el-button', '.el-input', '.el-select', '.el-switch', '.el-checkbox', '.el-radio',
    '.el-slider', '.el-color-picker', '.el-rate', '.el-pagination', '.el-dropdown',
    '.el-table th', '.el-table__column-resize-helper', '.el-table__column-resize-proxy',
    '.el-scrollbar__bar',
    '[contenteditable]',
  ].join(',')

  let el: HTMLElement | null = null
  let startX = 0
  let startY = 0
  let startLeft = 0
  let dragging = false

  function isInteractive(target: EventTarget | null): boolean {
    const node = target as HTMLElement | null
    if (!node || !(node instanceof Element)) return false
    if (INTERACTIVE_TAGS.has(node.tagName)) return true
    if ((node as HTMLElement).isContentEditable) return true
    return !!node.closest(INTERACTIVE_CLOSEST)
  }

  function findScrollable(target: EventTarget | null): HTMLElement | null {
    let node = target as HTMLElement | null
    while (node && node.nodeType === 1 && node !== document.documentElement) {
      if (node.scrollWidth > node.clientWidth + 1) {
        const ox = getComputedStyle(node).overflowX
        if (ox === 'auto' || ox === 'scroll' || ox === 'overlay' || ox === 'hidden') return node
      }
      node = node.parentElement
    }
    return null
  }

  function onMouseDown(e: MouseEvent): void {
    if (e.button !== 0) return
    const box = findScrollable(e.target)
    if (!box || isInteractive(e.target)) return
    // 按下位置落在容器底边滚动条高度内:是原生横向滚动条区域,让位原生拖拽
    const rect = box.getBoundingClientRect()
    if (e.clientY >= rect.bottom - 12) return
    el = box
    startX = e.clientX
    startY = e.clientY
    startLeft = box.scrollLeft
    dragging = false
    window.addEventListener('mousemove', onMouseMove)
    window.addEventListener('mouseup', onMouseUp)
  }

  function onMouseMove(e: MouseEvent): void {
    if (!el) return
    const dx = e.clientX - startX
    const dy = e.clientY - startY
    if (!dragging) {
      if (Math.abs(dx) < DRAG_THRESHOLD && Math.abs(dy) < DRAG_THRESHOLD) return
      if (Math.abs(dy) > Math.abs(dx)) { stop(); return } // 纵向意图:让位原生滚动
      dragging = true
      el.classList.add('pod-dragging')
      const sel = window.getSelection()
      if (sel && !sel.isCollapsed) sel.removeAllRanges()
    }
    e.preventDefault()
    el.scrollLeft = startLeft - dx
  }

  function onMouseUp(): void {
    stop()
  }

  function stop(): void {
    if (el) {
      el.classList.remove('pod-dragging')
      el = null
    }
    dragging = false
    window.removeEventListener('mousemove', onMouseMove)
    window.removeEventListener('mouseup', onMouseUp)
  }

  // capture:在 Element Plus 等组件自身 mousedown 处理之前判定,避免被 stopPropagation 拦截
  document.addEventListener('mousedown', onMouseDown, true)
}
