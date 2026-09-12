import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import './styles/theme.css'
import App from './App.vue'
import router from './router'
import { i18n } from './i18n'
import { useDragScroll } from './composables/useDragScroll'

// 持久化主题(暗色默认;设置中心可切换亮色)
document.documentElement.dataset.theme = localStorage.getItem('podcloud_theme') || 'dark'
// 持久化字号缩放(--pod-font-scale 为 CSS 变量,刷新后必须在此恢复,否则字号回落默认)
document.documentElement.style.setProperty('--pod-font-scale', localStorage.getItem('podcloud_font_scale') || '1')

const app = createApp(App)
app.use(createPinia())
app.use(router)
app.use(i18n)
app.use(ElementPlus)
document.documentElement.lang = i18n.global.locale.value as string
app.mount('#app')

// 全局横向拖拽滚动:任何区域内容超出可视范围时按住左键即可左右拖动
useDragScroll()

// 版本心跳:部署滚动更新后,旧页面自动感知新版本并整页刷新
// (根治「旧 JS 缓存导致功能回归/不回显」:无需用户手动强刷)
async function checkVersion(): Promise<void> {
  try {
    const resp = await fetch('/version.json', { cache: 'no-store' })
    const data = (await resp.json()) as { version?: string }
    const meta = document.querySelector('meta[name="app-version"]')
    const current = meta?.getAttribute('content') || ''
    if (data.version && current && data.version !== current) {
      window.location.reload()
    }
  } catch {
    /* 静默 */
  }
}
setInterval(checkVersion, 30000)
