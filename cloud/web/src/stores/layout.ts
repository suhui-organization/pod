import { defineStore } from 'pinia'
import { usePreferences, PREF_KEYS } from '../composables/usePreferences'

export interface DetailsTab {
  id: string
  kind: string
  title: string
  payload: Record<string, unknown>
}

/** 模块面板的固定模块 tab kind:激活时自动加宽到推荐宽度 */
const MODULE_KINDS = new Set([
  'tasks', 'jobs', 'approvals',
])
const MODULES_WIDTH = 520
const MODULES_MIN = 320
const MODULES_MAX = 960

/**
 * 全局布局框架状态:左侧导航折叠 + 右侧模块面板
 * 持久化走 usePreferences(后端 sqlite,跨设备同步);fallback 默认值保证首次加载可用
 */
export const useLayoutStore = defineStore('layout', {
  state: () => {
    const prefs = usePreferences()
    return {
      /** 左侧导航是否收起为图标栏 */
      navCollapsed: prefs.get<boolean>('fh_nav_collapsed', true),  // 默认收起(图标栏)
      /** 左侧导航展开时的宽度(可拖拽调节) */
      navWidth: prefs.get<number>('fh_nav_w', 200),
      /** 会话侧栏宽度(ChatView 内部 PageColumns 用) */
      sidebarWidth: prefs.get<number>('fh_sidebar_w', 220),

      /** 模块面板(右侧)宽度与折叠 */
      modulesWidth: prefs.get<number>('fh_modules_w', MODULES_WIDTH),
      modulesCollapsed: prefs.get<boolean>('fh_modules_collapsed', true),  // 默认收起(工作台面板)
      /** 模块面板 Tab 模型 */
      tabs: [] as DetailsTab[],
      /** 当前激活的模块 tab(由 setActive 持久化) */
      activeTabId: prefs.get<string>('fh_active_tab', ''),
    }
  },
  getters: {
    /** 兼容旧代码(PageColumns 等);返回模块面板宽度 */
    detailsWidth(): number {
      return this.modulesWidth
    },
  },
  actions: {
    setSidebarWidth(w: number) {
      const v = Math.min(Math.max(Math.round(w), 180), 420)
      this.sidebarWidth = v
      usePreferences().set('fh_sidebar_w', v)
    },
    toggleNavCollapsed() {
      this.navCollapsed = !this.navCollapsed
      usePreferences().set('fh_nav_collapsed', this.navCollapsed)
    },
    setNavWidth(w: number) {
      // 仅在展开态生效;折叠态固定 56
      const v = Math.min(Math.max(Math.round(w), 120), 280)
      this.navWidth = v
      usePreferences().set('fh_nav_w', v)
    },

    setModulesWidth(w: number) {
      const v = Math.min(Math.max(Math.round(w), MODULES_MIN), MODULES_MAX)
      this.modulesWidth = v
      usePreferences().set('fh_modules_w', v)
    },
    toggleModulesCollapsed() {
      this.modulesCollapsed = !this.modulesCollapsed
      usePreferences().set('fh_modules_collapsed', this.modulesCollapsed)
    },
    /** 显式设置模块面板折叠态(移动端进入时自动折叠用) */
    setModulesCollapsed(v: boolean) {
      if (this.modulesCollapsed === v) return
      this.modulesCollapsed = v
      usePreferences().set('fh_modules_collapsed', v)
    },

    /** 兼容旧 API(后续会清理调用点后删除) */
    setDetailsWidth(w: number) { this.setModulesWidth(w) },

    /**
     * 添加/激活模块面板 Tab(id 已存在则仅激活)。
     * opts.activate = false 时仅注册,用于固定模块 tab 批量注册。
     * 激活模块 tab 时自动加宽模块面板(若折叠则不强行展开,尊重用户)。
     */
    addTab(id: string, kind: string, title: string, payload: Record<string, unknown> = {}, opts: { activate?: boolean } = {}) {
      const activate = opts.activate !== false
      const exist = this.tabs.find((t) => t.id === id)
      if (exist) {
        exist.payload = payload
        exist.title = title
      } else {
        this.tabs.push({ id, kind, title, payload })
      }
      if (activate) {
        this.activeTabId = id
        if (MODULE_KINDS.has(kind) && this.modulesWidth < MODULES_WIDTH) {
          this.setModulesWidth(MODULES_WIDTH)
        }
      }
    },
    closeTab(id: string) {
      const idx = this.tabs.findIndex((t) => t.id === id)
      if (idx === -1) return
      this.tabs.splice(idx, 1)
      if (this.activeTabId === id) {
        const next = this.tabs[Math.min(idx, this.tabs.length - 1)]
        this.activeTabId = next ? next.id : ''
      }
    },
    setActive(id: string) {
      this.activeTabId = id
      usePreferences().set('fh_active_tab', id)
      const tab = this.tabs.find((t) => t.id === id)
      if (tab && MODULE_KINDS.has(tab.kind) && this.modulesWidth < MODULES_WIDTH) {
        this.setModulesWidth(MODULES_WIDTH)
      }
    },
  },
})

/** 启动时执行:迁移老 localStorage + 拉取后端偏好。供 App.vue 调用。 */
export async function bootstrapLayoutPreferences() {
  const prefs = usePreferences()
  // 先迁移老 localStorage(只跑一次)
  await prefs.migrateFromLocalStorage(PREF_KEYS)
  // 再拉取后端
  await prefs.load()
}

/** 把后端偏好回填到当前 store(由 App.vue 在 load 完成后调用) */
export function applyPreferencesToStore() {
  const prefs = usePreferences()
  const store = useLayoutStore()
  store.$patch({
    navCollapsed: prefs.get('fh_nav_collapsed', true),
    navWidth: prefs.get('fh_nav_w', 200),
    sidebarWidth: prefs.get('fh_sidebar_w', 220),
    modulesWidth: prefs.get('fh_modules_w', MODULES_WIDTH),
    modulesCollapsed: prefs.get('fh_modules_collapsed', true),
    activeTabId: prefs.get('fh_active_tab', ''),
  })
}
