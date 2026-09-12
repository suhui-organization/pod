/**
 * 用户偏好(替代 localStorage,跨设备同步)
 *
 * 用法:
 *   const prefs = usePreferences()
 *   prefs.get<number>('fh_nav_w', 200)              // 读取(同步,先用内存,无则默认值)
 *   prefs.set('fh_nav_w', 260)                     // 写入(自动 debounce 推到后端)
 *   await prefs.load()                              // 启动时从后端拉取
 *   await prefs.migrateFromLocalStorage(keys)       // 老用户 localStorage 迁移
 *
 * 设计要点:
 *  - 内存为单一可信源(后端只是持久化),UI 不会闪烁
 *  - set() 触发 debounce(600ms)合并多次改动为单次 PUT,避免拖拽时频繁请求
 *  - 后端失败不抛错:降级到仅内存,下次再试
 *  - 启动时不阻塞:先用默认值渲染,后台拉取后回填
 */
import { ref } from 'vue'
import { api } from '../api'
import { STORAGE_KEYS } from '../api/client'

// 与布局 store 配合的 key 集合(老 localStorage 也用这套 key,便于迁移)
export const PREF_KEYS = [
  'fh_nav_w',
  'fh_nav_collapsed',
  'fh_sidebar_w',
  'fh_modules_w',
  'fh_modules_collapsed',
  'fh_active_tab',
] as const
export type PrefKey = typeof PREF_KEYS[number]

const STORE_KEY = '__finharness_prefs_cache__' // 进程内单一可信源
const LS_MIGRATION_FLAG = 'fh_prefs_migrated_v1'

interface PrefCache {
  loaded: boolean            // 是否从后端拉取过
  values: Record<string, unknown>  // 已加载的所有偏好
  /** 内部订阅者:set() 后通知所有读取方重新取值 */
  rev: number
}

const cache: PrefCache = (() => {
  try {
    const raw = sessionStorage.getItem(STORE_KEY)
    if (raw) return JSON.parse(raw) as PrefCache
  } catch { /* ignore */ }
  return { loaded: false, values: {}, rev: 0 }
})()
function bumpRev() {
  cache.rev++
  try { sessionStorage.setItem(STORE_KEY, JSON.stringify(cache)) } catch { /* ignore */ }
}

let pendingTimer: ReturnType<typeof setTimeout> | null = null
let pendingValues: Record<string, unknown> = {}
const DEBOUNCE_MS = 600

async function flushPending() {
  pendingTimer = null
  const payload = { ...pendingValues }
  pendingValues = {}
  if (Object.keys(payload).length === 0) return
  try {
    await api.putMyPreferences({ preferences: payload })
  } catch (e) {
    // 后端失败不抛错:仅 console.warn,下次 set 时再重试合并
    console.warn('[usePreferences] PUT 失败', e, payload)
    // 重新合入 pendingValues 以便下次 flush 重试
    pendingValues = { ...payload, ...pendingValues }
  }
}

let inFlightLoad = false
async function loadFromBackend() {
  if (inFlightLoad) return
  // 未登录时不要打这个接口:它需要鉴权,必然 401,而 401 会被 http 拦截器
  // 当成"登录态过期"→ 整页跳登录页,把 /reset-password、/legal/* 这些
  // 公开页面也一并弹走(登录页自己也会白挨一次 401 报错)。
  if (!localStorage.getItem(STORAGE_KEYS.token)) {
    cache.loaded = true
    bumpRev()
    return
  }
  inFlightLoad = true
  try {
    const resp = await api.getMyPreferences()
    cache.values = { ...(resp.preferences || {}) }
    cache.loaded = true
    bumpRev()
  } catch (e) {
    console.warn('[usePreferences] GET 失败,使用默认值', e)
    cache.loaded = true // 标记已尝试,避免反复请求
    bumpRev()
  } finally {
    inFlightLoad = false
  }
}

// 单例 controller(供整个 App 共享同一份内存缓存)
const subs = new Set<() => void>()
function notify() {
  subs.forEach((fn) => fn())
  bumpRev()
}

export interface UsePreferences {
  /** 同步读取:内存有则用内存,否则用默认值 */
  get<T>(key: PrefKey | string, fallback: T): T
  /** 写入:同时更新内存 + debounce 推后端 */
  set(key: PrefKey | string, value: unknown): void
  /** 异步从后端拉取并填充(应用启动时调用一次) */
  load(): Promise<void>
  /** 单次迁移:把 localStorage 里 fh_* 键的值搬运到后端,完成后清掉旧键 */
  migrateFromLocalStorage(keys: readonly string[]): Promise<void>
  /** 当前是否已从后端加载完成(供 UI 在数据回填前避免闪烁) */
  isLoaded: () => boolean
  /** 订阅变化(供 reactive 订阅者;一般组件用 get() 即可) */
  subscribe: (fn: () => void) => () => void
}

let singleton: UsePreferences | null = null
export function usePreferences(): UsePreferences {
  if (singleton) return singleton
  singleton = {
    get<T>(key: string, fallback: T): T {
      return cache.loaded && key in cache.values
        ? (cache.values[key] as T)
        : fallback
    },
    set(key, value) {
      cache.values[key] = value
      pendingValues[key] = value
      notify()
      if (pendingTimer) clearTimeout(pendingTimer)
      pendingTimer = setTimeout(flushPending, DEBOUNCE_MS)
    },
    load() {
      return loadFromBackend()
    },
    migrateFromLocalStorage(keys) {
      if (localStorage.getItem(LS_MIGRATION_FLAG) === '1') return Promise.resolve()
      const collected: Record<string, unknown> = {}
      for (const k of keys) {
        const raw = localStorage.getItem(k)
        if (raw == null) continue
        try {
          const v: unknown = JSON.parse(raw)
          if (typeof v === 'string') {
            // 字符串(简单 boolean 等)需要带引号;非字符串保持原值
            collected[k] = isFinite(Number(v)) && v !== '' && !isNaN(Number(v))
              ? (v === 'true' ? true : v === 'false' ? false : Number(v))
              : v
          } else {
            collected[k] = v
          }
        } catch {
          collected[k] = raw
        }
        localStorage.removeItem(k)
      }
      if (Object.keys(collected).length === 0) {
        localStorage.setItem(LS_MIGRATION_FLAG, '1')
        return Promise.resolve()
      }
      return api.putMyPreferences({ preferences: collected }).then(() => {
        localStorage.setItem(LS_MIGRATION_FLAG, '1')
        // 把迁移的值也写进内存缓存,避免重新拉取
        cache.values = { ...cache.values, ...collected }
        notify()
      })
    },
    isLoaded() {
      return cache.loaded
    },
    subscribe(fn) {
      subs.add(fn)
      return () => subs.delete(fn)
    },
  }
  return singleton
}

/** 给 reactive 用的辅助:订阅 cache.rev 变化,触发 get 重新求值 */
export function useReactivePrefs<T>(key: string, fallback: T) {
  const rev = ref(cache.rev)
  usePreferences().subscribe(() => {
    rev.value = cache.rev
  })
  return {
    get value(): T {
      // 显式引用 rev.value 以建立依赖
      // eslint-disable-next-line @typescript-eslint/no-unused-expressions
      rev.value
      return usePreferences().get<T>(key, fallback)
    },
  }
}
