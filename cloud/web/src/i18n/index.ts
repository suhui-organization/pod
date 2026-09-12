import { createI18n } from 'vue-i18n'
import elementEn from 'element-plus/es/locale/lang/en'
import elementZh from 'element-plus/es/locale/lang/zh-cn'
import { enUS } from './en-US'

/**
 * 中英切换。
 *
 * 设计取舍：**中文原文即 key**，不另造一套 key 名。
 *   `t('订阅')` 在 zh-CN 下直接返回 '订阅'（zh 词表为空，走 fallback），
 *   在 en-US 下查 `enUS['订阅']`。
 *
 * 这么做有两个好处，恰好是"给已有项目补 i18n"最需要的：
 *   1. 可以**逐页迁移**——没迁移的字符串原样显示中文，不会渲染出 key 名或空白，
 *      所以不存在"必须先翻完 20 个页面才能合并"的阻塞；
 *   2. 看代码就知道界面上会显示什么，不用在词表和模板之间来回跳。
 *
 * 代价是带参数的句子要写 `t('已用 {n} 个', { n })`，且 key 较长——
 * 对这个只有几十条文案的控制台来说，收益大于代价。
 */
export const SUPPORTED_LOCALES = ['zh-CN', 'en-US'] as const
export type Locale = (typeof SUPPORTED_LOCALES)[number]

const STORAGE_KEY = 'podcloud_locale'

function initialLocale(): Locale {
  const saved = localStorage.getItem(STORAGE_KEY)
  if (saved === 'zh-CN' || saved === 'en-US') return saved
  // 没存过就跟浏览器走：中文环境用中文，其余用英文（开源项目面向英文用户）
  return navigator.language?.toLowerCase().startsWith('zh') ? 'zh-CN' : 'en-US'
}

export const i18n = createI18n({
  legacy: false,
  globalInjection: true,
  // zh-CN 词表刻意为空：中文原文即 key，走 fallback 直接显示原文
  locale: initialLocale(),
  fallbackLocale: 'zh-CN',
  messages: { 'zh-CN': {}, 'en-US': enUS },
})

export function currentLocale(): Locale {
  return i18n.global.locale.value as Locale
}

/** 浏览器标签页标题也跟着切——否则英文界面的标签页还挂着中文（index.html 里是静态的） */
function syncDocumentTitle(): void {
  document.title = i18n.global.t('Pod Cloud — AI Agent 安全舱')
}
syncDocumentTitle()

export function setLocale(locale: Locale): void {
  i18n.global.locale.value = locale
  localStorage.setItem(STORAGE_KEY, locale)
  document.documentElement.lang = locale
  syncDocumentTitle()
}

/** 供 useI18n() 之外的地方（如 Element Plus 配置）读当前语言 */
export function useLocaleRef() {
  return i18n.global.locale
}

/** Element Plus 的语言包与我们的 locale 对齐（日期选择器、分页文案等） */
export function elementLocale(locale: Locale) {
  return locale === 'en-US' ? elementEn : elementZh
}
