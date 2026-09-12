/**
 * CLI 与各个包的文案国际化。
 *
 * 约定与前端的完全一致：**中文原文即词条键**。
 *   - zh-CN 下 `t('已写入 {path}', { path })` 直接回填原文；
 *   - en-US 下查词表；查不到就回填原文。
 * 所以可以逐条补英文，没补的地方照常显示中文，不会出现 key 名或空白。
 *
 * 为什么不按模块分 key（如 `cli.scan.title`）：这些文案本来就是"给人看的一句话"，
 * 用原文当 key 让**代码即文档**——读到 `t('已写入 {path}')` 就知道界面会显示什么，
 * 不用在词表和调用点之间来回跳。
 *
 * 语言来源（优先级从高到低）：
 *   1. `setLocale()` 显式设置（CLI 的 `--lang` 走这条）
 *   2. `POD_LANG` 环境变量
 *   3. `LC_ALL` / `LANG`（zh_* → 中文，其余 → 英文）
 *   4. 默认 zh-CN
 */

export type Locale = 'zh-CN' | 'en-US'

export const SUPPORTED_LOCALES: readonly Locale[] = ['zh-CN', 'en-US'] as const

let current: Locale | null = null

/** 把 各种写法（en / en_US / en-US.UTF-8）归一成我们支持的两种 */
export function normalizeLocale(raw: string | undefined | null): Locale | null {
  if (!raw) return null
  const tag = raw.trim().toLowerCase().replace('_', '-').split('.')[0]!.split('-')[0]!
  if (tag === 'en') return 'en-US'
  if (tag === 'zh') return 'zh-CN'
  return null
}

export function resolveLocale(env: NodeJS.ProcessEnv = process.env): Locale {
  return (
    normalizeLocale(env.POD_LANG) ??
    normalizeLocale(env.LC_ALL) ??
    normalizeLocale(env.LANG) ??
    'zh-CN'
  )
}

export function setLocale(locale: Locale | null): void {
  current = locale
}

export function getLocale(): Locale {
  return current ?? (current = resolveLocale())
}

/** 词表：key = 中文原文。各语言一个文件，缺失回退到原文。 */
import { enUS } from './en-US.js'

const CATALOGS: Record<Locale, Record<string, string>> = {
  'zh-CN': {}, // 空词表：中文原文即结果
  'en-US': enUS,
}

/**
 * 取一条文案。
 * - `{name}` 占位符用第二个参数替换；
 * - 词表里没有该条时**原样返回**（未翻译 ≠ 出错）；
 * - 占位符缺失时也原样返回，不让格式化失败再制造一个错误。
 */
export function t(message: string, vars?: Record<string, string | number>): string {
  const catalog = CATALOGS[getLocale()]
  const template = catalog[message] ?? message
  if (!vars) return template
  return template.replace(/\{(\w+)\}/g, (m, key: string) =>
    vars[key] === undefined ? m : String(vars[key]),
  )
}

/** 给测试与"查看某语言下这条怎么写"用 */
export function translate(message: string, locale: Locale, vars?: Record<string, string | number>): string {
  const prev = current
  current = locale
  try {
    return t(message, vars)
  } finally {
    current = prev
  }
}

/** 当前语言下的完整词表（供测试断言覆盖率用） */
export function catalog(locale: Locale): Record<string, string> {
  return CATALOGS[locale]
}
