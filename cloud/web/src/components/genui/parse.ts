/**
 * GenUI 白名单校验器(P2,对应 DSH dsh-genui):JSON spec → 组件树校验。
 * 校验:组件名白名单、必填字段、嵌套结构;返回 {ok, errors[]}。
 */
export interface GenuiError {
  path: string
  message: string
}

const COMPONENT_WHITELIST = new Set([
  // 布局
  'text', 'row', 'col', 'card', 'divider',
  // 展示
  'badge', 'stat', 'progress', 'table', 'keyvalue', 'list', 'code', 'json',
  // 交互
  'button', 'input', 'select', 'switch', 'tabs',
])

const CONTAINERS = new Set(['row', 'col', 'card', 'tabs'])

function check(spec: any, path: string, errors: GenuiError[]): void {
  if (spec === null || typeof spec !== 'object') {
    errors.push({ path, message: '节点必须是对象' })
    return
  }
  const type = spec.type
  if (typeof type !== 'string' || !COMPONENT_WHITELIST.has(type)) {
    errors.push({ path, message: `未知组件类型: ${String(type)}` })
    return
  }
  if (CONTAINERS.has(type)) {
    const children = spec.children || spec.items || []
    if (!Array.isArray(children)) {
      errors.push({ path, message: `${type} 的 children/items 必须是数组` })
      return
    }
    children.forEach((c, i) => check(c, `${path}.children[${i}]`, errors))
  }
  if (type === 'table') {
    const rows = spec.rows
    if (!Array.isArray(rows) || (spec.columns && !Array.isArray(spec.columns))) {
      errors.push({ path, message: 'table 需要 columns(可选)与 rows 数组' })
    }
  }
  if (type === 'tabs') {
    const items = spec.items
    if (!Array.isArray(items) || !items.every((it: any) => it && typeof it.label === 'string')) {
      errors.push({ path, message: 'tabs 需要 items[{label, content|children}]' })
    } else {
      items.forEach((it: any, i: number) => {
        if (it.children) check(it, `${path}.items[${i}].children`, errors)
      })
    }
  }
  // 交互组件必须带 action
  if (['button', 'input', 'select', 'switch'].includes(type) && !spec.action) {
    errors.push({ path, message: `${type} 交互组件缺少 action` })
  }
}

export function validateGenui(spec: any): { ok: boolean; errors: GenuiError[] } {
  const errors: GenuiError[] = []
  if (!spec || typeof spec !== 'object') {
    return { ok: false, errors: [{ path: '$', message: 'spec 必须是对象' }] }
  }
  const items = spec.items
  if (!Array.isArray(items)) {
    return { ok: false, errors: [{ path: '$.items', message: '缺少 items 数组' }] }
  }
  items.forEach((it, i) => check(it, `$.items[${i}]`, errors))
  return { ok: errors.length === 0, errors }
}

/**
 * 解析消息内容中的 dsh-ui 围栏:```dsh-ui\n{json}\n```
 * 返回 [{type:'md', text} | {type:'ui', spec}] 段序列。
 */
export function splitDshUi(content: string): Array<{ type: 'md' | 'ui'; text?: string; spec?: any }> {
  const parts: Array<{ type: 'md' | 'ui'; text?: string; spec?: any }> = []
  const re = /```dsh-ui\s*\n([\s\S]*?)```/g
  let last = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(content)) !== null) {
    if (m.index > last) {
      parts.push({ type: 'md', text: content.slice(last, m.index) })
    }
    try {
      const spec = JSON.parse(m[1])
      parts.push({ type: 'ui', spec })
    } catch {
      parts.push({ type: 'md', text: m[0] }) // 坏 JSON 降级为代码文本
    }
    last = m.index + m[0].length
  }
  if (last < content.length) {
    parts.push({ type: 'md', text: content.slice(last) })
  }
  if (!parts.length) parts.push({ type: 'md', text: content })
  return parts
}
