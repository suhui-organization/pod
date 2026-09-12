/**
 * 策略语义摘要：把 `policy_json` 这坨原始 JSON 压成"一眼能读完"的形状。
 *
 * 为什么需要它：策略页要回答的是"这份策略放行了什么、挡住了什么"，
 * 而答案散在 JSON 的三层里——`defaultDecision` / `servers[].{allow,approve,deny}`
 * / `secrets.{deny_input_paths,deny_output_matching}`。逐行读 JSON 不叫人看得懂。
 *
 * 这里只做**机械抽取**（数数、摊平），不做判断。判断在 `policyPosture()`。
 */

/** 单个 server 的摘要 */
export interface ServerSummary {
  name: string
  allow: number
  approve: number
  deny: number
  /** 供应链锁定：`source` 里声明的启动来源（命令或包名），未声明 = null */
  source: string | null
  /** 声明了 source 但没锁版本 —— 供应链防线不完整，值得提示 */
  sourceUnpinned: boolean
  /** 已放行的具体工具名（点开明细时用） */
  allowedTools: string[]
  approvedTools: string[]
  deniedTools: string[]
}

export interface PolicySummary {
  /** `policy_json` 是否能解析成预期的结构。false 时其余字段为空，界面必须显式说明 */
  readable: boolean
  /** 不可读的原因（JSON 语法错误 / 结构不合法），可读时为 null */
  reason: string | null
  /** 未登记的工具走哪条路：`deny` = fail-closed（安全），`allow` = fail-open（危险） */
  defaultDecision: string
  servers: ServerSummary[]
  allow: number
  approve: number
  deny: number
  /** `secrets.deny_input_paths` 条数：命中即拒绝入参 */
  secretPaths: number
  /** `secrets.deny_output_matching` 条数：命中即阻断响应 */
  secretPatterns: number
  /** 输出侧熵检测是否开启（正则之外的未知格式密钥兜底） */
  entropy: boolean
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : []
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}
}

/** 把 `source` 声明渲染成一行可读文本；未声明返回 null */
function describeSource(source: Record<string, unknown>): { text: string; pinned: boolean } {
  const command = typeof source.command === 'string' ? source.command : ''
  const pkg = typeof source.package === 'string' ? source.package : ''
  const version = typeof source.version === 'string' ? source.version : ''
  if (!command && !pkg) return { text: '', pinned: false }
  const name = command || pkg
  return { text: version ? `${name}@${version}` : name, pinned: Boolean(version) }
}

/**
 * 从原始 `policy_json` 字符串算出摘要。**不抛异常**——策略可能是人手写的，
 * 也可能是老版本落库的，解析失败必须变成界面上的一个状态，而不是白屏。
 */
export function summarizePolicy(raw: string): PolicySummary {
  const empty: PolicySummary = {
    readable: false,
    reason: null,
    defaultDecision: '',
    servers: [],
    allow: 0,
    approve: 0,
    deny: 0,
    secretPaths: 0,
    secretPatterns: 0,
    entropy: false,
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (err) {
    return { ...empty, reason: err instanceof Error ? err.message : 'JSON 语法错误' }
  }

  const root = asRecord(parsed)
  const serversObj = asRecord(root.servers)
  const servers: ServerSummary[] = Object.entries(serversObj).map(([name, value]) => {
    const rule = asRecord(value)
    const allowedTools = asStringArray(rule.allow)
    const approvedTools = asStringArray(rule.approve)
    const deniedTools = asStringArray(rule.deny)
    const source = describeSource(asRecord(rule.source))
    return {
      name,
      allow: allowedTools.length,
      approve: approvedTools.length,
      deny: deniedTools.length,
      source: source.text || null,
      sourceUnpinned: Boolean(source.text) && !source.pinned,
      allowedTools,
      approvedTools,
      deniedTools,
    }
  })

  const secrets = asRecord(root.secrets)
  const entropy = asRecord(secrets.entropy)

  return {
    readable: true,
    reason: null,
    defaultDecision:
      typeof root.defaultDecision === 'string' && root.defaultDecision
        ? root.defaultDecision
        : 'deny',
    servers,
    allow: servers.reduce((n, s) => n + s.allow, 0),
    approve: servers.reduce((n, s) => n + s.approve, 0),
    deny: servers.reduce((n, s) => n + s.deny, 0),
    secretPaths: asStringArray(secrets.deny_input_paths).length,
    secretPatterns: asStringArray(secrets.deny_output_matching).length,
    entropy: entropy.enabled === true,
  }
}

export type PostureTone = 'strict' | 'balanced' | 'loose' | 'unreadable'

export interface PolicyPosture {
  tone: PostureTone
  /** 二到四字的结论，显示在列表里 */
  label: string
  /** 一句话说清为什么，只读成员靠它判断该不该细看 */
  note: string
}

/**
 * 把摘要判成一个姿态。
 *
 * 这是整页唯一带"判断"的地方，所以也是唯一需要产品观点的地方——
 * 什么叫做太松？`defaultDecision: allow` 和 `deny` 不是一个量级的差别：
 * 前者意味着**任何没被显式拒绝的工具都自动放行**（fail-open），
 * 一条 deny 清单再长也堵不住它。其余情况下大致按 approve 的密度分档。
 *
 * 口径（已定；改这里等于改产品判断，改前先想清楚它会让哪一类策略被误读）：
 * 1. 解析失败自己占一档，绝不混进正常分档——读不懂就别装作读懂了；
 * 2. `defaultDecision` 不是 deny → 默认放行（fail-open 的优先级高于一切计数器）；
 * 3. 一条规则都没登记 → 空策略，同样是 fail-open 的近亲，归入 loose；
 * 4. 审批超过半数规则 → 审批偏多（准确性没问题，但日常会被频繁打断）；
 * 5. 其余 → 默认拒绝（strict），此时三个计数器才是可靠的读数。
 */
export function policyPosture(summary: PolicySummary): PolicyPosture {
  if (!summary.readable) {
    return { tone: 'unreadable', label: '无法解析', note: '策略内容不是合法 JSON，网关侧行为未知' }
  }

  const explicit = summary.allow + summary.approve + summary.deny

  if (summary.defaultDecision !== 'deny') {
    return {
      tone: 'loose',
      label: '默认放行',
      note: `defaultDecision=${summary.defaultDecision || '未写'}：没被显式拒绝的工具都会放行`,
    }
  }

  if (explicit === 0) {
    return { tone: 'loose', label: '空策略', note: '没有登记任何工具，全部依赖默认拒绝' }
  }

  const approvalHeavy = summary.approve * 2 > explicit
  if (approvalHeavy) {
    return {
      tone: 'balanced',
      label: '审批偏多',
      note: `${summary.approve}/${explicit} 条规则要审批：日常操作会频繁打断`,
    }
  }

  return {
    tone: 'strict',
    label: '默认拒绝',
    note: `放行 ${summary.allow} · 审批 ${summary.approve} · 拒绝 ${summary.deny}，未登记一律拒绝`,
  }
}
