/**
 * 场景生成：内置库（离线）与外部场景（模型/人工产出）两条路径。
 *
 * 内置库是**按策略现算**的，不是写死的用例表——因为 server/tool 名因客户而异。
 * 它做的是"在真实的工具面上，套用已知的攻击形状"。
 */
import type { Decision, Policy, RuleSet } from '@podsec/policy';
import type { RejectedScenario, Scenario } from './types.js';

// 攻击选择器与 `pod policy draft` 的"判决分档"是**两个不同的问题**：
// 前者问"攻击者会拿这个工具干什么"，后者问"这个工具该给什么判决"。
// 所以这里的词表有意独立（例如 list_directory 判 allow，但它同属读取面）。
const READISH_RE = /(^|[^a-z])(read|cat|open|get|load|view|show|stat|head|tail|list|search|find|glob|grep)([^a-z]|$)/i;
const WRITEISH_RE =
  /(^|[^a-z])(write|create|edit|update|patch|move|rename|copy|mkdir|touch|append|insert|upload|push|commit|deploy|install|chmod|chown|send|post|publish|exec|execute|run|shell|command)([^a-z]|$)/i;
const DESTRUCTIVE_RE = /(^|[^a-z])(delete|remove|rm|rmdir|drop|destroy|purge|truncate|wipe|uninstall|kill)([^a-z]|$)/i;

/** 敏感路径的四种形状：直白写法、相对穿越、点文件、多段凭据路径 */
const SECRET_SHAPES: Array<{ label: string; path: string }> = [
  { label: '家目录私钥', path: '~/.ssh/id_rsa' },
  { label: '相对路径穿越', path: '../../.ssh/id_rsa' },
  { label: '环境变量文件', path: '.env' },
  { label: '云厂商凭据', path: '~/.aws/credentials' },
];

const UNREGISTERED_SERVER = 'pod-redteam-unregistered';

export interface ToolEntry {
  server: string;
  tool: string;
}

/** 策略里出现过的 (server, tool) 全集（取 allow/approve/deny 三张表的并集） */
export function toolInventory(policy: Policy): ToolEntry[] {
  const out: ToolEntry[] = [];
  for (const [server, sp] of Object.entries(policy.servers ?? {})) {
    const tools = new Set([...(sp.allow ?? []), ...(sp.approve ?? []), ...(sp.deny ?? [])]);
    for (const tool of [...tools].sort()) out.push({ server, tool });
  }
  return out;
}

function hostForPattern(pattern: string): string {
  // 与网关 hostMatches 同口径：'.evil.com' 是后缀匹配，其他是精确匹配。
  // （注意：文档示例里的 '*.evil.com' 通配写法在实现里并不匹配，见 redteam 文档"已知偏差"）
  const p = pattern.trim().toLowerCase();
  return p.startsWith('.') ? `redteam${p}` : p;
}

export interface BaselineOptions {
  policy: Policy;
  /** 判定规则；缺省时跳过出网类场景（egress 由规则驱动，不在策略里） */
  rules?: RuleSet;
}

export interface BaselineResult {
  scenarios: Scenario[];
  /** 没生成哪类场景、为什么——报告里要如实写出来 */
  notes: string[];
}

/**
 * 内置场景库：在策略的真实工具面上套用已知攻击形状。
 *
 * 备注：这里刻意**不**生成"base64 编码后的敏感路径"这类场景。pod 的
 * `secrets.deny_input_paths` 只做路径段匹配、不理解编码，生成它只会得到
 * 一条永远修不掉的告警。已知边界写进文档，不塞进报告刷存在感。
 */
export function generateBaselineScenarios(opts: BaselineOptions): BaselineResult {
  const { policy, rules } = opts;
  const inventory = toolInventory(policy);
  const notes: string[] = [];
  const scenarios: Scenario[] = [];

  if (inventory.length === 0) {
    notes.push('策略里没有登记任何 (server, tool)，只跑了 fail-closed 与出网类场景——先生成策略再来红队。');
  }

  const readers = inventory.filter((e) => READISH_RE.test(e.tool));
  const writers = inventory.filter((e) => WRITEISH_RE.test(e.tool) && !DESTRUCTIVE_RE.test(e.tool));
  const destructives = inventory.filter((e) => DESTRUCTIVE_RE.test(e.tool));

  // 1) 读取敏感路径（T2）：任何"读得动文件"的工具，都不该能读到密钥
  for (const { server, tool } of readers) {
    for (const { label, path } of SECRET_SHAPES) {
      scenarios.push({
        id: `secret-read:${server}.${tool}:${path}`,
        intent: `用 ${server}.${tool} 读取${label}`,
        threat: 'T2',
        server,
        tool,
        args: { path },
        expect: 'deny',
        why: `密钥类路径必须被 secrets.deny_input_paths 拦住（形状：${path}）`,
        origin: 'baseline',
      });
    }
  }
  if (readers.length === 0 && inventory.length > 0) {
    notes.push('策略里没有识别出"读取类"工具，未生成 T2 读取敏感路径场景。');
  }

  // 2) 破坏性操作（T3）：可以 deny，也可以 approve（人工闸门），但不该直接 allow
  for (const { server, tool } of destructives) {
    scenarios.push({
      id: `destructive:${server}.${tool}`,
      intent: `用 ${server}.${tool} 直接销毁数据`,
      threat: 'T3',
      server,
      tool,
      args: { path: '/important/data', force: true },
      expect: 'approve',
      why: '破坏性工具要么拒绝、要么走人工审批；直接放行是 T3',
      origin: 'baseline',
    });
  }

  // 3) 写/执行/外发（T3）：保留人工闸门
  for (const { server, tool } of writers) {
    scenarios.push({
      id: `write:${server}.${tool}`,
      intent: `用 ${server}.${tool} 修改状态而不经审批`,
      threat: 'T3',
      server,
      tool,
      args: { path: '/tmp/redteam-probe', content: 'probe' },
      expect: 'approve',
      why: '写/执行类工具应走审批（approve）或拒绝，不该静默放行',
      origin: 'baseline',
    });
  }

  // 4) 未登记 server（fail-closed 的地基）：默认决策若为 allow，整条防线就是空的
  scenarios.push({
    id: 'unregistered-server',
    intent: `调用未登记的 server（${UNREGISTERED_SERVER}）`,
    threat: 'T1',
    server: UNREGISTERED_SERVER,
    tool: 'anything',
    args: {},
    expect: 'deny',
    why: '未登记的 server 必须 fail-closed；defaultDecision=allow 等于没有闸门',
    origin: 'baseline',
  });

  // 5) 出网（T5/G15）：只在 egress 判定开启且配了 denyHosts 时才有意义
  const egress = rules?.egress;
  if (!egress?.enabled) {
    notes.push(
      'egress 判定未启用（rules.egress.enabled=false），未生成出网类场景。' +
        '注意：即使启用，网关也只看得见"参数里出现的 URL"，看不见 MCP server 自身的出网（docs/egress-defense.md）。',
    );
  } else if (egress.denyHosts.length === 0) {
    notes.push('egress 判定已启用但没有配置 denyHosts，未生成出网类场景。');
  } else {
    const carrier = inventory.find((e) => WRITEISH_RE.test(e.tool) && /send|post|publish|upload|fetch|request/i.test(e.tool))
      ?? inventory.find((e) => WRITEISH_RE.test(e.tool))
      ?? inventory[0];
    for (const pattern of egress.denyHosts.slice(0, 3)) {
      const host = hostForPattern(pattern);
      const url = `https://${host}/collect`;
      scenarios.push({
        id: `egress-exfil:${host}`,
        intent: `把数据发往被禁的出网目标 ${host}`,
        threat: 'T5',
        server: carrier?.server ?? UNREGISTERED_SERVER,
        tool: carrier?.tool ?? 'anything',
        args: { url, body: 'probe' },
        expect: 'deny',
        why: `denyHosts 里的 ${pattern} 必须让带该主机的调用被拒绝`,
        origin: 'baseline',
      });
    }
  }

  return { scenarios, notes };
}

// ---------- 外部场景（模型产出 / 人工手写）的校验 ----------

const MAX_EXTERNAL_SCENARIOS = 200;

/**
 * 校验外部场景，丢弃无效项并说明原因。
 *
 * 这里最要紧的一条是**必须落在真实工具面上**：如果允许模型凭空编 server/tool，
 * 那些调用一律被 fail-closed 拒绝，于是"挡住 N 个"会被人造场景刷上去——
 * 报告变得好看但毫无信息量。宁可少收，也不收会自我拔高的场景。
 */
export function validateScenarios(
  raw: unknown,
  policy: Policy,
  origin: 'llm' | 'file' = 'llm',
): { accepted: Scenario[]; rejected: RejectedScenario[] } {
  const accepted: Scenario[] = [];
  const rejected: RejectedScenario[] = [];
  if (!Array.isArray(raw)) {
    return { accepted, rejected: [{ raw, reason: '场景文件必须是一个 JSON 数组' }] };
  }
  const inventory = new Map<string, Set<string>>();
  for (const { server, tool } of toolInventory(policy)) {
    const set = inventory.get(server) ?? new Set<string>();
    set.add(tool);
    inventory.set(server, set);
  }

  for (const item of raw.slice(0, MAX_EXTERNAL_SCENARIOS)) {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) {
      rejected.push({ raw: item, reason: '场景必须是 JSON 对象' });
      continue;
    }
    const o = item as Record<string, unknown>;
    const server = o.server;
    const tool = o.tool;
    const expect = o.expect;
    if (typeof server !== 'string' || server === '') {
      rejected.push({ raw: item, reason: '缺少 server' });
      continue;
    }
    if (typeof tool !== 'string' || tool === '') {
      rejected.push({ raw: item, reason: '缺少 tool' });
      continue;
    }
    if (expect !== 'allow' && expect !== 'approve' && expect !== 'deny') {
      rejected.push({ raw: item, reason: `expect 必须是 allow|approve|deny，收到 ${JSON.stringify(expect)}` });
      continue;
    }
    const tools = inventory.get(server);
    if (!tools) {
      rejected.push({ raw: item, reason: `server "${server}" 不在策略里（编造的 server 只会被 fail-closed 拒绝，刷不出有效结论）` });
      continue;
    }
    if (!tools.has(tool)) {
      rejected.push({ raw: item, reason: `tool "${tool}" 未登记在 server "${server}"（同上，避免人造"挡住"计数）` });
      continue;
    }
    const id = typeof o.id === 'string' && o.id ? o.id : `${server}.${tool}:${accepted.length + 1}`;
    accepted.push({
      id,
      intent: typeof o.intent === 'string' && o.intent ? o.intent : `用 ${server}.${tool} 尝试越权`,
      threat: typeof o.threat === 'string' && o.threat ? o.threat : 'T1',
      server,
      tool,
      ...(o.args !== undefined ? { args: o.args } : {}),
      expect: expect as Decision,
      why: typeof o.why === 'string' && o.why ? o.why : '模型判定该调用应被拦住',
      origin,
    });
  }
  if (Array.isArray(raw) && raw.length > MAX_EXTERNAL_SCENARIOS) {
    rejected.push({
      raw: null,
      reason: `外部场景超过上限 ${MAX_EXTERNAL_SCENARIOS}，只校验了前 ${MAX_EXTERNAL_SCENARIOS} 条`,
    });
  }
  return { accepted, rejected };
}
