/**
 * 规则包（Rule Pack）— B「订阅式加固」的分发单元。
 *
 * 定位：用户手里的 rules.json 是**判定规则本身**；规则包是**这份规则的更新**。
 * 订阅卖的是"对抗知识的持续更新"（新注入词表、新钩子风险模式、新供应链指纹），
 * 而不是锁住功能——这与 D3「本地优先、规则属于用户」并不冲突：包是增量，
 * 应用后规则仍然完整躺在用户自己的 ~/.pod/rules.json 里，可读、可改、可删。
 *
 * 三层防线（对应"订阅通道被投毒"这一类新增威胁）：
 *   1. schema/字段校验：结构不对直接抛错（fail-closed）；
 *   2. Ed25519 验签：包内容与签发者绑定，网络来源必须验签（见 CLI 的 pull）；
 *   3. **放宽守卫**：包不得静默削弱用户已有的加固（detectRelaxations）。
 *      第 3 条是订阅模式最容易被忽略的风险——"更新"本身可以是一次攻击：
 *      只要让订阅者以为在升级，实际把 deny 列表清空即可。
 *
 * 合并语义与 rules.json 完全一致（复用 mergeRules）：对象深合并、数组整体替换。
 * 因此一个"只写了 hookRisk.riskPatterns 的包"会替换掉默认的整张模式表——
 * 这正是放宽守卫要盯住的场景。
 */
import { stableStringify } from '@podsec/audit';
import { signDetached, verifyDetached } from './sign.js';
import {
  mergeRules,
  severityRank,
  validateRules,
  type RuleSet,
  type RuleSetOverride,
  type Severity,
} from './rules.js';

const SEVERITY_NAMES = new Set(['high', 'medium', 'low']);

export const RULE_PACK_SCHEMA = 'pod-rules-pack/v1';

export class RulePackError extends Error {}

export interface RulePack {
  schema: typeof RULE_PACK_SCHEMA;
  /** 包版本。订阅方按它判断"有没有更新"（不解析成 semver，纯标识符） */
  packVersion: string;
  /** 签发者标识。写进审计，便于日后回答"这条规则是谁给的" */
  issuedBy: string;
  /** 签发时间（ISO） */
  issuedAt: string;
  /** 给人看的说明，如"新增 3 条 Claude Code 钩子外联模式" */
  note?: string;
  /** 增量规则（不是完整 RuleSet）：未提到的字段保持用户现值 */
  rules: RuleSetOverride;
}

/** 带签名的规则包：签名对"除 signature 外的全部字段"生效 */
export interface SignedRulePack extends RulePack {
  signature?: string;
}

export interface RulePackMeta {
  packVersion: string;
  issuedBy: string;
  issuedAt?: string;
  note?: string;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * 规范序列化：键排序后序列化**除 signature 外**的全部字段。
 * 排除 signature 是必须的——签名不能把签名自己算进去。
 * 注意：调用方不要构造值为 undefined 的键（stableStringify 会把它写成 null，
 * 导致签名与验签口径不一致）。buildRulePack 用条件展开保证这一点。
 */
export function canonicalRulePack(pack: SignedRulePack): string {
  const { signature: _ignored, ...rest } = pack;
  return stableStringify(rest);
}

/** 构造规则包（未签名）。packVersion / issuedBy 是必填——没有它们无法追溯来源 */
export function buildRulePack(rules: RuleSetOverride, meta: RulePackMeta): RulePack {
  if (!meta.packVersion) throw new RulePackError('packVersion 不能为空');
  if (!meta.issuedBy) throw new RulePackError('issuedBy 不能为空');
  if (!isPlainObject(rules)) throw new RulePackError('rules 必须是一个 JSON 对象（增量规则）');
  return {
    schema: RULE_PACK_SCHEMA,
    packVersion: meta.packVersion,
    issuedBy: meta.issuedBy,
    issuedAt: meta.issuedAt ?? new Date().toISOString(),
    ...(meta.note ? { note: meta.note } : {}),
    rules,
  };
}

/** 解析规则包文本；结构不合法一律抛错（fail-closed，不静默用默认值） */
export function parseRulePack(text: string): SignedRulePack {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new RulePackError(`规则包不是合法 JSON：${err instanceof Error ? err.message : String(err)}`);
  }
  if (!isPlainObject(parsed)) throw new RulePackError('规则包必须是一个 JSON 对象');
  if (parsed.schema !== RULE_PACK_SCHEMA) {
    throw new RulePackError(`规则包 schema 必须是 "${RULE_PACK_SCHEMA}"，收到 ${JSON.stringify(parsed.schema)}`);
  }
  if (typeof parsed.packVersion !== 'string' || parsed.packVersion === '') {
    throw new RulePackError('规则包缺少 packVersion');
  }
  if (typeof parsed.issuedBy !== 'string' || parsed.issuedBy === '') {
    throw new RulePackError('规则包缺少 issuedBy');
  }
  if (typeof parsed.issuedAt !== 'string' || parsed.issuedAt === '') {
    throw new RulePackError('规则包缺少 issuedAt');
  }
  if (!isPlainObject(parsed.rules)) throw new RulePackError('规则包缺少 rules 对象');
  if (parsed.signature !== undefined && typeof parsed.signature !== 'string') {
    throw new RulePackError('规则包 signature 必须是 base64 字符串');
  }
  return parsed as unknown as SignedRulePack;
}

/** 签名：返回带 signature 的新包（原对象不改） */
export function signRulePack(pack: RulePack, privateKeyPem: string): SignedRulePack {
  return { ...pack, signature: signDetached(canonicalRulePack(pack), privateKeyPem) };
}

/** 验签；无签名或任何错误都返回 false */
export function verifyRulePack(pack: SignedRulePack, publicKeyPem: string): boolean {
  if (!pack.signature) return false;
  return verifyDetached(canonicalRulePack(pack), pack.signature, publicKeyPem);
}

// ---------- 规则差异与放宽守卫 ----------

export type ChangeKind = 'added' | 'removed' | 'changed';
/** tighten = 收紧，relax = 放宽，unknown = 方向不确定（如数值阈值，需人看） */
export type ChangeImpact = 'tighten' | 'relax' | 'unknown';

export interface RuleChange {
  /** 定位路径，如 hookRisk.riskPatterns[id=net-egress].severity */
  where: string;
  kind: ChangeKind;
  impact: ChangeImpact;
  from?: string;
  to?: string;
}

/** 数组元素的身份字段：用来把"改了一条"和"删了一条+加了一条"区分开 */
const ELEMENT_KEY_FIELDS = ['id', 'path', 'agent', 'name'] as const;

function elementKey(value: unknown): string | null {
  if (!isPlainObject(value)) return null;
  for (const field of ELEMENT_KEY_FIELDS) {
    const v = value[field];
    if (typeof v === 'string') return `${field}=${v}`;
  }
  return null;
}

function brief(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  const s = typeof value === 'string' ? value : stableStringify(value);
  return s.length > 120 ? `${s.slice(0, 117)}…` : s;
}

/** 方向判定：只对**语义明确**的字段下结论，其余标 unknown 交给人看 */
function classifyChange(where: string, from: unknown, to: unknown): ChangeImpact {
  if (where.endsWith('severity') && typeof from === 'string' && typeof to === 'string') {
    if (SEVERITY_NAMES.has(from) && SEVERITY_NAMES.has(to)) {
      const a = severityRank(from as Severity);
      const b = severityRank(to as Severity);
      return b > a ? 'tighten' : b < a ? 'relax' : 'unknown';
    }
  }
  // 布尔：true→false 是关掉某项检查，一定是放宽
  if (typeof from === 'boolean' && typeof to === 'boolean') {
    if (from && !to) return 'relax';
    if (!from && to) return 'tighten';
  }
  // 数值阈值（maxIdleHours / maxDepth / min_length …）方向因字段而异，
  // ponytail: 不做方向猜测——猜错会让守卫放行真正的放宽。需要精确覆盖时，
  // 在这里为具体路径补方向表（where → 'higher-is-looser' | 'higher-is-tighter'）。
  return 'unknown';
}

function walk(from: unknown, to: unknown, where: string, out: RuleChange[]): void {
  if (from === undefined) {
    out.push({ where, kind: 'added', impact: 'tighten', to: brief(to) });
    return;
  }
  if (to === undefined) {
    out.push({ where, kind: 'removed', impact: 'relax', from: brief(from) });
    return;
  }
  if (Array.isArray(from) && Array.isArray(to)) {
    walkArray(from, to, where, out);
    return;
  }
  if (isPlainObject(from) && isPlainObject(to)) {
    const keys = [...new Set([...Object.keys(from), ...Object.keys(to)])].sort();
    for (const key of keys) walk(from[key], to[key], where ? `${where}.${key}` : key, out);
    return;
  }
  if (stableStringify(from) === stableStringify(to)) return;
  out.push({ where, kind: 'changed', impact: classifyChange(where, from, to), from: brief(from), to: brief(to) });
}

function walkArray(from: unknown[], to: unknown[], where: string, out: RuleChange[]): void {
  const fromKeys = from.map(elementKey);
  const toKeys = to.map(elementKey);
  const keyed = [...fromKeys, ...toKeys].some((k) => k !== null);
  if (!keyed) {
    // 标量数组（路径表、注入词表）：按集合语义比对，丢元素即放宽
    const fromSet = new Set(from.map((v) => stableStringify(v)));
    const toSet = new Set(to.map((v) => stableStringify(v)));
    for (const item of from) {
      if (!toSet.has(stableStringify(item))) out.push({ where, kind: 'removed', impact: 'relax', from: brief(item) });
    }
    for (const item of to) {
      if (!fromSet.has(stableStringify(item))) out.push({ where, kind: 'added', impact: 'tighten', to: brief(item) });
    }
    return;
  }
  const toByKey = new Map<string, number>();
  // 元素没有身份字段时的回退口径：内容完全相同就算"同一项"，避免把
  // "只改了顺序"误报成"删一条 + 加一条"
  const toByContent = new Map<string, number[]>();
  to.forEach((item, j) => {
    const key = toKeys[j]!;
    if (key !== null) toByKey.set(key, j);
    const c = stableStringify(item);
    const list = toByContent.get(c);
    if (list) list.push(j);
    else toByContent.set(c, [j]);
  });

  const matched = new Set<number>();
  const takeContentMatch = (item: unknown): number | undefined => {
    for (const j of toByContent.get(stableStringify(item)) ?? []) {
      if (!matched.has(j)) return j;
    }
    return undefined;
  };

  from.forEach((item, i) => {
    const key = fromKeys[i]!;
    const byKey = key === null ? undefined : toByKey.get(key);
    if (byKey !== undefined && !matched.has(byKey)) {
      matched.add(byKey);
      walk(item, to[byKey], `${where}[${key}]`, out);
      return;
    }
    const byContent = takeContentMatch(item);
    if (byContent !== undefined) {
      matched.add(byContent);
      return;
    }
    out.push({ where: key === null ? `${where}[${i}]` : `${where}[${key}]`, kind: 'removed', impact: 'relax', from: brief(item) });
  });

  to.forEach((item, j) => {
    if (matched.has(j)) return;
    const key = toKeys[j]!;
    out.push({
      where: key === null ? `${where}[${j}]` : `${where}[${key}]`,
      kind: 'added',
      impact: 'tighten',
      to: brief(item),
    });
  });
}

/** 比较两套规则的差异（纯函数）。impact 只对语义明确的字段下结论 */
export function diffRules(from: RuleSet, to: RuleSet): RuleChange[] {
  const out: RuleChange[] = [];
  walk(from as unknown, to as unknown, '', out);
  return out;
}

/** 从差异里挑出**放宽**项——订阅守卫只拦这一类 */
export function detectRelaxations(changes: RuleChange[]): RuleChange[] {
  return changes.filter((c) => c.impact === 'relax');
}

// ---------- 收紧守卫：放宽守卫的反方向 ----------

/** 短于这个长度的子串信号会匹配一切，是笔误而不是安全策略 */
export const MIN_SIGNAL_TEXT_LENGTH = 3;

export interface BlockingExpansion {
  /** 本次新增的、达到阻断级别的信号 id */
  newBlockingSignals: string[];
  /** 短到会匹配一切的新信号 */
  tooShort: Array<{ id: string; text: string }>;
}

/**
 * 检出"阻断面扩张"：本次包新增了多少条会真的拦东西的信号。
 *
 * 为什么放宽守卫不够：它只看"削弱"。而反方向的攻击同样成立——往订阅通道里
 * 推一条文本长度为 1 的信号（或一批把正常输出也命中的模式），就能让**所有**
 * 机器的工具输出被大面积拦下。这不是"更安全"，这是可用性攻击。
 * 更常见的来源其实是自己发错包：词表里手滑写个 "."，效果与攻击一样。
 */
export function detectBlockingExpansion(base: RuleSet, next: RuleSet): BlockingExpansion {
  const before = new Set(base.injection.signals.map((s) => s.id));
  const threshold = severityRank(next.injection.blockAtOrAbove);
  const newBlockingSignals: string[] = [];
  const tooShort: Array<{ id: string; text: string }> = [];
  for (const signal of next.injection.signals) {
    if (before.has(signal.id)) continue;
    if (severityRank(signal.severity) >= threshold) newBlockingSignals.push(signal.id);
    if (signal.text.trim().length < MIN_SIGNAL_TEXT_LENGTH) tooShort.push({ id: signal.id, text: signal.text });
  }
  return { newBlockingSignals, tooShort };
}

/**
 * 一次订阅包最多允许新增多少条"会阻断"的信号？
 *
 * TODO(walden) 这 5–10 行留给你——它是一个纯产品判断，没有唯一正确答案：
 *   · 定得太小：正常的批量规则更新（比如一次补 10 条新注入词）会被自己人拒掉，
 *     订阅的价值打折，用户会开始用 --allow-expansion 绕过，守卫名存实亡；
 *   · 定得太大：一次误发包（或云端被攻破）就能让所有客户的工具输出大面积被拦，
 *     而本地验签是"通过"的——签名只证明来源，不证明这份规则合理。
 * 换个角度：这个数就是"你愿意让一次推送造成多大影响面"的上限。
 *
 * 现状默认：现有阻断级信号的 20%，下限 3 条。
 * 备选思路：改成"每日累计新增上限"（需要本地记状态），比"单次上限"更抗多包慢速推。
 */
export function tighteningBudget(current: RuleSet): number {
  const blocking = current.injection.signals.filter(
    (signal) => severityRank(signal.severity) >= severityRank(current.injection.blockAtOrAbove),
  ).length;
  return Math.max(3, Math.ceil(blocking * 0.2));
}

export interface ApplyRulePackOptions {
  /** 默认 false：包一旦放宽任何已有规则就拒绝应用（fail-closed） */
  allowRelax?: boolean;
  /** 默认 false：包一次把阻断面扩得过大（或含会匹配一切的短信号）时拒绝应用 */
  allowExpansion?: boolean;
}

export interface ApplyRulePackResult {
  rules: RuleSet;
  changes: RuleChange[];
  relaxations: RuleChange[];
}

/**
 * 应用规则包：合并 → 校验 → 差异分析 → 放宽守卫。
 * 校验在**合并后**做——增量包单独看是不完整的，只有合进用户规则才谈得上合法。
 */
export function applyRulePack(
  base: RuleSet,
  pack: RulePack,
  opts: ApplyRulePackOptions = {},
): ApplyRulePackResult {
  const merged = mergeRules(base, pack.rules);
  // mergeRules 对"把整个子对象置为 null"这类输入不做防御，校验器可能抛
  // TypeError 而不是 RuleSetError；统一收成 RulePackError，避免 CLI 吐堆栈。
  try {
    validateRules(merged);
  } catch (err) {
    if (err instanceof RulePackError) throw err;
    throw new RulePackError(
      `规则包 ${pack.packVersion} 与当前规则合并后不合法（已拒绝应用）：${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const changes = diffRules(base, merged);
  const relaxations = detectRelaxations(changes);
  if (relaxations.length > 0 && opts.allowRelax !== true) {
    const preview = relaxations
      .slice(0, 5)
      .map((r) => `  - ${r.where}（${r.kind}）`)
      .join('\n');
    throw new RulePackError(
      `规则包 ${pack.packVersion} 放宽了 ${relaxations.length} 项已有规则，已拒绝应用：\n${preview}\n` +
        `若确认这是有意的，加 --allow-relax 重跑。`,
    );
  }

  // 反方向守卫：不能悄悄削弱你，也不能一次把阻断面炸开（见 detectBlockingExpansion 注释）
  const expansion = detectBlockingExpansion(base, merged);
  if (expansion.tooShort.length > 0 && opts.allowExpansion !== true) {
    const preview = expansion.tooShort
      .slice(0, 5)
      .map((s) => `  - "${s.text}"（${s.id}）`)
      .join('\n');
    throw new RulePackError(
      `规则包 ${pack.packVersion} 新增了会匹配一切的过短信号（子串 < ${MIN_SIGNAL_TEXT_LENGTH} 字符），已拒绝应用：\n${preview}\n` +
        `这类信号会把正常工具输出也拦下——确认无误再加 --allow-expansion 重跑。`,
    );
  }
  const budget = tighteningBudget(base);
  if (expansion.newBlockingSignals.length > budget && opts.allowExpansion !== true) {
    throw new RulePackError(
      `规则包 ${pack.packVersion} 一次新增 ${expansion.newBlockingSignals.length} 条会阻断的信号，` +
        `超过本次上限 ${budget}（上限见 rules-pack.ts 的 tighteningBudget）。\n` +
        `这不是"包有问题"的断言，而是让一次推送的影响面可控；确认无误再加 --allow-expansion 重跑。`,
    );
  }
  return { rules: merged, changes, relaxations };
}
