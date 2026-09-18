/**
 * pod guard 的数据模型。
 *
 * 三层，与 posture 同构（事实 → 判定 → 报表），但作用域是**多 agent / 多 harness**：
 *
 *   Facts（本机现在是什么样）
 *     └─ detect()（规则 × 事实 → Finding，纯函数）
 *          └─ renderGuardReport()（漏洞清单 + 建议清单）
 *
 * 两条不可让步的约束：
 * - 采集只读、不联网、不改任何文件（与 pod scan 一致）；
 * - 判定阈值来自用户规则（RuleSet.guard），代码只给默认值。
 */
import type { Severity } from '@podsec/policy';
import type { GuardCategory } from './catalog.js';

/** 一个 harness（agent 平台）的安装事实 */
export interface HarnessFact {
  /** 稳定 id：claude-code / codex / cursor / dsh / openclaw / opencode / gemini-cli … */
  id: string;
  label: string;
  installed: boolean;
  /** 证明"装了"的路径（可点回出处） */
  evidence: string[];
  /** 找到的配置文件（绝对路径） */
  configFiles: string[];
  /** 这个 harness 是否被 pod 纳管（有策略 / 有审计 / 有身份） */
  managed: boolean;
  /** 纳管的证据来源 */
  managedBy: Array<'policy' | 'audit' | 'identity'>;
  /** 在用的 agent 名（从策略/审计里推断；可能与 harness id 不同） */
  agentNames: string[];
}

export type ServerTransport = 'stdio' | 'http' | 'sse';

export interface ServerFact {
  harness: string;
  /** 配置里的 server 名 */
  name: string;
  transport: ServerTransport;
  command: string;
  args: string[];
  url?: string;
  /** 只记变量名，不记值——配置文件里的明文由 secrets 单独掩码报出 */
  envKeys: string[];
  headerKeys: string[];
  /** 从 npx/npm 命令行解析出的包与版本 */
  package?: { name: string; version: string | null };
  /** command+args 的指纹：同名 server 换包/改参数会被 AG-14 抓到 */
  fingerprint: string;
  /** 是否经过 pod 网关 */
  behindGateway: boolean;
  /**
   * 经过网关、但包装命令带 `--record-only`（只录不拦）。
   *
   * 为什么要单独记：接管之后"进了网关"与"真的在拦"是两件事。
   * 只看 behindGateway 会把"只录不拦"显示成"已保护"——那是这个产品最不该犯的错。
   */
  recordOnly: boolean;
  /** 配置文件的可读标签（~ 缩写） */
  file: string;
  scope: 'user' | 'project';
}

export interface HookFact {
  harness: string;
  format: 'claude-hooks' | 'pod-hooks' | 'launchd' | 'codex-notify' | 'gemini-hooks' | 'generic';
  file: string;
  event: string;
  command: string;
  index: number;
  fingerprint: string;
}

export interface SecretFact {
  file: string;
  /** 命中的变量名（结构化配置里能拿到）或 'unknown' */
  key: string;
  category: string;
  /** 掩码显示，永不出现原文 */
  masked: string;
}

export interface MemoryFact {
  harness: string;
  file: string;
  exists: boolean;
  bytes: number;
  /**
   * 是否已被 `rules.memory.paths` 覆盖（即 pod posture 已经在为它做漂移检查）。
   * 未覆盖 = 这份记忆可以被静默改写而没人知道。
   */
  managed: boolean;
}

export interface ProjectFact {
  /** 工作区根 */
  root: string;
  /** 命中项目级自动执行配置的文件（相对 root，便于报表） */
  autoExecConfigs: string[];
  /** 项目里的记忆文件（可被写入 = 可投毒） */
  memoryFiles: string[];
}

export interface Facts {
  harnesses: HarnessFact[];
  servers: ServerFact[];
  hooks: HookFact[];
  secrets: SecretFact[];
  memory: MemoryFact[];
  projects: ProjectFact[];
  /** 已建立的姿态基线路径存在与否——决定漂移类判定能不能成立 */
  baselinePresent: boolean;
  /** 当前生效的规则与策略开关（用于 AG-15/AG-17 的"防线关着"判定） */
  controls: ControlState;
  /** 采集阶段解释不了的东西（解析失败、超限跳过的文件）。绝不静默丢弃 */
  notes: string[];
}

export interface ControlState {
  /** rules.injection.block */
  injectionBlock: boolean;
  injectionBlockAtOrAbove: string;
  /** rules.egress.enabled */
  egressEnabled: boolean;
  /** rules.toolMetadata.block */
  toolMetadataBlock: boolean;
  /** rules.packages.requireVersionPin */
  requireVersionPin: boolean;
  /** rules.packages.requireIntegrity */
  requireIntegrity: boolean;
  /** rules.identity.required */
  identityRequired: boolean;
  /** rules.auditHealth.enabled */
  auditHealthEnabled: boolean;
  /** 有 pod 策略文件的 agent 名（用来判断 harness 是否纳管） */
  policyAgents: string[];
  /** 有审计链的 agent 名 */
  auditAgents: string[];
  /** 有身份的 agent 名 */
  identityAgents: string[];
}

export interface Finding {
  /** 稳定 id：<threat>:<harness>:<subject>，便于基线豁免与跨轮 diff */
  id: string;
  /** 威胁目录编号 AG-xx */
  threat: string;
  category: GuardCategory;
  severity: Severity;
  /** 受影响的 harness / agent（报表分组用） */
  harness: string;
  subject: string;
  message: string;
  /** 证据：能点回出处的具体条目（路径 / 命令行 / 变量名） */
  evidence: string[];
}

export interface RemediationItem {
  /** 这条建议消掉哪些 finding（1 条建议常覆盖多条 finding） */
  threat: string;
  /** 受影响的 harness 列表 */
  affects: string[];
  /** 优先级：severity 排序后的序号，1 最先做 */
  priority: number;
  action: string;
  /**
   * 可直接复制执行的 pod 命令。
   * 只影响一个 harness 时给出**带 harness 的命令**（`pod agents enroll --harness claude-code`），
   * 影响多个 harness 时才是通用形态——一条跑不到实处的命令比没有命令更浪费人。
   */
  command?: string;
  /** 命令跑完之后，用什么证明它生效了 */
  verify?: string;
  why: string;
  automation: 'proposal' | 'manual';
  /** 这条 threat 对 pod 的覆盖程度，避免用户以为做完就绝对安全 */
  coverage: 'covered' | 'partial' | 'gap';
  /** true = 这条动作只能降低风险 / 让它变得可发现，不能根治 */
  residualRisk?: boolean;
  /** 相关 finding 数 */
  count: number;
}

export interface GuardReport {
  generatedAt: string;
  home: string;
  /** 采集到的事实总量，报表用它解释"扫了什么" */
  scanned: {
    harnesses: number;
    installedHarnesses: number;
    servers: number;
    hooks: number;
    secrets: number;
    projects: number;
  };
  findings: Finding[];
  /** 建议清单（按优先级排序）；每条 finding 都能在这里找到对应项 */
  remediations: RemediationItem[];
  /** 覆盖声明：能自动判定的 / 只能提示的 / 看不到的 */
  coverage: {
    automated: number;
    partial: number;
    gap: number;
  };
  /** 采集阶段解释不了的输入（解析失败的配置等）。绝不静默丢弃 */
  notes: string[];
}

export const SEVERITY_ORDER: Record<Severity, number> = { high: 0, medium: 1, low: 2 };

/** 报表分区顺序（与用户的提问顺序一致：先凭据，再供应链，再边界…） */
export const CATEGORY_ORDER: GuardCategory[] = [
  'credential',
  'execution',
  'boundary',
  'network',
  'supply-chain',
  'permission',
  'memory',
  'identity',
  'visibility',
];
