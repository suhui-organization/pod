/**
 * Agent 资产（Asset Registry）数据契约。
 *
 * 这里只放类型：浏览器端（apps/web）与 Node 端（@podsec/console 聚合、`pod ui`
 * 服务）共用同一份定义，避免两侧字段漂移。
 *
 * 数据全部来自 ~/.pod 下已落盘的产物（policies / audit / graph）+ 本机 agent
 * 发现；控制台不改写任何状态。
 */

export type DecisionState = 'allow' | 'approve' | 'deny';

export type RiskKind =
  /** capability graph 里的毒性链（跨 agent / agent 内） */
  | 'toxic-path'
  /** MCP server 未锁定版本（供应链，T4） */
  | 'unpinned-package'
  /** 审计里出现敏感路径拒绝（T2） */
  | 'sensitive-path'
  /** 有真实调用但没有任何策略绑定——影子 agent（T6） */
  | 'unregistered'
  /** 登记了策略但从未观测到调用 */
  | 'no-activity';

export type RiskSeverity = 'high' | 'medium' | 'low';

export interface AgentRisk {
  kind: RiskKind;
  severity: RiskSeverity;
  /** 一句话结论 */
  label: string;
  /** 证据：能点回出处的具体条目 */
  detail: string;
  count: number;
}

export interface AgentPermissions {
  /** 策略里登记的 server 数 */
  servers: number;
  /** 策略里出现过的工具数（去重） */
  tools: number;
  allow: number;
  approve: number;
  deny: number;
}

export interface AgentDecisionSummary {
  decision: DecisionState;
  server: string;
  tool: string;
  at: string;
  /** false = 仅记录未强制执行（pod record 模式） */
  enforced: boolean;
  reason: string | null;
}

export interface AgentActivity {
  /** 审计条目总数 */
  entries: number;
  lastCallAt: string | null;
  /** 近 7 天调用量，从最早到最新，长度固定 7；无数据处为 0 */
  calls7d: number[];
  calls7dTotal: number;
  deny7d: number;
  approve7d: number;
  lastDecision: AgentDecisionSummary | null;
}

export interface AgentPolicyRef {
  file: string;
  version: string;
  defaultDecision: DecisionState;
}

export interface AgentAsset {
  /** agent 身份（策略里的 policy.agent / 审计里的 entry.agent） */
  id: string;
  label: string;
  /** 平台来源，如 "claude-code" / "cursor" / "openclaw"；无法判定为 null */
  platform: string | null;
  /** active = 近 7 天有调用；idle = 有策略但无近期调用；unobserved = 有调用无策略 */
  status: 'active' | 'idle' | 'unobserved';
  policy: AgentPolicyRef | null;
  permissions: AgentPermissions;
  risks: AgentRisk[];
  activity: AgentActivity;
}

export interface DiscoveredPlatform {
  platform: string;
  detail: string | null;
}

/**
 * 一个可纳管的 harness（`pod guard` 的扫描结果，按控制台的需要裁剪）。
 *
 * 与 `discovered` 的区别：`discovered` 是 v0 的粗粒度列表（只有平台名），
 * 这里带上了纳管所需的全部信息——是否已纳管、建议的 agent 名、server 概况、
 * 漏洞计数——控制台的"加入监控"按钮直接消费它。
 */
export interface HarnessCandidate {
  /** harness id（claude-code / codex / …） */
  id: string;
  label: string;
  installed: boolean;
  /** 证明"装了"的路径（已 ~ 缩写） */
  evidence: string[];
  /** 读到的配置文件（已 ~ 缩写） */
  configFiles: string[];
  /** 已纳管：策略/身份/审计里至少有一处出现 */
  managed: boolean;
  managedBy: Array<'policy' | 'audit' | 'identity'>;
  /**
   * 是否有绑定的策略。
   *
   * 与 managed 分开是必要的：移除纳管后身份与审计目录仍在（身份是刻意保留的），
   * 于是 managed 依然为真——但"没有策略"意味着它其实还没被约束。
   * 界面按这两个字段区分"已纳管"与"只有身份/审计"。
   */
  hasPolicy: boolean;
  /** 已纳管时对应的 agent 名 */
  agentNames: string[];
  /** 建议的 agent 名（默认 = harness id，或已存在的 agent 名） */
  suggestedAgent: string;
  /** 该 harness 配置里的 MCP server 概况 */
  servers: {
    total: number;
    /** 经过 pod 网关的 server 数 */
    behindGateway: number;
    /** 其中还是"只录不拦"的（包装命令带 --record-only） */
    recordOnly: number;
    /** 其中已经在执法的（经过网关且没有 --record-only） */
    enforcing: number;
  };
  /** 该 harness 对应 agent 的审计条目数——用来判断"语料够不够编译策略" */
  corpus: number;
  /** 漏洞计数（来自 pod guard 的检测器） */
  findings: { high: number; medium: number; low: number };
  /** 由控制台纳管的记录（不在台账里为 null，例如用户自己手动建的） */
  enrolledAt: string | null;
  /**
   * 由控制台接管的记录（把 MCP server 包进网关）。null = 没接管过。
   * 有记录不等于当前仍在网关后面——以 servers.behindGateway 为准。
   */
  takeover: { takenOverAt: string; takenOverBy: string; configCount: number } | null;
  /** 由控制台接管的当前模式（没接管过为 null） */
  takeoverMode: 'record-only' | 'enforce' | null;
  /**
   * 包装命令里实际指向的策略文件（已 ~ 缩写）。
   *
   * 为什么必须显示：纳管会写一份零权限策略，编译后又会多一份 draft——于是
   * "一个 agent 两份策略"成了常态。控制台必须直接回答"哪一份是真的在用"，
   * 否则用户只能靠猜。多个 server 指向不同策略时为 null。
   */
  enforcedPolicy: string | null;
}

export interface AgentAssetsCapabilities {
  /** 控制台是否允许写操作（pod ui --read-only 时为 false，前端据此隐藏按钮） */
  writes: boolean;
}

export interface AgentAssetsPayload {
  generatedAt: string;
  podHome: string;
  dirs: { policies: string; audit: string; graph: string };
  /** 本机扫描到的 harness（可纳管），按"已安装 → 未安装"排序 */
  harnesses: HarnessCandidate[];
  capabilities: AgentAssetsCapabilities;
  agents: AgentAsset[];
  totals: {
    agents: number;
    servers: number;
    tools: number;
    calls7d: number;
    deny7d: number;
    agentsWithRisks: number;
  };
  /** 本机发现、但未出现在策略/审计里的 agent 平台（T6 影子 agent 提示） */
  discovered: DiscoveredPlatform[];
  /** 数据缺口与降级说明——没有数据时必须直说，不编造 */
  notes: string[];
}

/**
 * 接管计划与结果（浏览器与服务端共用的契约）。
 *
 * 用 `export type` 转出：类型在编译期被擦除，所以浏览器端不会因此把
 * 服务端的 node:fs 代码带进包。
 */
export type {
  EnforceEntryPlan,
  EnforcePlan,
  EnforceResult,
  EnforceServerPlan,
  PolicySummary,
  TakeoverEntryPlan,
  TakeoverPlan,
  TakeoverResult,
  TakeoverServerPlan,
  RevertResult as TakeoverRevertResult,
} from './takeover.js';
