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

export interface AgentAssetsPayload {
  generatedAt: string;
  podHome: string;
  dirs: { policies: string; audit: string; graph: string };
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
