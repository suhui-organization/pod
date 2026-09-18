import type { Severity } from '@podsec/policy';
import type { DelegationToken } from '@podsec/identity';

/** 一条生命周期钩子（G3）：来自 agent 配置或 launchd，命令以主机权限运行 */
export interface HookFact {
  format: 'claude-hooks' | 'pod-hooks' | 'launchd';
  file: string;
  event: string;
  command: string;
  /** 同一文件内的序号，用于基线与报表定位 */
  index: number;
  /** 内容的稳定指纹（基线比对用） */
  fingerprint: string;
}

export interface ConfigFact {
  path: string;
  exists: boolean;
  hash: string | null;
  bytes: number;
}

export interface MemoryFact {
  path: string;
  exists: boolean;
  hash: string | null;
  bytes: number;
}

export interface PackageFact {
  server: string;
  source: string;
  package?: string;
  version?: string;
  /** 版本是否锁死（非 latest、非缺省） */
  pinned: boolean;
  /** command+args 的指纹：同名 server 换包/换参数会被这条抓到 */
  fingerprint: string;
}

export interface IdentityFact {
  agent: string;
  hasIdentity: boolean;
  hasPrivateKey: boolean;
  fingerprint: string | null;
  /** 这个 agent 是从哪发现的（策略文件 / 审计目录 / 已有身份） */
  origin: Array<'policy' | 'audit' | 'identity'>;
  /**
   * 身份无法加载时的原因（例如 agent 名含空格，永远不可能有合法身份目录）。
   *
   * 为什么需要这个字段：`~/.pod/policies` 里一个名字带空格的历史策略文件，
   * 会让 `loadAgentIdentity` 抛错——而那是**只读报表**命令。报表不能因为
   * 一个坏输入整条崩掉（用户会以为"pod 坏了"，而不是"有个文件要改"）。
   */
  error?: string;
}

export interface DelegationFact {
  file: string;
  token: DelegationToken | null;
  ok: boolean;
  errors: string[];
  capabilities: string[];
  depth: number;
  hops: string[];
}

/** 审计链健康（G16）：链是否完整、最后一次写入距今多久 */
export interface AuditFact {
  agent: string;
  server: string;
  path: string;
  entries: number;
  /** 最后一条记录的 ts；空链为 null */
  lastTs: string | null;
  idleHours: number;
  /** 链校验是否通过——false 意味着该 agent 之后的写入会被拒绝（静默丢数据） */
  valid: boolean;
  /** 断链位置（seq），valid=false 时有值 */
  brokenAt?: number;
}

export interface Facts {
  hooks: HookFact[];
  configs: ConfigFact[];
  memory: MemoryFact[];
  packages: PackageFact[];
  identities: IdentityFact[];
  delegations: DelegationFact[];
  audits: AuditFact[];
}

export type FindingCategory =
  | 'hook'
  | 'config'
  | 'memory'
  | 'package'
  | 'identity'
  | 'delegation'
  | 'audit';

export interface Finding {
  /** 稳定 id：category:subject[:ruleId]，便于 CI 做基线豁免 */
  id: string;
  category: FindingCategory;
  severity: Severity;
  subject: string;
  message: string;
  evidence?: string[];
}

export interface Baseline {
  v: 1;
  createdAt: string;
  configs: Record<string, string>;
  memory: Record<string, string>;
  hooks: Record<string, string>;
  packages: Record<string, string>;
}

export interface PostureResult {
  generatedAt: string;
  findings: Finding[];
  facts: Facts;
  /** 基线缺失时为 true——此时漂移类判定不成立（不是"没问题"，是"还没基线"） */
  baselineMissing: boolean;
}

export const SEVERITY_ORDER: Record<Severity, number> = { high: 0, medium: 1, low: 2 };
