/**
 * 红队场景的数据模型。
 *
 * 核心边界：**场景是数据，不是代码**。
 * 场景数组可以来自内置生成器，也可以来自大模型或人工手写；无论来源如何，
 * 它都只被喂给一个纯函数判定器（`decideCall`），永远不会被执行。
 * 这是"用大模型做自动化红队"在本项目里安全的前提——模型拿不到任何执行权。
 */
import type { Decision, Severity } from '@podsec/policy';

export interface Scenario {
  /** 稳定 id，便于 CI 里做基线豁免与跨版本对比 */
  id: string;
  /** 攻击者想达成什么（给人看的一句话） */
  intent: string;
  /** 对应威胁模型编号（T1/T2/T3/T5…） */
  threat: string;
  server: string;
  tool: string;
  args?: unknown;
  /** 按安全目标，这个调用**应该**得到的判决 */
  expect: Decision;
  /** 为什么应该这样 */
  why: string;
  origin: 'baseline' | 'llm' | 'file';
}

/** blocked = 实际判决不松于预期；bypassed = 实际比预期更宽松（这就是红队发现） */
export type ScenarioOutcome = 'blocked' | 'bypassed';

export interface ScenarioResult {
  scenario: Scenario;
  outcome: ScenarioOutcome;
  actual: Decision;
  /** 判定器命中的规则位置（EvalResult.matched），可追溯到具体规则 */
  matched: string;
  reason: string;
  /** bypassed 的严重级别由 expect 推导：本该 deny 的放行了 = high */
  severity: Severity;
}

export interface RejectedScenario {
  raw: unknown;
  reason: string;
}

export interface RedteamReport {
  generatedAt: string;
  agent: string;
  policyVersion: string;
  total: number;
  blocked: number;
  bypassed: number;
  results: ScenarioResult[];
  findings: ScenarioResult[];
  /** 生成阶段没生成/被丢掉的东西，及其原因（不假装覆盖） */
  notes: string[];
}
