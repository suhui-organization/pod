/**
 * `pod guard` 的内核：多 agent / 多 harness 的漏洞扫描与加固建议。
 *
 * 一次 runGuardScan 做四件事（全部本地、只读）：
 *   采集事实 → 按用户规则判定 → 生成建议清单 → 打包成可消费的 GuardReport
 *
 * 它不执行任何加固动作。加固建议要么由用户手动执行，要么由
 * `pod guard remediate --llm` 生成**建议物**（规则包/策略补丁），
 * 而且必须过 pod 既有的放宽守卫才能生效——模型拿了建议权，没拿执行权。
 */
import { existsSync, readFileSync } from 'node:fs';
import { expandHome, type RuleSet } from '@podsec/policy';
import { collectFacts, type CollectOptions } from './collect.js';
import { detect, type DetectOptions } from './detect.js';
import { parseGuardBaseline, type GuardBaseline } from './baseline.js';
import { buildRemediations, renderGuardReport } from './report.js';
import { THREAT_CATALOG } from './catalog.js';
import type { Facts, Finding, GuardReport } from './types.js';

export * from './types.js';
export * from './catalog.js';
export * from './harnesses.js';
export * from './baseline.js';
export * from './watch.js';
export { collectFacts, collectControlState, behindGateway, expandPattern, tilde, parsePackageFrom } from './collect.js';
export type { CollectOptions } from './collect.js';
export { detect, matchesGlob } from './detect.js';
export type { DetectOptions } from './detect.js';
export {
  buildRemediations,
  renderGuardReport,
  guardReportJson,
  renderThreatCatalog,
  categoryLabel,
  SEVERITY_ICON,
  renderFunnelSection,
  paren,
  enumSep,
  findingsLabel,
} from './report.js';
export {
  buildFunnelPlan,
  harnessArg,
  nextCommandFor,
  nextVerifyFor,
} from './funnel.js';
export type { FunnelPlan, NextAction, NextActionKind } from './funnel.js';

export interface GuardScanOptions {
  home: string;
  rules: RuleSet;
  auditDir?: string;
  workspaces?: string[];
  /** 覆盖 rules.guard.baselinePath */
  baselinePath?: string;
  now?: Date;
}

export interface GuardScanResult {
  report: GuardReport;
  facts: Facts;
  findings: Finding[];
  markdown: string;
}

/** 读取基线；文件损坏时抛错而不是当"没有基线"（否则会静默跳过所有漂移检查） */
export function readGuardBaseline(path: string): GuardBaseline | null {
  if (!existsSync(path)) return null;
  try {
    return parseGuardBaseline(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new Error(
      `guard 基线损坏，无法解析：${path}（${err instanceof Error ? err.message : String(err)}）——删掉它重新 pod guard baseline`,
    );
  }
}

export function resolveBaselinePath(rules: RuleSet, home: string): string {
  return expandHome(rules.guard.baselinePath, home);
}

export function runGuardScan(opts: GuardScanOptions): GuardScanResult {
  const now = opts.now ?? new Date();
  const collectOptions: CollectOptions = {
    home: opts.home,
    rules: opts.rules,
    ...(opts.auditDir ? { auditDir: opts.auditDir } : {}),
    ...(opts.workspaces ? { workspaces: opts.workspaces } : {}),
    ...(opts.baselinePath ? { baselinePath: opts.baselinePath } : {}),
    now,
  };
  const facts = collectFacts(collectOptions);
  const baselinePath = opts.baselinePath ?? resolveBaselinePath(opts.rules, opts.home);
  const detectOptions: DetectOptions = {
    home: opts.home,
    baseline: readGuardBaseline(baselinePath),
    now,
  };
  const findings = detect(opts.rules, facts, detectOptions);

  const coverage = { automated: 0, partial: 0, gap: 0 };
  for (const entry of THREAT_CATALOG) {
    // 覆盖声明描述的是"扫描面"，不是"本轮触发了什么"——否则干净机器会显示 0/0/0
    if (entry.coverage === 'covered') coverage.automated++;
    else if (entry.coverage === 'partial') coverage.partial++;
    else coverage.gap++;
  }

  const report: GuardReport = {
    generatedAt: now.toISOString(),
    home: opts.home,
    scanned: {
      harnesses: facts.harnesses.length,
      installedHarnesses: facts.harnesses.filter((h) => h.installed).length,
      servers: facts.servers.length,
      hooks: facts.hooks.length,
      secrets: facts.secrets.length,
      projects: facts.projects.length,
    },
    findings,
    remediations: buildRemediations(findings),
    coverage,
    notes: facts.notes,
  };

  return { report, facts, findings, markdown: renderGuardReport(report) };
}
