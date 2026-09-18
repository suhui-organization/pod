/**
 * 采集本机健康摘要（端 A → 端 B 的心跳载荷）。
 *
 * 三条纪律，与审计同步保持一致：
 * 1. **只读**：不写任何文件、不改任何状态（`pod sync` 是定时任务，不能有副作用）；
 * 2. **只出计数**：路径、主机名、配置原文、工具参数一律不出本机；
 * 3. **坏消息要说**：采集失败的项报 null 并把原因放进 `errors`，不用 0 冒充"健康"。
 */
import type { RuleSet } from '@podsec/policy';
import { runGuardScan } from '@podsec/guard';
import { loadAllAuditFiles } from './evidence.js';
import type { PodHealth } from './protocol.js';

export interface HealthInput {
  home: string;
  auditDir: string;
  rules: RuleSet;
  now?: Date;
}

/**
 * 审计链健康 + 网关活跃度：一次遍历拿到三个数。
 * `broken > 0` 是最重要的信号——它意味着本地记录被改过（或写坏了），
 * 而云端此前完全看不到这件事。
 */
function auditHealth(auditDir: string): { audit: PodHealth['audit']; errors: string[] } {
  const audit: PodHealth['audit'] = { chains: 0, broken: 0, last_call_at: null };
  const errors: string[] = [];
  let files: ReturnType<typeof loadAllAuditFiles> = [];
  try {
    files = loadAllAuditFiles(auditDir);
  } catch (err) {
    errors.push(`审计目录读取失败：${err instanceof Error ? err.message : String(err)}`);
    return { audit, errors };
  }
  for (const { log } of files) {
    audit.chains++;
    try {
      if (!log.verify().ok) audit.broken++;
    } catch (err) {
      audit.broken++;
      errors.push(`链校验异常：${err instanceof Error ? err.message : String(err)}`);
    }
    for (const entry of log.entries) {
      // 只看工具调用：控制平面事件（config-change / llm-call…）不代表"网关在干活"
      if ((entry.kind ?? 'tool-call') !== 'tool-call') continue;
      if (!audit.last_call_at || entry.ts > audit.last_call_at) audit.last_call_at = entry.ts;
    }
  }
  return { audit, errors };
}

export function buildHealthSnapshot(input: HealthInput): PodHealth {
  const now = input.now ?? new Date();
  const { audit, errors } = auditHealth(input.auditDir);

  let coverage: PodHealth['coverage'] = { servers: 0, unmanaged: 0 };
  let guard: PodHealth['guard'] = null;
  try {
    // 只读扫描：同时给出"有几个 server 绕过网关"与"扫出多少 high/medium/low"
    const scan = runGuardScan({
      home: input.home,
      rules: input.rules,
      auditDir: input.auditDir,
      now,
    });
    coverage = {
      servers: scan.facts.servers.length,
      unmanaged: scan.facts.servers.filter((s) => !s.behindGateway).length,
    };
    const count = (severity: string): number => scan.findings.filter((f) => f.severity === severity).length;
    guard = {
      high: count('high'),
      medium: count('medium'),
      low: count('low'),
      scanned_at: now.toISOString(),
    };
  } catch (err) {
    // 规则写错会 fail-closed 抛错——这里不能吞掉，但也不能让整次同步失败
    errors.push(`guard 扫描失败：${err instanceof Error ? err.message : String(err)}`);
  }

  return { audit, coverage, guard, errors };
}
