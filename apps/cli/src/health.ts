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
import { cliVersion, machineId, type FindingsPayload, type InventoryPayload, type PodHealth } from './protocol.js';
import { runPosture } from './control-plane.js';

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
  return collectReports(input).health;
}

export interface MachineReports {
  health: PodHealth;
  /** ② 资产：这台机器上有什么 */
  inventory: InventoryPayload;
  /** ③ 发现：扫出来的问题（只出威胁/级别/harness/计数） */
  findings: FindingsPayload;
}

/**
 * 一次采集三样东西（健康 / 资产 / 发现）。
 *
 * 为什么合成一次：三样都要跑同一轮只读扫描（guard 只认事实、posture 只读基线），
 * 分三次采会重复扫三遍；而 `pod sync` 是定时任务，成本要可控。
 */
export function collectReports(input: HealthInput & { baselinePath?: string }): MachineReports {
  const now = input.now ?? new Date();
  const { audit, errors } = auditHealth(input.auditDir);

  let coverage: PodHealth['coverage'] = { servers: 0, unmanaged: 0 };
  let guard: PodHealth['guard'] = null;
  const inventory: InventoryPayload = {
    pod_version: cliVersion(),
    rules_version: input.rules.version,
    scanned_at: now.toISOString(),
    machine_id: machineId(),
    coverage: { servers: 0, unmanaged: 0 },
    harnesses: [],
    servers: [],
  };
  const findings: FindingsPayload = {
    scanned_at: now.toISOString(),
    totals: { high: 0, medium: 0, low: 0 },
    findings: [],
  };
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

    // ---- ② 资产：harness 与 server 的身份/状态，仅标识与布尔 ----
    inventory.coverage = coverage;
    inventory.harnesses = scan.facts.harnesses
      .filter((h) => h.installed)
      .map((h) => ({
        id: h.id,
        label: h.label,
        installed: true,
        managed: h.managed,
        managed_by: h.managedBy,
      }));
    inventory.servers = scan.facts.servers.slice(0, 200).map((s) => ({
      name: s.name,
      harness: s.harness,
      transport: s.transport,
      behind_gateway: s.behindGateway,
      record_only: s.recordOnly,
      scope: s.scope,
      package: s.package?.name ?? '',
      pinned: Boolean(s.package?.version && s.package.version !== 'latest'),
    }));

    // ---- ③ 发现：guard 的威胁清单，按 (威胁, 级别, harness) 聚合 ----
    const guardGroups = new Map<string, FindingsPayload['findings'][number]>();
    for (const f of scan.findings) {
      const key = `${f.threat}\u0000${f.severity}\u0000${f.harness}`;
      const row = guardGroups.get(key);
      if (row) row.count++;
      else {
        guardGroups.set(key, {
          source: 'guard',
          key: f.threat,
          severity: f.severity,
          harness: f.harness,
          count: 1,
        });
      }
    }
    findings.findings.push(...guardGroups.values());
  } catch (err) {
    // 规则写错会 fail-closed 抛错——这里不能吞掉，但也不能让整次同步失败
    errors.push(`guard 扫描失败：${err instanceof Error ? err.message : String(err)}`);
  }

  // ---- ③ 发现：控制平面姿态（钩子/配置/记忆/包来源/身份/委托的漂移）----
  try {
    const posture = runPosture({
      rules: input.rules,
      auditDir: input.auditDir,
      baselinePath: input.baselinePath ?? '',
      home: input.home,
      now,
      // 只读采集：绝不因为一次心跳就给本机写链（与 pod posture 默认行为一致）
      writeAudit: false,
    });
    const groups = new Map<string, FindingsPayload['findings'][number]>();
    for (const f of posture.result.findings) {
      const key = `${f.category}\u0000${f.severity}`;
      const row = groups.get(key);
      if (row) row.count++;
      else {
        groups.set(key, {
          source: 'posture',
          key: f.category,
          severity: f.severity,
          harness: 'machine',
          count: 1,
        });
      }
    }
    findings.findings.push(...groups.values());
  } catch (err) {
    errors.push(`posture 扫描失败：${err instanceof Error ? err.message : String(err)}`);
  }

  const rank: Record<string, keyof FindingsPayload['totals']> = {
    high: 'high',
    medium: 'medium',
    low: 'low',
  };
  for (const f of findings.findings) {
    const bucket = rank[f.severity];
    if (bucket) findings.totals[bucket] += f.count;
  }

  return { health: { audit, coverage, guard, errors }, inventory, findings };
}
