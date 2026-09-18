/**
 * 规则 × 事实 → findings。
 * 所有阈值、正则、严重级别都来自 RuleSet（用户可编辑）；
 * 这里不出现魔法数字，唯一例外是"没有基线时不做漂移判定"这一结构性判断。
 */
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import type { RuleSet, Severity } from '@podsec/policy';
import { expandHome } from '@podsec/policy';
import type { Baseline, Facts, Finding } from './types.js';
import { t } from '@podsec/i18n';
import { SEVERITY_ORDER } from './types.js';

function shortId(...parts: string[]): string {
  return parts.filter(Boolean).join(':');
}

/** 基线指纹：只用内容哈希，不存原文（T2 原则） */
export function buildBaseline(facts: Facts, now: Date = new Date()): Baseline {
  const configs: Record<string, string> = {};
  for (const c of facts.configs) if (c.exists && c.hash) configs[c.path] = c.hash;
  const memory: Record<string, string> = {};
  for (const m of facts.memory) if (m.exists && m.hash) memory[m.path] = m.hash;
  const hooks: Record<string, string> = {};
  for (const h of facts.hooks) hooks[`${h.file}#${h.index}`] = h.fingerprint;
  const packages: Record<string, string> = {};
  for (const p of facts.packages) packages[p.server] = p.fingerprint;
  return { v: 1, createdAt: now.toISOString(), configs, memory, hooks, packages };
}

export interface LoadedBaseline {
  baseline: Baseline;
  path: string;
}

export function parseBaseline(text: string): Baseline {
  const raw = JSON.parse(text) as Partial<Baseline>;
  if (raw.v !== 1 || typeof raw.configs !== 'object') {
    throw new Error('基线文件格式不支持（期望 v=1）');
  }
  return {
    v: 1,
    createdAt: raw.createdAt ?? '',
    configs: raw.configs ?? {},
    memory: raw.memory ?? {},
    hooks: raw.hooks ?? {},
    packages: raw.packages ?? {},
  };
}

/** 命中 glob 的路径（** 与 * 都支持）；用于 trustedSources 判定 */
function matchesGlob(path: string, pattern: string, home: string): boolean {
  const re = new RegExp(
    '^' +
      expandHome(pattern, home)
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*\*/g, '\u0000')
        .replace(/\*/g, '[^/]*')
        .replace(/\u0000/g, '.*') +
      '$',
  );
  return re.test(path);
}

// ---------- 钩子（G3） ----------

export function evaluateHooks(rules: RuleSet, facts: Facts, baseline: Baseline | null, home: string): Finding[] {
  const findings: Finding[] = [];
  const patterns = rules.hookRisk.riskPatterns.map((p) => ({ ...p, regex: new RegExp(p.re) }));

  for (const hook of facts.hooks) {
    const trusted = rules.hookRisk.trustedSources.some((p) => matchesGlob(hook.file, p, home));
    for (const p of patterns) {
      if (!p.regex.test(hook.command)) continue;
      const severity: Severity = trusted ? 'low' : p.severity;
      findings.push({
        id: shortId('hook', `${hook.file}#${hook.index}`, p.id),
        category: 'hook',
        severity,
        subject: `${hook.event} @ ${hook.file}`,
        // 规则里的 why 是用户可改的数据：命中内置默认值时才翻，用户自己写的说明原样显示
        message: t('{why}（规则 {rule}）：{command}', {
          why: p.why ? t(p.why) : t('钩子命中风险规则'),
          rule: p.id,
          command: hook.command,
        }),
        evidence: [hook.command],
      });
    }
    if (rules.hookRisk.requireSigned) {
      const sigFile = `${hook.file}.sig`;
      if (!existsSync(sigFile)) {
        findings.push({
          id: shortId('hook', `${hook.file}#${hook.index}`, 'unsigned'),
          category: 'hook',
          severity: 'medium',
          subject: `${hook.event} @ ${hook.file}`,
          message: t('钩子配置没有配套签名（{sig} 不存在），无法验证来源与时效', { sig: sigFile }),
        });
      }
    }
  }

  if (baseline) {
    const changeSeverity: Severity = rules.freeze.requireApprovalToChange ? 'high' : 'medium';
    const current = new Map<string, string>();
    for (const h of facts.hooks) current.set(`${h.file}#${h.index}`, h.fingerprint);
    for (const [key, hash] of current) {
      const before = baseline.hooks[key];
      if (before === undefined) {
        findings.push({
          id: shortId('hook', key, 'added'),
          category: 'hook',
          severity: changeSeverity,
          subject: key,
          message: t('基线之后新增了生命周期钩子（hook 以主机权限运行，需人工确认来源）'),
        });
      } else if (before !== hash) {
        findings.push({
          id: shortId('hook', key, 'changed'),
          category: 'hook',
          severity: changeSeverity,
          subject: key,
          message: t('生命周期钩子内容与基线不一致（可能被插件更新静默改写）'),
        });
      }
    }
    for (const key of Object.keys(baseline.hooks)) {
      if (!current.has(key)) {
        findings.push({
          id: shortId('hook', key, 'removed'),
          category: 'hook',
          severity: 'low',
          subject: key,
          message: t('基线中的钩子已消失（确认是否为正常卸载）'),
        });
      }
    }
  }

  return findings;
}

// ---------- 配置冻结（G2） ----------

export function evaluateConfigs(rules: RuleSet, facts: Facts, baseline: Baseline | null): Finding[] {
  const findings: Finding[] = [];
  const severity: Severity = rules.freeze.requireApprovalToChange ? 'high' : 'medium';
  if (!baseline) return findings;
  for (const fact of facts.configs) {
    if (!fact.exists || !fact.hash) continue;
    const before = baseline.configs[fact.path];
    if (before === undefined) {
      findings.push({
        id: shortId('config', fact.path, 'added'),
        category: 'config',
        severity,
        subject: fact.path,
        message: t('基线之后新出现的被冻结配置文件（未经带外审批的变更）'),
      });
    } else if (before !== fact.hash) {
      findings.push({
        id: shortId('config', fact.path, 'changed'),
        category: 'config',
        severity,
        subject: fact.path,
        message: t('冻结项内容与基线不一致（审批模式、网关地址、权限范围可能被降级）'),
      });
    }
  }
  for (const path of Object.keys(baseline.configs)) {
    if (!facts.configs.some((c) => c.path === path && c.exists)) {
      findings.push({
        id: shortId('config', path, 'removed'),
        category: 'config',
        severity: 'low',
        subject: path,
        message: t('基线中的配置文件已不存在'),
      });
    }
  }
  return findings;
}

// ---------- 记忆完整性（G14） ----------

export function evaluateMemory(facts: Facts, baseline: Baseline | null): Finding[] {
  const findings: Finding[] = [];
  if (!baseline) return findings;
  for (const fact of facts.memory) {
    if (!fact.exists || !fact.hash) continue;
    const before = baseline.memory[fact.path];
    if (before === undefined) continue;
    if (before !== fact.hash) {
      findings.push({
        id: shortId('memory', fact.path, 'changed'),
        category: 'memory',
        severity: 'high',
        subject: fact.path,
        message: t('长期记忆文件与基线不一致——记忆投毒会影响当前与后续会话，需人工确认写入来源'),
      });
    }
  }
  return findings;
}

// ---------- MCP 包来源（G5） ----------

export function evaluatePackages(rules: RuleSet, facts: Facts, baseline: Baseline | null): Finding[] {
  const findings: Finding[] = [];
  for (const pkg of facts.packages) {
    if (rules.packages.requireVersionPin && !pkg.pinned) {
      findings.push({
        id: shortId('package', pkg.server, 'unpinned'),
        category: 'package',
        severity: 'medium',
        subject: pkg.server,
        message: t('MCP server 来源未锁定版本（{source}）——上游更新会直接进入你的机器', { source: pkg.source }),
        evidence: [pkg.source],
      });
    }
    if (rules.packages.requireIntegrity && baseline) {
      const before = baseline.packages[pkg.server];
      if (before !== undefined && before !== pkg.fingerprint) {
        findings.push({
          id: shortId('package', pkg.server, 'source-changed'),
          category: 'package',
          severity: 'high',
          subject: pkg.server,
          message: t('同名 MCP server 的启动命令/参数与基线不一致（可能被换成另一个包）'),
          evidence: [pkg.source],
        });
      }
    }
  }
  return findings;
}

// ---------- 身份（G11） ----------

export function evaluateIdentities(rules: RuleSet, facts: Facts): Finding[] {
  const findings: Finding[] = [];
  if (!rules.identity.required) return findings;
  for (const id of facts.identities) {
    if (id.origin.length === 1 && id.origin[0] === 'identity') continue; // 只有身份、没有使用者
    if (id.error) {
      // 名字本身就是问题：它永远不可能有身份目录，先让用户改名
      findings.push({
        id: shortId('identity', id.agent, 'invalid-name'),
        category: 'identity',
        severity: 'high',
        subject: id.agent,
        message: t('这个 agent 名无法映射到身份目录（{error}）——先改名，再 pod identity init', { error: id.error }),
      });
      continue;
    }
    if (!id.hasIdentity) {
      findings.push({
        id: shortId('identity', id.agent, 'missing'),
        category: 'identity',
        severity: 'high',
        subject: id.agent,
        message: t('这个 agent 没有独立密码学身份（共享凭证无法回答"是谁做的"）'),
      });
      continue;
    }
    if (!id.hasPrivateKey) {
      findings.push({
        id: shortId('identity', id.agent, 'key-missing'),
        category: 'identity',
        severity: 'medium',
        subject: id.agent,
        message: t('身份存在但私钥缺失，无法签名（fingerprint={fp}）', { fp: id.fingerprint ?? '' }),
      });
    }
  }
  return findings;
}

// ---------- 委托链（G13） ----------

export function evaluateDelegations(facts: Facts): Finding[] {
  const findings: Finding[] = [];
  for (const d of facts.delegations) {
    if (d.ok) continue;
    findings.push({
      id: shortId('delegation', d.file, 'invalid'),
      category: 'delegation',
      severity: 'high',
      subject: d.file,
      message: t('委托链校验失败：{errors}', { errors: d.errors.join('；') }),
      evidence: d.hops,
    });
  }
  return findings;
}

/**
 * 审计链健康（G16）。
 * - 链断裂 → high：这不是"少了几条记录"，而是**从那一点之后一条都写不进去**
 *   （追加前会校验整条链），而 agent 侧完全无感。
 * - 长时间没有新写入 → medium：钩子/网关可能已经静默停摆。
 */
export function evaluateAudits(rules: RuleSet, facts: Facts, now: Date = new Date()): Finding[] {
  const findings: Finding[] = [];
  if (!rules.auditHealth.enabled) return findings;

  // 1) 断链：逐链报 high。这不是"少几条记录"，而是断点之后一条都写不进去——
  //    必须精确到链，不能聚合，否则一条坏链会被同一 agent 的其他链掩盖。
  for (const audit of facts.audits) {
    if (!audit.valid) {
      findings.push({
        id: shortId('audit', `${audit.agent}/${audit.server}`, 'broken'),
        category: 'audit',
        severity: 'high',
        subject: audit.path,
        message: t('审计链在 seq {seq} 处断裂——追加会被拒绝，该链自断点起不再记录任何事件（云端也会以 409 拒收）', { seq: String(audit.brokenAt ?? '?') }),
      });
    }
  }

  // 2) 空闲：按 agent 聚合。期望活跃度是 agent 级属性——"这条 server 没人用"
  //    不是故障（codex 每天在动，但它未必通过 pod 用 filesystem）。
  //    故障信号是"这个 agent 的所有链都不动了"。
  const byAgent = new Map<string, typeof facts.audits>();
  for (const audit of facts.audits) {
    const list = byAgent.get(audit.agent) ?? [];
    list.push(audit);
    byAgent.set(audit.agent, list);
  }
  for (const [agent, chains] of byAgent) {
    const withTs = chains.filter((c) => c.lastTs !== null);
    if (withTs.length === 0) continue;
    const freshest = Math.max(...withTs.map((c) => new Date(c.lastTs!).getTime()));
    const idleHours = (now.getTime() - freshest) / 3_600_000;
    const expectation = rules.auditHealth.expectations.find((e) => e.agent === agent);
    const threshold = expectation?.maxIdleHours ?? rules.auditHealth.maxIdleHours;
    if (idleHours <= threshold) continue;
    findings.push({
      id: shortId('audit', agent, 'idle'),
      category: 'audit',
      severity: 'medium',
      subject: agent,
      message:
        `该 agent 已有 ${Math.floor(idleHours)} 小时没有任何审计写入` +
        `（${expectation ? `期望阈值 ${threshold}h` : `默认阈值 ${threshold}h`}${
          expectation?.why ? `，因为${expectation.why}` : ''
        }）——钩子或网关可能在静默失败`,
      evidence: withTs.map((c) => `${c.server}: last=${c.lastTs} entries=${c.entries}`),
    });
  }
  return findings;
}

export interface EvaluateOptions {
  home: string;
  now?: Date;
}

export function evaluatePosture(
  rules: RuleSet,
  facts: Facts,
  baseline: Baseline | null,
  opts: EvaluateOptions,
): Finding[] {
  const findings = [
    ...evaluateHooks(rules, facts, baseline, opts.home),
    ...evaluateConfigs(rules, facts, baseline),
    ...evaluateMemory(facts, baseline),
    ...evaluatePackages(rules, facts, baseline),
    ...evaluateIdentities(rules, facts),
    ...evaluateDelegations(facts),
    ...evaluateAudits(rules, facts, opts.now ?? new Date()),
  ];
  return findings.sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.id.localeCompare(b.id),
  );
}

export function fingerprintOf(text: string): string {
  return createHash('sha256').update(text).digest('hex').slice(0, 16);
}
